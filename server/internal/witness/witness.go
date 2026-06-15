// Package witness is the customer-controlled, append-only WITNESS for signed checkpoints (spec §7,
// RCP §10). A checkpoint written to an out-of-vendor-control, object-locked store (e.g. S3 Object
// Lock / WORM) makes a later omission or rewrite of that checkpoint DETECTABLE: the suppressed or
// edited chain no longer matches the immutable witness copy. This closes (partially) threats #1
// (omission) and #15 (single-key self-host suppression of a parallel chain). The witness only ever
// appends; it never mutates or deletes an existing checkpoint entry.
//
// This package also models the TSA client abstraction used to externally anchor a checkpoint's
// `checkpoint_hash` in real time (RFC 3161 trusted timestamp — threat #3 backdating). The witness
// and the TSA are independent trust anchors: the TSA proves "this hash existed by time T", the
// witness proves "this exact checkpoint chain was published and cannot be silently dropped".
package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

// ErrFork is returned when a DIFFERENT checkpoint claims a checkpoint_seq that is already witnessed
// for the project. Two distinct checkpoints at the same seq, signed by the same key, are a fork
// attempt (threat #2). Because the witness is append-only and outside vendor control, the conflict
// is preserved as evidence rather than silently overwritten.
var ErrFork = errors.New("witness: fork — different checkpoint already witnessed at this checkpoint_seq")

// Witness is an append-only log of signed checkpoint JSON, partitioned by project. Append is
// idempotent on identical bytes and rejects a conflicting entry at an already-used checkpoint_seq.
type Witness interface {
	// Append records a checkpoint. Appending the exact same bytes again is a no-op (idempotent).
	// Appending DIFFERENT bytes at a checkpoint_seq that is already present returns ErrFork.
	Append(ctx context.Context, projectID string, checkpointJSON []byte) error
	// List returns all witnessed checkpoints for the project, ordered by checkpoint_seq ascending.
	List(ctx context.Context, projectID string) ([][]byte, error)
}

// seqOf parses checkpoint_seq from a checkpoint JSON document. The seq is the per-project monotonic
// index (from 0, +1, no gaps) the fork check keys on. We deliberately parse only this one field so
// the witness stays agnostic to the rest of the (signed) schema.
func seqOf(checkpointJSON []byte) (int64, error) {
	var cp struct {
		// json.Number tolerates either an integer literal or a quoted number without floating it.
		CheckpointSeq *json.Number `json:"checkpoint_seq"`
	}
	dec := json.NewDecoder(bytes.NewReader(checkpointJSON))
	dec.UseNumber()
	if err := dec.Decode(&cp); err != nil {
		return 0, fmt.Errorf("witness: invalid checkpoint JSON: %w", err)
	}
	if cp.CheckpointSeq == nil {
		return 0, errors.New("witness: checkpoint JSON missing checkpoint_seq")
	}
	n, err := cp.CheckpointSeq.Int64()
	if err != nil {
		return 0, fmt.Errorf("witness: checkpoint_seq not an integer: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("witness: checkpoint_seq must be >= 0, got %d", n)
	}
	return n, nil
}

// canonHash is the identity of a checkpoint entry for idempotency/fork comparison. We hash the RAW
// bytes the caller appended — the bytes the customer actually published — so "identical" means
// byte-identical, never a re-serialization that might differ. (The checkpoint is already canonical
// signed JSON from the core; the witness does not re-canonicalize.)
func canonHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- MemWitness (tests / single-node dev) ----

// MemWitness is an in-memory append-only Witness. Entries are immutable once stored.
type MemWitness struct {
	mu       sync.Mutex
	projects map[string]map[int64]memEntry // projectID -> seq -> entry
}

type memEntry struct {
	bytes []byte // a private copy; never handed out by reference
	hash  string
}

func NewMemWitness() *MemWitness {
	return &MemWitness{projects: map[string]map[int64]memEntry{}}
}

func (w *MemWitness) Append(ctx context.Context, projectID string, checkpointJSON []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if projectID == "" {
		return errors.New("witness: projectID required")
	}
	seq, err := seqOf(checkpointJSON)
	if err != nil {
		return err
	}
	h := canonHash(checkpointJSON)

	w.mu.Lock()
	defer w.mu.Unlock()
	byProj := w.projects[projectID]
	if byProj == nil {
		byProj = map[int64]memEntry{}
		w.projects[projectID] = byProj
	}
	if existing, ok := byProj[seq]; ok {
		if existing.hash == h {
			return nil // idempotent: identical bytes re-appended
		}
		// Append-only: a different checkpoint at a used seq is a fork. We do NOT overwrite.
		return ErrFork
	}
	// store a defensive copy so a later mutation of the caller's slice can't alter the witness entry
	cp := make([]byte, len(checkpointJSON))
	copy(cp, checkpointJSON)
	byProj[seq] = memEntry{bytes: cp, hash: h}
	return nil
}

func (w *MemWitness) List(ctx context.Context, projectID string) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	byProj := w.projects[projectID]
	seqs := make([]int64, 0, len(byProj))
	for s := range byProj {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := make([][]byte, 0, len(seqs))
	for _, s := range seqs {
		e := byProj[s]
		cp := make([]byte, len(e.bytes))
		copy(cp, e.bytes) // hand out a copy; the stored entry stays immutable
		out = append(out, cp)
	}
	return out, nil
}

// ---- FSWitness (durable, one immutable file per checkpoint) ----

// FSWitness persists each checkpoint as its own immutable file:
//
//	<root>/<sanitized projectID>/checkpoint-<zero-padded seq>.json
//
// Append-only is enforced two ways:
//  1. We never open an existing entry for writing. A new entry is written to a temp file and then
//     os.Link'd into place; os.Link FAILS if the destination already exists, so a concurrent or
//     repeated writer can never clobber a stored checkpoint (the kernel makes create-or-fail atomic).
//  2. On any link collision we read the stored bytes back: identical bytes => idempotent success;
//     different bytes => ErrFork (the existing file is left untouched).
//
// SECURITY: this local-disk implementation is for dev/tests and single-node durability. The real
// guarantee in spec §7 requires the bytes to land in an OUT-OF-VENDOR-CONTROL, object-locked
// (WORM / S3 Object Lock retention) bucket so that even an operator with disk access cannot rewrite
// history. We document that limit rather than imply WORM semantics that local files cannot provide.
type FSWitness struct {
	root string
	mu   sync.Mutex // serializes a project's append (single-node); cross-host safety is the link() race-free create
}

func NewFSWitness(root string) (*FSWitness, error) {
	if root == "" {
		return nil, errors.New("witness: FSWitness root required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("witness: mkdir root: %w", err)
	}
	return &FSWitness{root: root}, nil
}

// sanitizeProject keeps a project's witness files inside its own directory and rejects any id that
// could traverse the tree (path separators, "..", control chars). The witness must never be coaxed
// into writing outside <root> by a crafted project id.
func sanitizeProject(projectID string) (string, error) {
	if projectID == "" {
		return "", errors.New("witness: projectID required")
	}
	if len(projectID) > 200 {
		return "", errors.New("witness: projectID too long")
	}
	for _, r := range projectID {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !ok {
			return "", fmt.Errorf("witness: projectID has disallowed character %q", r)
		}
	}
	// reject "." / ".." and anything that would still resolve to a traversal after cleaning
	if projectID == "." || projectID == ".." || filepath.Clean(projectID) != projectID {
		return "", errors.New("witness: invalid projectID")
	}
	return projectID, nil
}

func (w *FSWitness) projectDir(projectID string) (string, error) {
	safe, err := sanitizeProject(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(w.root, safe), nil
}

// entryName is zero-padded so a lexical directory listing is also seq order.
func entryName(seq int64) string {
	return fmt.Sprintf("checkpoint-%016d.json", seq)
}

func (w *FSWitness) Append(ctx context.Context, projectID string, checkpointJSON []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	seq, err := seqOf(checkpointJSON)
	if err != nil {
		return err
	}
	dir, err := w.projectDir(projectID)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("witness: mkdir project: %w", err)
	}
	dst := filepath.Join(dir, entryName(seq))

	// Write to a temp file in the same dir, then hard-link it into place. os.Link returns an error
	// if dst already exists, which is exactly the append-only invariant we want.
	tmp, err := os.CreateTemp(dir, ".tmp-"+strconv.FormatInt(seq, 10)+"-*")
	if err != nil {
		return fmt.Errorf("witness: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // always clean up the temp (link leaves the dst, not the temp)
	if _, err := tmp.Write(checkpointJSON); err != nil {
		tmp.Close()
		return fmt.Errorf("witness: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("witness: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("witness: close temp: %w", err)
	}

	if err := os.Link(tmpName, dst); err != nil {
		if os.IsExist(err) {
			// An entry already exists at this seq. Read it back and decide idempotent vs fork.
			existing, rerr := os.ReadFile(dst)
			if rerr != nil {
				return fmt.Errorf("witness: read existing entry: %w", rerr)
			}
			if canonHash(existing) == canonHash(checkpointJSON) {
				return nil // idempotent re-append of identical bytes
			}
			return ErrFork // different bytes at a used seq — never overwrite the witnessed file
		}
		return fmt.Errorf("witness: link entry: %w", err)
	}
	return nil
}

func (w *FSWitness) List(ctx context.Context, projectID string) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := w.projectDir(projectID)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no checkpoints witnessed yet for this project
		}
		return nil, fmt.Errorf("witness: read project dir: %w", err)
	}
	type item struct {
		seq   int64
		bytes []byte
	}
	var items []item
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || len(name) < len("checkpoint-") || name[:len("checkpoint-")] != "checkpoint-" {
			continue // skip stray/temp files; only committed entries match the pattern
		}
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			return nil, fmt.Errorf("witness: read entry %s: %w", name, rerr)
		}
		seq, serr := seqOf(b)
		if serr != nil {
			return nil, fmt.Errorf("witness: corrupt entry %s: %w", name, serr)
		}
		items = append(items, item{seq: seq, bytes: b})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	out := make([][]byte, len(items))
	for i, it := range items {
		out[i] = it.bytes
	}
	return out, nil
}
