// Package keylineage implements averin's recording-key rotation (AVE-04): the retired-key list, the signed
// key-rotation statements that link a retiring key to its successor, and the startup checks that refuse an
// inconsistent lineage. The statement format and signing domain are the ones core/src/verify.rs
// (evaluate_key_rotations) verifies offline; the two must stay byte-identical.
package keylineage

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Tag is the Ed25519 signing domain of a key-rotation statement (core verify::KEY_ROTATION_SIG_TAG).
const Tag = "averin.key_rotation.v1"

const pubPrefix = "ed25519pub:"

// Hasher is the keyless RCP-canonical digest the Rust core provides (the single cross-language canonicaliser).
type Hasher interface {
	RcpEvidenceHash(bodyJSON string) (string, error)
}

// Key is a recording key as the bundle publishes it.
type Key struct {
	ID        string
	Epoch     int64
	PublicKey string // ed25519pub:<base64url>
}

// Retired is a recording key that no longer signs. Status is "retired" (a scheduled rotation: its records stay
// integrity-proven) or "compromised" (records not anchored before ChangedAt do not elevate).
type Retired struct {
	Key
	Status    string
	ChangedAt string // canonical RCP timestamp
}

var canonTS = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$`)

// IsCanonicalTS reports whether s is a canonical RCP timestamp (YYYY-MM-DDThh:mm:ss.mmmZ).
func IsCanonicalTS(s string) bool { return canonTS.MatchString(s) }

func keyMap(k Key) map[string]any {
	return map[string]any{"signing_key_id": k.ID, "key_epoch": k.Epoch, "public_key": k.PublicKey}
}

// PubString renders an Ed25519 public key as the ed25519pub: string.
func PubString(pub ed25519.PublicKey) string {
	return pubPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

func decodePub(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(s, pubPrefix)
	if !ok {
		return nil, fmt.Errorf("public key lacks the %s prefix", pubPrefix)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is not a base64url Ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

// preimage is LP4(tag) || utf8(digest), the message sign::sign signs (RCP section 9.2).
func preimage(digest string) []byte {
	pre := make([]byte, 0, 4+len(Tag)+len(digest))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(Tag)))
	pre = append(pre, lp[:]...)
	pre = append(pre, Tag...)
	return append(pre, digest...)
}

func sign(digest string, sk ed25519.PrivateKey) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, preimage(digest)))
}

func verifySig(digest, sig string, pub ed25519.PublicKey) bool {
	raw, ok := strings.CutPrefix(sig, "ed25519:")
	if !ok {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, preimage(digest), b)
}

func digestOf(h Hasher, body map[string]any) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return h.RcpEvidenceHash(string(b))
}

// Sign builds a signed rotation statement. reason is "scheduled" (oldSK signs too, so a verifier that pinned the
// old key accepts the successor) or "compromise" (oldSK may be nil; the stolen key proves nothing, so the
// statement is signed by the successor alone and extends no trust).
func Sign(h Hasher, old, successor Key, rotatedAt, reason string, oldSK, newSK ed25519.PrivateKey) (map[string]any, error) {
	if reason != "scheduled" && reason != "compromise" {
		return nil, fmt.Errorf("reason must be scheduled or compromise")
	}
	if !IsCanonicalTS(rotatedAt) {
		return nil, fmt.Errorf("rotated_at %q is not a canonical timestamp YYYY-MM-DDThh:mm:ss.mmmZ", rotatedAt)
	}
	if reason == "scheduled" && oldSK == nil {
		return nil, fmt.Errorf("a scheduled rotation needs the old key's signature (use reason compromise when the old key is lost or stolen)")
	}
	if newSK == nil {
		return nil, fmt.Errorf("the successor key must sign")
	}
	if got := PubString(newSK.Public().(ed25519.PublicKey)); got != successor.PublicKey {
		return nil, fmt.Errorf("the successor seed does not match its public key")
	}
	if reason == "scheduled" {
		if got := PubString(oldSK.Public().(ed25519.PublicKey)); got != old.PublicKey {
			return nil, fmt.Errorf("the old seed does not match its public key")
		}
	}
	body := map[string]any{
		"kind": "key_rotation", "old_key": keyMap(old), "new_key": keyMap(successor),
		"rotated_at": rotatedAt, "reason": reason,
	}
	digest, err := digestOf(h, body)
	if err != nil {
		return nil, err
	}
	body["sig_new"] = sign(digest, newSK)
	if reason == "scheduled" {
		body["sig_old"] = sign(digest, oldSK)
	}
	return body, nil
}

func keyOf(v any) (Key, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return Key{}, false
	}
	id, ok1 := m["signing_key_id"].(string)
	ep, ok2 := m["key_epoch"].(float64)
	pk, ok3 := m["public_key"].(string)
	if !ok1 || !ok2 || !ok3 || ep != float64(int64(ep)) || id == "" {
		return Key{}, false
	}
	return Key{ID: id, Epoch: int64(ep), PublicKey: pk}, true
}

// Verified is a statement that passed Verify.
type Verified struct {
	Old, New  Key
	RotatedAt string
	Reason    string
	Raw       map[string]any
}

// Verify checks one statement exactly as the offline verifier does: closed field set, canonical time, both
// signatures where required. It fails closed on anything unexpected.
func Verify(h Hasher, st map[string]any) (Verified, error) {
	// A statement built in memory and one decoded from the rotations file must be judged identically.
	raw, err := json.Marshal(st)
	if err != nil {
		return Verified{}, err
	}
	st = nil
	if err := json.Unmarshal(raw, &st); err != nil || st == nil {
		return Verified{}, fmt.Errorf("statement is not a JSON object")
	}
	for k := range st {
		switch k {
		case "kind", "old_key", "new_key", "rotated_at", "reason", "sig_new", "sig_old":
		default:
			return Verified{}, fmt.Errorf("unknown field %q", k)
		}
	}
	if st["kind"] != "key_rotation" {
		return Verified{}, fmt.Errorf("kind is not key_rotation")
	}
	reason, _ := st["reason"].(string)
	if reason != "scheduled" && reason != "compromise" {
		return Verified{}, fmt.Errorf("reason is not scheduled|compromise")
	}
	at, _ := st["rotated_at"].(string)
	if !IsCanonicalTS(at) {
		return Verified{}, fmt.Errorf("rotated_at is not a canonical timestamp")
	}
	old, ok1 := keyOf(st["old_key"])
	nw, ok2 := keyOf(st["new_key"])
	if !ok1 || !ok2 {
		return Verified{}, fmt.Errorf("old_key/new_key must be exactly {signing_key_id, key_epoch, public_key}")
	}
	if (old.ID == nw.ID && old.Epoch == nw.Epoch) || old.PublicKey == nw.PublicKey {
		return Verified{}, fmt.Errorf("old and new key are the same key")
	}
	opub, err := decodePub(old.PublicKey)
	if err != nil {
		return Verified{}, fmt.Errorf("old_key: %w", err)
	}
	npub, err := decodePub(nw.PublicKey)
	if err != nil {
		return Verified{}, fmt.Errorf("new_key: %w", err)
	}
	body := map[string]any{}
	for k, v := range st {
		if k != "sig_new" && k != "sig_old" {
			body[k] = v
		}
	}
	digest, err := digestOf(h, body)
	if err != nil {
		return Verified{}, err
	}
	if s, _ := st["sig_new"].(string); !verifySig(digest, s, npub) {
		return Verified{}, fmt.Errorf("sig_new does not verify under the new key")
	}
	if reason == "scheduled" {
		if s, _ := st["sig_old"].(string); !verifySig(digest, s, opub) {
			return Verified{}, fmt.Errorf("a scheduled rotation needs a valid sig_old from the old key")
		}
	}
	return Verified{Old: old, New: nw, RotatedAt: at, Reason: reason, Raw: st}, nil
}

// Lineage is the validated key history a server publishes in every bundle.
type Lineage struct {
	Current   Key
	Retired   []Retired
	Rotations []map[string]any
}

// Entries is the bundle `keys` array: the current key first, then every retired key with its status.
func (l *Lineage) Entries(currentStatus string) []any {
	out := []any{map[string]any{
		"signing_key_id": l.Current.ID, "key_epoch": l.Current.Epoch,
		"public_key": l.Current.PublicKey, "key_status": currentStatus,
	}}
	for _, r := range l.Retired {
		out = append(out, map[string]any{
			"signing_key_id": r.ID, "key_epoch": r.Epoch, "public_key": r.PublicKey,
			"key_status": r.Status, "status_changed_at": r.ChangedAt,
		})
	}
	return out
}

// RetiredFile is the JSON shape of AVERIN_RETIRED_SIGNING_KEYS_FILE.
type RetiredFile struct {
	SigningKeyID    string `json:"signing_key_id"`
	KeyEpoch        int64  `json:"key_epoch"`
	PublicKey       string `json:"public_key"`
	KeyStatus       string `json:"key_status"`
	StatusChangedAt string `json:"status_changed_at"`
}

// Build validates the configuration and returns the lineage, or an error that must stop the server (a lineage
// that does not hold together would publish history no verifier can check):
//   - every retired key has a canonical status_changed_at and status retired|compromised, differs from the
//     current key and from every other retired key (id/epoch and public key);
//   - every statement verifies (Verify);
//   - every retired key is the old_key of a statement, so no retired key is left unlinked;
//   - the current key is the new_key of a statement when any key is retired (the chain reaches the key in use);
//   - a statement names only the current key and the retired keys.
func Build(h Hasher, current Key, retired []RetiredFile, statements []map[string]any) (*Lineage, error) {
	if current.ID == "" || current.Epoch < 0 {
		return nil, fmt.Errorf("current signing key id/epoch is invalid")
	}
	l := &Lineage{Current: current}
	seen := map[string]bool{fmt.Sprintf("%s/%d", current.ID, current.Epoch): true}
	seenPub := map[string]bool{current.PublicKey: true}
	for i, r := range retired {
		if r.SigningKeyID == "" || r.KeyEpoch < 0 {
			return nil, fmt.Errorf("retired key %d: signing_key_id/key_epoch invalid", i)
		}
		if r.KeyStatus != "retired" && r.KeyStatus != "compromised" {
			return nil, fmt.Errorf("retired key %d: key_status must be retired or compromised", i)
		}
		if !IsCanonicalTS(r.StatusChangedAt) {
			return nil, fmt.Errorf("retired key %d: status_changed_at must be a canonical timestamp", i)
		}
		if _, err := decodePub(r.PublicKey); err != nil {
			return nil, fmt.Errorf("retired key %d: %w", i, err)
		}
		id := fmt.Sprintf("%s/%d", r.SigningKeyID, r.KeyEpoch)
		if seen[id] || seenPub[r.PublicKey] {
			return nil, fmt.Errorf("retired key %d duplicates the current key or another retired key", i)
		}
		seen[id], seenPub[r.PublicKey] = true, true
		l.Retired = append(l.Retired, Retired{
			Key:    Key{ID: r.SigningKeyID, Epoch: r.KeyEpoch, PublicKey: r.PublicKey},
			Status: r.KeyStatus, ChangedAt: r.StatusChangedAt,
		})
	}
	known := map[string]string{} // id/epoch -> public key
	known[fmt.Sprintf("%s/%d", current.ID, current.Epoch)] = current.PublicKey
	for _, r := range l.Retired {
		known[fmt.Sprintf("%s/%d", r.ID, r.Epoch)] = r.PublicKey
	}
	linkedOld := map[string]bool{}
	reachesCurrent := false
	for i, st := range statements {
		v, err := Verify(h, st)
		if err != nil {
			return nil, fmt.Errorf("key rotation %d: %w", i, err)
		}
		for _, k := range []Key{v.Old, v.New} {
			if pk, ok := known[fmt.Sprintf("%s/%d", k.ID, k.Epoch)]; !ok || pk != k.PublicKey {
				return nil, fmt.Errorf("key rotation %d names key %s/%d, which is neither the current key nor a configured retired key", i, k.ID, k.Epoch)
			}
		}
		linkedOld[fmt.Sprintf("%s/%d", v.Old.ID, v.Old.Epoch)] = true
		if v.New.ID == current.ID && v.New.Epoch == current.Epoch {
			reachesCurrent = true
		}
		l.Rotations = append(l.Rotations, st)
	}
	for _, r := range l.Retired {
		if !linkedOld[fmt.Sprintf("%s/%d", r.ID, r.Epoch)] {
			return nil, fmt.Errorf("retired key %s/%d has no signed rotation statement linking it to a successor (averin-keyrotate)", r.ID, r.Epoch)
		}
	}
	if len(l.Retired) > 0 && !reachesCurrent {
		return nil, fmt.Errorf("no key rotation statement names the current key %s/%d as its successor", current.ID, current.Epoch)
	}
	return l, nil
}
