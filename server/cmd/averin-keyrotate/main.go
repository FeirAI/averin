// Command averin-keyrotate records a rotation of averin's own recording key (AVE-04). It signs a key-rotation
// statement that links the retiring key to its successor and appends it, together with the retired-key entry,
// to the two files the server reads (AVERIN_KEY_ROTATIONS_FILE and AVERIN_RETIRED_SIGNING_KEYS_FILE).
//
// Scheduled rotation (the old key is still held): both seeds sign, so an auditor who pinned only the old key
// accepts every record the new key signs.
//
//	averin-keyrotate --reason scheduled --rotated-at 2026-11-01T00:00:00.000Z \
//	  --old-id k0 --old-epoch 0 --old-seed-file old.seed \
//	  --new-id k1 --new-epoch 1 --new-seed-file new.seed \
//	  --rotations-file rotations.json --retired-file retired.json
//
// Compromise (the old key is stolen or lost): only the successor signs, the old key is listed as compromised
// from --rotated-at, and the statement extends no trust: auditors must pin the new key themselves. Give the old
// PUBLIC key with --old-public-key instead of --old-seed-file.
//
// Then restart averin-server with AVERIN_SIGNING_SEED(_FILE) set to the new seed, AVERIN_SIGNING_KEY_ID and
// AVERIN_SIGNING_KEY_EPOCH set to the new id and epoch, and both files configured. Anchor a checkpoint under the
// old key before the switch (see docs/dev/KEY-ROTATION.md).
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/keylineage"
)

func main() {
	reason := flag.String("reason", "scheduled", "scheduled | compromise")
	at := flag.String("rotated-at", "", "rotation time, canonical UTC YYYY-MM-DDThh:mm:ss.mmmZ (for a compromise: the earliest time the old key may have been misused)")
	oldID := flag.String("old-id", "", "old signing_key_id")
	oldEpoch := flag.Int64("old-epoch", 0, "old key_epoch")
	oldSeed := flag.String("old-seed-file", "", "owner-only file with the old 64-hex seed (scheduled rotation)")
	oldPub := flag.String("old-public-key", "", "old ed25519pub:... (compromise, when the seed is gone)")
	newID := flag.String("new-id", "", "new signing_key_id")
	newEpoch := flag.Int64("new-epoch", 1, "new key_epoch (must differ from the old one)")
	newSeed := flag.String("new-seed-file", "", "owner-only file with the new 64-hex seed")
	rotFile := flag.String("rotations-file", "", "JSON array file to append the statement to (AVERIN_KEY_ROTATIONS_FILE)")
	retFile := flag.String("retired-file", "", "JSON array file to append the retired-key entry to (AVERIN_RETIRED_SIGNING_KEYS_FILE)")
	flag.Parse()

	if *oldID == "" || *newID == "" || *at == "" || *rotFile == "" || *retFile == "" || *newSeed == "" {
		fatal("--old-id, --new-id, --rotated-at, --new-seed-file, --rotations-file and --retired-file are required")
	}
	newSK, err := loadKey(*newSeed)
	if err != nil {
		fatal("new seed: " + err.Error())
	}
	var oldSK ed25519.PrivateKey
	oldPubStr := strings.TrimSpace(*oldPub)
	if *oldSeed != "" {
		if oldSK, err = loadKey(*oldSeed); err != nil {
			fatal("old seed: " + err.Error())
		}
		got := keylineage.PubString(oldSK.Public().(ed25519.PublicKey))
		if oldPubStr != "" && oldPubStr != got {
			fatal("--old-public-key does not match --old-seed-file")
		}
		oldPubStr = got
	}
	if oldPubStr == "" {
		fatal("give --old-seed-file (scheduled) or --old-public-key (compromise)")
	}
	h, err := core.New(strings.Repeat("0", 64)) // keyless RCP digest only
	if err != nil {
		fatal("init core: " + err.Error())
	}
	old := keylineage.Key{ID: *oldID, Epoch: *oldEpoch, PublicKey: oldPubStr}
	succ := keylineage.Key{ID: *newID, Epoch: *newEpoch, PublicKey: keylineage.PubString(newSK.Public().(ed25519.PublicKey))}
	stmt, err := keylineage.Sign(h, old, succ, *at, *reason, oldSK, newSK)
	if err != nil {
		fatal(err.Error())
	}
	if _, err := keylineage.Verify(h, stmt); err != nil { // never write a statement the server would refuse
		fatal("self-check: " + err.Error())
	}
	status := "retired"
	if *reason == "compromise" {
		status = "compromised"
	}
	entry := keylineage.RetiredFile{SigningKeyID: old.ID, KeyEpoch: old.Epoch, PublicKey: old.PublicKey, KeyStatus: status, StatusChangedAt: *at}
	if err := appendJSON(*rotFile, stmt); err != nil {
		fatal(err.Error())
	}
	if err := appendJSON(*retFile, entry); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "recorded %s rotation %s/%d -> %s/%d\nnew key: %s\nstart averin-server with AVERIN_SIGNING_KEY_ID=%s AVERIN_SIGNING_KEY_EPOCH=%d\n",
		*reason, old.ID, old.Epoch, succ.ID, succ.Epoch, succ.PublicKey, succ.ID, succ.Epoch)
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("must be a regular owner-only file (mode 0600)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("must hold 64 hex chars (a 32-byte ed25519 seed)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// appendJSON appends v to the JSON array in path, creating the file when absent.
func appendJSON(path string, v any) error {
	var arr []json.RawMessage
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &arr); err != nil {
			return fmt.Errorf("%s is not a JSON array: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	arr = append(arr, raw)
	out, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "averin-keyrotate: "+msg)
	os.Exit(1)
}
