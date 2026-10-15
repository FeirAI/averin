package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/keylineage"
)

// loadKeyLineage reads the epoch and the two lineage files; unset means the single-key default (epoch 0).
func TestLoadKeyLineage_DefaultAndConfigured(t *testing.T) {
	newSeed := strings.Repeat("cd", 32)
	c, err := core.New(newSeed)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AVERIN_SIGNING_KEY_EPOCH", "")
	t.Setenv("AVERIN_RETIRED_SIGNING_KEYS_FILE", "")
	t.Setenv("AVERIN_KEY_ROTATIONS_FILE", "")
	l := loadKeyLineage(c, "k0")
	if l.Current.Epoch != 0 || len(l.Retired) != 0 {
		t.Fatalf("default lineage: %+v", l)
	}

	oldRaw, _ := hex.DecodeString(strings.Repeat("ab", 32))
	newRaw, _ := hex.DecodeString(newSeed)
	oSK, nSK := ed25519.NewKeyFromSeed(oldRaw), ed25519.NewKeyFromSeed(newRaw)
	old := keylineage.Key{ID: "k0", Epoch: 0, PublicKey: keylineage.PubString(oSK.Public().(ed25519.PublicKey))}
	cur := keylineage.Key{ID: "k1", Epoch: 1, PublicKey: c.PubKey()}
	at := "2026-07-01T00:00:00.000Z"
	stmt, err := keylineage.Sign(c, old, cur, at, "scheduled", oSK, nSK)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, v any) string {
		b, _ := json.Marshal(v)
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	t.Setenv("AVERIN_SIGNING_KEY_EPOCH", "1")
	t.Setenv("AVERIN_RETIRED_SIGNING_KEYS_FILE", write("ret.json", []keylineage.RetiredFile{{
		SigningKeyID: "k0", KeyEpoch: 0, PublicKey: old.PublicKey, KeyStatus: "retired", StatusChangedAt: at}}))
	t.Setenv("AVERIN_KEY_ROTATIONS_FILE", write("rot.json", []any{stmt}))
	l = loadKeyLineage(c, "k1")
	if l.Current.Epoch != 1 || len(l.Retired) != 1 || len(l.Rotations) != 1 {
		t.Fatalf("configured lineage: %+v", l)
	}
}
