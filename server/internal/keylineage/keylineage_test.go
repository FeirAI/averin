package keylineage_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/keylineage"
)

const (
	oldSeed = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	newSeed = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	at      = "2026-07-01T00:00:00.000Z"
)

func priv(t *testing.T, h string) ed25519.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(b)
}

type fx struct {
	h        *core.Core
	old, cur keylineage.Key
	ret      []keylineage.RetiredFile
	stmt     map[string]any
}

func setup(t *testing.T, reason string) fx {
	h, err := core.New(newSeed)
	if err != nil {
		t.Fatal(err)
	}
	o, n := priv(t, oldSeed), priv(t, newSeed)
	f := fx{h: h,
		old: keylineage.Key{ID: "k0", Epoch: 0, PublicKey: keylineage.PubString(o.Public().(ed25519.PublicKey))},
		cur: keylineage.Key{ID: "k1", Epoch: 1, PublicKey: keylineage.PubString(n.Public().(ed25519.PublicKey))}}
	if reason != "scheduled" {
		o = nil
	}
	f.stmt, err = keylineage.Sign(h, f.old, f.cur, at, reason, o, n)
	if err != nil {
		t.Fatal(err)
	}
	f.ret = []keylineage.RetiredFile{{SigningKeyID: "k0", KeyEpoch: 0, PublicKey: f.old.PublicKey, KeyStatus: "retired", StatusChangedAt: at}}
	return f
}

func TestBuildAcceptsAConsistentLineageAndPublishesBothKeys(t *testing.T) {
	f := setup(t, "scheduled")
	l, err := keylineage.Build(f.h, f.cur, f.ret, []map[string]any{f.stmt})
	if err != nil {
		t.Fatal(err)
	}
	e := l.Entries("active")
	if len(e) != 2 {
		t.Fatalf("want current + retired, got %v", e)
	}
	if got := e[1].(map[string]any); got["key_status"] != "retired" || got["status_changed_at"] != at {
		t.Fatalf("retired entry: %v", got)
	}
}

func TestBuildRefusesAnInconsistentLineage(t *testing.T) {
	f := setup(t, "scheduled")
	cases := map[string]func() error{
		"retired key without a statement": func() error {
			_, err := keylineage.Build(f.h, f.cur, f.ret, nil)
			return err
		},
		"statement tampered after signing": func() error {
			bad := map[string]any{}
			for k, v := range f.stmt {
				bad[k] = v
			}
			bad["rotated_at"] = "2026-07-02T00:00:00.000Z"
			_, err := keylineage.Build(f.h, f.cur, f.ret, []map[string]any{bad})
			return err
		},
		"unknown field": func() error {
			bad := map[string]any{"x": 1}
			for k, v := range f.stmt {
				bad[k] = v
			}
			_, err := keylineage.Build(f.h, f.cur, f.ret, []map[string]any{bad})
			return err
		},
		"current key is also listed as retired": func() error {
			r := append([]keylineage.RetiredFile{}, f.ret...)
			r = append(r, keylineage.RetiredFile{SigningKeyID: "k1", KeyEpoch: 1, PublicKey: f.cur.PublicKey, KeyStatus: "retired", StatusChangedAt: at})
			_, err := keylineage.Build(f.h, f.cur, r, []map[string]any{f.stmt})
			return err
		},
		"status not retired or compromised": func() error {
			r := []keylineage.RetiredFile{f.ret[0]}
			r[0].KeyStatus = "active"
			_, err := keylineage.Build(f.h, f.cur, r, []map[string]any{f.stmt})
			return err
		},
		"status_changed_at not canonical": func() error {
			r := []keylineage.RetiredFile{f.ret[0]}
			r[0].StatusChangedAt = "2026-07-01"
			_, err := keylineage.Build(f.h, f.cur, r, []map[string]any{f.stmt})
			return err
		},
		"compromise statement signed by a key that is not the successor": func() error {
			c := setup(t, "compromise")
			bad, err := keylineage.Sign(c.h, c.old, c.cur, at, "compromise", nil, priv(t, newSeed))
			if err != nil {
				return err
			}
			bad["sig_new"] = forgedSig(t, c, bad)
			_, err = keylineage.Build(c.h, c.cur, c.ret, []map[string]any{bad})
			return err
		},
		"chain does not reach the current key": func() error {
			other := keylineage.Key{ID: "k2", Epoch: 2, PublicKey: f.cur.PublicKey}
			_, err := keylineage.Build(f.h, other, f.ret, []map[string]any{f.stmt})
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: Build accepted it", name)
		}
	}
}

func TestSignRefusesAScheduledRotationWithoutTheOldKey(t *testing.T) {
	f := setup(t, "scheduled")
	if _, err := keylineage.Sign(f.h, f.old, f.cur, at, "scheduled", nil, priv(t, newSeed)); err == nil {
		t.Fatal("scheduled without the old seed must be refused")
	}
	if _, err := keylineage.Sign(f.h, f.old, f.cur, at, "scheduled", priv(t, newSeed), priv(t, newSeed)); err == nil || !strings.Contains(err.Error(), "old seed") {
		t.Fatalf("a seed that is not the old key's must be refused: %v", err)
	}
	if _, err := keylineage.Sign(f.h, f.old, f.cur, "yesterday", "scheduled", priv(t, oldSeed), priv(t, newSeed)); err == nil {
		t.Fatal("a non-canonical time must be refused")
	}
}

func TestCompromiseStatementCarriesNoOldKeySignature(t *testing.T) {
	f := setup(t, "compromise")
	if _, ok := f.stmt["sig_old"]; ok {
		t.Fatal("a compromise statement must not carry sig_old")
	}
	f.ret[0].KeyStatus = "compromised"
	if _, err := keylineage.Build(f.h, f.cur, f.ret, []map[string]any{f.stmt}); err != nil {
		t.Fatal(err)
	}
}

// forgedSig signs the statement's digest with a key that is not the successor's.
func forgedSig(t *testing.T, f fx, st map[string]any) string {
	t.Helper()
	thief := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	fake := keylineage.Key{ID: f.cur.ID, Epoch: f.cur.Epoch, PublicKey: keylineage.PubString(thief.Public().(ed25519.PublicKey))}
	s2, err := keylineage.Sign(f.h, f.old, fake, at, "compromise", nil, thief)
	if err != nil {
		t.Fatal(err)
	}
	// the same message layout, signed by the thief over the thief's own statement: it must not verify for ours
	return s2["sig_new"].(string)
}
