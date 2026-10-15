package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/keylineage"
	"github.com/feirai/averin/server/internal/store"
)

const (
	oldSeedHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	newSeedHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	rotatedAt  = "2026-07-01T00:00:00.000Z"
)

func rotSeedKey(t *testing.T, h string) ed25519.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(b)
}

type rotationFixture struct {
	oldCore, newCore *core.Core
	oldKey, newKey   keylineage.Key
	stmt             map[string]any
}

func newRotationFixture(t *testing.T, reason string) rotationFixture {
	t.Helper()
	oc, err := core.New(oldSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := core.New(newSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	f := rotationFixture{
		oldCore: oc, newCore: nc,
		oldKey: keylineage.Key{ID: "k0", Epoch: 0, PublicKey: oc.PubKey()},
		newKey: keylineage.Key{ID: "k1", Epoch: 1, PublicKey: nc.PubKey()},
	}
	var osk ed25519.PrivateKey
	if reason == "scheduled" {
		osk = rotSeedKey(t, oldSeedHex)
	}
	f.stmt, err = keylineage.Sign(nc, f.oldKey, f.newKey, rotatedAt, reason, osk, rotSeedKey(t, newSeedHex))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// historyThenRotation seals records and a checkpoint under the OLD key, then a second server on the same store
// seals more under the NEW key and returns its export. The lineage the second server publishes is lin.
func (f rotationFixture) history(t *testing.T, status, reasonStatusAt string) string {
	t.Helper()
	st := store.NewMem()
	a := api.New(f.oldCore, st, f.oldKey.ID).Routes()
	postRecord(t, a, `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"db.query"}`)
	if code, resp := do(t, a, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("old checkpoint (%d): %s", code, resp)
	}
	lin, err := keylineage.Build(f.newCore, f.newKey, []keylineage.RetiredFile{{
		SigningKeyID: f.oldKey.ID, KeyEpoch: f.oldKey.Epoch, PublicKey: f.oldKey.PublicKey,
		KeyStatus: status, StatusChangedAt: reasonStatusAt,
	}}, []map[string]any{f.stmt})
	if err != nil {
		t.Fatalf("lineage: %v", err)
	}
	b := api.New(f.newCore, st, f.newKey.ID).WithKeyLineage(lin).Routes()
	rec, _ := postRecord(t, b, `{"idempotency_key":"b1","project_id":"p1","session_id":"s1","action":"db.query"}`)
	if kb, _ := rec["key"].(map[string]any); kb["signing_key_id"] != "k1" || kb["key_epoch"] != float64(1) {
		t.Fatalf("new record not stamped with the new key and epoch: %v", rec["key"])
	}
	if code, resp := do(t, b, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("new checkpoint (%d): %s", code, resp)
	}
	code, exp := do(t, b, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	return exp
}

func pinOnly(pub string) string {
	b, _ := json.Marshal(map[string]any{"signing_keys": []string{pub}})
	return string(b)
}

func dropRotations(t *testing.T, bundle string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundle), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["key_rotations"]; !ok {
		t.Fatal("export carries no key_rotations")
	}
	delete(m, "key_rotations")
	out, _ := json.Marshal(m)
	return string(out)
}

// The end to end claim: a verifier that pinned ONLY the old key proves history sealed by both keys once the
// server publishes the signed rotation, and proves the old half only when the statement is stripped.
func TestRotatedKeyHistoryVerifiesFromTheOldPin(t *testing.T) {
	f := newRotationFixture(t, "scheduled")
	exp := f.history(t, "retired", rotatedAt)
	if !strings.Contains(exp, `"key_epoch":1`) || !strings.Contains(exp, `"key_status":"retired"`) {
		t.Fatalf("export does not publish both keys with their epochs: %s", exp)
	}
	rep := f.newCore.VerifyBundleWith(exp, pinOnly(f.oldKey.PublicKey))
	if !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"key_rotations_chain_trusted":1`) {
		t.Fatalf("history across a rotation must verify from the old pin: %s", rep)
	}
	stripped := f.newCore.VerifyBundleWith(dropRotations(t, exp), pinOnly(f.oldKey.PublicKey))
	if strings.Contains(stripped, `"ok":true`) {
		t.Fatalf("without the signed statement the new key's records must not verify from the old pin: %s", stripped)
	}
}

func TestCompromisedKeyRotationExtendsNoTrust(t *testing.T) {
	f := newRotationFixture(t, "compromise")
	exp := f.history(t, "compromised", rotatedAt)
	rep := f.newCore.VerifyBundleWith(exp, pinOnly(f.oldKey.PublicKey))
	if strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"key_rotations_chain_trusted":0`) {
		t.Fatalf("a compromise statement must not carry trust from the old pin: %s", rep)
	}
}

func TestDefaultServerStampsEpochZeroAndPublishesOneKey(t *testing.T) {
	h := newSrv(t)
	rec, _ := postRecord(t, h, `{"idempotency_key":"d1","project_id":"p1","session_id":"s1","action":"x"}`)
	kb, _ := rec["key"].(map[string]any)
	if kb["key_epoch"] != float64(0) || kb["key_status"] != "active" {
		t.Fatalf("default stamp changed: %v", kb)
	}
	do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp, "key_rotations") || strings.Count(exp, `"public_key"`) != 1 {
		t.Fatalf("an unrotated server must publish exactly one key and no rotations: %s", exp)
	}
}
