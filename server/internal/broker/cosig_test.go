package broker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/goldenvec"
)

func TestCosigApprovalChallengeGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file (spec/golden-vectors/broker-preimages.json), also
	// loaded by core/tests/adversarial.rs — MUST equal Rust averin_decision_core::verify::cosig_approval_challenge.
	// Drift in the LP4/BE8 layout fails here AND in Rust against the same one file (ADR 0005 M6).
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.CosigApprovalChallenge) == 0 {
		t.Fatal("shared vector: cosig_approval_challenge section is empty")
	}
	for _, c := range v.CosigApprovalChallenge {
		got := hex.EncodeToString(CosigApprovalChallenge(c.GrantID, c.ApproverKid, c.CredentialBinding, c.ThresholdM, c.Exp))
		if got != c.ExpectHex {
			t.Fatalf("cosig_approval_challenge case %q drifted from the shared vector: got %s want %s", c.Name, got, c.ExpectHex)
		}
	}
}

// prepareGrant mints a single_operation grant via the real broker path (so credential_binding/exp are
// fixed exactly as production), returning the Prepared for cosig attachment.
func prepareGrant(t *testing.T) Prepared {
	t.Helper()
	agentSeed := make([]byte, ed25519.SeedSize)
	agentSeed[0] = 7
	agentPriv := ed25519.NewKeyFromSeed(agentSeed)
	agentPub := agentPriv.Public().(ed25519.PublicKey)
	issSeed := make([]byte, ed25519.SeedSize)
	issSeed[0] = 9
	issuing := ed25519.NewKeyFromSeed(issSeed)
	req := Request{
		AgentID:     "agent-x",
		Action:      "db.query:orders-ro",
		Resource:    "orders-db",
		Scope:       "single_operation",
		AgentPubKey: base64.RawURLEncoding.EncodeToString(agentPub),
		TTL:         time.Hour,
	}
	req.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(agentPriv, req.Challenge()))
	p, err := Prepare(req, "grant-x", func() (int64, error) { return 1, nil }, time.Unix(1_718_445_600, 0), issuing)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return p
}

// signApproval produces a valid cosignature from an approver over the prepared grant.
func signApproval(t *testing.T, p Prepared, approver ed25519.PrivateKey, thresholdM int) Cosignature {
	t.Helper()
	pub := approver.Public().(ed25519.PublicKey)
	kid := KeyID(pub)
	exp := p.Evidence["exp"].(int64)
	sig := ed25519.Sign(approver, CosigApprovalChallenge(p.GrantID, kid, p.CredentialBinding, int64(thresholdM), exp))
	return Cosignature{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}
}

func TestAttachCosignaturesThresholdMet(t *testing.T) {
	p := prepareGrant(t)
	a1 := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // seed all-zero
	a2seed := make([]byte, ed25519.SeedSize)
	a2seed[0] = 1
	a2 := ed25519.NewKeyFromSeed(a2seed)
	cosigs := []Cosignature{signApproval(t, p, a1, 2), signApproval(t, p, a2, 2)}
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	if err := AttachCosignatures(&p, 2, cosigs, approvers); err != nil {
		t.Fatalf("AttachCosignatures (2-of-2): %v", err)
	}
	if p.Evidence["cosig_threshold"] != 2 {
		t.Fatalf("cosig_threshold not embedded: %v", p.Evidence["cosig_threshold"])
	}
	embedded, ok := p.Evidence["cosignatures"].([]map[string]any)
	if !ok || len(embedded) != 2 {
		t.Fatalf("cosignatures not embedded as 2 entries: %v", p.Evidence["cosignatures"])
	}
	if embedded[0]["approver_kid"] != cosigs[0].ApproverKid || embedded[0]["sig"] != cosigs[0].Sig {
		t.Fatalf("embedded cosignature 0 mismatch: %v", embedded[0])
	}
}

func TestAttachCosignaturesBelowThresholdFails(t *testing.T) {
	p := prepareGrant(t)
	a1 := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	a2seed := make([]byte, ed25519.SeedSize)
	a2seed[0] = 1
	a2 := ed25519.NewKeyFromSeed(a2seed)
	// only a1 signs, but threshold is 2.
	cosigs := []Cosignature{signApproval(t, p, a1, 2)}
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	if err := AttachCosignatures(&p, 2, cosigs, approvers); err == nil {
		t.Fatal("expected an error: 1-of-2 must not satisfy the threshold")
	}
	if _, present := p.Evidence["cosig_threshold"]; present {
		t.Fatal("a failed AttachCosignatures must not mutate the grant evidence")
	}
}

func TestAttachCosignaturesDuplicateApproverCountsOnce(t *testing.T) {
	p := prepareGrant(t)
	a1 := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	a2seed := make([]byte, ed25519.SeedSize)
	a2seed[0] = 1
	a2 := ed25519.NewKeyFromSeed(a2seed)
	dup := signApproval(t, p, a1, 2)
	// a1 signs twice (identical deterministic sig); distinct approvers = 1 < 2.
	cosigs := []Cosignature{dup, dup}
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	if err := AttachCosignatures(&p, 2, cosigs, approvers); err == nil {
		t.Fatal("one approver signing twice must not satisfy a 2-of-N threshold")
	}
}

func TestAttachCosignaturesForgedSignatureFails(t *testing.T) {
	p := prepareGrant(t)
	a1 := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	impSeed := make([]byte, ed25519.SeedSize)
	impSeed[0] = 99
	imposter := ed25519.NewKeyFromSeed(impSeed)
	// claim a1's kid but sign with the imposter key.
	kid := KeyID(a1.Public().(ed25519.PublicKey))
	exp := p.Evidence["exp"].(int64)
	forged := ed25519.Sign(imposter, CosigApprovalChallenge(p.GrantID, kid, p.CredentialBinding, 1, exp))
	cosigs := []Cosignature{{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(forged)}}
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey)}
	if err := AttachCosignatures(&p, 1, cosigs, approvers); err == nil {
		t.Fatal("a cosignature claiming a1's kid but signed by another key must not verify")
	}
}
