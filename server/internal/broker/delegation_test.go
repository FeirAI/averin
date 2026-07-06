package broker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/goldenvec"
)

func TestDelegationHopChallengeGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file — MUST equal Rust verify::delegation_hop_challenge.
	// Drift in the LP4/BE8 layout fails here AND in Rust against the same one file (ADR 0005 M2).
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.DelegationHopChallenge) == 0 {
		t.Fatal("shared vector: delegation_hop_challenge section is empty")
	}
	for _, c := range v.DelegationHopChallenge {
		got := hex.EncodeToString(DelegationHopChallenge(c.GrantID, c.HopIndex, c.DelegatorKid, c.DelegateKid, c.Scope, c.Action, c.ResourceID, c.Exp))
		if got != c.ExpectHex {
			t.Fatalf("delegation_hop_challenge case %q drifted from the shared vector: got %s want %s", c.Name, got, c.ExpectHex)
		}
	}
}

// prepareDelegableGrant mints a single_operation grant and tags its evidence with a scope (the chain holds it
// equal under the demonstrator monotonicity), returning the Prepared + the root agent key the grant is for.
func prepareDelegableGrant(t *testing.T) (Prepared, ed25519.PrivateKey) {
	t.Helper()
	rootSeed := make([]byte, ed25519.SeedSize)
	rootSeed[0] = 7
	root := ed25519.NewKeyFromSeed(rootSeed)
	rootPub := root.Public().(ed25519.PublicKey)
	issSeed := make([]byte, ed25519.SeedSize)
	issSeed[0] = 9
	issuing := ed25519.NewKeyFromSeed(issSeed)
	req := Request{
		AgentID:     "agent-root",
		Action:      "db.query:orders-ro",
		Resource:    "orders-db",
		Scope:       "read:orders",
		AgentPubKey: base64.RawURLEncoding.EncodeToString(rootPub),
		TTL:         time.Hour,
	}
	req.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, req.Challenge()))
	p, err := Prepare(req, "grant-d", func() (int64, error) { return 1, nil }, time.Unix(1_718_445_600, 0), issuing)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// the grant's cnf_kid is the root agent's KeyID; the chain's hop 0 delegator must match it.
	if p.Evidence["cnf_kid"] != KeyID(rootPub) {
		t.Fatalf("grant cnf_kid %v != root KeyID %v", p.Evidence["cnf_kid"], KeyID(rootPub))
	}
	return p, root
}

func delAgent(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s)
}

// signHop produces a valid DelegationHop from delegator -> delegate over the prepared grant's scope/action/res.
func signHop(p Prepared, hopIndex int64, delegator, delegate ed25519.PrivateKey, scope, action, resource string, exp int64) DelegationHop {
	gid := p.Evidence["grant_id"].(string)
	dpub := delegator.Public().(ed25519.PublicKey)
	epub := delegate.Public().(ed25519.PublicKey)
	challenge := DelegationHopChallenge(gid, hopIndex, KeyID(dpub), KeyID(epub), scope, action, resource, exp)
	return DelegationHop{
		DelegatorCnf: base64.RawURLEncoding.EncodeToString(dpub),
		DelegateCnf:  base64.RawURLEncoding.EncodeToString(epub),
		Scope:        scope, Action: action, ResourceID: resource, Exp: exp,
		Sig: base64.RawURLEncoding.EncodeToString(ed25519.Sign(delegator, challenge)),
	}
}

func TestAttachDelegationValidChain(t *testing.T) {
	p, root := prepareDelegableGrant(t)
	leaf := delAgent(41)
	hop := signHop(p, 0, root, leaf, "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200)
	if err := AttachDelegation(&p, []DelegationHop{hop}); err != nil {
		t.Fatalf("AttachDelegation (valid 1-hop): %v", err)
	}
	embedded, ok := p.Evidence["delegation_assertions"].([]map[string]any)
	if !ok || len(embedded) != 1 {
		t.Fatalf("delegation_assertions not embedded as 1 entry: %v", p.Evidence["delegation_assertions"])
	}
	if embedded[0]["delegator_cnf"] != hop.DelegatorCnf || embedded[0]["sig"] != hop.Sig {
		t.Fatalf("embedded hop mismatch: %v", embedded[0])
	}
}

func TestAttachDelegationTwoHopValid(t *testing.T) {
	p, root := prepareDelegableGrant(t)
	mid, leaf := delAgent(42), delAgent(43)
	hops := []DelegationHop{
		signHop(p, 0, root, mid, "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200),
		signHop(p, 1, mid, leaf, "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200),
	}
	if err := AttachDelegation(&p, hops); err != nil {
		t.Fatalf("AttachDelegation (valid 2-hop): %v", err)
	}
}

func TestAttachDelegationRejectsBadChains(t *testing.T) {
	root := delAgent(7) // matches prepareDelegableGrant's root seed
	cases := []struct {
		name string
		hops func(p Prepared) []DelegationHop
	}{
		{"wrong root", func(p Prepared) []DelegationHop {
			stranger := delAgent(44)
			return []DelegationHop{signHop(p, 0, stranger, delAgent(41), "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200)}
		}},
		{"broken link", func(p Prepared) []DelegationHop {
			return []DelegationHop{
				signHop(p, 0, root, delAgent(42), "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200),
				signHop(p, 1, delAgent(99), delAgent(43), "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200), // delegator != prev delegate
			}
		}},
		{"widened scope", func(p Prepared) []DelegationHop {
			return []DelegationHop{signHop(p, 0, root, delAgent(41), "admin:all", "db.query:orders-ro", "orders-db", 1_718_449_200)}
		}},
		{"forged sig", func(p Prepared) []DelegationHop {
			h := signHop(p, 0, root, delAgent(41), "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200)
			imposter := delAgent(99)
			gid := p.Evidence["grant_id"].(string)
			dkid := KeyID(root.Public().(ed25519.PublicKey))
			ekid := KeyID(delAgent(41).Public().(ed25519.PublicKey))
			ch := DelegationHopChallenge(gid, 0, dkid, ekid, "read:orders", "db.query:orders-ro", "orders-db", 1_718_449_200)
			h.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(imposter, ch)) // signed by imposter, not root
			return []DelegationHop{h}
		}},
		{"empty chain", func(p Prepared) []DelegationHop { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := prepareDelegableGrant(t)
			if err := AttachDelegation(&p, tc.hops(p)); err == nil {
				t.Fatalf("%s: expected AttachDelegation to reject the chain", tc.name)
			}
			if _, present := p.Evidence["delegation_assertions"]; present {
				t.Fatalf("%s: a rejected chain must not mutate the grant evidence", tc.name)
			}
		})
	}
}
