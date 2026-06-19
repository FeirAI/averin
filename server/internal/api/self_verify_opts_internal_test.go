package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

// TestSelfVerifyOptsPinsMeaningfulRolesNotAttestation (#14): selfVerifyOpts must pin every trust root whose verdict
// is meaningful WITHOUT the externally-held TSA key (broker/federation, resource, revocation, cosig) and must NOT
// pin the attestation role (its D7 freshness is unreachable without a TSA key, so self-pinning could only ever
// yield a false-alarm `failed`). The TSA itself is never self-pinned (the server does not hold it).
func TestSelfVerifyOptsPinsMeaningfulRolesNotAttestation(t *testing.T) {
	const serverSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const resSeed = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"
	c, err := core.New(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resSeed)
	if err != nil {
		t.Fatal(err)
	}
	gen := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	att, rev, brokerIssue, approver := gen(), gen(), gen(), gen()

	// Fully-configured FEDERATED server: broker_id set -> the broker key pins under federated_broker_keys.
	s := New(c, store.NewMem(), "k0").
		WithBroker(brokerIssue).
		WithBrokerID("broker-A").
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithCosigPolicy(1, []ed25519.PublicKey{approver.Public().(ed25519.PublicKey)}).
		WithRevocation(rev)

	var opts map[string]any
	if err := json.Unmarshal([]byte(s.selfVerifyOpts()), &opts); err != nil {
		t.Fatalf("selfVerifyOpts must be valid JSON: %v", err)
	}

	// Meaningful-without-TSA roles MUST be pinned.
	fed, ok := opts["federated_broker_keys"].(map[string]any)
	if !ok || fed["broker-A"] == nil {
		t.Fatalf("federated server must pin federated_broker_keys[broker-A]: %v", opts)
	}
	for _, k := range []string{"resource_authority_keys", "revocation_keys", "cosig_approver_keys"} {
		if opts[k] == nil {
			t.Fatalf("self-view must pin %s: %v", k, opts)
		}
	}
	// With broker_id set, the flat broker_authority_keys must NOT be used (federation is precise to this broker).
	if opts["broker_authority_keys"] != nil {
		t.Fatalf("a federated server must not also set broker_authority_keys: %v", opts)
	}
	// The attestation and TSA roles must NEVER be self-pinned.
	if opts["attestation_keys"] != nil {
		t.Fatalf("attestation must NOT be self-pinned (unreachable without a TSA key -> false-alarm failed): %v", opts)
	}
	if opts["tsa_keys"] != nil {
		t.Fatalf("the TSA key is external and must never be self-pinned: %v", opts)
	}

	// Non-federated server: the broker key pins under the flat broker_authority_keys, no federation map.
	s2 := New(c, store.NewMem(), "k0").WithBroker(brokerIssue).WithResource(rc, "orders-db")
	var opts2 map[string]any
	if err := json.Unmarshal([]byte(s2.selfVerifyOpts()), &opts2); err != nil {
		t.Fatal(err)
	}
	if opts2["broker_authority_keys"] == nil {
		t.Fatalf("non-federated server must pin broker_authority_keys: %v", opts2)
	}
	if opts2["federated_broker_keys"] != nil {
		t.Fatalf("non-federated server must not set federated_broker_keys: %v", opts2)
	}
}
