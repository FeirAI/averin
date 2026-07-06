package broker

import (
	"encoding/hex"
	"testing"

	"github.com/averin-dev/averin/server/internal/goldenvec"
)

func TestFederationCertChallengeGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file — MUST equal Rust verify::federation_cert_challenge.
	// Drift in the LP4/BE8 layout (incl. the subject_kid binding) fails here AND in Rust against the same one
	// file (ADR 0005 M4 cross_broker_cert).
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.FederationCertChallenge) == 0 {
		t.Fatal("shared vector: federation_cert_challenge section is empty")
	}
	for _, c := range v.FederationCertChallenge {
		got := hex.EncodeToString(FederationCertChallenge(c.IssuerBrokerID, c.SubjectBrokerID, c.SubjectKid, c.Scope, c.ResourceID, c.NotAfter))
		if got != c.ExpectHex {
			t.Errorf("federation_cert_challenge case %q drifted from the shared vector: got %s want %s", c.Name, got, c.ExpectHex)
		}
	}
}
