package broker

import (
	"encoding/hex"
	"testing"

	"github.com/feir-dev/feir/server/internal/goldenvec"
)

func TestIntrospectionTranscriptChallengeGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file — MUST equal Rust verify::introspection_transcript_challenge.
	// Drift in the LP4/BE8 layout fails here AND in Rust against the same one file (ADR 0005 M3).
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.IntrospectionTranscriptChallenge) == 0 {
		t.Fatal("shared vector: introspection_transcript_challenge section is empty")
	}
	for _, c := range v.IntrospectionTranscriptChallenge {
		got := hex.EncodeToString(IntrospectionTranscriptChallenge(c.GrantID, c.CredentialRef, c.EffectiveScope, c.ResourceID, c.IntrospectedAt, c.EffectiveExp))
		if got != c.ExpectHex {
			t.Errorf("introspection_transcript_challenge case %q drifted from the shared vector: got %s want %s", c.Name, got, c.ExpectHex)
		}
	}
}
