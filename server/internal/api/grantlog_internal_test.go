package api

import (
	"testing"

	"github.com/feir-dev/feir/server/internal/store"
)

// TestGrantLogClassificationAndBoundary exercises grantLog's D6 membership rule directly (it is
// unexported, so this is an internal test): a record is in the transparency log iff it carries the
// (kind=grant, enforcement_point=credential_broker) tuple AND a broker_seq >= 1. Pre-D6 grants (tuple
// but no broker_seq) are SKIPPED (the activation boundary), not a fatal error; use receipts and generic
// records are excluded; output is sorted by broker_seq.
func TestGrantLogClassificationAndBoundary(t *testing.T) {
	recs := []store.Record{
		{ContentHash: "sha256:g1", JSON: `{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":1}}}}`},
		// pre-D6 grant: tuple present, NO broker_seq -> skipped (boundary), must NOT error/wedge.
		{ContentHash: "sha256:legacy", JSON: `{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant","grant_evidence":{}}}}`},
		// use receipt: kind=use -> not a grant.
		{ContentHash: "sha256:u1", JSON: `{"authority":{"enforcement_point":"tool_gateway"},"extensions":{"broker":{"kind":"use"}}}`},
		// generic record: no extensions.broker -> not a grant.
		{ContentHash: "sha256:r1", JSON: `{"action":"x"}`},
		// a grant marker WITHOUT the credential_broker enforcement_point -> not a D6 grant (tuple mismatch).
		{ContentHash: "sha256:fake", JSON: `{"authority":{"enforcement_point":"caller_declared"},"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":9}}}}`},
		// second real D6 grant, supplied out of seq order -> must sort after g1.
		{ContentHash: "sha256:g2", JSON: `{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":2}}}}`},
	}
	gl, err := grantLog(recs)
	if err != nil {
		t.Fatalf("grantLog must skip pre-D6 grants without erroring, got: %v", err)
	}
	if len(gl) != 2 {
		t.Fatalf("want exactly the 2 D6 grants, got %d: %+v", len(gl), gl)
	}
	if gl[0].Seq != 1 || gl[0].ContentHash != "sha256:g1" {
		t.Fatalf("entry 0 = %+v; want seq 1, g1", gl[0])
	}
	if gl[1].Seq != 2 || gl[1].ContentHash != "sha256:g2" {
		t.Fatalf("entry 1 = %+v; want seq 2, g2 (sorted)", gl[1])
	}
}
