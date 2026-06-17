package broker

import (
	"testing"

	"github.com/feir-dev/feir/server/internal/goldenvec"
)

func TestGrantHeadRootGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file (spec/golden-vectors/broker-preimages.json),
	// also loaded by core/tests/adversarial.rs — MUST equal Rust feir_decision_core::verify::grant_head_root.
	// Drift in the LP4/BE8 layout fails here AND in Rust against the same file.
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.GrantHeadRoot) == 0 {
		t.Fatal("shared vector: grant_head_root section is empty")
	}
	var three []GrantSeqHash
	for _, c := range v.GrantHeadRoot {
		grants := make([]GrantSeqHash, len(c.Grants))
		for i, g := range c.Grants {
			grants[i] = GrantSeqHash{Seq: g.Seq, ContentHash: g.ContentHash}
		}
		if got := GrantHeadRoot(grants); got != c.Expect {
			t.Fatalf("grant_head_root case %q drifted from the shared vector: got %s want %s", c.Name, got, c.Expect)
		}
		if len(grants) == 3 {
			three = grants
		}
	}
	// Order-sensitive: a renumber/reorder yields a different root (the suppression-detection property).
	if len(three) != 3 {
		t.Fatal("the shared vector must carry a 3-grant case")
	}
	reordered := []GrantSeqHash{three[1], three[0], three[2]}
	if GrantHeadRoot(reordered) == GrantHeadRoot(three) {
		t.Fatal("grant_head_root must be order-sensitive")
	}
}

func TestBrokerGrantHead(t *testing.T) {
	grants := []GrantSeqHash{
		{Seq: 1, ContentHash: "sha256:aa"},
		{Seq: 2, ContentHash: "sha256:bb"},
	}
	head := BrokerGrantHead(grants, "sha256:prior")
	if head["max_seq"] != int64(2) {
		t.Fatalf("max_seq = %v, want 2", head["max_seq"])
	}
	if head["prior_head_hash"] != "sha256:prior" {
		t.Fatalf("prior_head_hash = %v, want sha256:prior", head["prior_head_hash"])
	}
	if head["cumulative_root"] != GrantHeadRoot(grants) {
		t.Fatalf("cumulative_root must equal grant_head_root over the grants")
	}
	// empty log: max_seq 0, root = empty-log seed.
	empty := BrokerGrantHead(nil, EmptyGrantHeadRoot())
	if empty["max_seq"] != int64(0) || empty["cumulative_root"] != EmptyGrantHeadRoot() {
		t.Fatalf("empty head = %v; want max_seq 0 + empty root", empty)
	}
}
