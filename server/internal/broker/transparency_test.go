package broker

import "testing"

func TestGrantHeadRootGoldenVector(t *testing.T) {
	// Cross-language pinned vectors — MUST equal Rust feir_decision_core::verify::grant_head_root
	// (golden test in core/tests/adversarial.rs). Drift in the LP4/BE8 layout fails here.
	if got := GrantHeadRoot(nil); got != "sha256:ac2cfdddb12235d5eff3a497e169b50fec13c9e7052e3b53c2a29d9318f9126d" {
		t.Fatalf("empty grant_head_root drifted from Rust: %s", got)
	}
	grants := []GrantSeqHash{
		{Seq: 1, ContentHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		{Seq: 2, ContentHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
		{Seq: 3, ContentHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
	}
	if got := GrantHeadRoot(grants); got != "sha256:03becbd3622a271d2f4e144c3402c6a6de8f06dfa58f3b6be3d9248ea42bdaac" {
		t.Fatalf("3-grant grant_head_root drifted from Rust: %s", got)
	}
	// Order-sensitive: a renumber/reorder yields a different root (the suppression-detection property).
	reordered := []GrantSeqHash{grants[1], grants[0], grants[2]}
	if GrantHeadRoot(reordered) == GrantHeadRoot(grants) {
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
