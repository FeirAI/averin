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
