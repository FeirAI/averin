package api

import (
	"encoding/json"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// TestSelfVerifyOpts_ApproverBindingPolicy (AVE-10): the server's own verify and export carry the strict
// approver-binding policy and its cutover only when configured, and carry neither by default.
func TestSelfVerifyOpts_ApproverBindingPolicy(t *testing.T) {
	c := testCore(t)
	s := New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore())
	var opts map[string]any
	if err := json.Unmarshal([]byte(s.selfVerifyOpts()), &opts); err != nil {
		t.Fatal(err)
	}
	if _, ok := opts["require_approver_binding"]; ok {
		t.Fatalf("default must not set the policy: %v", opts)
	}
	s.WithRequireApproverBinding(true, "")
	opts = map[string]any{}
	json.Unmarshal([]byte(s.selfVerifyOpts()), &opts)
	if opts["require_approver_binding"] != true {
		t.Fatalf("policy on must reach the verifier opts: %v", opts)
	}
	if _, ok := opts["approver_binding_since"]; ok {
		t.Fatalf("no cutover configured: %v", opts)
	}
	s.WithRequireApproverBinding(true, "2026-10-01T00:00:00.000Z")
	opts = map[string]any{}
	json.Unmarshal([]byte(s.selfVerifyOpts()), &opts)
	if opts["approver_binding_since"] != "2026-10-01T00:00:00.000Z" {
		t.Fatalf("cutover must reach the verifier opts: %v", opts)
	}
}
