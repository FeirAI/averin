package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type verdictCase struct {
	Name                 string `json:"name"`
	StripAnchor          bool   `json:"strip_anchor"`
	MalformedDisclosures bool   `json:"malformed_disclosures"`
	PinSigner            bool   `json:"pin_signer"`
}

func TestGeneratedVerdictCorpusCgo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "fixtures", "verdict-generated.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name                       string            `json:"name"`
		BundleJSON                 string            `json:"bundle_json"`
		OptsJSON                   string            `json:"opts_json"`
		ExpectedBundleDigest       string            `json:"expected_bundle_digest"`
		ExpectedClaims             map[string]string `json:"expected_claims"`
		ExpectedOK                 bool              `json:"expected_ok"`
		ExpectedActionCompleteness string            `json:"expected_action_completeness"`
		ExpectedUnmatchedViolation int               `json:"expected_unmatched_violation"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 30 {
		t.Fatalf("expected generated signed cases, got %d", len(rows))
	}
	c, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	authorized := false
	brokeredComplete := false
	nativeComplete := false
	partialAnchorFailedPoP := false
	for _, row := range rows {
		var report struct {
			BundleDigest       string            `json:"bundle_digest"`
			Claims             map[string]string `json:"claims"`
			OK                 bool              `json:"ok"`
			ActionCompleteness string            `json:"action_completeness"`
			UnmatchedViolation int               `json:"unmatched_violation"`
		}
		if err := json.Unmarshal([]byte(c.VerifyBundleWith(row.BundleJSON, row.OptsJSON)), &report); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		if report.BundleDigest != row.ExpectedBundleDigest ||
			!reflect.DeepEqual(report.Claims, row.ExpectedClaims) || report.OK != row.ExpectedOK ||
			report.ActionCompleteness != row.ExpectedActionCompleteness ||
			report.UnmatchedViolation != row.ExpectedUnmatchedViolation {
			t.Fatalf("%s: cgo report diverged from native corpus: %+v", row.Name, report)
		}
		if row.Name == "v3_authorized/anchors_1/base" {
			authorized = report.Claims["authorized"] == "satisfied"
		}
		if row.Name == "v3_capstone/anchors_1/base" {
			brokeredComplete = report.Claims["complete_brokered"] == "satisfied"
		}
		if row.Name == "v3_native_capstone/anchors_1/base" {
			nativeComplete = report.Claims["complete_introspected"] == "satisfied"
		}
		if row.Name == "failed_pop_partial_anchor/anchors_1/base" {
			partialAnchorFailedPoP = !report.OK && report.UnmatchedViolation > 0
		}
	}
	if !authorized || !brokeredComplete || !nativeComplete || !partialAnchorFailedPoP {
		t.Fatalf("missing nonvacuous corpus baselines: authorized=%t brokered=%t native=%t partial-anchor-PoP=%t",
			authorized, brokeredComplete, nativeComplete, partialAnchorFailedPoP)
	}
}

func TestSharedAttachmentCorpusClaimSupportErasure(t *testing.T) {
	read := func(name string, target any) {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(bytes, target); err != nil {
			t.Fatal(err)
		}
	}
	var source map[string]json.RawMessage
	read("bundle-broker-valid.json", &source)
	var cases []verdictCase
	read("verdict-attachment-cases.json", &cases)
	if len(cases) != 8 {
		t.Fatalf("expected all 8 attachment cases, got %d", len(cases))
	}
	core, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	support := make(map[string]map[string]bool)
	fields := []string{"integrity", "authenticated", "authorized", "temporal", "complete_brokered", "complete_introspected"}
	for _, tc := range cases {
		var bundle map[string]any
		var opts map[string]any
		if err := json.Unmarshal(source["bundle"], &bundle); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(source["opts"], &opts); err != nil {
			t.Fatal(err)
		}
		if tc.StripAnchor {
			for _, raw := range bundle["checkpoints"].([]any) {
				delete(raw.(map[string]any), "anchor")
			}
		}
		if tc.MalformedDisclosures {
			bundle["disclosures"] = "bad optional disclosure"
		}
		if tc.PinSigner {
			keys := make([]string, 0)
			for _, raw := range bundle["keys"].([]any) {
				keys = append(keys, raw.(map[string]any)["public_key"].(string))
			}
			opts["signing_keys"] = keys
		}
		bundleJSON, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		optsJSON, err := json.Marshal(opts)
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			ClaimsVersion string            `json:"claims_version"`
			Claims        map[string]string `json:"claims"`
		}
		if err := json.Unmarshal([]byte(core.VerifyBundleWith(string(bundleJSON), string(optsJSON))), &report); err != nil {
			t.Fatal(err)
		}
		if report.ClaimsVersion != "1" {
			t.Fatalf("%s: claims version %q", tc.Name, report.ClaimsVersion)
		}
		if report.Claims["requested_decision"] != report.Claims[report.Claims["requested"]] {
			t.Fatalf("%s: requested decision disagrees with typed claim", tc.Name)
		}
		support[tc.Name] = make(map[string]bool)
		for _, field := range fields {
			support[tc.Name][field] = report.Claims[field] == "satisfied"
		}
	}
	subset := func(small, large string) {
		t.Helper()
		for _, field := range fields {
			if support[small][field] && !support[large][field] {
				t.Fatalf("%s gained %s after erasing support from %s", small, field, large)
			}
		}
	}
	subset("anchor_removed", "full")
	subset("self_signed_anchor_removed", "self_signed")
	subset("anchor_removed_malformed", "malformed_optional")
	subset("self_signed_anchor_removed_malformed", "self_signed_malformed")
	subset("full", "malformed_optional")
	subset("malformed_optional", "full")
	subset("self_signed", "full")
}
