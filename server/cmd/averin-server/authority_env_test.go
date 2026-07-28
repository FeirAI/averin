package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// authority_env_test.go pins the CONFIGURATION surface for the authority posture — the layer the F2 and F3
// defects lived in. F2 was an env var (AVERIN_DELEGATE_SIGNED_PUBKEY) that govder's operator tool prints,
// that WithPolicyEngineKey accepts, and that main() never read: a control that read as live and was inert.
// F3 was a fail-closed guard that defaulted OFF and was set in no shipped config.

func pubHex(b byte) (string, ed25519.PublicKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), pub
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// pinsBySource indexes resolved pins by "project|source" for assertions.
func pinsBySource(pins []resolvedAuthorityPin) map[string]resolvedAuthorityPin {
	out := map[string]resolvedAuthorityPin{}
	for _, p := range pins {
		out[p.pin.project+"|"+p.pin.source] = p
	}
	return out
}

// TestGovderDerivePubkeysOutputPinsAllThreeSources (F2) feeds authorityPinsFromEnv EXACTLY the three
// variables `govder-derive-pubkeys` prints. All three must become pins. Before the fix
// AVERIN_DELEGATE_SIGNED_PUBKEY was read by nothing, so an operator who pasted the tool's output verbatim
// still had delegate_signed unpinned — and every delegate-agent approval record sealed at the forgeable
// caller_declared with no indication anything was wrong.
func TestGovderDerivePubkeysOutputPinsAllThreeSources(t *testing.T) {
	peHex, pePub := pubHex(0x11)
	hsHex, hsPub := pubHex(0x12)
	dsHex, dsPub := pubHex(0x13)

	pins := pinsBySource(authorityPinsFromEnv(envMap(map[string]string{
		"AVERIN_POLICY_ENGINE_PUBKEY":   peHex,
		"AVERIN_HUMAN_SIGNED_PUBKEY":    hsHex,
		"AVERIN_DELEGATE_SIGNED_PUBKEY": dsHex,
	})))

	for _, tc := range []struct {
		key  string
		want ed25519.PublicKey
		env  string
	}{
		{"|policy_engine_signed", pePub, "AVERIN_POLICY_ENGINE_PUBKEY"},
		{"|human_signed", hsPub, "AVERIN_HUMAN_SIGNED_PUBKEY"},
		{"|delegate_signed", dsPub, "AVERIN_DELEGATE_SIGNED_PUBKEY"},
	} {
		got, ok := pins[tc.key]
		if !ok {
			t.Fatalf("%s produced NO pin for %q — the variable is read by nothing (F2)", tc.env, tc.key)
		}
		if !got.key.Equal(tc.want) {
			t.Fatalf("%s pinned the wrong key for %q", tc.env, tc.key)
		}
		if got.env != tc.env {
			t.Fatalf("pin %q attributed to %q, want %q", tc.key, got.env, tc.env)
		}
	}
	if len(pins) != 3 {
		t.Fatalf("want exactly 3 pins, got %d: %v", len(pins), pins)
	}
}

// TestAuthorityKeysAcceptsDelegateSignedAndProjectScope (F1 + F2): AVERIN_AUTHORITY_KEYS accepts
// delegate_signed (it used to log.Fatal on it) and the "[project:]source=pubkey" per-tenant form.
func TestAuthorityKeysAcceptsDelegateSignedAndProjectScope(t *testing.T) {
	acmeHex, acmePub := pubHex(0x21)
	globexHex, globexPub := pubHex(0x22)
	dsHex, dsPub := pubHex(0x23)

	pins := pinsBySource(authorityPinsFromEnv(envMap(map[string]string{
		"AVERIN_AUTHORITY_KEYS": "tenant_acme:human_signed=" + acmeHex +
			", tenant_globex:human_signed=" + globexHex +
			", delegate_signed=" + dsHex,
	})))

	if p, ok := pins["tenant_acme|human_signed"]; !ok || !p.key.Equal(acmePub) {
		t.Fatalf("tenant_acme:human_signed not pinned per-project (F1): %v", pins)
	}
	if p, ok := pins["tenant_globex|human_signed"]; !ok || !p.key.Equal(globexPub) {
		t.Fatalf("tenant_globex:human_signed not pinned per-project (F1): %v", pins)
	}
	if p, ok := pins["|delegate_signed"]; !ok || !p.key.Equal(dsPub) {
		t.Fatalf("delegate_signed rejected by AVERIN_AUTHORITY_KEYS (F2): %v", pins)
	}
	if len(pins) != 3 {
		t.Fatalf("want 3 pins, got %d: %v", len(pins), pins)
	}
}

// TestAuthorityPinsFromEnvIsDeterministic: AVERIN_AUTHORITY_KEYS pins install in a stable (project, source)
// order, so a duplicate-pin fatal is reproducible instead of depending on Go map iteration order.
func TestAuthorityPinsFromEnvIsDeterministic(t *testing.T) {
	aHex, _ := pubHex(0x31)
	bHex, _ := pubHex(0x32)
	cHex, _ := pubHex(0x33)
	env := envMap(map[string]string{
		"AVERIN_AUTHORITY_KEYS": "zeta:human_signed=" + aHex + ",alpha:human_signed=" + bHex + ",alpha:policy_engine_signed=" + cHex,
	})
	want := []string{"alpha|human_signed", "alpha|policy_engine_signed", "zeta|human_signed"}
	for i := 0; i < 20; i++ {
		pins := authorityPinsFromEnv(env)
		if len(pins) != len(want) {
			t.Fatalf("got %d pins, want %d", len(pins), len(want))
		}
		for j, p := range pins {
			if got := p.pin.project + "|" + p.pin.source; got != want[j] {
				t.Fatalf("iteration %d: pin[%d] = %q, want %q", i, j, got, want[j])
			}
		}
	}
}

// TestRequirePinnedAuthorityDefaultsOn (F3) is the regression test for the fail-open default: UNSET must
// resolve to the fail-CLOSED posture. Before the fix, unset meant a record CLAIMING an authority averin
// could not verify was permanently sealed at the forgeable caller_declared — and no shipped config set the
// variable, so that was the posture of every deployment.
func TestRequirePinnedAuthorityDefaultsOn(t *testing.T) {
	for _, raw := range []string{"", "   ", "1", "true", "TRUE", " True "} {
		on, err := requirePinnedAuthorityFromEnv(raw)
		if err != nil {
			t.Fatalf("AVERIN_REQUIRE_PINNED_AUTHORITY=%q: unexpected error %v", raw, err)
		}
		if !on {
			t.Fatalf("AVERIN_REQUIRE_PINNED_AUTHORITY=%q resolved FAIL-OPEN; the default and every truthy value must be fail-closed (F3)", raw)
		}
	}
	for _, raw := range []string{"0", "false", "FALSE", " 0 "} {
		on, err := requirePinnedAuthorityFromEnv(raw)
		if err != nil {
			t.Fatalf("AVERIN_REQUIRE_PINNED_AUTHORITY=%q: unexpected error %v", raw, err)
		}
		if on {
			t.Fatalf("AVERIN_REQUIRE_PINNED_AUTHORITY=%q must select the explicit fail-open opt-out", raw)
		}
	}
	// A typo must be FATAL, never a silently-guessed posture: "off"/"no"/"yes" are not accepted spellings,
	// and guessing wrong in either direction is a security decision made by a typo.
	for _, raw := range []string{"off", "no", "yes", "on", "2", "disabled"} {
		if _, err := requirePinnedAuthorityFromEnv(raw); err == nil {
			t.Fatalf("AVERIN_REQUIRE_PINNED_AUTHORITY=%q must be a fatal config error, not a guessed posture", raw)
		}
	}
}
