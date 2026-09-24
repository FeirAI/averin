package api_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// F1 — MULTI-TENANT AUTHORITY PINNING.
//
// govder derives its authority signing key per (tenant, role) (govder internal/authority/keystore.go
// DeriveSeed) and a govder tenant IS the averin project (internal/authority/signer.go: "project =
// req.TenantID // averin project axis defaults to the govder tenant"). averin pinned at most ONE key per
// SOURCE, globally, so on any deployment recording more than one tenant every tenant but one had its
// policy_engine_signed / human_signed / delegate_signed evidence fail key verification — and be SILENTLY
// sealed at the forgeable caller_declared.
//
// The pin set is now keyed by (project, source) with the un-scoped pin as the global default.

const (
	tenantAcme   = "tenant_acme"
	tenantGlobex = "tenant_globex"
)

// authorityRecord builds a record in `project` claiming `source`, with evidence signed by `signer` over the
// canonical authority preimage for (source, project, recordID, evidence_hash).
func authorityRecord(idem, project, recordID, source string, signer ed25519.PrivateKey) string {
	sum := sha256.Sum256([]byte("authority-evidence:" + recordID))
	eh := "sha256:" + hex.EncodeToString(sum[:])
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": project, "session_id": "s1", "record_id": recordID,
		"event_type": "decision", "status": "ok", "action": "kill",
		"authority": map[string]any{
			"source": source, "evidence_hash": eh,
			"evidence_sig": signAuthorityEvidence(source, project, recordID, eh, signer),
		},
	})
	return string(body)
}

func sealedAuthoritySource(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	code, resp := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusCreated {
		t.Fatalf("ingest rejected (%d): %s", code, resp)
	}
	var out struct {
		Results []struct {
			Record map[string]any `json:"record"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, resp)
	}
	auth, _ := out.Results[0].Record["authority"].(map[string]any)
	src, _ := auth["source"].(string)
	return src
}

// TestPerTenantAuthorityKeysElevateInTheirOwnProject (F1): two tenants, each with its OWN govder-derived
// human_signed key, both pinned against their own project. BOTH tenants' kill records must elevate to
// human_signed. Before the fix the pin map was keyed by source alone, so pinning two keys for human_signed
// was impossible (a duplicate-source panic) and, with one global key, tenant B's kill records silently
// downgraded to the forgeable caller_declared.
func TestPerTenantAuthorityKeysElevateInTheirOwnProject(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	acmeKey := ed25519.NewKeyFromSeed(peSeed(0x60))   // govder DeriveSeed(seed, "tenant_acme",   approval)
	globexKey := ed25519.NewKeyFromSeed(peSeed(0x61)) // govder DeriveSeed(seed, "tenant_globex", approval)

	h := api.New(c, store.NewMem(), "k0").
		WithProjectAuthorityKey(tenantAcme, "human_signed", acmeKey.Public().(ed25519.PublicKey)).
		WithProjectAuthorityKey(tenantGlobex, "human_signed", globexKey.Public().(ed25519.PublicKey)).
		Routes()

	if src := sealedAuthoritySource(t, h, authorityRecord("a1", tenantAcme, "kill-acme-1", "human_signed", acmeKey)); src != "human_signed" {
		t.Fatalf("tenant_acme kill record authority.source = %q, want human_signed", src)
	}
	// THE F1 REGRESSION: the SECOND tenant. With a single global pin this record's evidence failed to verify
	// and it was sealed at caller_declared — a kill permanently recorded at forgeable authority.
	if src := sealedAuthoritySource(t, h, authorityRecord("g1", tenantGlobex, "kill-globex-1", "human_signed", globexKey)); src != "human_signed" {
		t.Fatalf("tenant_globex kill record authority.source = %q, want human_signed — a second tenant's govder-derived key must be pinnable (F1)", src)
	}

	// Offline verify agrees: pinning BOTH published keys as authority_keys reads both as `verified`.
	for project, recordID := range map[string]string{tenantAcme: "kill-acme-1", tenantGlobex: "kill-globex-1"} {
		_, exp := do(t, h, "GET", "/v2/export?project="+project, "")
		pubs := fmt.Sprintf("%q,%q",
			"ed25519pub:"+base64.RawURLEncoding.EncodeToString(acmeKey.Public().(ed25519.PublicKey)),
			"ed25519pub:"+base64.RawURLEncoding.EncodeToString(globexKey.Public().(ed25519.PublicKey)))
		rep := c.VerifyBundleWith(exp, fmt.Sprintf(`{"authority_keys":[%s]}`, pubs))
		var report struct {
			RecordTrust []struct {
				RecordID  string `json:"record_id"`
				Authority string `json:"authority"`
			} `json:"record_trust"`
		}
		if err := json.Unmarshal([]byte(rep), &report); err != nil {
			t.Fatalf("decode report: %v\n%s", err, rep)
		}
		found := false
		for _, rt := range report.RecordTrust {
			if rt.RecordID == recordID {
				found = true
				if rt.Authority != "legacy_unbound" {
					t.Fatalf("%s (%s) offline authority = %q, want verified: %s", recordID, project, rt.Authority, rep)
				}
			}
		}
		if !found {
			t.Fatalf("%s missing from %s export report: %s", recordID, project, rep)
		}
	}
}

// TestTenantAuthorityKeyIsNotAuthoritativeInAnotherTenantsProject (F1): a GLOBAL pin is authoritative in
// EVERY project, so the project_id bound into the authority preimage stopped a signed block being COPIED
// across projects but did NOT stop the holder of tenant A's key from MINTING a fresh, valid block for
// tenant B's project. With per-project pins, tenant A's key elevates nothing in tenant B's project.
func TestTenantAuthorityKeyIsNotAuthoritativeInAnotherTenantsProject(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	acmeKey := ed25519.NewKeyFromSeed(peSeed(0x60))
	globexKey := ed25519.NewKeyFromSeed(peSeed(0x61))
	h := api.New(c, store.NewMem(), "k0").
		WithProjectAuthorityKey(tenantAcme, "human_signed", acmeKey.Public().(ed25519.PublicKey)).
		WithProjectAuthorityKey(tenantGlobex, "human_signed", globexKey.Public().(ed25519.PublicKey)).
		Routes()

	// POSITIVE CONTROL FIRST. Without this the test is satisfied by a server that rejects EVERYTHING — which
	// is exactly what the pre-fix, source-only lookup does when project-scoped pins are configured. globex's
	// OWN key must elevate in globex's project.
	if src := sealedAuthoritySource(t, h, authorityRecord("g0", tenantGlobex, "kill-globex-ok", "human_signed", globexKey)); src != "human_signed" {
		t.Fatalf("positive control: tenant_globex's own key must elevate in its own project, got %q", src)
	}

	// acme's key signs a FRESH, well-formed human_signed block bound to GLOBEX's project.
	forged := authorityRecord("x1", tenantGlobex, "kill-globex-forged", "human_signed", acmeKey)
	code, resp := do(t, h, "POST", "/v2/records", forged)
	if code != http.StatusInternalServerError {
		t.Fatalf("tenant_acme's key must not mint authority in tenant_globex's project: got %d: %s", code, resp)
	}
	// Only the legitimate record is in the ledger; the cross-tenant forgery sealed nothing.
	_, list := do(t, h, "GET", "/v2/records?project="+tenantGlobex, "")
	if !strings.Contains(list, `"total":1`) {
		t.Fatalf("the cross-tenant forgery must seal NOTHING (only the positive-control record may exist): %s", list)
	}
	if strings.Contains(list, "kill-globex-forged") {
		t.Fatalf("the cross-tenant forgery entered the ledger: %s", list)
	}
}

// TestGlobalAuthorityPinRemainsTheDefault (F1 back-compat): an un-scoped pin still applies to every project
// that has no project-scoped pin of its own — the historical single-key deployment is unchanged.
func TestGlobalAuthorityPinRemainsTheDefault(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	global := ed25519.NewKeyFromSeed(peSeed(0x62))
	scoped := ed25519.NewKeyFromSeed(peSeed(0x63))
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("human_signed", global.Public().(ed25519.PublicKey)). // global default
		WithProjectAuthorityKey(tenantAcme, "human_signed", scoped.Public().(ed25519.PublicKey)).
		Routes()

	// A project with NO scoped pin falls back to the global default.
	if src := sealedAuthoritySource(t, h, authorityRecord("g1", tenantGlobex, "k-globex", "human_signed", global)); src != "human_signed" {
		t.Fatalf("the global pin must still apply to an unscoped project, got %q", src)
	}
	// The scoped project uses ITS key...
	if src := sealedAuthoritySource(t, h, authorityRecord("a1", tenantAcme, "k-acme", "human_signed", scoped)); src != "human_signed" {
		t.Fatalf("the project-scoped pin must elevate its own tenant, got %q", src)
	}
	// ...and the project-scoped pin WINS: the global key no longer elevates inside that project.
	code, resp := do(t, h, "POST", "/v2/records", authorityRecord("a2", tenantAcme, "k-acme-2", "human_signed", global))
	if code != http.StatusInternalServerError {
		t.Fatalf("a project-scoped pin must override the global default, got %d: %s", code, resp)
	}
}

// TestPerTenantPinsCoverEveryVerifiedSource (F1 + F2): all three govder roles — policy_engine_signed (budget
// verdicts), human_signed (kill/approval), delegate_signed (delegate-agent approvals) — are pinnable
// per-project, so a second tenant's WHOLE governance feed elevates, not just one source.
func TestPerTenantPinsCoverEveryVerifiedSource(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	srv := api.New(c, store.NewMem(), "k0")
	keys := map[string]map[string]ed25519.PrivateKey{}
	b := byte(0x70)
	for _, tenant := range []string{tenantAcme, tenantGlobex} {
		keys[tenant] = map[string]ed25519.PrivateKey{}
		for _, source := range []string{"policy_engine_signed", "human_signed", "delegate_signed"} {
			k := ed25519.NewKeyFromSeed(peSeed(b))
			b++
			keys[tenant][source] = k
			srv = srv.WithProjectAuthorityKey(tenant, source, k.Public().(ed25519.PublicKey))
		}
	}
	h := srv.Routes()
	for _, tenant := range []string{tenantAcme, tenantGlobex} {
		for _, source := range []string{"policy_engine_signed", "human_signed", "delegate_signed"} {
			id := tenant + "-" + source
			got := sealedAuthoritySource(t, h, authorityRecord(id, tenant, id, source, keys[tenant][source]))
			if got != source {
				t.Fatalf("%s/%s sealed authority.source = %q, want %q", tenant, source, got, source)
			}
		}
	}
}
