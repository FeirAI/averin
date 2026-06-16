// Package taxonomy signs the operation taxonomy the offline verifier pins (ADR 0004 D4 / threat F8).
//
// The taxonomy is a verifier-pinned, out-of-band artifact: an auditor pins (taxonomy, taxonomy_keys,
// taxonomy_digest, taxonomy_version) and the verifier elevates a matched single_operation use to
// action_verified only when its (resource_id, action) is listed and the signature/digest/version/window
// all check. This package AUTHORS + SIGNS + ROTATES such an artifact — the piece that was missing (the
// verifier and its consumption path already exist). The taxonomy issuer holds NO runtime authority over
// grants or uses: its key is role-separated and the verifier fatal-aborts if it overlaps the
// broker/resource/tsa/attestation key sets.
package taxonomy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Entry is a resource-bound operation the taxonomy classifies: a (resource_id, action) pair.
type Entry struct {
	ResourceID string
	Action     string
}

// Hasher computes the RCP-canonical evidence hash the verifier re-derives. *core.Core satisfies it; the
// interface keeps this package testable and makes the cgo dependency explicit at the call site.
type Hasher interface {
	RcpEvidenceHash(json string) (string, error)
}

func entriesJSON(es []Entry) []map[string]any {
	out := make([]map[string]any, len(es))
	for i, e := range es {
		out[i] = map[string]any{"action": e.Action, "resource_id": e.ResourceID}
	}
	return out
}

// Sign builds and signs an operation taxonomy body and returns the signed JSON plus the (digest, version)
// an auditor must pin as taxonomy_digest / taxonomy_version. The digest is sha256_prefixed of the
// RCP-canonical body MINUS sig — computed by the core (h.RcpEvidenceHash), NEVER Go json.Marshal, since RCP
// canonicalization (NFC keys, UTF-16 key sort, integer-only) is the single cross-language source of truth.
// The sig is ed25519 over LP4("feir.taxonomy.v1") ‖ utf8(digest), byte-identical to the Rust verifier's
// sign::sign. taxKey MUST be role-separated from the broker/resource/tsa/attestation keys (the verifier
// treats an overlap as a fatal configuration error).
func Sign(h Hasher, taxKey ed25519.PrivateKey, version, effectiveFrom, effectiveUntil int64, single, escalating []Entry) (taxJSON, digest string, ver int64, err error) {
	if len(single) == 0 {
		return "", "", 0, fmt.Errorf("taxonomy needs at least one single_operation_actions entry")
	}
	if effectiveFrom > effectiveUntil {
		return "", "", 0, fmt.Errorf("effective_from %d is after effective_until %d", effectiveFrom, effectiveUntil)
	}
	body := map[string]any{
		"kind":                     "operation_taxonomy",
		"version":                  version,
		"effective_from":           effectiveFrom,
		"effective_until":          effectiveUntil,
		"single_operation_actions": entriesJSON(single),
	}
	if len(escalating) > 0 {
		body["escalating_actions"] = entriesJSON(escalating) // omitted when empty (the verifier defaults it)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", "", 0, fmt.Errorf("marshal taxonomy body: %w", err)
	}
	digest, err = h.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return "", "", 0, fmt.Errorf("taxonomy digest: %w", err)
	}
	body["sig"] = signTaxonomy(digest, taxKey)
	out, err := json.Marshal(body)
	if err != nil {
		return "", "", 0, fmt.Errorf("marshal signed taxonomy: %w", err)
	}
	return string(out), digest, version, nil
}

// signTaxonomy = ed25519(taxKey, LP4("feir.taxonomy.v1") ‖ utf8(digest)) -> "ed25519:"+base64url-no-pad,
// byte-identical to the Rust core's sign::sign over the feir.taxonomy.v1 domain (RCP §9.2). The signed
// message is the digest STRING (not the body bytes). Cross-language agreement is exercised by the e2e test
// that verifies a Go-signed taxonomy under the Rust verifier.
func signTaxonomy(digest string, sk ed25519.PrivateKey) string {
	const tag = "feir.taxonomy.v1"
	pre := make([]byte, 0, 4+len(tag)+len(digest))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(tag)))
	pre = append(pre, lp[:]...)
	pre = append(pre, tag...)
	pre = append(pre, digest...)
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, pre))
}
