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
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
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
// The sig is ed25519 over LP4("averin.taxonomy.v1") ‖ utf8(digest), byte-identical to the Rust verifier's
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

// signTaxonomy = ed25519(taxKey, LP4("averin.taxonomy.v1") ‖ utf8(digest)) -> "ed25519:"+base64url-no-pad,
// byte-identical to the Rust core's sign::sign over the averin.taxonomy.v1 domain (RCP §9.2). The signed
// message is the digest STRING (not the body bytes). Cross-language agreement is exercised by the e2e test
// that verifies a Go-signed taxonomy under the Rust verifier.
func signTaxonomy(digest string, sk ed25519.PrivateKey) string {
	const tag = "averin.taxonomy.v1"
	pre := make([]byte, 0, 4+len(tag)+len(digest))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(tag)))
	pre = append(pre, lp[:]...)
	pre = append(pre, tag...)
	pre = append(pre, digest...)
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, pre))
}

// Verify checks a signed taxonomy artifact against pins: the RCP-canonical digest of the body (minus sig)
// must equal the pinned digest, the body version must equal the pinned version, and sig must be a valid
// averin.taxonomy.v1 Ed25519 signature over that digest by one of the pinned issuer keys (the form
// "ed25519pub:" + base64url-no-pad). It is the offline counterpart of the verifier's taxonomy check, which
// downgrades any mismatch to a quiet "untrusted"; here every mismatch is an error. Errors name the failed
// pin but never echo key material. Time windows are not judged (the verifier judges them per use).
func Verify(h Hasher, artifact []byte, pubkeys []string, wantDigest string, wantVersion int64) error {
	if len(pubkeys) == 0 {
		return fmt.Errorf("no issuer public key pinned")
	}
	dec := json.NewDecoder(bytes.NewReader(artifact))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return fmt.Errorf("artifact is not a JSON object: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("artifact has trailing data")
	}
	if k, _ := body["kind"].(string); k != "operation_taxonomy" {
		return fmt.Errorf("artifact kind is not operation_taxonomy")
	}
	sigStr, _ := body["sig"].(string)
	if sigStr == "" {
		return fmt.Errorf("artifact is unsigned (no sig)")
	}
	delete(body, "sig")
	vn, ok := body["version"].(json.Number)
	if !ok {
		return fmt.Errorf("artifact has no integer version")
	}
	gotVersion, err := vn.Int64()
	if err != nil {
		return fmt.Errorf("artifact version is not an integer")
	}
	if gotVersion != wantVersion {
		return fmt.Errorf("version pin mismatch: artifact has %d, pin is %d", gotVersion, wantVersion)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("re-marshal body: %w", err)
	}
	digest, err := h.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return fmt.Errorf("taxonomy digest: %w", err)
	}
	if digest != wantDigest {
		return fmt.Errorf("digest pin mismatch: artifact digests to %s, pin is %s", digest, wantDigest)
	}
	const sigPrefix = "ed25519:"
	if !strings.HasPrefix(sigStr, sigPrefix) {
		return fmt.Errorf("sig is not ed25519")
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sigStr, sigPrefix))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("sig is malformed")
	}
	const tag = "averin.taxonomy.v1"
	pre := make([]byte, 0, 4+len(tag)+len(digest))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(tag)))
	pre = append(pre, lp[:]...)
	pre = append(pre, tag...)
	pre = append(pre, digest...)
	for _, pk := range pubkeys {
		raw, ok := strings.CutPrefix(pk, "ed25519pub:")
		if !ok {
			continue
		}
		kb, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(kb) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(kb), pre, sig) {
			return nil
		}
	}
	return fmt.Errorf("signature does not verify under any pinned issuer key")
}
