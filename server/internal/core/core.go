// Package core binds the Rust decision-core via cgo. Canonicalize / seal / verify live in Rust
// (the single source of truth); Go never reimplements them. Build the library first with
// `cargo build` (produces target/debug/libaverin_decision_core.a).
package core

/*
#cgo CFLAGS: -I${SRCDIR}/../../../core/include
#cgo LDFLAGS: ${SRCDIR}/../../../target/debug/libaverin_decision_core.a
#include <averin_core.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// Core wraps the Rust integrity core with a held signing seed (self-host). Production backs signing
// with a KMS instead of a raw seed.
type Core struct {
	seedHex string
	pubKey  string
}

// New validates the seed and caches the derived public key.
func New(seedHex string) (*Core, error) {
	cs := C.CString(seedHex)
	defer C.free(unsafe.Pointer(cs))
	pk := goStrFree(C.averin_pubkey_from_seed(cs))
	if pk == "" || strings.Contains(pk, `"error"`) {
		return nil, fmt.Errorf("invalid signing seed: %s", pk)
	}
	return &Core{seedHex: seedHex, pubKey: pk}, nil
}

// PubKey returns the ed25519pub: public key for the held seed.
func (c *Core) PubKey() string { return c.pubKey }

// RcpCanonicalize returns the RCP-v1 canonical form (or a string starting with "ERROR:").
func (c *Core) RcpCanonicalize(jsonDoc string) string {
	cs := C.CString(jsonDoc)
	defer C.free(unsafe.Pointer(cs))
	return goStrFree(C.averin_rcp_canonicalize(cs))
}

// RcpEvidenceHash returns "sha256:<hex>" over the RCP-v1 canonical form of payloadJSON — the single
// source of truth for an evidence_hash. The broker/resource computes evidence_hash this way (NOT via
// Go json.Marshal) so the offline verifier can re-derive the SAME hash from the evidence payload it
// embeds in the record (ADR 0003 R1). Errors fail-closed (a parse error is surfaced, never a silent
// empty hash).
func (c *Core) RcpEvidenceHash(payloadJSON string) (string, error) {
	cs := C.CString(payloadJSON)
	defer C.free(unsafe.Pointer(cs))
	return checkValue(goStrFree(C.averin_rcp_evidence_hash(cs)))
}

// SealRecord seals a Decision Record body, returning the sealed JSON.
func (c *Core) SealRecord(bodyJSON string) (string, error) {
	cb := C.CString(bodyJSON)
	cs := C.CString(c.seedHex)
	defer C.free(unsafe.Pointer(cb))
	defer C.free(unsafe.Pointer(cs))
	return checkSeal(goStrFree(C.averin_seal_record(cb, cs)))
}

// SealCheckpoint seals a checkpoint body.
func (c *Core) SealCheckpoint(bodyJSON string) (string, error) {
	cb := C.CString(bodyJSON)
	cs := C.CString(c.seedHex)
	defer C.free(unsafe.Pointer(cb))
	defer C.free(unsafe.Pointer(cs))
	return checkSeal(goStrFree(C.averin_seal_checkpoint(cb, cs)))
}

// nulRejectReport is the fail-closed JSON report for a bundle that contains a NUL byte. A C string is
// NUL-terminated, so an interior 0x00 would truncate the input at the FFI boundary and could be
// reported "ok" over only the prefix before it. Valid RCP never contains 0x00, so reject it here where
// the true Go-string length is known, mirroring the verifier's own fail-closed verdict on such input.
func nulRejectReport(at int) string {
	b, _ := json.Marshal(map[string]any{
		"ok":    false,
		"error": fmt.Sprintf("bundle contains a NUL byte at offset %d (not valid RCP)", at),
	})
	return string(b)
}

// VerifyBundle verifies an export bundle and returns the JSON report.
func (c *Core) VerifyBundle(bundleJSON string) string {
	if i := strings.IndexByte(bundleJSON, 0); i >= 0 {
		return nulRejectReport(i)
	}
	cb := C.CString(bundleJSON)
	defer C.free(unsafe.Pointer(cb))
	return goStrFree(C.averin_verify_bundle_json(cb))
}

// VerifyBundleWith verifies a bundle with out-of-band pinned trust roots (optsJSON: arrays of
// authority_keys/signing_keys/tsa_keys as "ed25519pub:" + tsa_spki_b64). Returns the JSON report.
func (c *Core) VerifyBundleWith(bundleJSON, optsJSON string) string {
	if i := strings.IndexByte(bundleJSON, 0); i >= 0 {
		return nulRejectReport(i)
	}
	// Guard optsJSON too: C.CString stops at the first NUL, so a 0x00 in opts could silently truncate the
	// pinned trust roots (e.g. drop a resource_authority_keys entry). Valid opts (ed25519pub:/base64url) never
	// contain 0x00, so reject fail-closed rather than verify under a truncated trust set. (The truncation-proof
	// ABI averin_verify_bundle_with_n is what the wasm verifier exports — the NUL-truncatable C-string variants are
	// compiled ONLY for native/cgo, where this Go-side guard covers them.)
	if i := strings.IndexByte(optsJSON, 0); i >= 0 {
		return nulRejectReport(i)
	}
	cb := C.CString(bundleJSON)
	co := C.CString(optsJSON)
	defer C.free(unsafe.Pointer(cb))
	defer C.free(unsafe.Pointer(co))
	return goStrFree(C.averin_verify_bundle_with(cb, co))
}

// VerifyBundleWithAuthority verifies a bundle pinning the given recording keys (in self-host, the
// single server signing key) as BOTH the broker authority set and the generic authority set, so a
// credential-broker grant elevates under the BROKER role (ADR 0003 R2) while any generic
// policy_engine_signed/human_signed record still elevates under the generic set. The keys are NOT
// pinned as resource keys (those use a separate WithResource recording key), so the R2 disjointness
// invariant (broker ∩ resource = ∅) holds.
func (c *Core) VerifyBundleWithAuthority(bundleJSON string, authorityPubKeys []string) string {
	opts, _ := json.Marshal(map[string]any{
		"authority_keys":        authorityPubKeys,
		"broker_authority_keys": authorityPubKeys,
	})
	return c.VerifyBundleWith(bundleJSON, string(opts))
}

// VerifyBundleWithRoles pins the BROKER recording keys and the RESOURCE recording keys separately
// (ADR 0003 R2), so a grant elevates only under a broker key and a use receipt only under a resource
// key. The two sets MUST be disjoint (the verifier rejects an intersection as a fatal config error).
// brokerKeys are also pinned as the generic authority set for any non-broker authority record.
func (c *Core) VerifyBundleWithRoles(bundleJSON string, brokerKeys, resourceKeys []string) string {
	opts, _ := json.Marshal(map[string]any{
		"authority_keys":          brokerKeys,
		"broker_authority_keys":   brokerKeys,
		"resource_authority_keys": resourceKeys,
	})
	return c.VerifyBundleWith(bundleJSON, string(opts))
}

// ---- content commitments (RCP §9.3, threat #6) ----
//
// Low-entropy fields (input/output/rationale) are committed (hiding) rather than stored in clear in
// the signed body. The raw value lives in the content store; the record carries only the commitment;
// selective disclosure later reveals (value, nonce). The crypto lives in Rust — Go only marshals.

// RandomNonce mints a fresh 32-byte hiding-commitment nonce as 64 lowercase hex chars.
func (c *Core) RandomNonce() (string, error) {
	return checkValue(goStrFree(C.averin_random_nonce()))
}

// Commit computes the hiding commitment "sha256:<hex>" over value under domain (one of
// "input"/"output"/"rationale"), hidden by a 64-hex-char nonce. The value is sent base64url-no-pad
// (the FFI's wire form); the commitment binds the raw bytes, not the encoding.
//
// nonceHex is client-reachable (POST /v2/use params_nonce): a C string is NUL-terminated, so an
// interior 0x00 would truncate domain/nonceHex at the FFI boundary and let Rust commit over only the
// prefix while the FULL untruncated value is stored for later disclosure — a commitment that can
// never be reopened offline. Reject fail-closed here, where the true Go-string length is known,
// mirroring VerifyBundle/VerifyBundleWith's NUL guard above. domain is small and server-controlled,
// but guarding it too is cheap and keeps the two inputs to this call consistent.
func (c *Core) Commit(domain string, value []byte, nonceHex string) (string, error) {
	if i := strings.IndexByte(domain, 0); i >= 0 {
		return "", fmt.Errorf("commit: NUL byte at offset %d in domain (would truncate the committed preimage)", i)
	}
	if i := strings.IndexByte(nonceHex, 0); i >= 0 {
		return "", fmt.Errorf("commit: NUL byte at offset %d in nonce (would truncate the committed preimage)", i)
	}
	cd := C.CString(domain)
	cv := C.CString(base64.RawURLEncoding.EncodeToString(value))
	cn := C.CString(nonceHex)
	defer C.free(unsafe.Pointer(cd))
	defer C.free(unsafe.Pointer(cv))
	defer C.free(unsafe.Pointer(cn))
	return checkValue(goStrFree(C.averin_commit(cd, cv, cn)))
}

// SignEvidence signs an authority evidence statement bound to (source, projectID, recordID, evidenceHash)
// with the held key — the credential broker (and policy engine) uses this to produce the `evidence_sig`
// that elevates a record to `verified` under the pinned authority key. projectID binds the evidence to its
// tenant so a verified triple cannot be replayed into another project (Codex). source must be one of
// "policy_engine_signed"|"human_signed"|"gateway_enforced" (others are rejected — they could never
// verify). evidenceHash must be "sha256:<64 LOWERCASE hex>". Returns "ed25519:<base64url>".
//
// Trust boundary: this signs evidenceHash as an opaque value; it does NOT check that
// evidenceHash == sha256(the real canonical evidence). The caller (broker) must guarantee that
// binding (the broker TCB — ADR 0002 broker_trust: assumed).
func (c *Core) SignEvidence(source, projectID, recordID, evidenceHash string) (string, error) {
	cs := C.CString(source)
	cproj := C.CString(projectID)
	crid := C.CString(recordID)
	ceh := C.CString(evidenceHash)
	cseed := C.CString(c.seedHex)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cproj))
	defer C.free(unsafe.Pointer(crid))
	defer C.free(unsafe.Pointer(ceh))
	defer C.free(unsafe.Pointer(cseed))
	return checkValue(goStrFree(C.averin_sign_evidence(cs, cproj, crid, ceh, cseed)))
}

// VerifyCommitment reports whether the disclosed (value, nonce) opens commitment under domain.
func (c *Core) VerifyCommitment(commitment, domain string, value []byte, nonceHex string) (bool, error) {
	cc := C.CString(commitment)
	cd := C.CString(domain)
	cv := C.CString(base64.RawURLEncoding.EncodeToString(value))
	cn := C.CString(nonceHex)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(cd))
	defer C.free(unsafe.Pointer(cv))
	defer C.free(unsafe.Pointer(cn))
	out, err := checkValue(goStrFree(C.averin_verify_commitment(cc, cd, cv, cn)))
	if err != nil {
		return false, err
	}
	return out == "true", nil
}

// ---- cgo plumbing ----

func goStrFree(p *C.char) string {
	if p == nil {
		return ""
	}
	s := C.GoString(p)
	C.averin_string_free(p)
	return s
}

func checkSeal(out string) (string, error) {
	if out == "" {
		return "", errors.New("core returned null (invalid input)")
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(out), &e) == nil && e.Error != "" {
		return "", errors.New(e.Error)
	}
	return out, nil
}

// checkValue is checkSeal for the small scalar returns (nonce hex, "sha256:..." commitment,
// "true"/"false"). The Rust side signals failure with a {"error":"..."} JSON object; a bare
// non-JSON string is the success value. (A literal "false" is NOT JSON-object-shaped, so it is
// never mistaken for an error.)
func checkValue(out string) (string, error) {
	return checkSeal(out)
}
