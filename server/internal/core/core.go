// Package core binds the Rust decision-core via cgo. Canonicalize / seal / verify live in Rust
// (the single source of truth); Go never reimplements them. Build the library first with
// `cargo build` (produces target/debug/libfeir_decision_core.a).
package core

/*
#cgo CFLAGS: -I${SRCDIR}/../../../core/include
#cgo LDFLAGS: ${SRCDIR}/../../../target/debug/libfeir_decision_core.a
#include <feir_core.h>
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
	pk := goStrFree(C.feir_pubkey_from_seed(cs))
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
	return goStrFree(C.feir_rcp_canonicalize(cs))
}

// SealRecord seals a Decision Record body, returning the sealed JSON.
func (c *Core) SealRecord(bodyJSON string) (string, error) {
	cb := C.CString(bodyJSON)
	cs := C.CString(c.seedHex)
	defer C.free(unsafe.Pointer(cb))
	defer C.free(unsafe.Pointer(cs))
	return checkSeal(goStrFree(C.feir_seal_record(cb, cs)))
}

// SealCheckpoint seals a checkpoint body.
func (c *Core) SealCheckpoint(bodyJSON string) (string, error) {
	cb := C.CString(bodyJSON)
	cs := C.CString(c.seedHex)
	defer C.free(unsafe.Pointer(cb))
	defer C.free(unsafe.Pointer(cs))
	return checkSeal(goStrFree(C.feir_seal_checkpoint(cb, cs)))
}

// VerifyBundle verifies an export bundle and returns the JSON report.
func (c *Core) VerifyBundle(bundleJSON string) string {
	cb := C.CString(bundleJSON)
	defer C.free(unsafe.Pointer(cb))
	return goStrFree(C.feir_verify_bundle_json(cb))
}

// ---- content commitments (RCP §9.3, threat #6) ----
//
// Low-entropy fields (input/output/rationale) are committed (hiding) rather than stored in clear in
// the signed body. The raw value lives in the content store; the record carries only the commitment;
// selective disclosure later reveals (value, nonce). The crypto lives in Rust — Go only marshals.

// RandomNonce mints a fresh 32-byte hiding-commitment nonce as 64 lowercase hex chars.
func (c *Core) RandomNonce() (string, error) {
	return checkValue(goStrFree(C.feir_random_nonce()))
}

// Commit computes the hiding commitment "sha256:<hex>" over value under domain (one of
// "input"/"output"/"rationale"), hidden by a 64-hex-char nonce. The value is sent base64url-no-pad
// (the FFI's wire form); the commitment binds the raw bytes, not the encoding.
func (c *Core) Commit(domain string, value []byte, nonceHex string) (string, error) {
	cd := C.CString(domain)
	cv := C.CString(base64.RawURLEncoding.EncodeToString(value))
	cn := C.CString(nonceHex)
	defer C.free(unsafe.Pointer(cd))
	defer C.free(unsafe.Pointer(cv))
	defer C.free(unsafe.Pointer(cn))
	return checkValue(goStrFree(C.feir_commit(cd, cv, cn)))
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
	out, err := checkValue(goStrFree(C.feir_verify_commitment(cc, cd, cv, cn)))
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
	C.feir_string_free(p)
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
