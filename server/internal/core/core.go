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
