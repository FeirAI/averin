// Package resourceshim is the resource-side gateway for Tier-B (Level 3 action accountability,
// ADR 0003). It is PURE logic with no cgo/server dependency: given a presented capability + a
// proof-of-possession at use time, it validates the capability, enforces single-use and PoP freshness
// through a consume-before-act ledger (R5), and produces the canonical use_evidence the api layer
// signs (with the RESOURCE key) and seals into a use receipt — the payload the offline verifier
// re-derives evidence_hash from (R1) and joins to the grant (step 5).
//
// TCB boundary (ADR 0003 MUST-FIX 4): this shim is the trusted enforcer of capability validity, PoP,
// nonce freshness, and consume-before-act. The offline verifier does NOT re-run the Ed25519 PoP check
// or verify ledger ordering; it checks the resource signature + evidence_hash re-derivation and that
// the receipt carries well-formed pop_challenge_hash / cnf_kid / nonce / jti / ledger_commitment.
package resourceshim

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/feir-dev/feir/server/internal/broker"
)

// usePoPTag domain-separates the use-time proof-of-possession challenge so a signature here cannot be
// repurposed as a request-time PoP (broker.popTag) or any other signature.
const usePoPTag = "feir.broker.use.pop.v1"

// ledgerTag domain-separates the ledger_commitment preimage from the PoP challenge (and any other
// hash), so the two length-prefixed digests can never collide.
const ledgerTag = "feir.broker.use.ledger.v1"

// ErrConsumed reports that a single-use credential (jti) or a PoP nonce was already consumed — a
// double-spend or a replay. It is returned by the ledger and surfaced by ValidateUse.
var ErrConsumed = errors.New("resourceshim: credential jti or nonce already consumed")

// Ledger is the durable consume-before-act store. Consumption is marked BEFORE the resource performs
// the side effect, so a crash after consumption cannot leave a live credential.
type Ledger interface {
	// ConsumeNonce atomically marks a PoP nonce consumed (replay protection); ErrConsumed if seen.
	ConsumeNonce(nonce string) error
	// ConsumeJTI atomically marks a single-use credential jti consumed (double-spend protection);
	// ErrConsumed if already spent.
	ConsumeJTI(jti string) error
}

// MemLedger is an in-memory Ledger for the demonstrator and tests. Production backs the ledger with a
// durable, atomically-consistent store. Safe for concurrent use.
type MemLedger struct {
	mu     sync.Mutex
	jti    map[string]struct{}
	nonces map[string]struct{}
}

// NewMemLedger returns an empty in-memory ledger.
func NewMemLedger() *MemLedger {
	return &MemLedger{jti: map[string]struct{}{}, nonces: map[string]struct{}{}}
}

// ConsumeNonce marks nonce consumed; ErrConsumed if it was already consumed.
func (l *MemLedger) ConsumeNonce(nonce string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nonces == nil {
		l.nonces = map[string]struct{}{} // tolerate a zero-value MemLedger{}
	}
	if _, ok := l.nonces[nonce]; ok {
		return ErrConsumed
	}
	l.nonces[nonce] = struct{}{}
	return nil
}

// ConsumeJTI marks jti consumed; ErrConsumed if it was already consumed.
func (l *MemLedger) ConsumeJTI(jti string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.jti == nil {
		l.jti = map[string]struct{}{} // tolerate a zero-value MemLedger{}
	}
	if _, ok := l.jti[jti]; ok {
		return ErrConsumed
	}
	l.jti[jti] = struct{}{}
	return nil
}

// Op is the operation a resource is about to perform under a presented capability. ResourceID comes
// from the shim config (not the caller), so the caller cannot claim to be a different resource.
type Op struct {
	// Action is the operation id; it MUST equal the capability's authorized action (claims.Act).
	Action string
	// ParamsCommitment is a sha256:<hex> hiding commitment over the operation parameters. It is bound
	// into the PoP challenge so a captured use_sig cannot be replayed against different params.
	ParamsCommitment string
}

// UseEvidence is the canonical use_evidence payload (ADR 0003 §"Canonical evidence schemas"). The api
// layer marshals it, signs evidence_hash = sha256(RCP-canonicalize(use_evidence)) with the resource
// key, and embeds it at extensions.broker.use_evidence; the verifier reads every match input from it.
// Field order is irrelevant — RCP canonicalizes — but the keys and types are fixed by the schema.
type UseEvidence struct {
	Kind             string `json:"kind"`               // "use" (role/shape discriminator)
	GrantID          string `json:"grant_id"`           // join key to grant_evidence.grant_id
	Action           string `json:"action"`             // == grant_evidence.action
	ResourceID       string `json:"resource_id"`        // == grant_evidence.resource_id
	JTI              string `json:"jti"`                // single-use id; == grant_id for single_operation
	Nonce            string `json:"nonce"`              // PoP freshness nonce (R4)
	PopChallengeHash string `json:"pop_challenge_hash"` // sha256:<hex> of the PoP challenge (R4/MUST-FIX 4)
	CnfKid           string `json:"cnf_kid"`            // == grant_evidence.cnf_kid (the cnf key id)
	LedgerCommitment string `json:"ledger_commitment"`  // sha256:<hex> of the consumed ledger entry (R5)
	UsedAt           int64  `json:"used_at"`            // unix seconds; must lie in [issued_at, exp]
}

// Shim is the resource-side gateway, configured once with the broker's capability-issuing public key,
// this resource's id, and the durable ledger.
type Shim struct {
	issuingPub ed25519.PublicKey
	resourceID string
	ledger     Ledger
}

// New constructs a Shim. resourceID is this resource's audience id (capabilities whose aud differs are
// rejected); issuingPub is the broker's capability-signing public key.
func New(issuingPub ed25519.PublicKey, resourceID string, ledger Ledger) *Shim {
	return &Shim{issuingPub: issuingPub, resourceID: resourceID, ledger: ledger}
}

// ValidateUse validates a presented capability + proof-of-possession for op, consumes the credential
// (consume-before-act), and returns the canonical use_evidence. The ordering is: validate everything
// that can fail WITHOUT consuming (capability signature, validity window, audience/action coverage,
// PoP-at-use), and only THEN consume the nonce (replay) and, for a single-use credential, the jti
// (double-spend). This keeps a failed/forged request from burning a victim's credential, while still
// consuming before the side effect (which the caller performs only after a successful return).
func (s *Shim) ValidateUse(token, useSigB64 string, op Op, nonce string, now time.Time) (UseEvidence, error) {
	// 1. Capability signature + decode (the broker minted and signed this descriptor).
	claims, err := broker.VerifyCapability(token, s.issuingPub)
	if err != nil {
		return UseEvidence{}, err
	}
	// 2. Validity window (threat B8: short-lived credentials).
	unix := now.UTC().Unix()
	if unix < claims.Nbf {
		return UseEvidence{}, fmt.Errorf("resourceshim: capability not yet valid (nbf %d > now %d)", claims.Nbf, unix)
	}
	if unix >= claims.Exp {
		return UseEvidence{}, fmt.Errorf("resourceshim: capability expired (exp %d <= now %d)", claims.Exp, unix)
	}
	// 3. Audience + action coverage: the capability must authorize THIS resource and THIS action.
	if claims.Aud != s.resourceID {
		return UseEvidence{}, fmt.Errorf("resourceshim: capability audience %q does not match this resource %q", claims.Aud, s.resourceID)
	}
	if op.Action == "" || op.Action != claims.Act {
		return UseEvidence{}, fmt.Errorf("resourceshim: operation %q is not the authorized action %q", op.Action, claims.Act)
	}
	if strings.TrimSpace(nonce) == "" {
		return UseEvidence{}, errors.New("resourceshim: a one-time PoP nonce is required")
	}
	// 4. PoP-at-use (R4): the holder must sign the fully-bound challenge with the cnf private key, so a
	// stolen token (without the cnf key) cannot be used.
	cnfPub, err := base64.RawURLEncoding.DecodeString(claims.Cnf)
	if err != nil || len(cnfPub) != ed25519.PublicKeySize {
		return UseEvidence{}, errors.New("resourceshim: capability cnf is not a valid ed25519 public key")
	}
	binding, err := credentialBinding(token)
	if err != nil {
		return UseEvidence{}, err
	}
	challenge := usePoPChallenge(claims.Jti, s.resourceID, op.Action, op.ParamsCommitment, binding, nonce)
	useSig, err := base64.RawURLEncoding.DecodeString(useSigB64)
	if err != nil || len(useSig) != ed25519.SignatureSize {
		return UseEvidence{}, errors.New("resourceshim: use_sig must be a base64url-no-pad ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(cnfPub), challenge, useSig) {
		return UseEvidence{}, errors.New("resourceshim: use_sig does not prove possession of the cnf key (PoP failed)")
	}
	// 5. Consume-before-act (R5): mark the nonce (replay) and, for a single-use credential, the jti
	// (double-spend) consumed BEFORE the caller performs the side effect. A second receipt for the same
	// single-use jti, or a replay of the same nonce, fails here.
	if err := s.ledger.ConsumeNonce(nonce); err != nil {
		return UseEvidence{}, fmt.Errorf("resourceshim: nonce replay: %w", err)
	}
	if claims.SingleUse {
		if err := s.ledger.ConsumeJTI(claims.Jti); err != nil {
			return UseEvidence{}, fmt.Errorf("resourceshim: single-use double-spend: %w", err)
		}
	}
	// 6. Build the canonical use_evidence. For a single_operation grant jti == grant_id (the broker
	// mints jti = grant_id), so grant_id and jti coincide here — the verifier's per-grant_id single-use
	// rule and the shim's per-jti ledger provably agree (R5 rev 4).
	usedAt := unix
	return UseEvidence{
		Kind:             "use",
		GrantID:          claims.Jti,
		Action:           op.Action,
		ResourceID:       s.resourceID,
		JTI:              claims.Jti,
		Nonce:            nonce,
		PopChallengeHash: "sha256:" + hex.EncodeToString(challenge),
		CnfKid:           broker.KeyID(ed25519.PublicKey(cnfPub)),
		LedgerCommitment: ledgerCommitment(claims.Jti, nonce, usedAt),
		UsedAt:           usedAt,
	}, nil
}

// usePoPChallenge is the 32-byte digest the holder signs with the cnf key (R4):
// sha256( LP(tag) ‖ LP(grant_id) ‖ LP(resource_id) ‖ LP(action) ‖ LP(params_commitment) ‖
// LP(credential_binding) ‖ LP(nonce) ), where LP is a 4-byte big-endian length prefix. Length-prefixing
// makes the concatenation unambiguous (no field-boundary confusion). Agent and shim both compute it,
// so the encoding only needs to agree between them; the offline verifier checks the carried
// pop_challenge_hash for presence/integrity, not by re-running this (MUST-FIX 4).
func usePoPChallenge(grantID, resourceID, action, paramsCommitment, credentialBinding, nonce string) []byte {
	h := sha256.New()
	for _, part := range []string{usePoPTag, grantID, resourceID, action, paramsCommitment, credentialBinding, nonce} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

// ledgerCommitment is sha256:<hex> over the consumed ledger entry (jti, nonce, used_at), carried in
// use_evidence so an auditor can cross-check duplicate consumption across visible receipts (R5).
func ledgerCommitment(jti, nonce string, usedAt int64) string {
	h := sha256.New()
	for _, part := range []string{ledgerTag, jti, nonce} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(usedAt))
	h.Write(ts[:])
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// credentialBinding recomputes sha256:<hex> of the capability's descriptor bytes (the token payload),
// matching the broker's credential_binding (broker mints the capability over exactly these bytes), so
// the PoP challenge binds the specific credential presented.
func credentialBinding(token string) (string, error) {
	enc, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("resourceshim: malformed capability token (want <payload>.<sig>)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", errors.New("resourceshim: capability payload is not valid base64url")
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// UsePoPChallenge exposes the challenge an agent must sign with its cnf key for a given use, so an SDK
// (or a test) can produce a valid use_sig. Returns the 32-byte digest to sign.
func UsePoPChallenge(grantID, resourceID, action, paramsCommitment, credentialBinding, nonce string) []byte {
	return usePoPChallenge(grantID, resourceID, action, paramsCommitment, credentialBinding, nonce)
}

// CredentialBinding exposes the credential_binding for a token (so an agent can compute the PoP
// challenge without re-deriving the descriptor hash itself).
func CredentialBinding(token string) (string, error) { return credentialBinding(token) }
