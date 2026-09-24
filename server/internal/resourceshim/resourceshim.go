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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/feirai/averin/server/internal/broker"
)

// usePoPTag domain-separates the use-time proof-of-possession challenge so a signature here cannot be
// repurposed as a request-time PoP (broker.popTag) or any other signature.
const usePoPTag = "averin.broker.use.pop.v1"

// ledgerTag domain-separates the ledger_commitment preimage from the PoP challenge (and any other
// hash), so the two length-prefixed digests can never collide.
const ledgerTag = "averin.broker.use.ledger.v1"

// ErrConsumed reports that a single-use credential (jti) or a PoP nonce was already consumed — a
// double-spend or a replay. It is returned by the ledger and surfaced by ValidateUse.
var ErrConsumed = errors.New("resourceshim: credential jti or nonce already consumed")

// ErrRevoked reports that the presented capability's grant has been revoked (ADR 0005 M5). ValidateUse returns
// it BEFORE consuming anything, so a revoked credential is never exercised and never burns a nonce.
var ErrRevoked = errors.New("resourceshim: the capability's grant is revoked")

// ErrRevocationCheck marks an unavailable authoritative revocation lookup.
// Callers must surface it as a server failure rather than a rejected credential.
var ErrRevocationCheck = errors.New("resourceshim: revocation check failed")

// Ledger is the durable consume-before-act store. Consumption is marked BEFORE the resource performs
// the side effect, so a crash after consumption cannot leave a live credential.
type Ledger interface {
	// Claims carry a random request owner. A release can remove only the exact claim acquired here.
	ConsumeNonce(claim NonceClaim) error
	// ConsumeJTI atomically marks a single-use credential jti consumed (double-spend protection);
	// ErrConsumed if already spent.
	ConsumeJTI(claim JTIClaim) error
	// ReleaseNonce / ReleaseJTI ROLL BACK a consumption when receipt construction fails AFTER ValidateUse
	// consumed the credential but BEFORE the caller acted (the caller acts only on a 2xx response). This
	// un-burns a single-use credential on a transient build error so an honest retry can re-validate, without
	// weakening double-spend protection: a SUCCESSFUL use never releases, and the caller never acted on the
	// failed one. Release is sound ONLY when the receipt definitively did not persist; a commit-ambiguous
	// store error must NOT release (the api layer keeps the credential consumed there). Releasing an entry
	// that was not consumed is a safe no-op.
	ReleaseNonce(claim NonceClaim)
	ReleaseJTI(claim JTIClaim)
}

// NonceClaim scopes replay to the verified capability project and this shim's configured resource.
// Owner is an unpredictable per-attempt value; copying the handle preserves its release authority.
type NonceClaim struct {
	ProjectID, ResourceID, Nonce string
	owner                        string
}

// JTIClaim stays global across projects and resources for the same capability/use index.
type JTIClaim struct {
	Key   string
	owner string
}

func (c NonceClaim) OwnerID() string { return c.owner }
func (c JTIClaim) OwnerID() string   { return c.owner }

func claimOwner() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("resourceshim: claim owner: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func NewNonceClaim(projectID, resourceID, nonce string) (NonceClaim, error) {
	if projectID == "" || resourceID == "" || nonce == "" {
		return NonceClaim{}, errors.New("resourceshim: nonce claim requires project, resource, and nonce")
	}
	owner, err := claimOwner()
	return NonceClaim{ProjectID: projectID, ResourceID: resourceID, Nonce: nonce, owner: owner}, err
}

func NewJTIClaim(key string) (JTIClaim, error) {
	if key == "" {
		return JTIClaim{}, errors.New("resourceshim: JTI claim requires a key")
	}
	owner, err := claimOwner()
	return JTIClaim{Key: key, owner: owner}, err
}

// MemLedger is an in-memory Ledger for the demonstrator and tests. Production backs the ledger with a
// durable, atomically-consistent store. Safe for concurrent use.
type MemLedger struct {
	mu     sync.Mutex
	jti    map[string]string
	nonces map[nonceScope]string
}

type nonceScope struct{ project, resource, nonce string }

// NewMemLedger returns an empty in-memory ledger.
func NewMemLedger() *MemLedger {
	return &MemLedger{jti: map[string]string{}, nonces: map[nonceScope]string{}}
}

func nonceKey(c NonceClaim) nonceScope {
	return nonceScope{c.ProjectID, c.ResourceID, c.Nonce}
}

// ConsumeNonce marks nonce consumed; ErrConsumed if it was already consumed.
func (l *MemLedger) ConsumeNonce(c NonceClaim) error {
	if c.ProjectID == "" || c.ResourceID == "" || c.Nonce == "" || c.owner == "" {
		return errors.New("resourceshim: invalid nonce claim")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nonces == nil {
		l.nonces = map[nonceScope]string{} // tolerate a zero-value MemLedger{}
	}
	key := nonceKey(c)
	if _, ok := l.nonces[key]; ok {
		return ErrConsumed
	}
	l.nonces[key] = c.owner
	return nil
}

// ConsumeJTI marks jti consumed; ErrConsumed if it was already consumed.
func (l *MemLedger) ConsumeJTI(c JTIClaim) error {
	if c.Key == "" || c.owner == "" {
		return errors.New("resourceshim: invalid JTI claim")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.jti == nil {
		l.jti = map[string]string{} // tolerate a zero-value MemLedger{}
	}
	if _, ok := l.jti[c.Key]; ok {
		return ErrConsumed
	}
	l.jti[c.Key] = c.owner
	return nil
}

// ReleaseNonce un-marks a consumed nonce (rollback when a receipt did not persist). No-op if not consumed.
func (l *MemLedger) ReleaseNonce(c NonceClaim) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := nonceKey(c)
	if c.owner != "" && l.nonces[key] == c.owner {
		delete(l.nonces, key)
	}
}

// ReleaseJTI un-marks a consumed jti (rollback when a receipt did not persist). No-op if not consumed.
func (l *MemLedger) ReleaseJTI(c JTIClaim) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.owner != "" && l.jti[c.Key] == c.owner {
		delete(l.jti, c.Key)
	}
}

// Op is the operation a resource is about to perform under a presented capability. ResourceID comes
// from the shim config (not the caller), so the caller cannot claim to be a different resource.
type Op struct {
	// Action is the operation id; it MUST equal the capability's authorized action (claims.Act).
	Action string
	// ParamsCommitment is a sha256:<hex> hiding commitment over the operation parameters. It is bound
	// into the PoP challenge so a captured use_sig cannot be replayed against different params.
	ParamsCommitment string
	// UseSequenceNumber (ADR 0005 M1, bounded_reuse only): the 1-based exercise index in [1, use_limit].
	// Ignored (0) for every other scope class.
	UseSequenceNumber int
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
	// ADR 0004 D2 — carried so the offline verifier can RE-RUN the Ed25519 PoP (off the shim TCB):
	CnfPub string `json:"cnf_pub"` // base64url agent cnf public key (id == cnf_kid)
	UseSig string `json:"use_sig"` // base64url PoP signature over the use_pop_challenge digest
	// ADR 0005 M1 (bounded_reuse): the 1-based exercise index; omitted for non-bounded uses.
	UseSequenceNumber int `json:"use_sequence_number,omitempty"`
	nonceClaim        NonceClaim
	jtiClaim          JTIClaim
}

// consumeKey is the ledger double-spend key. For single_operation it is the bare jti (== grant_id). For
// bounded_reuse it is (jti, use_sequence_number) so the SAME jti can be spent once per sequence number up
// to use_limit — generalizing the per-jti ledger to the per-(grant_id, usn) M1 rule.
func consumeKey(jti string, useSeq int) string {
	if useSeq > 0 {
		return fmt.Sprintf("%s#%d", jti, useSeq)
	}
	return jti
}

// Shim is the resource-side gateway, configured once with the broker's capability-issuing public key,
// this resource's id, and the durable ledger.
type Shim struct {
	issuingPub   ed25519.PublicKey
	resourceID   string
	projectID    string // authenticated route context; never inferred from the request body
	ledger       Ledger
	isRevoked    func(grantID string) bool // nil = no use-time revocation check
	isRevokedErr func(grantID string) (bool, error)
}

// New constructs a Shim. resourceID is this resource's audience id (capabilities whose aud differs are
// rejected); issuingPub is the broker's capability-signing public key.
func New(issuingPub ed25519.PublicKey, resourceID string, ledger Ledger) *Shim {
	return &Shim{issuingPub: issuingPub, resourceID: resourceID, ledger: ledger}
}

// WithProject binds this shim to the project authenticated for the route.
func (s *Shim) WithProject(projectID string) *Shim {
	s.projectID = projectID
	return s
}

// WithRevocationCheck makes ValidateUse consult the revoked set at use time: a capability whose grant_id (== the
// verified jti) isRevoked reports as revoked is rejected with ErrRevoked BEFORE anything is consumed. Without it
// a revoked grant stays usable at the resource until its expiry (the offline verifier only flags the use after
// the fact).
func (s *Shim) WithRevocationCheck(isRevoked func(grantID string) bool) *Shim {
	s.isRevoked = isRevoked
	return s
}

// WithRevocationCheckErr uses an authoritative lookup that can fail. A failed
// read fails closed before any ledger access and retains its server-error type.
func (s *Shim) WithRevocationCheckErr(isRevoked func(grantID string) (bool, error)) *Shim {
	s.isRevokedErr = isRevoked
	return s
}

// RollbackUse releases the nonce and (single-use) jti a prior ValidateUse consumed. Call it ONLY when the
// caller has NOT acted — receipt construction failed before any record persisted, so the api layer returns
// an error and the caller never received a 2xx — to un-burn the credential for an honest retry. MUST NOT be
// called after a commit-AMBIGUOUS store error (the receipt may be durable; releasing would allow a replay
// double-spend). Releasing a jti that was not consumed (a reusable credential) is a no-op.
func (s *Shim) RollbackUse(ev UseEvidence) {
	s.ledger.ReleaseNonce(ev.nonceClaim)
	// Release the SAME key ValidateUse consumed: bare jti (single_operation) or (jti, usn) (bounded_reuse).
	s.ledger.ReleaseJTI(ev.jtiClaim)
}

type preflightResult struct {
	claims    broker.Claims
	unix      int64
	challenge []byte
	cnfPub    ed25519.PublicKey
	useSig    []byte
	bounded   bool
	useSeq    int
}

// PreflightUse checks the signed capability, tenant, validity, audience, action,
// sender PoP, and sequence without reading revocation or touching the ledger.
// The caller must call ValidateUse again inside its project transaction before
// issuing a receipt: time, revocation, and replay state can change after this check.
func (s *Shim) PreflightUse(token, useSigB64 string, op Op, nonce string, now time.Time) error {
	_, err := s.preflightUse(token, useSigB64, op, nonce, now)
	return err
}

func (s *Shim) preflightUse(token, useSigB64 string, op Op, nonce string, now time.Time) (preflightResult, error) {
	// 1. Capability signature + decode (the broker minted and signed this descriptor).
	claims, err := broker.VerifyCapability(token, s.issuingPub)
	if err != nil {
		return preflightResult{}, err
	}
	// Tenant binding is an authorization gate, ahead of revocation and every
	// nonce/JTI read or write. Legacy capabilities have no signed project claim
	// and are refused by this explicit online cutoff.
	if s.projectID == "" {
		return preflightResult{}, errors.New("resourceshim: authenticated project is required")
	}
	switch claims.Version {
	case 2:
		if claims.ProjectID == "" || claims.ProjectID != s.projectID {
			return preflightResult{}, errors.New("resourceshim: capability project does not match authenticated project")
		}
	case 0:
		return preflightResult{}, errors.New("resourceshim: legacy capability project cannot be authenticated")
	default:
		return preflightResult{}, errors.New("resourceshim: unsupported capability version")
	}
	// 2. Validity window (threat B8: short-lived credentials).
	unix := now.UTC().Unix()
	// The issuer caps new grants at MaxTTL. Enforce the same bound at acceptance so an old
	// global exclusion can eventually retire after a DB-time cutover. Compare without subtracting
	// attacker-controlled signed int64 values (which could overflow).
	maxTTL := int64(broker.MaxTTL / time.Second)
	skew := int64(broker.RequestClockSkew / time.Second)
	if claims.Iat <= 0 || claims.Iat > math.MaxInt64-maxTTL || claims.Exp <= claims.Iat || claims.Exp > claims.Iat+maxTTL {
		return preflightResult{}, errors.New("resourceshim: capability lifetime exceeds accepted maximum")
	}
	if claims.Nbf < claims.Iat || claims.Nbf >= claims.Exp {
		return preflightResult{}, errors.New("resourceshim: invalid capability issue/not-before window")
	}
	if unix < 0 || unix > math.MaxInt64-skew || claims.Iat > unix+skew {
		return preflightResult{}, errors.New("resourceshim: capability issued too far in the future")
	}
	if unix < claims.Nbf {
		return preflightResult{}, fmt.Errorf("resourceshim: capability not yet valid (nbf %d > now %d)", claims.Nbf, unix)
	}
	if unix >= claims.Exp {
		return preflightResult{}, fmt.Errorf("resourceshim: capability expired (exp %d <= now %d)", claims.Exp, unix)
	}
	// 3. Audience + action coverage: the capability must authorize THIS resource and THIS action.
	if claims.Aud != s.resourceID {
		return preflightResult{}, fmt.Errorf("resourceshim: capability audience %q does not match this resource %q", claims.Aud, s.resourceID)
	}
	if op.Action == "" || op.Action != claims.Act {
		return preflightResult{}, fmt.Errorf("resourceshim: operation %q is not the authorized action %q", op.Action, claims.Act)
	}
	if strings.TrimSpace(nonce) == "" {
		return preflightResult{}, errors.New("resourceshim: a one-time PoP nonce is required")
	}
	// 4. PoP-at-use (R4): the holder must sign the fully-bound challenge with the cnf private key, so a
	// stolen token (without the cnf key) cannot be used.
	cnfPub, err := base64.RawURLEncoding.DecodeString(claims.Cnf)
	if err != nil || len(cnfPub) != ed25519.PublicKeySize {
		return preflightResult{}, errors.New("resourceshim: capability cnf is not a valid ed25519 public key")
	}
	binding, err := credentialBinding(token)
	if err != nil {
		return preflightResult{}, err
	}
	challenge := usePoPChallenge(claims.Jti, s.resourceID, op.Action, op.ParamsCommitment, binding, nonce)
	useSig, err := base64.RawURLEncoding.DecodeString(useSigB64)
	if err != nil || len(useSig) != ed25519.SignatureSize {
		return preflightResult{}, errors.New("resourceshim: use_sig must be a base64url-no-pad ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(cnfPub), challenge, useSig) {
		return preflightResult{}, errors.New("resourceshim: use_sig does not prove possession of the cnf key (PoP failed)")
	}
	// 4.5 M1 (bounded_reuse): the descriptor carries use_limit (>0) iff this is a bounded_reuse capability.
	// Validate the sequence number BEFORE consuming anything, so a bad usn never burns the nonce/credential.
	bounded := claims.UseLimit > 0
	useSeq := 0
	if bounded {
		useSeq = op.UseSequenceNumber
		if useSeq < 1 || useSeq > claims.UseLimit {
			return preflightResult{}, fmt.Errorf("resourceshim: use_sequence_number %d outside [1, %d] for bounded_reuse", useSeq, claims.UseLimit)
		}
	}
	return preflightResult{
		claims: claims, unix: unix, challenge: challenge,
		cnfPub: ed25519.PublicKey(cnfPub), useSig: useSig,
		bounded: bounded, useSeq: useSeq,
	}, nil
}

// ValidateUse repeats the pure preflight under the project transaction, then
// checks authoritative revocation and atomically consumes nonce/JTI before the
// caller records a receipt or performs the side effect.
func (s *Shim) ValidateUse(token, useSigB64 string, op Op, nonce string, now time.Time) (UseEvidence, error) {
	checked, err := s.preflightUse(token, useSigB64, op, nonce, now)
	if err != nil {
		return UseEvidence{}, err
	}
	claims, unix := checked.claims, checked.unix
	challenge, cnfPub, useSig := checked.challenge, checked.cnfPub, checked.useSig
	bounded, useSeq := checked.bounded, checked.useSeq
	// 4.6 M5 revocation: a revoked grant must not be exercised. Checked on the SIGNATURE-VERIFIED jti (== the
	// grant_id) and BEFORE consuming, so a revoked credential burns neither its nonce nor its jti.
	if s.isRevokedErr != nil {
		revoked, err := s.isRevokedErr(claims.Jti)
		if err != nil {
			return UseEvidence{}, fmt.Errorf("%w: %v", ErrRevocationCheck, err)
		}
		if revoked {
			return UseEvidence{}, fmt.Errorf("%w: grant %s", ErrRevoked, claims.Jti)
		}
	} else if s.isRevoked != nil && s.isRevoked(claims.Jti) {
		return UseEvidence{}, fmt.Errorf("%w: grant %s", ErrRevoked, claims.Jti)
	}
	// 5. Consume-before-act (R5): mark the nonce (replay) and the credential's double-spend key consumed
	// BEFORE the caller performs the side effect. The key is the bare jti for single_operation and
	// (jti, use_sequence_number) for bounded_reuse, so the same jti can be spent once per sequence number
	// up to use_limit. session_grant/batch_grant are unbounded reusable (no jti consume). A replayed key
	// or nonce fails here.
	nonceClaim, err := NewNonceClaim(s.projectID, s.resourceID, nonce)
	if err != nil {
		return UseEvidence{}, err
	}
	if err := s.ledger.ConsumeNonce(nonceClaim); err != nil {
		return UseEvidence{}, fmt.Errorf("resourceshim: nonce replay: %w", err)
	}
	var jtiClaim JTIClaim
	if claims.SingleUse || bounded {
		jtiClaim, err = NewJTIClaim(consumeKey(claims.Jti, useSeq))
		if err != nil {
			s.ledger.ReleaseNonce(nonceClaim)
			return UseEvidence{}, err
		}
		if err := s.ledger.ConsumeJTI(jtiClaim); err != nil {
			// The nonce was just consumed but this use fails here (double-spend) and produces no receipt —
			// release it so a definitively-pre-persistence failure leaves the consume-before-act ledger
			// consistent (mirror the handler's RollbackUse on later failures; adversarial review). The key stays consumed.
			s.ledger.ReleaseNonce(nonceClaim)
			return UseEvidence{}, fmt.Errorf("resourceshim: double-spend (R5): %w", err)
		}
	}
	// 6. Build the canonical use_evidence. For a single_operation grant jti == grant_id (the broker
	// mints jti = grant_id), so grant_id and jti coincide here — the verifier's per-grant_id single-use
	// rule and the shim's per-jti ledger provably agree (R5 rev 4).
	usedAt := unix
	return UseEvidence{
		nonceClaim:       nonceClaim,
		jtiClaim:         jtiClaim,
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
		// D2: the cnf pubkey (from the capability descriptor) + the verified use_sig, so the offline
		// verifier can reconstruct this exact challenge and re-run the Ed25519 PoP check itself. Both are
		// canonically re-encoded from their decoded bytes — Go's base64 decode is non-strict but the Rust
		// verifier rejects non-canonical base64url, so a non-canonical agent value would otherwise
		// false-fail re-verification.
		CnfPub:            base64.RawURLEncoding.EncodeToString(cnfPub),
		UseSig:            base64.RawURLEncoding.EncodeToString(useSig),
		UseSequenceNumber: useSeq, // 0 for non-bounded (omitted by json omitempty)
	}, nil
}

// usePoPChallenge is the 32-byte digest the holder signs with the cnf key (R4):
// sha256( LP(tag) ‖ LP(grant_id) ‖ LP(resource_id) ‖ LP(action) ‖ LP(params_commitment) ‖
// LP(credential_binding) ‖ LP(nonce) ), where LP is a 4-byte big-endian length prefix. Length-prefixing
// makes the concatenation unambiguous (no field-boundary confusion). The agent, the shim, AND the
// offline verifier all compute it identically (ADR 0004 D2): the verifier reconstructs this challenge
// from the receipt and RE-RUNS the Ed25519 PoP under the carried cnf pubkey, so the encoding is a
// cross-language binding kept in sync via the SHARED golden vector
// spec/golden-vectors/broker-preimages.json (loaded by both languages' tests).
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
