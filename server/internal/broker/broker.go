// Package broker is the credential-broker grant-issuance core (Level 3 Tier-A prototype, ADR 0002).
//
// It is PURE logic with no cgo/server dependency: the forbidden-scope policy, the canonical
// credential descriptor + its binding, the sender-constrained single-use capability minting, and the
// canonical grant evidence. The HTTP handler and the record-before-issue ingest live in the api
// package, which signs the evidence (core.SignEvidence) and seals the grant record.
//
// Canonical form: the credential_binding hash and the minted capability payload are taken over
// `json.Marshal` of a `map[string]any`, which Go emits with keys sorted bytewise — deterministic, and
// for ASCII keys aligned with RCP key ordering. These are broker-internal bindings the resource reads
// back, not values the offline verifier re-derives. The grant's `evidence_hash`, by contrast, IS
// re-derivable: the api layer computes it as sha256(RCP-canonicalize(Evidence)) via the Rust core
// (ADR 0003 R1) so an auditor can confirm the signed hash commits to the canonical grant_evidence
// embedded in the record. This package therefore returns the grant_evidence map and leaves the RCP
// hashing to the cgo-capable api layer (keeping this package pure Go, testable without cgo).
package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ScopeClass is how tightly a grant's scope maps to a single action (ADR Tier-B requirement 3).
type ScopeClass string

const (
	// ScopeSingleOperation: one credential = one operation. Tier-B-eligible.
	ScopeSingleOperation ScopeClass = "single_operation"
	// ScopeBoundedReuse (ADR 0005 M1 / N-Use): one credential = N uses of the IDENTICAL (action,
	// resource_id), capped by use_limit and indexed per use_sequence_number. Tier-B-eligible too
	// (action↔grant tightness is preserved), but reopens a bounded slice of B3 (reuse within one window).
	ScopeBoundedReuse ScopeClass = "bounded_reuse"
	// ScopeSession / ScopeBatch: explicit, labeled coarsenings — Tier-A-only (never counted as Tier B).
	ScopeSession ScopeClass = "session_grant"
	ScopeBatch   ScopeClass = "batch_grant"
)

// GrantType is the credential grant mechanism (authority.grant_type in the schema).
const GrantTypeIDJAG = "id-jag"

// ConformanceL1GrantOnly is the only conformance level the Tier-A prototype offers: the resource does
// NOT emit use receipts, so its grants support grant-accountability (Tier A) but not action-
// accountability (Tier B). A real L2_use_receipts resource is the Tier-B demonstrator (future).
const ConformanceL1GrantOnly = "L1_grant_only"

// MaxTTL caps a credential lifetime so the short-lived-credential property (threat B8) holds even if
// a caller asks for more — Prepare rejects TTL above this. Short by design; a longer-lived standing
// credential is exactly what the broker exists to avoid.
const MaxTTL = time.Hour

// IsForbiddenSingleOp reports whether scope is too powerful to be a single_operation grant. This is a
// COARSE PRE-FILTER, NOT the source of truth, and intentionally has both false positives and false
// negatives: scope strings are not standardized, so the AUTHORITATIVE scope_class classification is
// the signed resource operation taxonomy the verifier checks (ADR 0002 rev 3/4). It parses the scope
// as `namespace:action` (the common form) and flags it when:
//   - it contains a wildcard `*` (too broad);
//   - the namespace is inherently privileged (iam/sts/admin/credentials/secrets/kms/…) — so
//     `admin:reset` is flagged but `read:admin-dashboard` (namespace `read`) is NOT; or
//   - the action is a privilege-escalation verb (assume/delegate/impersonate/mint-credential/…).
//
// It deliberately does NOT try to catch every unbounded-async case (e.g. `webhook:create`); that is
// the taxonomy's job. A false positive remains recoverable via an explicit session_grant/batch_grant.
func IsForbiddenSingleOp(scope string) bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	if strings.Contains(s, "*") {
		return true
	}
	ns, action, hasColon := strings.Cut(s, ":")
	if privilegedNamespaces[ns] {
		return true
	}
	if !hasColon {
		action = ns // no namespace: treat the whole token as the action
	}
	// normalize separators so "assume-role" / "assume_role" / "assumerole" all match "assume".
	norm := strings.NewReplacer("-", "", "_", "", " ", "").Replace(action)
	for _, p := range escalationActionPrefixes {
		if strings.HasPrefix(norm, p) {
			return true
		}
	}
	return false
}

// privilegedNamespaces are scope namespaces (the part before the first ":") that confer authority
// management or admin power — never a single bounded operation.
var privilegedNamespaces = map[string]bool{
	"iam": true, "sts": true, "admin": true, "sudo": true, "root": true,
	"kms": true, "credential": true, "credentials": true, "secret": true, "secrets": true,
}

// escalationActionPrefixes mark an action (the part after ":") that mints or delegates authority.
var escalationActionPrefixes = []string{
	"assume", "delegate", "impersonate", "mintcredential", "createcredential",
	"issuecredential", "createkey", "createaccesskey", "escalate",
}

// Policy-denial sentinels mark a WELL-FORMED grant request the broker REFUSES on policy (B11 metadata
// oracle: a forbidden scope, an over-cap TTL, or a failed proof-of-possession) — as opposed to a malformed
// request (missing/ill-shaped fields). The api layer seals ONLY policy denials into the denied-grant log
// (matched via errors.Is); malformed input carries no policy signal and is excluded (pure DoS surface).
var (
	ErrForbiddenScope = errors.New("scope is too broad for a single_operation grant")
	ErrTTLExceeded    = errors.New("ttl exceeds the maximum allowed")
	ErrPoPFailed      = errors.New("agent_sig does not prove possession of agent_pubkey")
)

// ClassifyScope resolves the effective scope_class. requested defaults to single_operation. A
// single_operation request whose scope is forbidden (too broad) is REJECTED — the broker will not
// issue a Tier-B grant for it. session_grant / batch_grant are explicit Tier-A-only coarsenings and
// are allowed (the verifier will not count them toward Tier B).
func ClassifyScope(scope string, requested ScopeClass) (ScopeClass, error) {
	if requested == "" {
		requested = ScopeSingleOperation
	}
	switch requested {
	case ScopeSingleOperation, ScopeBoundedReuse:
		// bounded_reuse is also a TIGHT (action, resource_id) grant, so it is held to the same
		// forbidden-scope bar as single_operation (a broad/escalating scope must coarsen to
		// session_grant/batch_grant, which are Tier-A only).
		if IsForbiddenSingleOp(scope) {
			return "", fmt.Errorf(
				"scope %q is too broad for a %s grant: it can mint/delegate authority or trigger unbounded work; request session_grant/batch_grant (Tier-A only) if intentional: %w",
				scope, requested, ErrForbiddenScope)
		}
		return requested, nil
	case ScopeSession, ScopeBatch:
		return requested, nil
	default:
		return "", fmt.Errorf("unknown scope_class %q", requested)
	}
}

// Request is a validated grant request.
type Request struct {
	AgentID     string     // the agent's identity (subject)
	Action      string     // stable operation id, e.g. "db.query:orders-ro"
	Resource    string     // the target (audience)
	Scope       string     // the requested scope string
	ScopeClass  ScopeClass // requested class; "" -> single_operation
	UseLimit    int        // bounded_reuse only: the cap N (must be >= 1); ignored for other classes
	AgentPubKey string     // base64url ed25519 public key for the sender constraint (cnf)
	AgentSig    string     // base64url ed25519 signature over Challenge() — proves the
	// requester controls AgentPubKey (so it can't bind a key it
	// doesn't hold; see PoPVerify).
	Principal       string        // authorizing principal (policy/human/service)
	DelegationChain []string      // [caller, …, agent]
	Justification   string        // free text, recorded
	TTL             time.Duration // credential lifetime
}

const popTag = "feir.broker.pop.v1"

// Challenge is the deterministic bytes the agent must sign with its cnf private key to prove
// possession (binding the request's identity + operation + the cnf key itself). Domain-separated so
// a signature here cannot be repurposed. NOTE: it carries no nonce/timestamp, so a captured valid
// request is replayable — replay only yields a duplicate grant bound to the SAME agent key (usable
// only by that agent under resource-side PoP); anti-replay (a request nonce/expiry) is a hardening.
func (r Request) Challenge() []byte {
	c, _ := json.Marshal(map[string]any{
		"tag":          popTag,
		"agent_id":     r.AgentID,
		"action":       r.Action,
		"resource":     r.Resource,
		"scope":        r.Scope,
		"agent_pubkey": r.AgentPubKey,
	})
	return c
}

// Validate checks required fields, the sender-constraint key shape, the TTL cap, and proof of
// possession of the cnf key.
func (r Request) Validate() error {
	switch {
	case strings.TrimSpace(r.AgentID) == "":
		return errors.New("agent_id is required")
	case strings.TrimSpace(r.Action) == "":
		return errors.New("action is required")
	case strings.TrimSpace(r.Resource) == "":
		return errors.New("resource is required")
	case strings.TrimSpace(r.Scope) == "":
		return errors.New("scope is required")
	case r.TTL <= 0:
		return errors.New("ttl must be positive")
	}
	// cnf: a sender-constrained credential needs the agent's ed25519 public key (32 bytes).
	pub, err := base64.RawURLEncoding.DecodeString(r.AgentPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("agent_pubkey must be a base64url-no-pad ed25519 public key (32 bytes)")
	}
	// Proof of possession: the requester must sign the challenge with the cnf private key, so it
	// cannot bind a public key it does not control (e.g. a victim's) into the recorded grant.
	sig, err := base64.RawURLEncoding.DecodeString(r.AgentSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("agent_sig must be a base64url-no-pad ed25519 signature over the challenge")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), r.Challenge(), sig) {
		return ErrPoPFailed
	}
	// The TTL CAP is a POLICY check applied only AFTER structural validation + PoP succeed (Codex): the
	// broker seals a B11 ttl_exceeded denial on this error, so it must never fire for a malformed/unsigned
	// request — else an unauthenticated caller could inject durable denied-grant evidence with arbitrary
	// metadata. (The positive-TTL check above is a shape error, never logged.)
	if r.TTL > MaxTTL {
		return fmt.Errorf("ttl %s exceeds the maximum %s (credentials must be short-lived): %w", r.TTL, MaxTTL, ErrTTLExceeded)
	}
	return nil
}

// Prepared is everything the broker computed for a grant EXCEPT the evidence_sig (the api layer signs
// EvidenceHash with the recording key) and the sealed record (the api layer assembles + seals it).
type Prepared struct {
	GrantID           string
	ScopeClass        ScopeClass
	ConformanceLevel  string
	EvaluatedAt       string         // RFC3339 fixed-ms UTC
	ExpiresAt         string         // RFC3339 fixed-ms UTC
	Descriptor        map[string]any // the canonical credential claim set
	DescriptorBytes   []byte         // canonical bytes (committed via input_commit; == capability payload)
	CredentialBinding string         // sha256:<hex> of DescriptorBytes
	Evidence          map[string]any // canonical grant_evidence (ADR 0003); the api layer derives evidence_hash
	Capability        string         // the minted single-use sender-constrained token ("<payload>.<sig>")
}

// KeyID derives a stable, key-BOUND identifier for an issuing public key, so the descriptor's `kid`
// always identifies the key that actually signed (no caller-supplied, spoofable label).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + base64.RawURLEncoding.EncodeToString(sum[:8])
}

// Prepare computes the grant artifacts. grantID is the unique grant id (also the credential jti and
// the record_id the evidence is bound to); issuingKey mints the capability and its public half
// determines the descriptor `kid`. now is the issuance time; req.TTL bounds the credential.
// allocSeq is invoked to obtain this grant's gapless broker_seq (ADR 0004 D6). It is called ONLY after
// the request has FULLY validated (signature/scope/pubkey), so a rejected grant never burns a sequence
// number and manufactures a false-suppression gap — the caller (api) wires it to Store.AllocateBrokerSeq.
func Prepare(req Request, grantID string, allocSeq func() (int64, error), now time.Time, issuingKey ed25519.PrivateKey) (Prepared, error) {
	if err := req.Validate(); err != nil {
		return Prepared{}, err
	}
	if strings.TrimSpace(grantID) == "" {
		return Prepared{}, errors.New("grantID is required")
	}
	scopeClass, err := ClassifyScope(req.Scope, req.ScopeClass)
	if err != nil {
		return Prepared{}, err
	}
	// M1 (bounded_reuse): a positive cap is mandatory; reject otherwise so an "unbounded bounded" grant is
	// never minted. use_limit is ignored (and must not be carried) for the other classes.
	if scopeClass == ScopeBoundedReuse && req.UseLimit < 1 {
		return Prepared{}, errors.New("bounded_reuse requires use_limit >= 1")
	}
	evaluatedAt := now.UTC()
	expiresAt := evaluatedAt.Add(req.TTL)
	// kid is derived from the issuing key, never caller-supplied, so it can't claim a key it isn't.
	kid := KeyID(issuingKey.Public().(ed25519.PublicKey))
	// single_use only for a genuine single_operation grant; a session/batch coarsening is multi-use
	// by definition, so the credential must not assert single_use (it would be a false claim).
	singleUse := scopeClass == ScopeSingleOperation
	// Decode + CANONICALLY re-encode the agent cnf pubkey before it enters the descriptor (req.Validate
	// already checked the shape). Go's base64.RawURLEncoding decode is non-strict but the Rust offline
	// verifier rejects non-canonical base64url, so a caller-supplied non-canonical agent_pubkey would
	// false-fail D2 PoP re-verification; normalize here so the carried cnf is always canonical.
	cnfPub, err := base64.RawURLEncoding.DecodeString(req.AgentPubKey)
	if err != nil || len(cnfPub) != ed25519.PublicKeySize {
		return Prepared{}, errors.New("agent_pubkey is not a valid ed25519 public key")
	}
	cnfCanonical := base64.RawURLEncoding.EncodeToString(cnfPub)

	// All validation has passed — NOW allocate the gapless grant-transparency sequence (D6). Allocating
	// here (not before validation) means a rejected request never consumes a seq, so the only gap a
	// broker can produce is a genuinely abandoned-after-mint grant (a real suppression signal), never a
	// 400 from an unauthenticated caller.
	brokerSeq, err := allocSeq()
	if err != nil {
		return Prepared{}, fmt.Errorf("allocate broker_seq: %w", err)
	}
	if brokerSeq < 1 {
		return Prepared{}, errors.New("allocated broker_seq must be >= 1 (gapless grant-transparency sequence, ADR 0004 D6)")
	}

	// Canonical credential descriptor — the exact claim set credential_binding commits to and the
	// capability carries (ADR "Exact credential binding": typ/alg/kid/iss/sub/aud/act/jti/scope/cnf/
	// mode/nbf/iat/exp + single_use, not a four-field summary). `act` binds the authorized operation.
	descriptor := map[string]any{
		"typ":        "capability",
		"alg":        "ed25519",
		"kid":        kid,
		"iss":        "feir-broker",
		"sub":        req.AgentID,
		"aud":        req.Resource,
		"act":        req.Action,
		"jti":        grantID,
		"scope":      req.Scope,
		"cnf":        cnfCanonical, // sender constraint: only the holder of this key may use it (canonical b64url)
		"mode":       "capability",
		"nbf":        evaluatedAt.Unix(),
		"iat":        evaluatedAt.Unix(),
		"exp":        expiresAt.Unix(),
		"single_use": singleUse,
	}
	// M1: bounded_reuse carries its cap in BOTH the descriptor (so the resource shim enforces it and a
	// disclosed-descriptor cross-check can confirm it) and the grant_evidence below.
	if scopeClass == ScopeBoundedReuse {
		descriptor["use_limit"] = req.UseLimit
	}
	credentialBinding, descriptorBytes := canonHash(descriptor)

	delegation := req.DelegationChain
	if delegation == nil {
		delegation = []string{}
	}
	// cnf_kid identifies the agent's sender-constraint (cnf) key — a Tier-B use's PoP must verify under
	// it (ADR 0003 R4/R5). cnfPub was decoded + canonicalized above.
	// Canonical grant_evidence (ADR 0003 §"Canonical evidence schemas"): the ONLY payload the offline
	// verifier reads match inputs from. evidence_hash = sha256(RCP-canonicalize(grant_evidence)) is
	// computed by the api layer via the Rust core (R1) — NOT here — so the broker stays pure Go with
	// no cgo dependency. Times are unix seconds (RCP integers); resource is `resource_id`; `kind` and
	// `cnf_kid` are the role discriminator + the PoP key id Tier-B requires.
	evidence := map[string]any{
		"kind":                  "grant",
		"grant_id":              grantID,
		"grant_type":            GrantTypeIDJAG,
		"authorizing_principal": req.Principal,
		"delegation_chain":      delegation,
		"agent_id":              req.AgentID,
		"action":                req.Action, // the operation this grant authorizes (use↔grant match)
		"resource_id":           req.Resource,
		"scope":                 req.Scope,
		"scope_class":           string(scopeClass),
		"conformance_level":     ConformanceL1GrantOnly,
		"cnf_kid":               KeyID(ed25519.PublicKey(cnfPub)),
		"credential_binding":    credentialBinding,
		// broker_seq: the gapless grant-transparency sequence (ADR 0004 D6 / MF2), signed into the
		// evidence so the verifier can re-derive the anchored cumulative_root and detect suppression.
		"broker_seq": brokerSeq,
		"issued_at":  evaluatedAt.Unix(),
		"exp":        expiresAt.Unix(),
	}
	if scopeClass == ScopeBoundedReuse {
		evidence["use_limit"] = req.UseLimit // the verifier reads the cap from the SIGNED grant_evidence
	}

	// Mint the capability: payload = the canonical descriptor bytes, signed by the issuing key. Only
	// the holder of the cnf key can USE it (sender-constrained); single_use is declared for the
	// resource to consume (enforcement is the resource's job — Tier B).
	capability := mint(descriptorBytes, issuingKey)

	return Prepared{
		GrantID:           grantID,
		ScopeClass:        scopeClass,
		ConformanceLevel:  ConformanceL1GrantOnly,
		EvaluatedAt:       tsMillis(evaluatedAt),
		ExpiresAt:         tsMillis(expiresAt),
		Descriptor:        descriptor,
		DescriptorBytes:   descriptorBytes,
		CredentialBinding: credentialBinding,
		Evidence:          evidence,
		Capability:        capability,
	}, nil
}

// mint signs the canonical descriptor payload into a compact capability token "<b64url(payload)>.<b64url(sig)>".
func mint(payload []byte, issuingKey ed25519.PrivateKey) string {
	enc := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(issuingKey, []byte(enc))
	return enc + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// MintCapability re-mints the capability from already-canonical descriptor bytes. ed25519 signing is
// deterministic, so given the stored descriptor this reproduces the EXACT original token — used to
// return the original capability on an idempotent retry (never minting a second live credential).
func MintCapability(descriptorBytes []byte, issuingKey ed25519.PrivateKey) string {
	return mint(descriptorBytes, issuingKey)
}

// Claims is the typed credential descriptor a resource reads back from a capability. Numeric times
// are int64 (a typed struct avoids the float64 footgun of decoding into map[string]any).
type Claims struct {
	Typ       string `json:"typ"`
	Alg       string `json:"alg"`
	Kid       string `json:"kid"`
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Act       string `json:"act"`
	Jti       string `json:"jti"`
	Scope     string `json:"scope"`
	Cnf       string `json:"cnf"`
	Mode      string `json:"mode"`
	Nbf       int64  `json:"nbf"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	SingleUse bool   `json:"single_use"`
	// UseLimit is present (>= 1) ONLY on a bounded_reuse capability (ADR 0005 M1): the resource shim caps
	// uses at this N and indexes each by use_sequence_number. Absent/0 for every other scope class.
	UseLimit int `json:"use_limit,omitempty"`
}

// VerifyCapability validates a minted token under the issuing public key and returns the typed
// descriptor. This is what a resource/gateway shim (the Tier-B demonstrator) would call. It checks
// the signature only; the resource separately enforces cnf (proof-of-possession), exp, and
// single-use.
func VerifyCapability(token string, issuingPub ed25519.PublicKey) (Claims, error) {
	enc, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return Claims{}, errors.New("capability: malformed token (want <payload>.<sig>)")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Claims{}, errors.New("capability: malformed signature")
	}
	if !ed25519.Verify(issuingPub, []byte(enc), sig) {
		return Claims{}, errors.New("capability: signature does not verify under the issuing key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return Claims{}, errors.New("capability: malformed payload")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("capability: payload is not a descriptor: %w", err)
	}
	return c, nil
}

// canonHash returns ("sha256:<hex>", canonicalBytes) over json.Marshal(m) (Go sorts map keys).
func canonHash(m map[string]any) (string, []byte) {
	b, _ := json.Marshal(m)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), b
}

// tsMillis formats a time as the RCP fixed-millisecond UTC string the record schema requires.
func tsMillis(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
