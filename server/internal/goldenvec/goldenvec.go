// Package goldenvec loads the cross-language preimage golden vectors shared with the Rust core tests
// (spec/golden-vectors/broker-preimages.json). The SAME file is loaded here and by
// core/tests/adversarial.rs, so the LP4/BE8 domain-tagged broker/resource preimages
// (grant_head_root, ledger_commitment, use_pop_challenge, cnf_kid) stay byte-identical across the two
// languages: editing a preimage breaks BOTH test suites against this ONE file, forcing a lockstep
// update — unlike independently-hardcoded copies, which can silently diverge.
package goldenvec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Grant is one (broker_seq, grant content_hash) entry of a grant-transparency log.
type Grant struct {
	Seq         int64  `json:"seq"`
	ContentHash string `json:"content_hash"`
}

// GrantHeadCase pins grant_head_root over a fixed grant log.
type GrantHeadCase struct {
	Name   string  `json:"name"`
	Grants []Grant `json:"grants"`
	Expect string  `json:"expect"`
}

// LedgerCase pins ledger_commitment over fixed inputs.
type LedgerCase struct {
	JTI    string `json:"jti"`
	Nonce  string `json:"nonce"`
	UsedAt int64  `json:"used_at"`
	Expect string `json:"expect"`
}

// PoPCase pins the use_pop_challenge digest over fixed inputs (ExpectHex is the raw 32-byte digest).
type PoPCase struct {
	Name              string `json:"name"`
	GrantID           string `json:"grant_id"`
	ResourceID        string `json:"resource_id"`
	Action            string `json:"action"`
	ParamsCommitment  string `json:"params_commitment"`
	CredentialBinding string `json:"credential_binding"`
	Nonce             string `json:"nonce"`
	ExpectHex         string `json:"expect_hex"`
}

type GrantPoPV2Case struct {
	Name             string   `json:"name"`
	ProjectID        string   `json:"project_id"`
	IdempotencyKey   string   `json:"idempotency_key"`
	SessionID        string   `json:"session_id"`
	AgentID          string   `json:"agent_id"`
	Action           string   `json:"action"`
	Resource         string   `json:"resource"`
	Scope            string   `json:"scope"`
	ScopeClass       string   `json:"scope_class"`
	AgentPubKey      string   `json:"agent_pubkey"`
	Principal        string   `json:"principal"`
	Justification    string   `json:"justification"`
	UseLimit         int      `json:"use_limit"`
	TTLSeconds       int      `json:"ttl_seconds"`
	DelegationChain  []string `json:"delegation_chain"`
	IssuedAt         int64    `json:"issued_at"`
	RequestExpiresAt int64    `json:"request_expires_at"`
	PreimageHex      string   `json:"expect_preimage_hex"`
	ExpectHex        string   `json:"expect_hex"`
}

// CnfKidCase pins the cnf key-id derived from a 32-byte ed25519 seed.
type CnfKidCase struct {
	SeedHex string `json:"seed_hex"`
	Expect  string `json:"expect"`
}

// CosigCase pins the cosig_approval_challenge digest (ADR 0005 M6) over fixed inputs (ExpectHex is the
// raw 32-byte challenge digest the approver signs).
type CosigCase struct {
	Name              string `json:"name"`
	GrantID           string `json:"grant_id"`
	ApproverKid       string `json:"approver_kid"`
	CredentialBinding string `json:"credential_binding"`
	ThresholdM        int64  `json:"threshold_m"`
	Exp               int64  `json:"exp"`
	ExpectHex         string `json:"expect_hex"`
}

// DelegationCase pins the delegation_hop_challenge digest (ADR 0005 M2) over fixed inputs (ExpectHex is the
// raw 32-byte challenge digest the delegator signs).
type DelegationCase struct {
	Name         string `json:"name"`
	GrantID      string `json:"grant_id"`
	HopIndex     int64  `json:"hop_index"`
	DelegatorKid string `json:"delegator_kid"`
	DelegateKid  string `json:"delegate_kid"`
	Scope        string `json:"scope"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	Exp          int64  `json:"exp"`
	ExpectHex    string `json:"expect_hex"`
}

// IntrospectionCase pins the introspection_transcript_challenge digest (ADR 0005 M3) over fixed inputs
// (ExpectHex is the raw 32-byte challenge digest the resource signs).
type IntrospectionCase struct {
	Name           string `json:"name"`
	GrantID        string `json:"grant_id"`
	CredentialRef  string `json:"credential_ref"`
	EffectiveScope string `json:"effective_scope"`
	ResourceID     string `json:"resource_id"`
	IntrospectedAt int64  `json:"introspected_at"`
	EffectiveExp   int64  `json:"effective_exp"`
	ExpectHex      string `json:"expect_hex"`
}

// FederationCertCase pins the federation_cert_challenge digest (ADR 0005 M4, OPTIONAL cross_broker_cert) over
// fixed inputs (ExpectHex is the raw 32-byte challenge digest the issuer broker signs).
type FederationCertCase struct {
	Name            string `json:"name"`
	IssuerBrokerID  string `json:"issuer_broker_id"`
	SubjectBrokerID string `json:"subject_broker_id"`
	SubjectKid      string `json:"subject_kid"`
	Scope           string `json:"scope"`
	ResourceID      string `json:"resource_id"`
	NotAfter        int64  `json:"not_after"`
	ExpectHex       string `json:"expect_hex"`
}

// RevocationLeafCase pins the revocation_leaf VALUE (ADR 0005 M5 Merkle-non-disclosure) for a grant_id.
type RevocationLeafCase struct {
	Name      string `json:"name"`
	GrantID   string `json:"grant_id"`
	ExpectHex string `json:"expect_hex"`
}

// RevocationMerkleRootCase pins the full sorted, sentinel-bracketed Merkle root (sha256:<hex>) over a revoked set.
type RevocationMerkleRootCase struct {
	Name    string   `json:"name"`
	Revoked []string `json:"revoked"`
	Expect  string   `json:"expect"`
}

// Vectors is the whole shared file.
type Vectors struct {
	GrantPoPV2                       []GrantPoPV2Case           `json:"grant_pop_v2"`
	GrantHeadRoot                    []GrantHeadCase            `json:"grant_head_root"`
	LedgerCommitment                 []LedgerCase               `json:"ledger_commitment"`
	UsePoPChallenge                  []PoPCase                  `json:"use_pop_challenge"`
	CnfKid                           []CnfKidCase               `json:"cnf_kid"`
	CosigApprovalChallenge           []CosigCase                `json:"cosig_approval_challenge"`
	DelegationHopChallenge           []DelegationCase           `json:"delegation_hop_challenge"`
	IntrospectionTranscriptChallenge []IntrospectionCase        `json:"introspection_transcript_challenge"`
	FederationCertChallenge          []FederationCertCase       `json:"federation_cert_challenge"`
	RevocationLeaf                   []RevocationLeafCase       `json:"revocation_leaf"`
	RevocationMerkleRoot             []RevocationMerkleRootCase `json:"revocation_merkle_root"`
}

// Load reads the shared vector. It locates the repo root from THIS source file's path (runtime.Caller)
// so it is independent of the importing test's working directory.
func Load() (Vectors, error) {
	_, self, _, _ := runtime.Caller(0)
	// self = <repo>/server/internal/goldenvec/goldenvec.go -> repo root is three directories up.
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "spec", "golden-vectors", "broker-preimages.json"))
	if err != nil {
		return Vectors{}, err
	}
	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		return Vectors{}, err
	}
	return v, nil
}
