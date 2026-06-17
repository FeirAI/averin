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

// CnfKidCase pins the cnf key-id derived from a 32-byte ed25519 seed.
type CnfKidCase struct {
	SeedHex string `json:"seed_hex"`
	Expect  string `json:"expect"`
}

// Vectors is the whole shared file.
type Vectors struct {
	GrantHeadRoot    []GrantHeadCase `json:"grant_head_root"`
	LedgerCommitment []LedgerCase    `json:"ledger_commitment"`
	UsePoPChallenge  []PoPCase       `json:"use_pop_challenge"`
	CnfKid           []CnfKidCase    `json:"cnf_kid"`
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
