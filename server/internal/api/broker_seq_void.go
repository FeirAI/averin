package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// grantVoidDomain domain-separates a tombstone's void_evidence (its canonical bytes, and so its signed evidence_hash,
// can never equal a grant_evidence payload's). The offline verifier requires exactly this value.
const grantVoidDomain = "averin.broker.grant_void.v1"

// grantVoidIdemPrefix keys a tombstone record in the store (grant-void:<broker_seq>), so a repeated void of the same
// seq collapses onto the one tombstone. It is RESERVED (reservedIdem): no caller may pre-seed it.
const grantVoidIdemPrefix = "grant-void:"

// WithBrokerSeqVoidMinAge remains for callers compiled against the old API.
// Recovery now relies on a durable fence and ignores elapsed wall-clock age.
func (s *Server) WithBrokerSeqVoidMinAge(_ time.Duration) *Server { return s }

// brokerSeqVoidRequest is the POST /v2/broker-seq/void wire shape.
type brokerSeqVoidRequest struct {
	ProjectID   string `json:"project_id"`
	BrokerSeq   int64  `json:"broker_seq"`
	SessionID   string `json:"session_id"`   // optional: the session the tombstone is sealed into (default broker-seq-void)
	OperationID string `json:"operation_id"` // caller-chosen stable ID for this recovery action
	Reason      string `json:"reason"`       // required, bound into the signed void_evidence
	ActorID     string `json:"actor_id"`     // rejected if supplied; set only from authenticated context
}

// buildGrantVoidRecord assembles the unsealed grant_void tombstone. Its record_id IS the voided grant_id, so the
// store's per-project record_id uniqueness makes the tombstone and the grant it replaces mutually exclusive (and the
// verifier flags a bundle carrying both). The authority block is broker-signed exactly like a grant's
// (gateway_enforced, record_id-bound evidence_sig over sha256(RCP(void_evidence))), and the role discriminator
// (extensions.broker.kind = grant_void, authority.enforcement_point = credential_broker) classifies it to the
// verifier's grant_void role — never the grant role.
func (s *Server) buildGrantVoidRecord(vr brokerSeqVoidRequest, grantID string) (map[string]any, error) {
	now := ts(s.now())
	evidence := map[string]any{
		"domain":       grantVoidDomain,
		"project_id":   vr.ProjectID,
		"broker_seq":   vr.BrokerSeq,
		"grant_id":     grantID,
		"voided_at":    now,
		"actor_id":     vr.ActorID,
		"operation_id": vr.OperationID,
		"reason":       vr.Reason,
	}
	if s.brokerID != "" {
		evidence["broker_id"] = s.brokerID // M4: the tombstone fills the seq in THIS broker's partition
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("marshal void evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, fmt.Errorf("derive void evidence_hash: %w", err)
	}
	rec := map[string]any{
		"record_id":     grantID,
		"project_id":    vr.ProjectID,
		"session_id":    vr.SessionID,
		"agent_id":      "averin-broker",
		"agent_version": "averin-broker",
		"event_type":    "credential_grant_void", // NOT credential_grant: the verifier never counts it as a grant
		"observed_via":  "broker",
		"action":        "broker_seq.void",
		"status":        "void",
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "credential_broker",
			"grant_id":          grantID,
			"evidence_hash":     evidenceHash,
			"evaluated_at":      now,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":          "grant_void",
				"void_evidence": evidence,
			},
		},
	}
	if err := s.signLocalAuthorityV3(rec, s.core); err != nil {
		return nil, err
	}
	return rec, nil
}

// isVoidedGrant reports whether err is the store's refusal to allocate for a voided grant_id (mapped to 409).
func isVoidedGrant(err error) bool {
	return errors.Is(err, store.ErrBrokerSeqVoided) || errors.Is(err, store.ErrRecoveryFenced)
}

// grantIDTakenMsg maps a grant path's store error to a 409 message when the grant's own record could not be stored
// because a DIFFERENT record already holds its grant_id as record_id — in practice the grant_void tombstone of a void
// that won (it is sealed before its void marker, so a retry landing in between allocates the reserved seq and only
// then loses on record_id). The seq is left reserved (settleFailedGrantSeq never releases a reused seq, and
// ReleaseBrokerSeq never releases a record-held one), so the voided number is never re-issued. "" = not that case.
func grantIDTakenMsg(err error, grantID string) string {
	if !errors.Is(err, store.ErrRecordIDConflict) {
		return ""
	}
	return fmt.Sprintf("grant_id %s is already held by a different record (its broker_seq was voided: a grant_void tombstone fills it) — re-issue under a new idempotency key: %v", grantID, err)
}
