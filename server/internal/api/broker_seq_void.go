package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// DefaultBrokerSeqVoidMinAge is the default safety age (AVERIN_BROKER_SEQ_VOID_MIN_AGE) a reserved broker_seq must
// reach before POST /v2/broker-seq/void may void it: far longer than any in-flight grant can take to commit (the
// Postgres statement timeout is 30s, a two-phase pending grant expires after pendingTTL = 15m), so a void can never
// race a commit that is still landing.
const DefaultBrokerSeqVoidMinAge = time.Hour

// grantVoidDomain domain-separates a tombstone's void_evidence (its canonical bytes, and so its signed evidence_hash,
// can never equal a grant_evidence payload's). The offline verifier requires exactly this value.
const grantVoidDomain = "averin.broker.grant_void.v1"

// grantVoidIdemPrefix keys a tombstone record in the store (grant-void:<broker_seq>), so a repeated void of the same
// seq collapses onto the one tombstone. It is RESERVED (reservedIdem): no caller may pre-seed it.
const grantVoidIdemPrefix = "grant-void:"

// WithBrokerSeqVoidMinAge sets the safety age a reserved broker_seq must reach before it can be voided (see
// DefaultBrokerSeqVoidMinAge). main.go wires AVERIN_BROKER_SEQ_VOID_MIN_AGE (with a floor); tests may pass 0.
func (s *Server) WithBrokerSeqVoidMinAge(d time.Duration) *Server {
	s.brokerSeqVoidMinAge = d
	return s
}

// brokerSeqVoidRequest is the POST /v2/broker-seq/void wire shape.
type brokerSeqVoidRequest struct {
	ProjectID string `json:"project_id"`
	BrokerSeq int64  `json:"broker_seq"`
	SessionID string `json:"session_id"` // optional: the session the tombstone is sealed into (default broker-seq-void)
	Reason    string `json:"reason"`     // optional, bound into the signed void_evidence
}

// handleBrokerSeqVoid is the operator remediation for a WEDGED grant-transparency log (ADR 0004 D6). A broker_seq
// reserved by a grant that never recorded (an ambiguous commit whose client never retried, or an orphan left by a
// failed release) leaves the recorded set short of [1..MaxBrokerSeq], and createCheckpoint refuses to sign over that
// gap forever. This seals a broker-signed grant_void TOMBSTONE that fills exactly that seq: it binds (project_id,
// broker_seq, the reserved grant_id), is folded into broker_grant_head like a grant, and is never a grant (the
// offline verifier accepts it as filling its seq only; a real grant claiming the same seq is a duplicate-seq
// violation). The reservation is marked voided in the store FIRST — kept in the allocation ledger so MAX+1 never
// re-issues the number, and the grant_id retired so a late retry of that grant gets a 409 instead of the seq.
//
// It voids ONLY a seq that is (1) currently allocated, (2) not recorded — no record holds the reserved grant_id and
// no grant/tombstone record carries that broker_seq (the store read is the authority, so a commit that was ambiguous
// but actually landed is refused however old it is), (3) not backing a live two-phase pending grant, and (4) at least
// brokerSeqVoidMinAge old. A repeat of a completed void returns the existing tombstone (200, created:false).
func (s *Server) handleBrokerSeqVoid(w http.ResponseWriter, r *http.Request) {
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled (set AVERIN_BROKER_ISSUING_SEED)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var vr brokerSeqVoidRequest
	if err := decode(body, &vr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid void request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && vr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if vr.ProjectID == "" || vr.BrokerSeq < 1 {
		writeErr(w, http.StatusBadRequest, "project_id and broker_seq (>= 1) are required")
		return
	}
	if vr.SessionID == "" {
		vr.SessionID = "broker-seq-void"
	}
	if err := rejectNUL("project_id", vr.ProjectID, "session_id", vr.SessionID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		code    int
		errMsg  string
		sealed  string
		created bool
		grantID string
	)
	func() {
		s.ingestMu.Lock()
		defer s.ingestMu.Unlock()
		fail := func(c int, format string, a ...any) { code, errMsg = c, fmt.Sprintf(format, a...) }

		res, found, e := s.st.BrokerSeqAt(vr.ProjectID, vr.BrokerSeq)
		if e != nil {
			fail(http.StatusInternalServerError, "broker_seq lookup: %v", e)
			return
		}
		if !found {
			fail(http.StatusNotFound, "no broker_seq %d is allocated in project %q", vr.BrokerSeq, vr.ProjectID)
			return
		}
		grantID = res.GrantID
		idem := fmt.Sprintf("%s%d", grantVoidIdemPrefix, vr.BrokerSeq)
		if res.Voided {
			// Already voided: return the tombstone if it was sealed; else finish the interrupted void below (the
			// safety checks passed when the reservation was voided, and nothing can have recorded it since —
			// AllocateBrokerSeq refuses a voided grant_id).
			if existing, ok, le := s.st.RecordByIdem(vr.ProjectID, idem); le != nil {
				fail(http.StatusInternalServerError, "tombstone lookup: %v", le)
				return
			} else if ok {
				sealed, created, code = existing.JSON, false, http.StatusOK
				return
			}
		} else {
			// (2) the store must confirm NO record holds this seq — neither under the reserved grant_id (the
			// deterministic record_id of the grant it was reserved for) nor any grant/tombstone carrying the seq.
			if has, he := s.st.HasRecordID(vr.ProjectID, res.GrantID); he != nil {
				fail(http.StatusInternalServerError, "record lookup: %v", he)
				return
			} else if has {
				fail(http.StatusConflict, "broker_seq %d is recorded (a record holds its grant_id %s) — only a reserved, unrecorded seq can be voided", vr.BrokerSeq, res.GrantID)
				return
			}
			grantRecs, ge := s.st.GrantRecords(vr.ProjectID)
			if ge != nil {
				fail(http.StatusInternalServerError, "grant records: %v", ge)
				return
			}
			gl, ge := grantLog(grantRecs)
			if ge != nil {
				fail(http.StatusInternalServerError, "%v", ge)
				return
			}
			for _, g := range gl {
				if g.Seq == vr.BrokerSeq {
					fail(http.StatusConflict, "broker_seq %d is recorded (record %s carries it) — only a reserved, unrecorded seq can be voided", vr.BrokerSeq, g.ContentHash)
					return
				}
			}
			// (3) a live two-phase pending grant for this grant_id may still finalize (a finalize retry reclaims it).
			if s.pendingGrantLive(res.GrantID) {
				fail(http.StatusConflict, "broker_seq %d backs a live two-phase pending grant (%s) — retry its finalize, or wait for it to expire", vr.BrokerSeq, res.GrantID)
				return
			}
			// (4) the safety age: the reservation must be old enough that no commit for it can still be in flight.
			if age := s.now().Sub(res.AllocatedAt); age < s.brokerSeqVoidMinAge {
				fail(http.StatusConflict, "broker_seq %d was reserved %s ago; it can be voided once it is %s old (AVERIN_BROKER_SEQ_VOID_MIN_AGE) — retry the grant first if its client is still around", vr.BrokerSeq, age.Truncate(time.Second), s.brokerSeqVoidMinAge)
				return
			}
			if ve := s.st.VoidBrokerSeq(vr.ProjectID, res.GrantID, vr.BrokerSeq); ve != nil {
				fail(http.StatusInternalServerError, "void broker_seq: %v", ve)
				return
			}
		}
		rec, be := s.buildGrantVoidRecord(vr, res.GrantID)
		if be != nil {
			fail(http.StatusInternalServerError, "build tombstone: %v", be)
			return
		}
		st, c, se := s.sealAndStore(vr.ProjectID, vr.SessionID, idem, rec, nil)
		if se != nil {
			// The reservation stays voided (the grant_id is retired either way); a repeat of this call seals it.
			fail(http.StatusInternalServerError, "seal tombstone (the seq is voided; repeat this call to finish): %v", se)
			return
		}
		sealed, created, code = st, c, http.StatusCreated
		if !c {
			code = http.StatusOK
		}
	}()
	if errMsg != "" {
		writeErr(w, code, errMsg)
		return
	}
	writeJSON(w, code, map[string]any{
		"voided_broker_seq": vr.BrokerSeq,
		"grant_id":          grantID,
		"created":           created,
		"record":            json.RawMessage(sealed),
	})
}

// pendingGrantLive reports whether a two-phase pending grant (prepare done, finalize not committed) for grantID is
// still within pendingTTL. Void is a rare operator action, so a scan of the pending map is fine.
func (s *Server) pendingGrantLive(grantID string) bool {
	now := s.now()
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for _, p := range s.pending {
		if p.prepared.GrantID == grantID && now.Sub(p.created) <= pendingTTL {
			return true
		}
	}
	return false
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
		"domain":     grantVoidDomain,
		"project_id": vr.ProjectID,
		"broker_seq": vr.BrokerSeq,
		"grant_id":   grantID,
		"voided_at":  now,
		"reason":     vr.Reason,
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
	evidenceSig, err := s.core.SignEvidence("gateway_enforced", vr.ProjectID, grantID, evidenceHash)
	if err != nil {
		return nil, fmt.Errorf("sign void evidence: %w", err)
	}
	return map[string]any{
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
			"evidence_sig":      evidenceSig,
			"evaluated_at":      now,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":          "grant_void",
				"void_evidence": evidence,
			},
		},
	}, nil
}

// isVoidedGrant reports whether err is the store's refusal to allocate for a voided grant_id (mapped to 409).
func isVoidedGrant(err error) bool { return errors.Is(err, store.ErrBrokerSeqVoided) }
