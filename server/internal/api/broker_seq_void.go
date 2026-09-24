package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// DefaultBrokerSeqVoidMinAge is the safety age for remediating a durable
// orphaned broker sequence. The latest local attempt and process start are
// additional floors because a previous process may have forgotten an attempt.
// A database project guard serializes grant finalize and void on every replica;
// record_id uniqueness excludes a grant and its tombstone from coexisting.
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
	ProjectID   string `json:"project_id"`
	BrokerSeq   int64  `json:"broker_seq"`
	SessionID   string `json:"session_id"`   // optional: the session the tombstone is sealed into (default broker-seq-void)
	OperationID string `json:"operation_id"` // caller-chosen stable ID for this recovery action
	Reason      string `json:"reason"`       // required, bound into the signed void_evidence
	ActorID     string `json:"actor_id"`     // rejected if supplied; set only from authenticated context
}

// handleBrokerSeqVoid fills a committed, unrecorded broker sequence with a
// signed grant_void tombstone. It checks the reservation, durable pending state,
// age and record_id uniqueness inside one project transaction. Tombstone,
// void marker and optional revocation commit together; a failure rolls all of
// them back. A retry returns the existing tombstone. A legacy marker without a
// tombstone is rechecked against the record log before repair. The exact route
// requires a separate project-scoped recovery actor and operation ID.
func (s *Server) handleBrokerSeqVoid(w http.ResponseWriter, r *http.Request) {
	actor, authorized := auth.RecoveryActor(r.Context())
	if !authorized {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
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
	if vr.ActorID != "" {
		writeErr(w, http.StatusBadRequest, "actor_id is supplied by authentication")
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
	if strings.TrimSpace(vr.Reason) != vr.Reason || len(vr.Reason) < 1 || len(vr.Reason) > 512 ||
		!auth.ValidRecoveryID(vr.OperationID) {
		writeErr(w, http.StatusBadRequest, "operation_id must be 1..128 printable non-whitespace ASCII bytes and reason must be a bounded nonblank string")
		return
	}
	// The Rust RCP seal normalizes strings to NFC. Normalize only the human
	// reason before both signing and replay comparison, or an identical request
	// with decomposed Unicode would falsely conflict with its stored tombstone.
	reasonJSON, err := json.Marshal(vr.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid recovery reason")
		return
	}
	canonicalReason := s.core.RcpCanonicalize(string(reasonJSON))
	if json.Unmarshal([]byte(canonicalReason), &vr.Reason) != nil ||
		strings.TrimSpace(vr.Reason) != vr.Reason || len(vr.Reason) < 1 || len(vr.Reason) > 512 {
		writeErr(w, http.StatusBadRequest, "invalid recovery reason")
		return
	}
	vr.ActorID = actor
	if vr.SessionID == "" {
		vr.SessionID = "broker-seq-void"
	}
	if err := s.rejectOpaqueIdentity("project_id", vr.ProjectID, "session_id", vr.SessionID,
		"operation_id", vr.OperationID, "reason", vr.Reason); err != nil {
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
	var txFailure error
	txErr := s.withProjectWrite(r.Context(), vr.ProjectID, func(st store.Store) error {
		func() {
			fail := func(c int, format string, a ...any) {
				code, errMsg = c, fmt.Sprintf(format, a...)
				txFailure = errors.New(errMsg)
			}

			res, found, e := st.BrokerSeqAt(vr.ProjectID, vr.BrokerSeq)
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
			// inert names an old void marker that no tombstone backs (left by a void from before the tombstone-first
			// ordering whose seal then failed): it retires the grant_id at allocation but fills nothing.
			inert := ""
			if res.Voided {
				inert = " (the void marker already on this reservation is INERT: an earlier void was interrupted before its tombstone was sealed, and the grant's own record holds the seq)"
			}

			// A prior tombstone may be a legacy partial void. Repair its marker
			// and revocation in this transaction; new voids commit all three together.
			if existing, ok, le := st.RecordByIdem(vr.ProjectID, idem); le != nil {
				fail(http.StatusInternalServerError, "tombstone lookup: %v", le)
				return
			} else if ok {
				if !sameRecoveryAction(existing.JSON, vr, res.GrantID) {
					fail(http.StatusConflict, "broker_seq already has a recovery tombstone with different action parameters")
					return
				}
				if !res.Voided {
					if ve := st.VoidBrokerSeq(vr.ProjectID, res.GrantID, vr.BrokerSeq); ve != nil {
						fail(http.StatusInternalServerError, "broker_seq %d void marker failed; the transaction rolled back: %v", vr.BrokerSeq, ve)
						return
					}
				}
				if s.revocationKey != nil {
					if _, re := st.RevokeGrant(vr.ProjectID, res.GrantID); re != nil {
						fail(http.StatusServiceUnavailable, "revoke voided grant: %v", re)
						return
					}
				}
				sealed, created, code = existing.JSON, false, http.StatusOK
				return
			}

			// (b) No tombstone yet: every safety check, including for a reservation already carrying a (necessarily
			// inert) marker — its grant may have landed after all.
			// (0) the database backstop must be present (guard 3, see DefaultBrokerSeqVoidMinAge): without a UNIQUE
			// record_id index a still-in-flight commit of this grant (possibly on another instance) and its tombstone
			// could BOTH land, holding the seq twice — and every later checkpoint would refuse forever.
			if uniq, ue := st.RecordIDUniqueEnforced(); ue != nil {
				fail(http.StatusInternalServerError, "record_id uniqueness probe: %v", ue)
				return
			} else if !uniq {
				fail(http.StatusConflict, "broker_seq void refused: the store does not enforce record_id uniqueness (the UNIQUE index records_project_record_id_uniq is absent or non-unique — migration 0002 fell back to a plain index over historical duplicate record_ids). Without it a void could race a still-in-flight commit of grant %s and hold broker_seq %d twice. Resolve the historical duplicate and build the UNIQUE index first (docs/operator-verification.md)", res.GrantID, vr.BrokerSeq)
				return
			}
			// (2) the store must confirm NO record holds this seq — neither under the reserved grant_id (the
			// deterministic record_id of the grant it was reserved for) nor any grant/tombstone carrying the seq.
			if has, he := st.HasRecordID(vr.ProjectID, res.GrantID); he != nil {
				fail(http.StatusInternalServerError, "record lookup: %v", he)
				return
			} else if has {
				fail(http.StatusConflict, "broker_seq %d is recorded (a record holds its grant_id %s): grant landed; nothing to void%s", vr.BrokerSeq, res.GrantID, inert)
				return
			}
			grantRecs, ge := st.GrantRecords(vr.ProjectID)
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
					fail(http.StatusConflict, "broker_seq %d is recorded (record %s carries it): nothing to void%s", vr.BrokerSeq, g.ContentHash, inert)
					return
				}
			}
			if !res.Voided {
				// (3) a live two-phase pending grant for this grant_id may still finalize (a finalize retry reclaims it).
				// (An inert marker already retires the grant_id at allocation, so no finalize can start any more.)
				live, pe := st.PendingGrantLive(vr.ProjectID, res.GrantID, s.now(), pendingTTL)
				if pe != nil {
					fail(http.StatusServiceUnavailable, "pending grant lookup: %v", pe)
					return
				}
				if live {
					fail(http.StatusConflict, "broker_seq %d backs a live two-phase pending grant (%s) — retry its finalize, or wait for it to expire", vr.BrokerSeq, res.GrantID)
					return
				}
				// (4) the safety age: the reservation, its latest attempt AND this process's start must all be old enough
				// that no commit for it can still be in flight (allocated_at alone is never refreshed by a retry, and
				// the attempt map is in-memory — empty after a restart — see DefaultBrokerSeqVoidMinAge).
				last, what := res.AllocatedAt, "reserved"
				if t, ok := s.lastSeqAttempt(vr.ProjectID, res.GrantID); ok && t.After(last) {
					last, what = t, "last attempted by its grant"
				}
				if s.processStart.After(last) {
					last, what = s.processStart, "reserved before this process started (its attempt history is in-memory, so the age counts from the start)"
				}
				if age := s.now().Sub(last); age < s.brokerSeqVoidMinAge {
					fail(http.StatusConflict, "broker_seq %d was %s %s ago; it can be voided once that is %s old (AVERIN_BROKER_SEQ_VOID_MIN_AGE) — retry the grant first if its client is still around", vr.BrokerSeq, what, age.Truncate(time.Second), s.brokerSeqVoidMinAge)
					return
				}
			}

			// Seal the tombstone FIRST. Its record_id IS the reserved grant_id, so under the UNIQUE record_id index it
			// and the grant are mutually exclusive: if a still-in-flight commit of the grant wins (on Postgres the
			// tombstone's insert waits on the grant's uncommitted index entry, then conflicts), the seal fails with
			// ErrRecordIDConflict and NOTHING is voided — no marker is written, and the grant's retry returns it.
			rec, be := s.buildGrantVoidRecord(vr, res.GrantID)
			if be != nil {
				fail(http.StatusInternalServerError, "build tombstone: %v", be)
				return
			}
			sealedRecord, c, se := s.sealAndStore(st, vr.ProjectID, vr.SessionID, idem, rec, nil)
			if se != nil {
				if errors.Is(se, store.ErrRecordIDConflict) {
					fail(http.StatusConflict, "broker_seq %d is recorded: grant %s landed while its tombstone was being sealed (the database's record_id uniqueness let the grant win) — grant landed; nothing to void%s", vr.BrokerSeq, res.GrantID, inert)
					return
				}
				fail(http.StatusInternalServerError, "seal tombstone: %v — the reservation is NOT voided; repeat this call (if the tombstone's commit was ambiguous and landed, the repeat finds it and finishes the void)", se)
				return
			}
			// The marker and tombstone become visible together at COMMIT.
			if !res.Voided {
				if ve := st.VoidBrokerSeq(vr.ProjectID, res.GrantID, vr.BrokerSeq); ve != nil {
					fail(http.StatusInternalServerError, "broker_seq %d void marker failed; the transaction rolled back: %v", vr.BrokerSeq, ve)
					return
				}
			}
			if s.revocationKey != nil {
				if _, re := st.RevokeGrant(vr.ProjectID, res.GrantID); re != nil {
					fail(http.StatusServiceUnavailable, "revoke voided grant: %v", re)
					return
				}
			}
			sealed, created, code = sealedRecord, c, http.StatusCreated
			if !c {
				code = http.StatusOK
			}
		}()
		return txFailure
	})
	if txErr != nil && errMsg == "" {
		writeErr(w, http.StatusServiceUnavailable, "void transaction: "+txErr.Error())
		return
	}
	if errMsg != "" {
		writeErr(w, code, errMsg)
		return
	}
	out := map[string]any{
		"voided_broker_seq": vr.BrokerSeq,
		"grant_id":          grantID,
		"created":           created,
		"record":            json.RawMessage(sealed),
	}
	if s.revocationKey != nil {
		out["revoked"] = true
	}
	writeJSON(w, code, out)
}

// sameRecoveryAction prevents a retry from rewriting or claiming somebody
// else's tombstone. Legacy tombstones remain readable and verifiable, but lack
// the identity needed to accept a new authenticated retry.
func sameRecoveryAction(raw string, vr brokerSeqVoidRequest, grantID string) bool {
	var record struct {
		RecordID   string `json:"record_id"`
		ProjectID  string `json:"project_id"`
		SessionID  string `json:"session_id"`
		Extensions struct {
			Broker struct {
				Kind         string `json:"kind"`
				VoidEvidence struct {
					ProjectID   string `json:"project_id"`
					BrokerSeq   int64  `json:"broker_seq"`
					GrantID     string `json:"grant_id"`
					ActorID     string `json:"actor_id"`
					OperationID string `json:"operation_id"`
					Reason      string `json:"reason"`
				} `json:"void_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(raw), &record) != nil {
		return false
	}
	ev := record.Extensions.Broker.VoidEvidence
	return record.Extensions.Broker.Kind == "grant_void" && record.RecordID == grantID && record.ProjectID == vr.ProjectID && record.SessionID == vr.SessionID &&
		ev.ProjectID == vr.ProjectID && ev.BrokerSeq == vr.BrokerSeq && ev.GrantID == grantID &&
		ev.ActorID == vr.ActorID && ev.OperationID == vr.OperationID && ev.Reason == vr.Reason
}

// noteSeqAttempt stamps now as the latest attempt of (projectID, grantID) — see Server.seqAttempts. Entries older
// than brokerSeqVoidMinAge can no longer block a void, so the map is pruned of them whenever it doubles in size.
func (s *Server) noteSeqAttempt(projectID, grantID string) {
	now := s.now()
	s.seqAttemptsMu.Lock()
	defer s.seqAttemptsMu.Unlock()
	if s.seqAttempts == nil {
		s.seqAttempts = map[string]time.Time{}
	}
	s.seqAttempts[projectID+"\x00"+grantID] = now
	if len(s.seqAttempts) >= s.seqAttemptsPruneAt {
		for k, t := range s.seqAttempts {
			if now.Sub(t) >= s.brokerSeqVoidMinAge {
				delete(s.seqAttempts, k)
			}
		}
		s.seqAttemptsPruneAt = max(1024, 2*len(s.seqAttempts))
	}
}

// lastSeqAttempt returns the latest attempt time noted for (projectID, grantID) on this process, if any.
func (s *Server) lastSeqAttempt(projectID, grantID string) (time.Time, bool) {
	s.seqAttemptsMu.Lock()
	defer s.seqAttemptsMu.Unlock()
	t, ok := s.seqAttempts[projectID+"\x00"+grantID]
	return t, ok
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
func isVoidedGrant(err error) bool { return errors.Is(err, store.ErrBrokerSeqVoided) }

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
