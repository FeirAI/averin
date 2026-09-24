package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// recoveryTombstone returns "same", "legacy", or "conflict". A legacy
// tombstone lacks BOTH attribution fields; present null/empty fields are not
// silently attributed to today's operator.
// boundVoidRecord recognizes only a tombstone with the complete reserved
// project/grant/sequence tuple and broker role. An inert marker is not enough.
func boundVoidRecord(raw, projectID, grantID string) (int64, map[string]json.RawMessage, string, bool) {
	var r struct {
		RecordID  string `json:"record_id"`
		ProjectID string `json:"project_id"`
		SessionID string `json:"session_id"`
		EventType string `json:"event_type"`
		Authority struct {
			Source           string `json:"source"`
			EnforcementPoint string `json:"enforcement_point"`
			GrantID          string `json:"grant_id"`
		} `json:"authority"`
		Extensions struct {
			Broker struct {
				Kind         string                     `json:"kind"`
				VoidEvidence map[string]json.RawMessage `json:"void_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(raw), &r) != nil || r.RecordID != grantID || r.ProjectID != projectID ||
		r.EventType != "credential_grant_void" || r.Authority.Source != "gateway_enforced" ||
		r.Authority.EnforcementPoint != "credential_broker" || r.Authority.GrantID != grantID ||
		r.Extensions.Broker.Kind != "grant_void" {
		return 0, nil, "", false
	}
	ev := r.Extensions.Broker.VoidEvidence
	var domain, project, gid string
	var seq int64
	if json.Unmarshal(ev["domain"], &domain) != nil || domain != grantVoidDomain ||
		json.Unmarshal(ev["project_id"], &project) != nil || project != projectID ||
		json.Unmarshal(ev["grant_id"], &gid) != nil || gid != grantID ||
		json.Unmarshal(ev["broker_seq"], &seq) != nil || seq < 1 {
		return 0, nil, "", false
	}
	return seq, ev, r.SessionID, true
}

func recoveryTombstone(raw string, vr brokerSeqVoidRequest, grantID string) string {
	seq, ev, sessionID, valid := boundVoidRecord(raw, vr.ProjectID, grantID)
	if !valid || seq != vr.BrokerSeq {
		return "conflict"
	}
	var actor, op, reason string
	_, hasActor := ev["actor_id"]
	_, hasOp := ev["operation_id"]
	if !hasActor && !hasOp {
		return "legacy"
	}
	if !hasActor || !hasOp || json.Unmarshal(ev["actor_id"], &actor) != nil ||
		json.Unmarshal(ev["operation_id"], &op) != nil || json.Unmarshal(ev["reason"], &reason) != nil ||
		actor == "" || op == "" || actor != vr.ActorID || op != vr.OperationID ||
		reason != vr.Reason || sessionID != vr.SessionID {
		return "conflict"
	}
	return "same"
}

func recoveryDigest(v brokerSeqVoidRequest, grantID string) string {
	// A JSON array has unambiguous field boundaries and stable encoding. The
	// reason has already been NFC-normalized by the Rust canonicalizer.
	b, _ := json.Marshal([]any{v.ProjectID, v.BrokerSeq, grantID, v.ActorID, v.OperationID, v.SessionID, v.Reason})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *Server) parseRecoveryRequest(w http.ResponseWriter, r *http.Request) (brokerSeqVoidRequest, bool) {
	var v brokerSeqVoidRequest
	actor, ok := auth.RecoveryActor(r.Context())
	if !ok {
		writeErr(w, http.StatusForbidden, "forbidden")
		return v, false
	}
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled")
		return v, false
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return v, false
	}
	if err := decode(body, &v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid recovery request: "+err.Error())
		return v, false
	}
	if v.ActorID != "" || v.ProjectID != r.URL.Query().Get("project") || v.ProjectID == "" || v.BrokerSeq < 1 {
		writeErr(w, http.StatusBadRequest, "project_id must match authorized project, broker_seq must be positive, actor_id is supplied by authentication")
		return v, false
	}
	if !auth.ValidRecoveryID(v.OperationID) || strings.TrimSpace(v.Reason) != v.Reason || len(v.Reason) < 1 || len(v.Reason) > 512 {
		writeErr(w, http.StatusBadRequest, "operation_id and bounded nonblank reason are required")
		return v, false
	}
	b, _ := json.Marshal(v.Reason)
	if json.Unmarshal([]byte(s.core.RcpCanonicalize(string(b))), &v.Reason) != nil || strings.TrimSpace(v.Reason) != v.Reason || len(v.Reason) < 1 || len(v.Reason) > 512 {
		writeErr(w, http.StatusBadRequest, "invalid recovery reason")
		return v, false
	}
	v.ActorID = actor
	if v.SessionID == "" {
		v.SessionID = "broker-seq-void"
	}
	if err := s.rejectOpaqueIdentity("project_id", v.ProjectID, "session_id", v.SessionID, "operation_id", v.OperationID, "reason", v.Reason); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return v, false
	}
	return v, true
}

// handleBrokerSeqRecovery fences first, then reconciles in a second guarded
// transaction. A crash or ambiguous commit is resumed by the same operation.
func (s *Server) handleBrokerSeqRecovery(w http.ResponseWriter, r *http.Request) {
	v, ok := s.parseRecoveryRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	var fence store.RecoveryFence
	var res store.BrokerSeqReservation
	var preflightConflict string
	err := s.withProjectWrite(ctx, v.ProjectID, func(st store.Store) error {
		var found bool
		var e error
		res, found, e = st.BrokerSeqAt(v.ProjectID, v.BrokerSeq)
		if e != nil {
			return e
		}
		if !found {
			return store.ErrNotFound
		}
		if prior, found, e := st.RecordByIdem(v.ProjectID, fmt.Sprintf("%s%d", grantVoidIdemPrefix, v.BrokerSeq)); e != nil {
			return e
		} else if found {
			if recoveryTombstone(prior.JSON, v, res.GrantID) == "conflict" {
				preflightConflict = "existing signed tombstone belongs to a different or malformed recovery action"
				return store.ErrRecoveryConflict
			}
		}
		want := store.RecoveryFence{ProjectID: v.ProjectID, Seq: v.BrokerSeq, GrantID: res.GrantID, Generation: 1,
			OperationID: v.OperationID, ActorID: v.ActorID, SessionID: v.SessionID, Reason: v.Reason,
			RequestDigest: recoveryDigest(v, res.GrantID)}
		fence, _, e = st.PutRecoveryFence(want)
		return e
	})
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no reservation for broker_seq")
		return
	}
	if errors.Is(err, store.ErrRecoveryConflict) {
		if preflightConflict == "" {
			preflightConflict = "reservation already belongs to a different immutable recovery operation"
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": preflightConflict, "operation_id": v.OperationID, "outcome": "action_conflict"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "recovery fence outcome unresolved: " + err.Error(), "operation_id": v.OperationID, "retryable": true})
		return
	}
	var result store.RecoveryResult
	var winner store.Record
	var legacy, created bool
	var issue string
	err = s.withProjectWrite(ctx, v.ProjectID, func(st store.Store) error {
		current, found, e := st.RecoveryFenceAt(v.ProjectID, v.BrokerSeq)
		if e != nil {
			return e
		}
		if !found || current.RequestDigest != fence.RequestDigest {
			return store.ErrRecoveryConflict
		}
		if done, found, e := st.RecoveryResultAt(v.ProjectID, v.BrokerSeq); e != nil {
			return e
		} else if found {
			result = done
			winner, _, e = st.RecordByRecordID(v.ProjectID, res.GrantID)
			if e == nil && result.Outcome == "voided" {
				legacy = recoveryTombstone(winner.JSON, v, res.GrantID) == "legacy"
			}
			return e
		}
		winner, found, e = st.RecordByRecordID(v.ProjectID, res.GrantID)
		if e != nil {
			return e
		}
		if found {
			classification := recoveryTombstone(winner.JSON, v, res.GrantID)
			if classification == "same" || classification == "legacy" {
				legacy = classification == "legacy"
				if !res.Voided {
					if e := st.VoidBrokerSeq(v.ProjectID, res.GrantID, v.BrokerSeq); e != nil {
						return e
					}
				}
				if s.revocationKey != nil {
					if _, e := st.RevokeGrant(v.ProjectID, res.GrantID); e != nil {
						return e
					}
				}
				result.Outcome = "voided"
			} else if recordIsLandedGrant(winner.JSON, v.BrokerSeq) {
				result.Outcome = "recorded"
			} else {
				issue = "record_id belongs to an unexpected record; inspect original evidence"
				return store.ErrRecoveryConflict
			}
		} else {
			// A mismatched seq holder or malformed log must not be hidden by a tombstone.
			recs, e := st.GrantRecords(v.ProjectID)
			if e != nil {
				return e
			}
			gl, e := grantLog(recs)
			if e != nil {
				return e
			}
			for _, g := range gl {
				if g.Seq == v.BrokerSeq {
					issue = "broker_seq already has a different recorded entry"
					return store.ErrRecoveryConflict
				}
			}
			rec, e := s.buildGrantVoidRecord(v, res.GrantID)
			if e != nil {
				return e
			}
			sealed, c, e := s.sealAndStore(st, v.ProjectID, v.SessionID, fmt.Sprintf("%s%d", grantVoidIdemPrefix, v.BrokerSeq), rec, nil)
			if e != nil {
				return e
			}
			created = c
			winner, found, e = st.RecordByRecordID(v.ProjectID, res.GrantID)
			if e != nil || !found || winner.JSON != sealed {
				return fmt.Errorf("recovery tombstone did not resolve to its sealed record: %w", e)
			}
			if !res.Voided {
				if e := st.VoidBrokerSeq(v.ProjectID, res.GrantID, v.BrokerSeq); e != nil {
					return e
				}
			}
			if s.revocationKey != nil {
				if _, e := st.RevokeGrant(v.ProjectID, res.GrantID); e != nil {
					return e
				}
			}
			result.Outcome = "voided"
		}
		result.ProjectID, result.Seq, result.Generation, result.WinningRecordHash = v.ProjectID, v.BrokerSeq, 1, winner.ContentHash
		result, _, e = st.PutRecoveryResult(result)
		return e
	})
	if errors.Is(err, store.ErrRecoveryConflict) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": issue, "operation_id": v.OperationID, "outcome": "action_conflict"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "recovery reconciliation incomplete: " + err.Error(), "operation_id": v.OperationID, "retryable": true, "fenced": true})
		return
	}
	out := map[string]any{"operation_id": v.OperationID, "broker_seq": v.BrokerSeq, "grant_id": res.GrantID, "outcome": result.Outcome,
		"winning_record_hash": result.WinningRecordHash, "generation": result.Generation, "created": created, "record": json.RawMessage(winner.JSON)}
	if legacy {
		out["legacy_tombstone"] = true
		out["original_void_actor_unattributed"] = true
		out["reconciliation_actor_id"] = v.ActorID
	}
	if result.Outcome == "recorded" {
		out["error"] = "grant landed; nothing to void"
		writeJSON(w, http.StatusConflict, out)
		return
	}
	if s.revocationKey != nil {
		out["revoked"] = true
	}
	if created {
		writeJSON(w, http.StatusCreated, out)
	} else {
		writeJSON(w, http.StatusOK, out)
	}
}

func recordIsLandedGrant(raw string, seq int64) bool {
	var r struct {
		EventType string `json:"event_type"`
		Authority struct {
			EnforcementPoint string `json:"enforcement_point"`
		} `json:"authority"`
		Extensions struct {
			Broker struct {
				Kind          string `json:"kind"`
				GrantEvidence struct {
					BrokerSeq int64 `json:"broker_seq"`
				} `json:"grant_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	return json.Unmarshal([]byte(raw), &r) == nil && r.EventType == "credential_grant" && r.Authority.EnforcementPoint == "credential_broker" && r.Extensions.Broker.Kind == "grant" && r.Extensions.Broker.GrantEvidence.BrokerSeq == seq
}

// This early read avoids minting a new descriptor for a permanently fenced
// grant. The decisive check is still AllocateBrokerSeq under the write guard.
func (s *Server) grantFencedBeforeMint(ctx context.Context, projectID, grantID string) error {
	return s.st.WithProjectRead(ctx, projectID, func(st store.Store) error {
		f, found, err := st.RecoveryFenceByGrant(projectID, grantID)
		if err != nil || !found {
			return err
		}
		r, done, err := st.RecoveryResultAt(projectID, f.Seq)
		if err != nil {
			return err
		}
		if done && r.Outcome == "recorded" {
			return nil
		}
		return store.ErrRecoveryFenced
	})
}

func (s *Server) terminalGrantVoided(st store.Store, projectID, grantID string) (bool, error) {
	f, found, err := st.RecoveryFenceByGrant(projectID, grantID)
	if err != nil {
		return false, err
	}
	if found {
		r, done, e := st.RecoveryResultAt(projectID, f.Seq)
		if e != nil || (done && r.Outcome == "voided") {
			return done && r.Outcome == "voided", e
		}
	}
	// Legacy tombstones can predate the fence/result or have committed before
	// their operational marker. The signed, append-only record is the authority;
	// a marker alone must not retire a landed grant.
	winner, foundRecord, err := st.RecordByRecordID(projectID, grantID)
	if err != nil || !foundRecord {
		return false, err
	}
	seq, _, _, bound := boundVoidRecord(winner.JSON, projectID, grantID)
	if !bound || (found && f.Seq != seq) {
		return false, nil
	}
	res, reserved, err := st.BrokerSeqAt(projectID, seq)
	return reserved && res.GrantID == grantID, err
}

func (s *Server) handleBrokerSeqPreflight(w http.ResponseWriter, r *http.Request) {
	actor, ok := auth.RecoveryActor(r.Context())
	if !ok {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	project := r.URL.Query().Get("project")
	seq, err := strconv.ParseInt(r.URL.Query().Get("broker_seq"), 10, 64)
	if project == "" || err != nil || seq < 1 {
		writeErr(w, http.StatusBadRequest, "project and positive broker_seq are required")
		return
	}
	out := map[string]any{"project_id": project, "broker_seq": seq, "recovery_actor_id": actor, "diagnostic_only": true}
	err = s.st.WithProjectRead(r.Context(), project, func(st store.Store) error {
		unique, e := st.RecordIDUniqueEnforced()
		if e != nil {
			return e
		}
		out["record_id_unique_enforced"] = unique
		res, found, e := st.BrokerSeqAt(project, seq)
		if e != nil {
			return e
		}
		if !found {
			out["reservation"] = nil
			return nil
		}
		out["reservation"] = map[string]any{"grant_id": res.GrantID, "broker_seq": res.Seq, "allocated_at": res.AllocatedAt}
		out["void_marker"] = res.Voided
		pending, found, e := st.PendingGrantByGrant(project, res.GrantID)
		if e != nil {
			return e
		}
		if found {
			live, e := st.PendingGrantLive(project, res.GrantID, time.Now(), pendingTTL)
			if e != nil {
				return e
			}
			out["pending"] = map[string]any{"created_at": pending.Created, "live": live}
		} else {
			out["pending"] = nil
		}
		winner, found, e := st.RecordByRecordID(project, res.GrantID)
		if e != nil {
			return e
		}
		if found {
			out["winning_record_hash"] = winner.ContentHash
			out["winning_record"] = json.RawMessage(winner.JSON)
		} else {
			out["winning_record"] = nil
		}
		fence, found, e := st.RecoveryFenceAt(project, seq)
		if e != nil {
			return e
		}
		if found {
			out["fence"] = map[string]any{"grant_id": fence.GrantID, "generation": fence.Generation, "operation_id": fence.OperationID, "actor_id": fence.ActorID, "session_id": fence.SessionID, "reason": fence.Reason, "request_digest": fence.RequestDigest, "fenced_at": fence.FencedAt}
		} else {
			out["fence"] = nil
		}
		if winner.JSON != "" {
			v := brokerSeqVoidRequest{ProjectID: project, BrokerSeq: seq}
			if recoveryTombstone(winner.JSON, v, res.GrantID) == "legacy" {
				out["legacy_tombstone"] = true
				out["original_void_actor_unattributed"] = true
			}
		}
		result, found, e := st.RecoveryResultAt(project, seq)
		if e != nil {
			return e
		}
		if found {
			out["result"] = map[string]any{"outcome": result.Outcome, "winning_record_hash": result.WinningRecordHash, "generation": result.Generation, "completed_at": result.CompletedAt}
		} else {
			out["result"] = nil
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "recovery preflight: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
