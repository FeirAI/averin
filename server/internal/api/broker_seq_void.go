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
// reach before POST /v2/broker-seq/void may void it: far longer than any in-flight grant commit can take (the
// Postgres statement timeout is 30s, a two-phase pending grant expires after pendingTTL = 15m).
//
// The age ALONE does not make a void-vs-commit race impossible, because the store's allocated_at is stamped only on
// the FRESH insert and never refreshed when a retry of the same grant_id reuses the seq (fresh=false; on Postgres
// broker_seq is insert-only). A retry at T0+59m59s whose COMMIT is still in flight would otherwise let a void at
// T0+60m pass the age check while HasRecordID cannot yet see the uncommitted row. The guards that actually close it:
//
//  1. The age is measured from max(allocated_at, the LATEST attempt of that grant_id on this process, this process's
//     START) — every grant path (handleGrant, two-phase finalize, native grant) stamps an attempt when it
//     allocates/reuses the seq and again when it settles a failed attempt (s.noteSeqAttempt), so a recent retry
//     blocks the void. The attempt map is in-memory, so the process start is a BOOT FLOOR: right after a restart
//     (which forgot every earlier attempt) no void passes until the minimum age has elapsed since the start.
//  2. Within one process the void and every allocate→seal→store run under ingestMu, so a commit that has not
//     returned cannot interleave with the void's store reads.
//  3. The DATABASE backstop: the tombstone's record_id IS the voided grant_id, so under the UNIQUE record_id index
//     (records_project_record_id_uniq, migration 0002) at most one of {the grant, its tombstone} can ever land.
//     A Postgres DB where 0002 took the WARNING fallback (a NON-unique index, historical duplicates) lacks this
//     backstop, so the void REFUSES there (409) — see Store.RecordIDUniqueEnforced. The Mem store always enforces it.
//
// Guards 1 and 2 are PROCESS-LOCAL: a multi-instance deployment sharing one Postgres (a retry landing on instance
// A while the operator voids on instance B) is closed only by guard 3.
//
// Clock skew: allocated_at is the STORE's clock (Postgres now() on the DB host; the Mem store's injectable clock)
// while the age is taken against this process's clock. A DB clock that runs AHEAD only makes the age look smaller
// (conservative); one that runs BEHIND makes it look larger by the skew, so keep the configured minimum age far
// above any plausible DB↔app skew (the default 1h, and main.go's floor, dwarf NTP-disciplined skew). The latest-
// attempt time (guard 1) is app-clock on both sides and so is skew-free.
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
// violation). The tombstone is sealed FIRST and the reservation marked voided in the store SECOND (VoidBrokerSeq):
// kept in the allocation ledger so MAX+1 never re-issues the number, and the grant_id retired so a late retry of
// that grant gets a 409 instead of the seq. Tombstone-first means the marker is written only for a void that WON:
// if a still-in-flight commit of the grant wins the record_id race (the database backstop), the seal fails with
// ErrRecordIDConflict, the call returns 409 "grant landed; nothing to void" and nothing is marked. If the marker
// write fails after the tombstone is sealed (or the process dies between the two), the grant can already never
// record (its record_id is taken; a retry in that window allocates the reserved seq, loses on record_id → 409, and
// never releases the seq), and a repeat of this call finds the tombstone by its idempotency key and just writes
// the marker.
//
// It voids ONLY a seq that is (1) currently allocated, (2) not recorded — no record holds the reserved grant_id and
// no grant/tombstone record carries that broker_seq (the store read is the authority, so a commit that was ambiguous
// but actually landed is refused however old it is), (3) not backing a live two-phase pending grant, and (4) at least
// brokerSeqVoidMinAge old, measured from the later of its allocation and its grant's latest attempt — and only on a
// store that enforces record_id uniqueness (Store.RecordIDUniqueEnforced). A repeat of a completed void returns the
// existing tombstone (200, created:false). A reservation carrying a void marker but NO tombstone (left by a void
// from before the tombstone-first ordering whose seal failed) is re-checked like a fresh one: if its grant landed
// after all, the call returns 409 and names the marker inert.
//
// STALL RISK: the whole check→seal→mark runs under ingestMu (guard 2), and on Postgres the tombstone's INSERT waits on
// the UNIQUE record_id index entry of any in-flight (uncommitted) row holding the same record_id — e.g. the grant's
// commit on another instance — for up to the 30 s statement timeout. For that long every ingest/grant/use on this
// process queues behind the void. It is a rare operator action, and the wait ends as soon as that transaction
// commits or rolls back.
//
// When revocation is enabled (WithRevocation) the voided grant_id is also REVOKED (exactly as POST /v2/revoke would),
// so a capability minted for it before the void — e.g. at a two-phase prepare — stops being honored at /v2/use at
// once and is carried in the next signed revocation_list. If that revocation fails the call returns an error after
// the void; repeating it (idempotent) retries the revocation. Without revocation the capability stays usable until
// it expires (documented in docs/dev/API.md).
//
// AUTHZ: like every /v2 route this is gated only by the project-scoped API key — the server has no separate
// operator/admin privilege — so any writer for the project can void that project's aged, unrecorded seqs.
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

			// (a) The tombstone is already sealed: this is a repeat. The tombstone is sealed FIRST and the void marker
			// written SECOND, so a void interrupted between the two (a failed marker write, a crash) is finished here by
			// writing the marker — idempotent, and safe with no re-check: the sealed tombstone holds the grant_id as its
			// record_id, so the grant can never record (the UNIQUE record_id index), however late its commit is.
			if existing, ok, le := st.RecordByIdem(vr.ProjectID, idem); le != nil {
				fail(http.StatusInternalServerError, "tombstone lookup: %v", le)
				return
			} else if ok {
				if !res.Voided {
					if ve := st.VoidBrokerSeq(vr.ProjectID, res.GrantID, vr.BrokerSeq); ve != nil {
						fail(http.StatusInternalServerError, "broker_seq %d's grant_void tombstone is sealed but marking the reservation voided FAILED — repeat this call to finish (the tombstone already holds grant_id %s, so that grant can no longer record): %v", vr.BrokerSeq, res.GrantID, ve)
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
			// ...and mark the reservation voided SECOND (retiring the grant_id at allocation). A failure here leaves a
			// sealed tombstone without its marker, which step (a) of a repeat finishes.
			if !res.Voided {
				if ve := st.VoidBrokerSeq(vr.ProjectID, res.GrantID, vr.BrokerSeq); ve != nil {
					fail(http.StatusInternalServerError, "broker_seq %d's grant_void tombstone is sealed but marking the reservation voided FAILED — repeat this call to finish (the tombstone already holds grant_id %s, so that grant can no longer record): %v", vr.BrokerSeq, res.GrantID, ve)
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

// allocateBrokerSeq is the ONLY way a grant path allocates (or reuses) a broker_seq: it stamps the attempt BEFORE
// the store call (so even an allocation whose own outcome is ambiguous is covered) and delegates to the store.
func (s *Server) allocateBrokerSeq(projectID, grantID string) (int64, bool, error) {
	s.noteSeqAttempt(projectID, grantID)
	return s.st.AllocateBrokerSeq(projectID, grantID)
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
