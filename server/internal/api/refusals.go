package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// Gateway refusal records (feir-ops#1). POST /v2/refusals seals one `record_kind = gateway-refusal` record
// for an attempt the gateway refused. It copies the B11 denied-grant pattern: the SERVER builds the record
// from a closed set of fields (so a caller cannot choose a record id, a free-text reason, params or a URL),
// seals it, and chains it into the caller's session. The generic ingest path rejects every refusal marker
// (validateGenericRecordItem), because a server-signed record cannot be told apart from a generic one by its
// signature: reserving the markers at ingest is the only defence against forged refusals.

// refusalIdemPrefix namespaces the stored idempotency key of a refusal record. Like denialIdemPrefix it is
// reserved at every other entry point, so no caller can pre-seed a key the refusal endpoint will later use.
const refusalIdemPrefix = "refusal:"

// refusalRecordIDPrefix is the reserved record_id namespace of refusal records.
const refusalRecordIDPrefix = "refusal-"

// refusalClockSkew bounds how far in the future last_at may be.
const refusalClockSkew = 5 * time.Minute

// maxRefusalAttempts bounds attempts and each by_class count (mirrors core/src/refusal.rs MAX_ATTEMPTS).
const maxRefusalAttempts = 1_000_000_000

// refusalReasonClasses and refusalEntryPoints are the closed vocabularies. They mirror core/src/refusal.rs and
// vectors/refusal-classes.v1.json; refusals_vocab_test.go pins the three together.
var refusalReasonClasses = []string{
	"not_granted", "policy_deny", "kill_fence", "rate_limit", "spend_cap", "cross_tenant", "token_unusable",
	"llm_channel_only", "model_unpriced", "modifier_unpriced", "provider_disabled", "capability_undeclared",
	"approval_unavailable", "decision_unavailable",
}
var refusalEntryPoints = []string{"mcp", "execute", "llm", "approval_resume"}

func inSet(set []string, v string) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

// refusalName admits only a short plain identifier. Agent-supplied names (an unknown tool, an unresolved
// credential) reach the signed record only through this filter; anything else becomes invalidNameLiteral.
var refusalName = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

const invalidNameLiteral = "invalid_name"

// refusalRequest is the closed body of POST /v2/refusals. Unknown fields are a 400 (DisallowUnknownFields),
// so params, a URL or a free-text reason cannot be shipped.
type refusalRequest struct {
	ProjectID      string           `json:"project_id"`
	SessionID      string           `json:"session_id"`
	IdempotencyKey string           `json:"idempotency_key"`
	AgentID        string           `json:"agent_id"`
	Action         string           `json:"action"`
	EntryPoint     string           `json:"entry_point"`
	ReasonClass    string           `json:"reason_class"`
	Credential     string           `json:"credential"`
	Attempts       int64            `json:"attempts"`
	FirstAt        string           `json:"first_at"`
	LastAt         string           `json:"last_at"`
	Summary        bool             `json:"summary"`
	ByClass        map[string]int64 `json:"by_class"`
}

func decodeRefusalRequest(body []byte) (refusalRequest, error) {
	var rr refusalRequest
	if err := rejectUnpairedSurrogates(body); err != nil {
		return rr, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rr); err != nil {
		return rr, err
	}
	if dec.More() {
		return rr, errors.New("trailing data after the refusal body")
	}
	return rr, nil
}

func parseRefusalTime(field, v string, now time.Time) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be an RFC3339 timestamp", field)
	}
	return t.UTC(), nil
}

// validateRefusal checks the closed vocabularies and bounds and returns the normalized request.
func validateRefusal(rr *refusalRequest, now time.Time) error {
	if !refusalName.MatchString(rr.AgentID) {
		return errors.New("agent_id must match [A-Za-z0-9._:-]{1,128}")
	}
	if rr.EntryPoint != "" && !inSet(refusalEntryPoints, rr.EntryPoint) {
		return errors.New("entry_point is outside the closed set")
	}
	if rr.Attempts < 1 || rr.Attempts > maxRefusalAttempts {
		return errors.New("attempts must be an integer in 1..1000000000")
	}
	first, err := parseRefusalTime("first_at", rr.FirstAt, now)
	if err != nil {
		return err
	}
	last, err := parseRefusalTime("last_at", rr.LastAt, now)
	if err != nil {
		return err
	}
	if first.After(last) {
		return errors.New("first_at must not be after last_at")
	}
	if last.After(now.Add(refusalClockSkew)) {
		return errors.New("last_at is in the future beyond the allowed clock skew")
	}
	rr.FirstAt, rr.LastAt = ts(first), ts(last)
	if rr.Credential != "" && !refusalName.MatchString(rr.Credential) {
		rr.Credential = invalidNameLiteral
	}
	if rr.Summary {
		if rr.ReasonClass != "" {
			return errors.New("a summary refusal carries by_class, not reason_class")
		}
		if len(rr.ByClass) == 0 {
			return errors.New("a summary refusal requires by_class")
		}
		var sum int64
		for c, n := range rr.ByClass {
			if !inSet(refusalReasonClasses, c) {
				return fmt.Errorf("by_class names a class outside the closed set: %q", c)
			}
			if n < 1 || n > maxRefusalAttempts {
				return errors.New("by_class counts must be integers in 1..1000000000")
			}
			sum += n
		}
		if sum != rr.Attempts {
			return errors.New("attempts must equal the sum of by_class")
		}
		if rr.Action != "*" && !refusalName.MatchString(rr.Action) {
			rr.Action = invalidNameLiteral
		}
		return nil
	}
	if rr.ByClass != nil {
		return errors.New("by_class is only valid on a summary refusal")
	}
	if rr.EntryPoint == "" {
		return errors.New("entry_point is required")
	}
	if !inSet(refusalReasonClasses, rr.ReasonClass) {
		return errors.New("reason_class is outside the closed set")
	}
	if rr.Action == "" {
		return errors.New("action is required")
	}
	if !refusalName.MatchString(rr.Action) {
		rr.Action = invalidNameLiteral
	}
	return nil
}

func (s *Server) refusalSalt() (string, error) {
	s.refusalSaltOnce.Do(func() {
		s.refusalSaltVal, s.refusalSaltErr = s.core.RandomNonce()
	})
	return s.refusalSaltVal, s.refusalSaltErr
}

// handleRefusals seals one gateway refusal record. Role write (auth_roles.go).
func (s *Server) handleRefusals(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rr, err := decodeRefusalRequest(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid refusal request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && rr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if rr.ProjectID == "" || rr.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	idem := rr.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header)")
		return
	}
	if err := s.rejectOpaqueIdentity("project_id", rr.ProjectID, "session_id", rr.SessionID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRefusal(&rr, s.now()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	salt, err := s.refusalSalt()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "refusal salt unavailable")
		return
	}
	// The record id is salted with a server secret so a caller can neither precompute nor squat it.
	storedIdem := refusalIdemPrefix + idem
	recordID := refusalRecordIDPrefix + uuidV5Shaped("averin.refusal.id.v1", rr.ProjectID, salt+"\x00"+idem)

	g := map[string]any{
		"v": 1, "attempts": rr.Attempts, "first_at": rr.FirstAt, "last_at": rr.LastAt,
	}
	if rr.EntryPoint != "" {
		g["entry_point"] = rr.EntryPoint
	}
	if rr.Credential != "" {
		g["credential"] = rr.Credential
	}
	if rr.Summary {
		g["summary"] = true
		bc := make(map[string]any, len(rr.ByClass))
		keys := make([]string, 0, len(rr.ByClass))
		for c := range rr.ByClass {
			keys = append(keys, c)
		}
		sort.Strings(keys)
		for _, c := range keys {
			bc[c] = rr.ByClass[c]
		}
		g["by_class"] = bc
	} else {
		g["reason_class"] = rr.ReasonClass
	}
	rec := map[string]any{
		"record_id":     recordID,
		"project_id":    rr.ProjectID,
		"session_id":    rr.SessionID,
		"agent_id":      rr.AgentID,
		"agent_version": "vultrino-gateway",
		"event_type":    "gateway_refusal",
		"record_kind":   "gateway-refusal",
		"observed_via":  "gateway",
		"status":        "refused",
		"action":        rr.Action,
		// NO authority block and NO extensions.broker: a refusal is integrity-only evidence. It is never a
		// grant or a use, so it cannot enter the coverage closure, the D7 resource set or the taxonomy.
		"extensions": map[string]any{"gateway_refusal": g},
	}
	var existingID string
	var created bool
	err = s.withProjectWrite(r.Context(), rr.ProjectID, func(st store.Store) error {
		if stored, found, e := st.RecordByIdem(rr.ProjectID, storedIdem); e != nil {
			return e
		} else if found {
			var ex struct {
				RecordID  string `json:"record_id"`
				EventType string `json:"event_type"`
			}
			_ = json.Unmarshal([]byte(stored.JSON), &ex)
			existingID = ex.RecordID
			return nil
		}
		stored, fresh, e := s.sealAndStore(st, rr.ProjectID, rr.SessionID, storedIdem, rec, nil)
		if e != nil {
			return e
		}
		created = fresh
		var ex struct {
			RecordID string `json:"record_id"`
		}
		_ = json.Unmarshal([]byte(stored), &ex)
		existingID = ex.RecordID
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "seal refusal: "+err.Error())
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"record_id": existingID, "created": created})
}
