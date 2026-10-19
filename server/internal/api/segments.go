package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"

	"github.com/feirai/averin/server/internal/store"
)

// AVE-01: month segments. A project's history is served as one bundle per month, each chained to the previous
// month's last checkpoint, so no single export has to hold all history. The format and the verifier's rules
// are documented in core/src/segment.rs and docs/dev/SEGMENTS.md.

// segmentFormat names the `segment` block (core verify.rs SEGMENT_FORMAT).
const segmentFormat = "averin.segment.v1"

// maxSingleBundleBytes (a var only so a test can lower it) mirrors core MAX_BUNDLE_BYTES (core/src/verify.rs): the verifier refuses any bundle
// above it. The server refuses to build one rather than hand out a file nobody can verify.
var maxSingleBundleBytes = 256 << 20

var monthRE = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)

var (
	errBadMonth     = errors.New("month must be YYYY-MM")
	errNoSuchMonth  = errors.New("no checkpoint was created in that month")
	errBundleTooBig = errors.New("the project's whole history exceeds the single-bundle limit; export it month by month")
	errMonthTooBig  = errors.New("this month's records alone exceed the single-bundle limit, so no verifier would accept it")
)

// segmentPlan is one month cut out of the checkpoint chain: the checkpoints created in the month, the
// checkpoint before them (the base, nil for the first month) and the half-open record range they commit.
type segmentPlan struct {
	Month string
	Base  *store.Checkpoint
	Own   []store.Checkpoint
	// Records [From, To) in insertion order: the base checkpoint's record_count up to the last own checkpoint's.
	From, To int64
}

type cpMeta struct {
	Seq         int64  `json:"checkpoint_seq"`
	CreatedTS   string `json:"created_ts"`
	RecordCount int64  `json:"record_count"`
}

func parseCpMeta(c store.Checkpoint) (cpMeta, error) {
	var m cpMeta
	if err := json.Unmarshal([]byte(c.JSON), &m); err != nil {
		return m, fmt.Errorf("parse checkpoint %d: %w", c.Seq, err)
	}
	if len(m.CreatedTS) < 7 {
		return m, fmt.Errorf("checkpoint %d has no created_ts", c.Seq)
	}
	return m, nil
}

// planSegments groups the checkpoint chain by the UTC month of created_ts, oldest first. Months must not go
// backwards with the sequence (a clock set back would make a month label name two ranges); that is refused.
func planSegments(checks []store.Checkpoint) ([]segmentPlan, error) {
	sorted := append([]store.Checkpoint(nil), checks...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })
	var plans []segmentPlan
	var prev *store.Checkpoint
	var prevMeta cpMeta
	for i := range sorted {
		c := sorted[i]
		m, err := parseCpMeta(c)
		if err != nil {
			return nil, err
		}
		month := m.CreatedTS[:7]
		if n := len(plans); n > 0 && plans[n-1].Month > month {
			return nil, fmt.Errorf("checkpoint %d is dated %s after a checkpoint dated %s: cannot cut month segments", c.Seq, month, plans[n-1].Month)
		}
		if n := len(plans); n == 0 || plans[n-1].Month != month {
			p := segmentPlan{Month: month, Base: prev, From: 0}
			if prev != nil {
				p.From = prevMeta.RecordCount
			}
			plans = append(plans, p)
		}
		p := &plans[len(plans)-1]
		p.Own = append(p.Own, c)
		p.To = m.RecordCount
		cc := c
		prev, prevMeta = &cc, m
	}
	return plans, nil
}

func findSegment(plans []segmentPlan, month string) (segmentPlan, error) {
	if !monthRE.MatchString(month) {
		return segmentPlan{}, errBadMonth
	}
	for _, p := range plans {
		if p.Month == month {
			return p, nil
		}
	}
	return segmentPlan{}, errNoSuchMonth
}

// segmentBlock is the bundle's `segment` object for p.
func segmentBlock(p segmentPlan) map[string]any {
	b := map[string]any{"format": segmentFormat, "month": p.Month, "base_seq": nil, "base_checkpoint_hash": nil, "base_record_count": int64(0)}
	if p.Base != nil {
		b["base_seq"] = p.Base.Seq
		b["base_checkpoint_hash"] = p.Base.CheckpointHash
		b["base_record_count"] = p.From
	}
	return b
}

// segmentRecords reads the plan's record range inside the caller's snapshot, oldest first, by insertion
// ordinal: the n records after ordinal From, one index range read whose cost is the month's size and does not
// depend on how much history lies after it.
func segmentRecords(st store.Store, projectID string, p segmentPlan) ([]store.Record, error) {
	n := int(p.To - p.From)
	if n < 0 {
		return nil, fmt.Errorf("segment %s: checkpoint record counts run backwards (%d to %d)", p.Month, p.From, p.To)
	}
	page, err := st.RecordsAfter(projectID, p.From, n)
	if err != nil {
		return nil, err
	}
	if len(page) != n {
		return nil, fmt.Errorf("segment %s: expected %d records, store returned %d", p.Month, n, len(page))
	}
	// A deleted record inside the range would pull in the next one: the month must be exactly ordinals From+1..To.
	if err := store.CheckPageOrdinals(page, p.From); err != nil {
		return nil, fmt.Errorf("segment %s: %w", p.Month, err)
	}
	return page, nil
}

// handleSegments lists the project's month segments (GET /v2/segments?project=): what to pass as `month` to
// /v2/export and /v2/verify, with the record range and chain position of each. It reads checkpoints only.
func (s *Server) handleSegments(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	var checks []store.Checkpoint
	if err := s.st.WithProjectRead(r.Context(), projectID, func(st store.Store) error {
		var err error
		checks, err = st.Checkpoints(projectID)
		return err
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	plans, err := planSegments(checks)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		e := map[string]any{
			"month":          p.Month,
			"records":        p.To - p.From,
			"first_seq":      p.Own[0].Seq,
			"last_seq":       p.Own[len(p.Own)-1].Seq,
			"head_hash":      p.Own[len(p.Own)-1].CheckpointHash,
			"base_seq":       nil,
			"base_hash":      nil,
			"records_before": p.From,
		}
		if p.Base != nil {
			e["base_seq"] = p.Base.Seq
			e["base_hash"] = p.Base.CheckpointHash
		}
		out = append(out, e)
	}
	body, _ := json.Marshal(map[string]any{"project_id": projectID, "format": segmentFormat, "segments": out})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// writeBundleErr maps the bundle builders' sentinel errors to a client status.
func writeBundleErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBadMonth):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errNoSuchMonth):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errMonthTooBig):
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
	case errors.Is(err, errBundleTooBig):
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error()+" (GET /v2/segments lists the months; GET /v2/export?month=YYYY-MM)")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}
