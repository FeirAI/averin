package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/feirai/averin/server/internal/store"
)

// incrementalReadParams is the parsed form of GET /v2/records?project=&after=&order=asc[&limit=][&at_seq=].
type incrementalReadParams struct {
	after int64
	limit int
	atSeq int64
	hasAt bool
}

// parseIncrementalRead reports whether the query asks for the incremental read (any of after, order, at_seq is
// present) and, if so, validates it strictly: the incremental read is the API a consumer builds a frontier on, so
// a malformed or ambiguous request is a 400, never silently the newest-first list.
func parseIncrementalRead(q url.Values) (p incrementalReadParams, incremental bool, err error) {
	if !q.Has("after") && !q.Has("order") && !q.Has("at_seq") {
		return p, false, nil
	}
	if q.Get("order") != "asc" {
		return p, true, fmt.Errorf("the incremental read needs order=asc")
	}
	if !q.Has("after") {
		return p, true, fmt.Errorf("order=asc and at_seq need after (the record ordinal to read from; 0 reads from the first record)")
	}
	if q.Has("offset") {
		return p, true, fmt.Errorf("offset cannot be combined with after")
	}
	p.after, err = strconv.ParseInt(q.Get("after"), 10, 64)
	if err != nil || p.after < 0 {
		return p, true, fmt.Errorf("after must be a non-negative integer")
	}
	p.limit = 100
	if ls := q.Get("limit"); ls != "" {
		n, e := strconv.Atoi(ls)
		if e != nil || n < 1 {
			return p, true, fmt.Errorf("limit must be a positive integer")
		}
		p.limit = min(n, 1000)
	}
	if q.Has("at_seq") {
		p.atSeq, err = strconv.ParseInt(q.Get("at_seq"), 10, 64)
		if err != nil || p.atSeq < 0 {
			return p, true, fmt.Errorf("at_seq must be a non-negative integer")
		}
		p.hasAt = true
	}
	return p, true, nil
}

type readCheckpoint struct {
	Seq         int64  `json:"seq"`
	Hash        string `json:"hash"`
	RecordCount int64  `json:"record_count"`
}

func toReadCheckpoint(cp store.Checkpoint) (*readCheckpoint, error) {
	var b struct {
		RecordCount *int64 `json:"record_count"`
	}
	if err := json.Unmarshal([]byte(cp.JSON), &b); err != nil || b.RecordCount == nil || *b.RecordCount < 0 {
		// FAIL CLOSED: a checkpoint whose count cannot be read must not become a frontier.
		return nil, fmt.Errorf("checkpoint %d has no readable record_count", cp.Seq)
	}
	return &readCheckpoint{Seq: cp.Seq, Hash: cp.CheckpointHash, RecordCount: *b.RecordCount}, nil
}

// handleIncrementalRead serves the records after ordinal p.after oldest first, with the continuity snapshot a
// reader needs to bind a frontier to a signed checkpoint: the store total, the latest checkpoint and (when asked)
// the checkpoint at a given seq, all from one repeatable-read snapshot. It reads only the rows it returns plus two
// checkpoint rows, so its cost does not grow with history. It runs no verification and builds no bundle: what
// the reader holds afterwards is a read frontier bound to a signed checkpoint, not a verified one.
func (s *Server) handleIncrementalRead(w http.ResponseWriter, r *http.Request, projectID string, p incrementalReadParams) {
	var (
		total  int
		page   []store.Record
		latest *readCheckpoint
		at     *readCheckpoint
	)
	err := s.st.WithProjectRead(r.Context(), projectID, func(st store.Store) error {
		var e error
		if total, e = st.RecordCount(projectID); e != nil {
			return e
		}
		if page, e = st.RecordsAfter(projectID, p.after, p.limit); e != nil {
			return e
		}
		cp, ok, e := st.LatestCheckpoint(projectID)
		if e != nil {
			return e
		}
		if ok {
			if latest, e = toReadCheckpoint(cp); e != nil {
				return e
			}
		}
		if p.hasAt {
			cps, e := st.CheckpointsRange(projectID, p.atSeq, p.atSeq)
			if e != nil {
				return e
			}
			for _, c := range cps {
				if c.Seq == p.atSeq {
					if at, e = toReadCheckpoint(c); e != nil {
						return e
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		// FAIL CLOSED: a store error is a 500, never an empty page that reads as "nothing new".
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// FAIL CLOSED on an ordinal gap: next_after is positional (after + page length) while the store selects by
	// ordinal value and totals by the largest ordinal, so a gap (an owner-role delete, a hand-edited restore)
	// would repeat one record and hide another under a 200. The page must be exactly after+1..after+len, and
	// a page that stops short of the total must end at it. An empty page past the total is a reader that is
	// ahead of the store (a truncation it reads from total), not a gap.
	if err := ordinalGap(p.after, page, total, p.limit); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]json.RawMessage, len(page))
	for i, rec := range page {
		out[i] = json.RawMessage(rec.JSON)
	}
	next := p.after + int64(len(page))
	resp := map[string]any{
		"records":    out,
		"total":      total,
		"after":      p.after,
		"next_after": next,
		"more":       next < int64(total),
	}
	if latest != nil {
		resp["latest_checkpoint"] = latest
	}
	if at != nil {
		resp["at_seq"] = at
	}
	writeJSON(w, http.StatusOK, resp)
}

// ordinalGap returns nil when the page is exactly the ordinals after+1..after+len (the shared store check, the same
// one every paged fold uses) and, when the page is short (len < limit), when it also ends at the total: a short
// page is the last page, so it must reach the largest ordinal. A full page needs no end check, because the next
// page's own contiguity check starts from its end. An empty page at or past the total is a reader that is ahead of
// the store, not a gap; an empty page below the total is a missing ordinal.
func ordinalGap(after int64, page []store.Record, total, limit int) error {
	if err := store.CheckPageOrdinals(page, after); err != nil {
		return fmt.Errorf("record ordinal gap: %w", err)
	}
	if len(page) >= limit || (len(page) == 0 && after >= int64(total)) {
		return nil
	}
	if end := after + int64(len(page)); end != int64(total) {
		return fmt.Errorf("record ordinal gap: the page ends at ordinal %d but the store holds %d records (a record is missing)", end, total)
	}
	return nil
}
