package api

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
)

// quota.go (AVE-07): a per-project cap on stored records. The count is read and enforced inside the
// project write transaction (countedStore.PutRecord), so concurrent writers on one project, even on
// several replicas, are serialized by the project guard and the cap is exact: a transaction that would
// take the project past the cap is rolled back whole. A batch POST /v2/records is processed item by item
// (each item is its own transaction), so the items that fit before the cap stay stored and the first item
// past it is refused with 507. An idempotent replay creates nothing and is never refused.
//
// Handlers map unknown store errors to different statuses (some 400, some 500), so the refusal is made
// uniform here: the request context carries a mark, the transaction sets it when the cap is hit, and the
// response writer turns whatever status the handler chose into 507 with a fixed body.

// errProjectQuota is returned by the transaction that would exceed the cap.
var errProjectQuota = errors.New("project record quota exceeded")

type quotaMark struct{ hitFlag atomic.Bool }

func (m *quotaMark) hit() {
	if m != nil {
		m.hitFlag.Store(true)
	}
}

type quotaCtxKey struct{}

func quotaMarkFrom(ctx context.Context) *quotaMark {
	m, _ := ctx.Value(quotaCtxKey{}).(*quotaMark)
	return m
}

// WithProjectQuota caps the number of records stored per project. n <= 0 means unlimited (the default).
// A write that would pass the cap is refused with 507 and nothing from it is stored. The cap counts
// stored records of every kind (evidence, grants, receipts, denials), not bytes: the storage bound is the
// cap times the per-record body limit.
func (s *Server) WithProjectQuota(n int) *Server {
	if n < 0 {
		n = 0
	}
	s.projectQuota = n
	if n > 0 && s.mQuotaRejected == nil {
		s.mQuotaRejected = s.metrics.Counter("averin_quota_rejections_total",
			"Total write requests refused with 507 because the project record quota was reached.")
	}
	return s
}

// quotaGuard wraps the write routes so a quota refusal is always answered 507.
func (s *Server) quotaGuard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			h.ServeHTTP(w, r)
			return
		}
		mark := &quotaMark{}
		qw := &quotaWriter{ResponseWriter: w, mark: mark, rejected: s.mQuotaRejected}
		h.ServeHTTP(qw, r.WithContext(context.WithValue(r.Context(), quotaCtxKey{}, mark)))
	})
}

type quotaWriter struct {
	http.ResponseWriter
	mark        *quotaMark
	rejected    interface{ Inc() }
	wroteHeader bool
	swallow     bool
}

func (q *quotaWriter) WriteHeader(code int) {
	if q.wroteHeader {
		return
	}
	q.wroteHeader = true
	if q.mark.hitFlag.Load() {
		q.swallow = true
		if q.rejected != nil {
			q.rejected.Inc()
		}
		q.ResponseWriter.Header().Set("Content-Type", "application/json")
		q.ResponseWriter.Header().Del("Content-Length")
		q.ResponseWriter.WriteHeader(http.StatusInsufficientStorage)
		q.ResponseWriter.Write([]byte(`{"error":"project record quota exceeded"}` + "\n"))
		return
	}
	q.ResponseWriter.WriteHeader(code)
}

func (q *quotaWriter) Write(b []byte) (int, error) {
	if !q.wroteHeader {
		q.WriteHeader(http.StatusOK)
	}
	if q.swallow {
		return len(b), nil
	}
	return q.ResponseWriter.Write(b)
}

func (q *quotaWriter) Unwrap() http.ResponseWriter { return q.ResponseWriter }
