// Package meter is usage metering — the real Phase-1 revenue path (Stripe usage-based: per record
// beyond a free tier + per export). The integrity guarantees never depend on metering; this only
// counts and (optionally) reports to Stripe.
package meter

import "sync"

type Usage struct {
	Records int64 `json:"records"`
	Exports int64 `json:"exports"`
}

// Meter counts billable events per project.
type Meter interface {
	RecordsIngested(project string, n int)
	ExportIssued(project string)
	Usage(project string) Usage
}

// Mem is an in-memory meter (single node / tests).
type Mem struct {
	mu sync.Mutex
	m  map[string]*Usage
}

func NewMem() *Mem { return &Mem{m: map[string]*Usage{}} }

func (mt *Mem) get(p string) *Usage {
	u := mt.m[p]
	if u == nil {
		u = &Usage{}
		mt.m[p] = u
	}
	return u
}

func (mt *Mem) RecordsIngested(project string, n int) {
	if n <= 0 {
		return
	}
	mt.mu.Lock()
	mt.get(project).Records += int64(n)
	mt.mu.Unlock()
}

func (mt *Mem) ExportIssued(project string) {
	mt.mu.Lock()
	mt.get(project).Exports++
	mt.mu.Unlock()
}

func (mt *Mem) Usage(project string) Usage {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return *mt.get(project)
}

// FreeTierRecords is the number of sealed records included before per-record billing starts.
const FreeTierRecords = 1000

// Billable returns the number of records and exports that are chargeable (records above the free
// tier; every export). Pricing itself lives in Stripe.
func Billable(u Usage) (records, exports int64) {
	r := u.Records - FreeTierRecords
	if r < 0 {
		r = 0
	}
	return r, u.Exports
}
