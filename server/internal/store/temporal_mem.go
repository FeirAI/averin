package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Plan 009 in-memory implementation. The project write lock serializes the authorization
// order exactly as the Postgres guard row does.

func revEventKey(grantID, mode string) string { return grantID + "\x00" + mode }

func (m *Mem) IsRevoked(projectID, grantID string) (bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	_, total := p.revEvents[revEventKey(grantID, RevocationTotal)]
	_, prospective := p.revEvents[revEventKey(grantID, RevocationProspective)]
	_, void := p.voided[grantID]
	if total || prospective || void {
		return true, nil
	}
	// A tombstone can commit while the marker write fails. The signed record
	// already retires the grant ID, including when revocation is disabled.
	for _, rec := range p.records {
		if recordIDOf(rec.JSON) != grantID {
			continue
		}
		var shape struct {
			Extensions struct {
				Broker struct {
					Kind string `json:"kind"`
				} `json:"broker"`
			} `json:"extensions"`
		}
		if json.Unmarshal([]byte(rec.JSON), &shape) == nil && shape.Extensions.Broker.Kind == "grant_void" {
			return true, nil
		}
	}
	return false, nil
}

func (m *Mem) RevokeGrant(projectID, grantID string) (bool, error) {
	_, created, err := m.PutRevocationEvent(RevocationEvent{
		ProjectID: projectID, GrantID: grantID, Mode: RevocationTotal, Issuer: "averin", Reason: "total",
	})
	return created, err
}

func (m *Mem) RevokedGrantIDs(projectID string) ([]string, error) {
	if err := m.checkProject(projectID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]struct{}{}
	for _, ev := range m.proj(projectID).revEvents {
		seen[ev.GrantID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func validateRevocationEvent(ev RevocationEvent) error {
	if ev.ProjectID == "" || ev.GrantID == "" || ev.Issuer == "" {
		return errors.New("store: revocation event requires project, grant and issuer")
	}
	switch ev.Mode {
	case RevocationTotal:
		if ev.CutoffOrder != 0 {
			return errors.New("store: a total revocation has no cutoff")
		}
	case RevocationProspective:
		if ev.CutoffOrder < 0 {
			return errors.New("store: negative revocation cutoff")
		}
	default:
		return fmt.Errorf("store: unknown revocation mode %q", ev.Mode)
	}
	return nil
}

func (m *Mem) PutRevocationEvent(ev RevocationEvent) (RevocationEvent, bool, error) {
	if err := validateRevocationEvent(ev); err != nil {
		return RevocationEvent{}, false, err
	}
	unlock, err := m.mutation(ev.ProjectID)
	if err != nil {
		return RevocationEvent{}, false, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(ev.ProjectID)
	key := revEventKey(ev.GrantID, ev.Mode)
	if prior, ok := p.revEvents[key]; ok {
		return prior, false, nil
	}
	if ev.Mode == RevocationProspective && ev.CutoffOrder == 0 {
		p.authOrder++
		ev.CutoffOrder = p.authOrder
	}
	if ev.Mode == RevocationProspective && ev.CutoffOrder > p.authOrder {
		return RevocationEvent{}, false, errors.New("store: prospective cutoff beyond the allocated authorization order")
	}
	ev.Created = m.now()
	p.revEvents[key] = ev
	return ev, true, nil
}

func (m *Mem) RevocationEvents(projectID string) ([]RevocationEvent, error) {
	if err := m.checkProject(projectID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RevocationEvent, 0, len(m.proj(projectID).revEvents))
	for _, ev := range m.proj(projectID).revEvents {
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GrantID != out[j].GrantID {
			return out[i].GrantID < out[j].GrantID
		}
		return out[i].Mode < out[j].Mode
	})
	return out, nil
}

func (m *Mem) AllocateAuthorizationOrder(projectID string) (int64, error) {
	unlock, err := m.mutation(projectID)
	if err != nil {
		return 0, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	p.authOrder++
	return p.authOrder, nil
}

func (m *Mem) PutAuthorizationReceipt(projectID string, r AuthorizationReceipt) error {
	unlock, err := m.mutation(projectID)
	if err != nil {
		return err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if r.Ordinal < 1 || r.Ordinal > p.authOrder || r.RecordID == "" || r.GrantID == "" {
		return fmt.Errorf("store: invalid authorization receipt %+v", r)
	}
	if _, ok := p.receipts[r.Ordinal]; ok {
		return ErrAuthorizationOrderConflict
	}
	if _, ok := p.receiptByRecord[r.RecordID]; ok {
		return ErrAuthorizationOrderConflict
	}
	p.receipts[r.Ordinal] = r
	p.receiptByRecord[r.RecordID] = r.Ordinal
	return nil
}

func (m *Mem) SnapshotBoundary(projectID string) (time.Time, int64, error) {
	if err := m.checkProject(projectID); err != nil {
		return time.Time{}, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	at := m.snapshotAt
	if at.IsZero() {
		at = m.now()
	}
	return at.UTC(), m.proj(projectID).authOrder, nil
}
