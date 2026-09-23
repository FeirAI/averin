package store

import (
	"sort"
	"time"
)

func (m *Mem) PendingGrant(projectID, idemKey string) (PendingGrant, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return PendingGrant{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.proj(projectID).pending[idemKey]
	row.Payload = append([]byte(nil), row.Payload...)
	return row, ok, nil
}

func (m *Mem) PutPendingGrant(projectID, idemKey string, row PendingGrant) (PendingGrant, bool, error) {
	unlock, err := m.mutation(projectID)
	if err != nil {
		return PendingGrant{}, false, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if prior, ok := p.pending[idemKey]; ok {
		prior.Payload = append([]byte(nil), prior.Payload...)
		return prior, false, nil
	}
	row.Payload = append([]byte(nil), row.Payload...)
	p.pending[idemKey] = row
	return row, true, nil
}

func (m *Mem) DeletePendingGrant(projectID, idemKey string) error {
	unlock, err := m.mutation(projectID)
	if err != nil {
		return err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.proj(projectID).pending, idemKey)
	return nil
}

func (m *Mem) PendingGrantLive(projectID, grantID string, now time.Time, ttl time.Duration) (bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.proj(projectID).pending {
		if row.GrantID == grantID && now.Sub(row.Created) <= ttl {
			return true, nil
		}
	}
	return false, nil
}

func (m *Mem) IsRevoked(projectID, grantID string) (bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	_, rev := p.revoked[grantID]
	_, void := p.voided[grantID]
	return rev || void, nil
}

func (m *Mem) RevokeGrant(projectID, grantID string) (bool, error) {
	unlock, err := m.mutation(projectID)
	if err != nil {
		return false, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if _, ok := p.revoked[grantID]; ok {
		return false, nil
	}
	p.revoked[grantID] = struct{}{}
	return true, nil
}

func (m *Mem) RevokedGrantIDs(projectID string) ([]string, error) {
	if err := m.checkProject(projectID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.proj(projectID).revoked))
	for id := range m.proj(projectID).revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
