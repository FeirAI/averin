package store

import (
	"errors"

	"github.com/feirai/averin/server/internal/resourceshim"
)

func (m *Mem) ledgerProject() (*project, error) {
	if err := m.checkProject(m.boundProject); err != nil {
		return nil, err
	}
	if !m.inTx || m.readOnly {
		return nil, errors.New("store: ledger claim requires project write transaction")
	}
	return m.proj(m.boundProject), nil
}

func (m *Mem) ConsumeNonce(nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.ledgerProject()
	if err != nil {
		return err
	}
	if _, exists := p.nonces[nonce]; exists {
		return resourceshim.ErrConsumed
	}
	p.nonces[nonce] = struct{}{}
	return nil
}

func (m *Mem) ConsumeJTI(jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.ledgerProject()
	if err != nil {
		return err
	}
	if _, exists := p.consumedJTI[jti]; exists {
		return resourceshim.ErrConsumed
	}
	p.consumedJTI[jti] = struct{}{}
	return nil
}

func (m *Mem) ReleaseNonce(nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, err := m.ledgerProject(); err == nil {
		delete(p.nonces, nonce)
	}
}

func (m *Mem) ReleaseJTI(jti string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, err := m.ledgerProject(); err == nil {
		delete(p.consumedJTI, jti)
	}
}
