package store

import (
	"errors"

	"github.com/feirai/averin/server/internal/resourceshim"
)

func (m *Mem) ledgerRoot() (*Mem, error) {
	if err := m.checkProject(m.boundProject); err != nil {
		return nil, err
	}
	if !m.inTx || m.readOnly || m.root == nil {
		return nil, errors.New("store: ledger claim requires project write transaction")
	}
	return m.root, nil
}

func (m *Mem) consume(kind, key string) error {
	root, err := m.ledgerRoot()
	if err != nil {
		return err
	}
	claim := kind + "\x00" + key
	root.ledgerMu.Lock()
	defer root.ledgerMu.Unlock()
	if root.ledgerClaims == nil {
		root.ledgerClaims = make(map[string]*Mem)
	}
	if _, exists := root.ledgerClaims[claim]; exists {
		return resourceshim.ErrConsumed
	}
	root.ledgerClaims[claim] = m
	m.claimed = append(m.claimed, claim)
	return nil
}

func (m *Mem) ConsumeNonce(nonce string) error { return m.consume("nonce", nonce) }
func (m *Mem) ConsumeJTI(jti string) error     { return m.consume("jti", jti) }

func (m *Mem) release(kind, key string) {
	root, err := m.ledgerRoot()
	if err != nil {
		return
	}
	claim := kind + "\x00" + key
	root.ledgerMu.Lock()
	defer root.ledgerMu.Unlock()
	if owner, ok := root.ledgerClaims[claim]; ok && owner == m {
		delete(root.ledgerClaims, claim)
	}
}

func (m *Mem) ReleaseNonce(nonce string) { m.release("nonce", nonce) }
func (m *Mem) ReleaseJTI(jti string)     { m.release("jti", jti) }
