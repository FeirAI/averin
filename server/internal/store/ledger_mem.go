package store

import (
	"errors"

	"github.com/feirai/averin/server/internal/resourceshim"
)

type memClaimOwner struct {
	tx    *Mem
	owner string
}

type ledgerKey struct{ kind, project, resource, value string }

func (m *Mem) ledgerRoot() (*Mem, error) {
	if err := m.checkProject(m.boundProject); err != nil {
		return nil, err
	}
	if !m.inTx || m.readOnly || m.root == nil {
		return nil, errors.New("store: ledger claim requires project write transaction")
	}
	return m.root, nil
}

func (m *Mem) consume(key ledgerKey, owner string) error {
	root, err := m.ledgerRoot()
	if err != nil {
		return err
	}
	if key.value == "" || owner == "" {
		return errors.New("store: incomplete ledger claim")
	}
	root.ledgerMu.Lock()
	defer root.ledgerMu.Unlock()
	if root.ledgerClaims == nil {
		root.ledgerClaims = make(map[ledgerKey]memClaimOwner)
	}
	if _, exists := root.ledgerClaims[key]; exists {
		return resourceshim.ErrConsumed
	}
	root.ledgerClaims[key] = memClaimOwner{tx: m, owner: owner}
	m.claimed = append(m.claimed, key)
	return nil
}

func (m *Mem) ConsumeNonce(c resourceshim.NonceClaim) error {
	if err := m.checkProject(c.ProjectID); err != nil {
		return err
	}
	if c.ResourceID == "" || c.Nonce == "" {
		return errors.New("store: incomplete nonce scope")
	}
	return m.consume(ledgerKey{kind: "nonce", project: c.ProjectID, resource: c.ResourceID, value: c.Nonce}, c.OwnerID())
}

func (m *Mem) ConsumeJTI(c resourceshim.JTIClaim) error {
	return m.consume(ledgerKey{kind: "jti", value: c.Key}, c.OwnerID())
}

func (m *Mem) release(key ledgerKey, owner string) {
	root, err := m.ledgerRoot()
	if err != nil || owner == "" {
		return
	}
	root.ledgerMu.Lock()
	defer root.ledgerMu.Unlock()
	if held, ok := root.ledgerClaims[key]; ok && held.tx == m && held.owner == owner {
		delete(root.ledgerClaims, key)
	}
}

func (m *Mem) ReleaseNonce(c resourceshim.NonceClaim) {
	if m.checkProject(c.ProjectID) == nil {
		m.release(ledgerKey{kind: "nonce", project: c.ProjectID, resource: c.ResourceID, value: c.Nonce}, c.OwnerID())
	}
}

func (m *Mem) ReleaseJTI(c resourceshim.JTIClaim) {
	m.release(ledgerKey{kind: "jti", value: c.Key}, c.OwnerID())
}
