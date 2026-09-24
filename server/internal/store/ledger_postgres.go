package store

import (
	"errors"
	"fmt"

	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/jackc/pgx/v5"
)

func (p *Postgres) ledgerWrite() error {
	if err := p.checkProject(p.projectID); err != nil {
		return err
	}
	if p.tx == nil {
		return errors.New("store: ledger claim requires project write transaction")
	}
	return nil
}

func (p *Postgres) ConsumeNonce(c resourceshim.NonceClaim) error {
	if err := p.ledgerWrite(); err != nil {
		return err
	}
	if err := p.checkProject(c.ProjectID); err != nil {
		return err
	}
	if c.ResourceID == "" || c.Nonce == "" || c.OwnerID() == "" {
		return errors.New("store: incomplete nonce claim")
	}
	// Legacy rows have unknown project ownership. Until the DB-time exclusion
	// boundary, conservatively reject every matching nonce in all projects.
	// The exclusion cannot change after v6; this check and insert use the same
	// transaction as JTI and the signed receipt.
	var claimed bool
	err := p.tx.QueryRow(p.callContext(), `
		INSERT INTO consumed_nonces(project_id, resource_id, nonce, owner_id)
		SELECT $1,$2,$3,$4 FROM nonce_ledger_cutover c
		WHERE c.singleton AND c.legacy_exclusion_until > c.cutover_at AND NOT EXISTS (
			SELECT 1 FROM legacy_consume_exclusions l
			WHERE l.kind='nonce' AND l.consume_key=$3 AND statement_timestamp()<c.legacy_exclusion_until
		)
		ON CONFLICT DO NOTHING RETURNING true`, c.ProjectID, c.ResourceID, c.Nonce, c.OwnerID()).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceshim.ErrConsumed
	}
	if err != nil {
		return fmt.Errorf("store: consume nonce: %w", err)
	}
	if p.claims == nil {
		p.claims = make(map[ledgerKey]string)
	}
	p.claims[ledgerKey{kind: "nonce", project: c.ProjectID, resource: c.ResourceID, value: c.Nonce}] = c.OwnerID()
	return nil
}

func (p *Postgres) ConsumeJTI(c resourceshim.JTIClaim) error {
	if err := p.ledgerWrite(); err != nil {
		return err
	}
	if c.Key == "" || c.OwnerID() == "" {
		return errors.New("store: incomplete JTI claim")
	}
	var claimed bool
	err := p.tx.QueryRow(p.callContext(), `
		INSERT INTO consumed_jtis(consume_key, owner_id)
		SELECT $1,$2 FROM nonce_ledger_cutover c
		WHERE c.singleton AND c.legacy_exclusion_until > c.cutover_at AND NOT EXISTS (
			SELECT 1 FROM legacy_consume_exclusions l
			WHERE l.kind='jti' AND l.consume_key=$1 AND statement_timestamp()<c.legacy_exclusion_until
		)
		ON CONFLICT DO NOTHING RETURNING true`, c.Key, c.OwnerID()).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceshim.ErrConsumed
	}
	if err != nil {
		return fmt.Errorf("store: consume JTI: %w", err)
	}
	if p.claims == nil {
		p.claims = make(map[ledgerKey]string)
	}
	p.claims[ledgerKey{kind: "jti", value: c.Key}] = c.OwnerID()
	return nil
}

func (p *Postgres) ReleaseNonce(c resourceshim.NonceClaim) {
	key := ledgerKey{kind: "nonce", project: c.ProjectID, resource: c.ResourceID, value: c.Nonce}
	if p.ledgerWrite() != nil || p.checkProject(c.ProjectID) != nil || c.OwnerID() == "" || p.claims[key] != c.OwnerID() {
		return
	}
	if _, err := p.tx.Exec(p.callContext(), `DELETE FROM consumed_nonces
		WHERE project_id=$1 AND resource_id=$2 AND nonce=$3 AND owner_id=$4`, c.ProjectID, c.ResourceID, c.Nonce, c.OwnerID()); err == nil {
		delete(p.claims, key)
	}
}

func (p *Postgres) ReleaseJTI(c resourceshim.JTIClaim) {
	key := ledgerKey{kind: "jti", value: c.Key}
	if p.ledgerWrite() != nil || c.OwnerID() == "" || p.claims[key] != c.OwnerID() {
		return
	}
	if _, err := p.tx.Exec(p.callContext(), `DELETE FROM consumed_jtis WHERE consume_key=$1 AND owner_id=$2`, c.Key, c.OwnerID()); err == nil {
		delete(p.claims, key)
	}
}
