package store

import (
	"errors"
	"fmt"

	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/jackc/pgx/v5"
)

func (p *Postgres) consume(kind, key string) error {
	if err := p.checkProject(p.projectID); err != nil {
		return err
	}
	if p.tx == nil {
		return errors.New("store: ledger claim requires project write transaction")
	}
	var claimed bool
	err := p.tx.QueryRow(p.callContext(), `INSERT INTO consume_ledger(kind,consume_key) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING true`, kind, key).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceshim.ErrConsumed
	}
	if err != nil {
		return fmt.Errorf("store: consume %s: %w", kind, err)
	}
	return nil
}

func (p *Postgres) ConsumeNonce(nonce string) error { return p.consume("nonce", nonce) }
func (p *Postgres) ConsumeJTI(jti string) error     { return p.consume("jti", jti) }

func (p *Postgres) release(kind, key string) {
	if err := p.checkProject(p.projectID); err != nil {
		return
	}
	if p.tx == nil {
		return
	}
	_, _ = p.tx.Exec(p.callContext(), `DELETE FROM consume_ledger WHERE kind=$1 AND consume_key=$2`, kind, key)
}

func (p *Postgres) ReleaseNonce(nonce string) { p.release("nonce", nonce) }
func (p *Postgres) ReleaseJTI(jti string)     { p.release("jti", jti) }
