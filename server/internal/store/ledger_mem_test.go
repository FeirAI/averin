package store

import (
	"context"
	"errors"
	"testing"

	"github.com/feirai/averin/server/internal/resourceshim"
)

// TestLedgerInvalidClaimsAreInvariantErrors (review L3): claims the ledger refuses as malformed or out
// of place are marked ErrInvalidLedgerClaim (a 500), unlike database failures (a retryable 503), on
// both stores.
func TestLedgerInvalidClaimsAreInvariantErrors(t *testing.T) {
	stores := map[string]func(t *testing.T) (Store, func()){
		"mem": func(*testing.T) (Store, func()) { return NewMem(), func() {} },
		"postgres": func(t *testing.T) (Store, func()) {
			p, done := newTestStore(t)
			return p, done
		},
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			st, done := mk(t)
			defer done()
			claim, err := resourceshim.NewNonceClaim("p1", "res", "n1")
			if err != nil {
				t.Fatal(err)
			}
			other, err := resourceshim.NewNonceClaim("p2", "res", "n1")
			if err != nil {
				t.Fatal(err)
			}
			// Outside a project write transaction.
			if err := st.ConsumeNonce(claim); !errors.Is(err, resourceshim.ErrInvalidLedgerClaim) {
				t.Fatalf("claim outside a write transaction = %v", err)
			}
			err = st.WithProjectWrite(context.Background(), "p1", func(tx Store) error {
				if err := tx.ConsumeNonce(other); !errors.Is(err, resourceshim.ErrInvalidLedgerClaim) {
					t.Errorf("claim for another project = %v", err)
				}
				if err := tx.ConsumeNonce(resourceshim.NonceClaim{ProjectID: "p1"}); !errors.Is(err, resourceshim.ErrInvalidLedgerClaim) {
					t.Errorf("incomplete claim = %v", err)
				}
				if err := tx.ConsumeJTI(resourceshim.JTIClaim{}); !errors.Is(err, resourceshim.ErrInvalidLedgerClaim) {
					t.Errorf("incomplete JTI claim = %v", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
