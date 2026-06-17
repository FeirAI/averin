package api

import (
	"testing"

	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/resourceshim"
	"github.com/feir-dev/feir/server/internal/store"
)

// TestWithLedgerSeam verifies the consume-before-act ledger injection seam (Finding 7/44): WithResource
// installs the default (volatile) MemLedger, and a ledger injected with WithLedger BEFORE WithResource
// is preserved — so a durable ledger CAN be injected. This backs the honesty fix where the prior
// over-claim ("production injects a durable one") now describes a real seam.
func TestWithLedgerSeam(t *testing.T) {
	const serverSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const resSeed = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"
	c, err := core.New(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resSeed)
	if err != nil {
		t.Fatal(err)
	}

	// WithResource alone installs a (volatile) default ledger.
	s1 := New(c, store.NewMem(), "k0").WithResource(rc, "orders-db")
	if s1.ledger == nil {
		t.Fatal("WithResource must install a default ledger")
	}

	// A ledger injected with WithLedger BEFORE WithResource must NOT be clobbered by the default.
	custom := resourceshim.NewMemLedger()
	s2 := New(c, store.NewMem(), "k0").WithLedger(custom).WithResource(rc, "orders-db")
	if s2.ledger != custom {
		t.Fatal("WithLedger before WithResource must be preserved (durable-ledger injection seam)")
	}
}
