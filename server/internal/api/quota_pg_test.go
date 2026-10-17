package api_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// TestProjectQuotaAcrossReplicasPostgres (AVE-07): two server replicas on two Postgres pools, each writing
// concurrently to one project with a cap of 7. The project guard serializes the transactions and the count is
// read inside each one, so exactly 7 records are stored whatever the interleaving, every other write is a 507,
// and another project is not touched.
func TestProjectQuotaAcrossReplicasPostgres(t *testing.T) {
	first, admin := newVoidTestPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	second, err := store.NewPostgres(ctx, admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	const limit = 7
	newReplica := func(st store.Store) http.Handler {
		return api.New(mustCore(t), st, "k0").WithAuth(auth.NewOpenStore()).WithProjectQuota(limit).Routes()
	}
	h := []http.Handler{newReplica(first), newReplica(second)}

	var created, refused, other atomic.Int32
	var wg sync.WaitGroup
	for r := 0; r < 2; r++ {
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func(r, w int) {
				defer wg.Done()
				for i := 0; i < 4; i++ {
					code, _ := do(t, h[r], "POST", "/v2/records?project=pq", quotaRec("pq", fmt.Sprintf("r%d-w%d-i%d", r, w, i)))
					switch code {
					case http.StatusCreated:
						created.Add(1)
					case http.StatusInsufficientStorage:
						refused.Add(1)
					default:
						other.Add(1)
					}
				}
			}(r, w)
		}
	}
	wg.Wait()
	if other.Load() != 0 {
		t.Fatalf("every write must be 201 or 507, %d were something else", other.Load())
	}
	if created.Load() != limit || refused.Load() != 24-limit {
		t.Fatalf("want %d created and %d refused, got %d and %d", limit, 24-limit, created.Load(), refused.Load())
	}
	for i, hh := range h {
		if n := usageRecords(t, hh, "pq"); n != limit {
			t.Fatalf("replica %d sees %d stored records, want exactly %d", i, n, limit)
		}
	}
	if code, r := do(t, h[1], "POST", "/v2/records?project=pother", quotaRec("pother", "x1")); code != http.StatusCreated {
		t.Fatalf("another project must not be limited: %d %s", code, r)
	}
}
