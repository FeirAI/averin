package store

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"time"
)

// assertHeadsEqualFull is the equivalence the incremental table must keep: for every (project, session)
// the table-backed Heads() equals the full-scan definition, byte for byte and in the same order.
func assertHeadsEqualFull(t *testing.T, p *Postgres, projects, sessions []string, ctxMsg string) {
	t.Helper()
	for _, proj := range projects {
		for _, sess := range sessions {
			got, err := p.Heads(proj, sess)
			if err != nil {
				t.Fatalf("%s: Heads(%s,%s): %v", ctxMsg, proj, sess, err)
			}
			want, err := p.headsFull(proj, sess)
			if err != nil {
				t.Fatalf("%s: headsFull(%s,%s): %v", ctxMsg, proj, sess, err)
			}
			if got == nil || want == nil {
				t.Fatalf("%s: nil heads (got nil=%v want nil=%v)", ctxMsg, got == nil, want == nil)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: Heads(%s,%s) = %v, headsFull = %v", ctxMsg, proj, sess, got, want)
			}
		}
	}
}

// TestPostgresSessionHeadsEquivalentToFullScan builds random histories (forks, merges, server-forced
// cross-session parents, duplicate parents, idempotent replays, content-hash
// collapses, several sessions and projects) and asserts Heads() == headsFull() for every session after
// every single PutRecord.
func TestPostgresSessionHeadsEquivalentToFullScan(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			p, done := newTestStore(t)
			defer done()
			rng := rand.New(rand.NewSource(seed))
			projects := []string{"pa", "pb"}
			sessions := []string{"s1", "s2", "s3", "s4"}
			const steps = 120
			type placed struct{ proj, sess, hash string }
			var all []placed
			byProj := map[string][]placed{}
			for i := 1; i <= steps; i++ {
				proj := projects[rng.Intn(len(projects))]
				sess := sessions[rng.Intn(len(sessions))]
				hash := fmt.Sprintf("sha256:h%04d", i)
				var parents []string
				heads, err := p.Heads(proj, sess)
				if err != nil {
					t.Fatal(err)
				}
				switch rng.Intn(6) {
				case 0: // root
				case 1: // linear: the whole frontier (what the seal path does)
					parents = append(parents, heads...)
				case 2: // fork: one random older record of the session (not nec. a head)
					if recs := byProj[proj]; len(recs) > 0 {
						parents = append(parents, recs[rng.Intn(len(recs))].hash)
					}
				case 3: // merge with a server-forced cross-session parent
					parents = append(parents, heads...)
					if recs := byProj[proj]; len(recs) > 0 {
						parents = append(parents, recs[rng.Intn(len(recs))].hash)
					}
				case 4: // duplicate parents
					parents = append(parents, heads...)
					parents = append(parents, heads...)
					if len(parents) == 0 && len(byProj[proj]) > 0 {
						h := byProj[proj][rng.Intn(len(byProj[proj]))].hash
						parents = []string{h, h}
					}
				case 5: // merge of two older records of the project, with a duplicate
					for k := 0; k < 3 && len(byProj[proj]) > 0; k++ {
						parents = append(parents, byProj[proj][rng.Intn(len(byProj[proj]))].hash)
					}
					parents = append(parents, parents...)
				}
				r := rec(hash, sess, parents...)
				if _, created, err := p.PutRecord(proj, "k-"+hash, r); err != nil || !created {
					t.Fatalf("step %d put: created=%v err=%v", i, created, err)
				}
				all = append(all, placed{proj, sess, hash})
				byProj[proj] = append(byProj[proj], placed{proj, sess, hash})
				assertHeadsEqualFull(t, p, projects, sessions, fmt.Sprintf("seed %d step %d insert", seed, i))

				// Idempotent replays and collapses must not change anything.
				switch rng.Intn(4) {
				case 0: // same idem key, same record
					if _, created, err := p.PutRecord(proj, "k-"+hash, r); err != nil || created {
						t.Fatalf("replay: created=%v err=%v", created, err)
					}
				case 1: // new idem key, same content_hash: collapses onto the row
					if _, created, err := p.PutRecord(proj, "other-"+hash, r); err != nil || created {
						t.Fatalf("collapse: created=%v err=%v", created, err)
					}
				case 2: // an earlier record replayed with a stale view (its parents differ): still a no-op
					old := all[rng.Intn(len(all))]
					if old.proj == proj {
						if _, created, err := p.PutRecord(proj, "k-"+old.hash, rec(old.hash, old.sess, hash)); err != nil || created {
							t.Fatalf("stale replay: created=%v err=%v", created, err)
						}
					}
				}
				assertHeadsEqualFull(t, p, projects, sessions, fmt.Sprintf("seed %d step %d replay", seed, i))
			}
		})
	}
}

// TestPostgresSessionHeadsAtomicWithInsert proves the heads update and the record insert commit or roll
// back together inside one project transaction.
func TestPostgresSessionHeadsAtomicWithInsert(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	if _, _, err := p.PutRecord("proj", "k0", rec("sha256:a", "s")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errRollback := fmt.Errorf("force rollback")
	err := p.WithProjectWrite(ctx, "proj", func(st Store) error {
		if _, created, err := st.PutRecord("proj", "k1", rec("sha256:b", "s", "sha256:a")); err != nil || !created {
			return fmt.Errorf("put: %v %v", created, err)
		}
		if h, _ := st.Heads("proj", "s"); len(h) != 1 || h[0] != "sha256:b" {
			return fmt.Errorf("in-tx heads = %v, want [sha256:b]", h)
		}
		return errRollback
	})
	if err == nil {
		t.Fatal("expected the forced rollback error")
	}
	h, err := p.Heads("proj", "s")
	if err != nil || len(h) != 1 || h[0] != "sha256:a" {
		t.Fatalf("heads after rollback = %v, %v; want [sha256:a]", h, err)
	}
	assertHeadsEqualFull(t, p, []string{"proj"}, []string{"s"}, "after rollback")
}

// TestPostgresSealLatencyFlat seals N records into ONE session through the real PutRecord/Heads pair the
// seal path uses (heads read, then insert with those heads as parents) at N = 1k and N = 20k, and
// reports the per-seal time of the first and last 500 seals. It must not grow with N beyond noise.
// Set AVERIN_SEAL_LATENCY=1 to run (the 20k case takes a while).
func TestPostgresSealLatencyFlat(t *testing.T) {
	if testing.Short() || os.Getenv("AVERIN_SEAL_LATENCY") == "" {
		t.Skip("set AVERIN_SEAL_LATENCY=1 to run the seal latency scaling test")
	}
	for _, n := range []int{1000, 20000} {
		n := n
		t.Run(fmt.Sprintf("N%d", n), func(t *testing.T) {
			p, done := newTestStore(t)
			defer done()
			const window = 500
			const slice = 2000
			var first, last time.Duration
			var firstHeads, lastHeads time.Duration
			var sTotal, sHeads, sPut time.Duration
			for i := 0; i < n; i++ {
				t0 := time.Now()
				var hd, pd time.Duration
				err := p.WithProjectWrite(context.Background(), "proj", func(st Store) error {
					h0 := time.Now()
					heads, err := st.Heads("proj", "vultrino")
					hd = time.Since(h0)
					if err != nil {
						return err
					}
					p0 := time.Now()
					_, _, err = st.PutRecord("proj", fmt.Sprintf("k%d", i), rec(fmt.Sprintf("sha256:%08d", i), "vultrino", heads...))
					pd = time.Since(p0)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				d := time.Since(t0)
				sTotal += d
				sHeads += hd
				sPut += pd
				if (i+1)%slice == 0 {
					t.Logf("seals %d-%d mean: total %v (heads %v, put %v, begin+guard+commit %v)", i+1-slice, i, sTotal/slice, sHeads/slice, sPut/slice, (sTotal-sHeads-sPut)/slice)
					sTotal, sHeads, sPut = 0, 0, 0
				}
				if i < window {
					first += d
					firstHeads += hd
				}
				if i >= n-window {
					last += d
					lastHeads += hd
				}
			}
			t.Logf("N=%d per-seal (heads+insert+commit) first %d: %v, last %d: %v; Heads() alone first %v, last %v",
				n, window, first/window, window, last/window, firstHeads/window, lastHeads/window)
			assertHeadsEqualFull(t, p, []string{"proj"}, []string{"vultrino"}, "after soak")
		})
	}
}
