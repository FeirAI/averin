package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/feirai/averin/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// intentAndOutcomeScan is the pre-migration-0010 implementation of intentAndOutcome, verbatim: ONE pass over the
// whole session, decoding every record. It is the DEFINITION the indexed lookups must equal; it is kept for tests
// only and is never a hot path (it is O(session)).
func intentAndOutcomeScan(st store.Store, projectID, sessionID, intentRef string) (intentJSON string, intentFound bool, outcomeID string, outcomeFound bool, err error) {
	recs, err := st.SessionRecords(projectID, sessionID)
	if err != nil {
		return "", false, "", false, err
	}
	for _, rec := range recs {
		var probe struct {
			RecordID   string `json:"record_id"`
			Extensions struct {
				Broker struct {
					Kind       string `json:"kind"`
					UseOutcome struct {
						IntentRef string `json:"intent_ref"`
					} `json:"use_outcome"`
				} `json:"broker"`
			} `json:"extensions"`
		}
		if json.Unmarshal([]byte(rec.JSON), &probe) != nil || probe.Extensions.Broker.Kind == "" {
			continue
		}
		if !intentFound && probe.RecordID == intentRef {
			intentJSON, intentFound = rec.JSON, true
		}
		if !outcomeFound && probe.Extensions.Broker.Kind == "use_outcome" && probe.Extensions.Broker.UseOutcome.IntentRef == intentRef {
			outcomeID, outcomeFound = probe.RecordID, true
		}
		if intentFound && outcomeFound {
			break
		}
	}
	return intentJSON, intentFound, outcomeID, outcomeFound, nil
}

// newIOPostgres opens a Postgres store on a private, fully migrated schema (skips without
// AVERIN_TEST_DATABASE_URL) and returns it with an owner-role pool.
func newIOPostgres(t *testing.T) (*store.Postgres, *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run the Postgres-backed intent/outcome lookup tests")
	}
	schema := fmt.Sprintf("averin_io_test_%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	scoped := base + sep + "search_path=" + schema
	admin, err := pgxpool.New(ctx, scoped)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		_, _ = admin.Exec(dctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := pgschema.Migrate(ctx, scoped); err != nil {
		t.Fatalf("pgschema.Migrate: %v", err)
	}
	pg, err := store.NewPostgres(ctx, scoped)
	if err != nil {
		t.Fatalf("store.NewPostgres: %v", err)
	}
	t.Cleanup(pg.Close)
	return pg, admin
}

func ioJSON(recordID any, session string, kind any, intentRef any, withUseOutcome bool) string {
	m := map[string]any{"session_id": session}
	if recordID != nil {
		m["record_id"] = recordID
	}
	broker := map[string]any{}
	if kind != nil {
		broker["kind"] = kind
	}
	if withUseOutcome {
		uo := map[string]any{"status": "ok"}
		if intentRef != nil {
			uo["intent_ref"] = intentRef
		}
		broker["use_outcome"] = uo
	}
	if kind != nil || withUseOutcome {
		m["extensions"] = map[string]any{"broker": broker}
	} else {
		m["extensions"] = map[string]any{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ioHistory writes a random history into st and returns every record_id / intent_ref worth querying.
func ioHistory(t *testing.T, st store.Store, rng *rand.Rand, projects, sessions []string, n int) (refs []string) {
	t.Helper()
	seen := map[string]bool{}
	addRef := func(r string) {
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	type placed struct{ proj, sess, id string }
	var intents []placed
	longRef := strings.Repeat("L", 5000)
	for i := 1; i <= n; i++ {
		proj := projects[rng.Intn(len(projects))]
		sess := sessions[rng.Intn(len(sessions))]
		rid := fmt.Sprintf("rec-%04d", i)
		pickRef := func() string {
			switch rng.Intn(5) {
			case 0: // an intent of this session
				for _, p := range intents {
					if p.proj == proj && p.sess == sess && rng.Intn(3) == 0 {
						return p.id
					}
				}
			case 1: // an intent of ANY session or project (cross-session / cross-project reference)
				if len(intents) > 0 {
					return intents[rng.Intn(len(intents))].id
				}
			case 2: // absent
				return fmt.Sprintf("absent-%d", rng.Intn(20))
			case 3:
				return longRef
			}
			if len(intents) > 0 {
				return intents[rng.Intn(len(intents))].id
			}
			return "absent-x"
		}
		var js string
		switch k := rng.Intn(14); k {
		case 0, 1, 2: // use_intent
			js = ioJSON(rid, sess, "use_intent", nil, false)
			intents = append(intents, placed{proj, sess, rid})
		case 3, 4, 5: // use_outcome, possibly several for one intent
			ref := pickRef()
			js = ioJSON(rid, sess, "use_outcome", ref, true)
			addRef(ref)
		case 6: // generic record spoofing an intent's record_id is a different record: reuse a pre-seeded id
			js = ioJSON(rid, sess, nil, nil, false)
		case 7: // generic record carrying a use_outcome.intent_ref but no broker kind
			ref := pickRef()
			js = ioJSON(rid, sess, nil, ref, true)
			addRef(ref)
		case 8: // empty kind
			js = ioJSON(rid, sess, "", pickRef(), true)
			intents = append(intents, placed{proj, sess, rid})
		case 9: // a grant that carries a use_outcome block: not an outcome
			ref := pickRef()
			js = ioJSON(rid, sess, "grant", ref, true)
			addRef(ref)
			intents = append(intents, placed{proj, sess, rid})
		case 10: // type confusion: numeric record_id / kind / intent_ref, string use_outcome
			switch rng.Intn(5) {
			case 0:
				js = ioJSON(float64(i), sess, "use_intent", nil, false)
				addRef(fmt.Sprint(i))
			case 1:
				js = ioJSON(rid, sess, float64(7), nil, false)
				intents = append(intents, placed{proj, sess, rid})
			case 2:
				js = ioJSON(rid, sess, "use_outcome", float64(i), true)
				addRef(fmt.Sprint(i))
			case 3:
				js = fmt.Sprintf(`{"record_id":%q,"session_id":%q,"extensions":{"broker":{"kind":"use_intent","use_outcome":"x"}}}`, rid, sess)
				intents = append(intents, placed{proj, sess, rid})
			default:
				js = ioJSON(nil, sess, "use_outcome", pickRef(), true) // no record_id at all
			}
		case 11: // use_outcome whose own record_id is later used as an intent_ref / intent lookup
			js = ioJSON(rid, sess, "use_outcome", pickRef(), true)
			intents = append(intents, placed{proj, sess, rid})
		default: // another plain intent
			js = ioJSON(rid, sess, "use_intent", nil, false)
			intents = append(intents, placed{proj, sess, rid})
		}
		addRef(rid)
		r := store.Record{JSON: js, ContentHash: fmt.Sprintf("sha256:io%05d", i), SessionID: sess, Parents: []string{}}
		_, created, err := st.PutRecord(proj, fmt.Sprintf("idem-%d", i), r)
		if err != nil {
			t.Fatalf("put %d: %v (%s)", i, err, js)
		}
		if !created {
			t.Fatalf("put %d not created", i)
		}
		if i%7 == 0 { // idempotent replay changes nothing
			if _, created, err := st.PutRecord(proj, fmt.Sprintf("idem-%d", i), r); err != nil || created {
				t.Fatalf("replay %d: created=%v err=%v", i, created, err)
			}
		}
		if i%11 == 0 && strings.Contains(js, `"record_id":"`+rid+`"`) { // the same record_id in ANOTHER session of the project is impossible (unique per project)
			other := sessions[(rng.Intn(len(sessions)-1)+1+indexOf(sessions, sess))%len(sessions)]
			dup := store.Record{JSON: ioJSON(rid, other, "use_intent", nil, false), ContentHash: fmt.Sprintf("sha256:iodup%05d", i), SessionID: other, Parents: []string{}}
			if _, _, err := st.PutRecord(proj, fmt.Sprintf("idem-dup-%d", i), dup); !errors.Is(err, store.ErrRecordIDConflict) {
				t.Fatalf("record_id %s reused in session %s of project %s: err=%v, want ErrRecordIDConflict", rid, other, proj, err)
			}
		}
	}
	for _, x := range []string{"", "absent-q", `quo"te`, "unié世", "use_outcome", "use_intent", longRef + "x"} {
		addRef(x)
	}
	return refs
}

func indexOf(ss []string, s string) int {
	for i, x := range ss {
		if x == s {
			return i
		}
	}
	return 0
}

type ioResult struct {
	IntentJSON   string
	IntentFound  bool
	OutcomeID    string
	OutcomeFound bool
}

func assertIntentOutcomeEqualsScan(t *testing.T, st store.Store, projects, sessions, refs []string, label string) (hitIntent, hitOutcome int) {
	t.Helper()
	s := &Server{}
	for _, proj := range projects {
		for _, sess := range sessions {
			for _, ref := range refs {
				gj, gi, go_, gf, gerr := s.intentAndOutcome(st, proj, sess, ref)
				wj, wi, wo, wf, werr := intentAndOutcomeScan(st, proj, sess, ref)
				if gerr != nil || werr != nil {
					t.Fatalf("%s: errors (%s,%s,%.20q): lookup=%v scan=%v", label, proj, sess, ref, gerr, werr)
				}
				got, want := ioResult{gj, gi, go_, gf}, ioResult{wj, wi, wo, wf}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: (%s,%s,%.20q): indexed lookup = %+v, scan = %+v", label, proj, sess, ref, got, want)
				}
				if gi {
					hitIntent++
				}
				if gf {
					hitOutcome++
				}
			}
		}
	}
	return hitIntent, hitOutcome
}

func runIntentOutcomeEquivalence(t *testing.T, mk func(t *testing.T) store.Store) {
	for seed := int64(1); seed <= 4; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			st := mk(t)
			rng := rand.New(rand.NewSource(seed))
			projects := []string{"pa", "pb"}
			sessions := []string{"s1", "s2", "s3"}
			refs := ioHistory(t, st, rng, projects, sessions, 220)
			hi, ho := assertIntentOutcomeEqualsScan(t, st, projects, sessions, refs, fmt.Sprintf("seed %d", seed))
			if hi < 20 || ho < 20 {
				t.Fatalf("vacuous history: %d intent hits, %d outcome hits", hi, ho)
			}
			t.Logf("seed %d: %d refs x %d sessions x %d projects; %d intent hits, %d outcome hits, all equal to the scan", seed, len(refs), len(sessions), len(projects), hi, ho)
		})
	}
}

func TestIntentAndOutcomeLookupEqualsScanMem(t *testing.T) {
	runIntentOutcomeEquivalence(t, func(t *testing.T) store.Store { return store.NewMem() })
}

func TestIntentAndOutcomeLookupEqualsScanPostgres(t *testing.T) {
	runIntentOutcomeEquivalence(t, func(t *testing.T) store.Store {
		pg, _ := newIOPostgres(t)
		return pg
	})
}

// failLookupStore fails the indexed lookups on demand: any read error must propagate (averin#14), never
// degrade to "not found".
type failLookupStore struct {
	store.Store
	failIntent, failOutcome bool
}

func (f *failLookupStore) IntentRecord(p, s, id string) (store.Record, bool, error) {
	if f.failIntent {
		return store.Record{}, false, errors.New("injected IntentRecord failure")
	}
	return f.Store.IntentRecord(p, s, id)
}

func (f *failLookupStore) UseOutcomeFor(p, s, ref string) (string, bool, error) {
	if f.failOutcome {
		return "", false, errors.New("injected UseOutcomeFor failure")
	}
	return f.Store.UseOutcomeFor(p, s, ref)
}

func TestIntentAndOutcomeReadErrorsPropagate(t *testing.T) {
	mem := store.NewMem()
	js := ioJSON("use-1", "s1", "use_intent", nil, false)
	if _, _, err := mem.PutRecord("p", "i1", store.Record{JSON: js, ContentHash: "sha256:a", SessionID: "s1", Parents: []string{}}); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	for _, c := range []struct{ intent, outcome bool }{{true, false}, {false, true}, {true, true}} {
		f := &failLookupStore{Store: mem, failIntent: c.intent, failOutcome: c.outcome}
		_, found, _, ofound, err := s.intentAndOutcome(f, "p", "s1", "use-1")
		if err == nil || found || ofound {
			t.Fatalf("fail %+v: err=%v found=%v outcomeFound=%v; a read error must propagate and report nothing found", c, err, found, ofound)
		}
	}
	if _, ok, _, _, err := s.intentAndOutcome(&failLookupStore{Store: mem}, "p", "s1", "use-1"); err != nil || !ok {
		t.Fatalf("healthy lookup: ok=%v err=%v", ok, err)
	}
}
