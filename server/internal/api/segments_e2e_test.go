package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// AVE-01 end to end: a real server with broker, resource, revocation and attestation configured records three months
// of activity (the use-outcome of month three names the use-intent of month two as a forced parent, so month three has a
// parent that points before its base). Each month is exported, verified offline under pinned keys and chained
// to the previous month's head; the server's own /v2/verify answers per month; the whole-history export still
// verifies; and the month endpoints fail closed.

type segFixture struct {
	h     http.Handler
	c     *core.Core
	rc    *core.Core
	whole string
}

var segClock struct {
	sync.Mutex
	now time.Time
}

func segNow() time.Time {
	segClock.Lock()
	defer segClock.Unlock()
	return segClock.now
}

func setSegNow(t time.Time) {
	segClock.Lock()
	segClock.now = t
	segClock.Unlock()
}

func buildThreeMonths(t *testing.T) segFixture { return buildThreeMonthsOpt(t, false) }

func buildThreeMonthsOpt(t *testing.T, withRevocation bool) segFixture {
	t.Helper()
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	setSegNow(time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC))
	srv := api.New(c, store.NewMem().WithClock(segNow), "k0").
		WithClock(segNow).
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithAttestation(attestationKey())
	if withRevocation {
		srv = srv.WithRevocation(revocationKey())
	}
	h := srv.Routes()
	ak := grantAgentKey()
	plain := func(idem, session string) {
		t.Helper()
		body := fmt.Sprintf(`{"idempotency_key":%q,"project_id":"p1","session_id":%q,"record_id":%q}`, idem, session, idem)
		if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusCreated {
			t.Fatalf("record %s (%d): %s", idem, code, resp)
		}
	}
	checkpoint := func() {
		t.Helper()
		if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint: %d %s", code, r)
		}
	}

	// June: two plain records, one grant and a one-phase use
	plain("r-a", "s-a")
	plain("r-b", "s-b")
	g1, cap1 := mkGrantAt(t, h, ak, "idem-grant-1", segNow())
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-1", cap1, g1, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, r)
	}
	setSegNow(time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC))
	checkpoint()

	// July: a grant and a use-intent whose outcome only arrives in August
	setSegNow(time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC))
	g2, cap2 := mkGrantAt(t, h, ak, "idem-grant-2", segNow())
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent-2", cap2, g2, ak, "SELECT 2", "nonce-2"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	_ = json.Unmarshal([]byte(resp), &intent)
	plain("r-c", "s1")
	setSegNow(time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC))
	checkpoint()

	// August: the outcome for July's intent, one more record
	setSegNow(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC))
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome-2", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	plain("r-d", "s-b")
	setSegNow(time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC))
	checkpoint()

	code, whole := do(t, h, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("whole export (%d): %s", code, whole)
	}
	return segFixture{h: h, c: c, rc: rc, whole: whole}
}

func (f segFixture) pins(extra string) string {
	return fmt.Sprintf(`{"signing_keys":[%q],"broker_authority_keys":[%q],"resource_authority_keys":[%q]%s}`,
		f.c.PubKey(), f.c.PubKey(), f.rc.PubKey(), extra)
}

type segInfo struct {
	Month     string `json:"month"`
	Records   int    `json:"records"`
	FirstSeq  int64  `json:"first_seq"`
	LastSeq   int64  `json:"last_seq"`
	HeadHash  string `json:"head_hash"`
	BaseSeq   *int64 `json:"base_seq"`
	BaseHash  string `json:"base_hash"`
	Before    int    `json:"records_before"`
	BaseCount int    `json:"-"`
}

func listSegments(t *testing.T, h http.Handler) []segInfo {
	t.Helper()
	code, resp := do(t, h, "GET", "/v2/segments?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("segments (%d): %s", code, resp)
	}
	var out struct {
		Format   string    `json:"format"`
		Segments []segInfo `json:"segments"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil || out.Format != "averin.segment.v1" {
		t.Fatalf("segments body: %v %s", err, resp)
	}
	return out.Segments
}

type segReport struct {
	OK      bool     `json:"ok"`
	Issues  []string `json:"issues"`
	Records int      `json:"records_total"`
	Broker  string   `json:"broker_trust"`
	Segment *struct {
		Month       string `json:"month"`
		Link        string `json:"link"`
		HeadHash    string `json:"head_checkpoint_hash"`
		HeadCount   int    `json:"head_record_count"`
		EarlierRefs int    `json:"earlier_parent_refs"`
		Unresolved  []struct {
			Kind string `json:"kind"`
			Ref  string `json:"ref"`
		} `json:"unresolved_cross_month"`
		NotEvaluated []string `json:"not_evaluated"`
	} `json:"segment"`
}

func parseSegReport(t *testing.T, s string) segReport {
	t.Helper()
	var r segReport
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("report: %v\n%s", err, s)
	}
	return r
}

func TestMonthSegmentsExportVerifyAndChain(t *testing.T) {
	f := buildThreeMonths(t)

	// the whole-history export still verifies
	if r := parseSegReport(t, f.c.VerifyBundleWith(f.whole, f.pins(""))); !r.OK || r.Segment != nil {
		t.Fatalf("whole export: ok=%v issues=%v", r.OK, r.Issues)
	}

	segs := listSegments(t, f.h)
	if len(segs) != 3 || segs[0].Month != "2026-06" || segs[1].Month != "2026-07" || segs[2].Month != "2026-08" {
		t.Fatalf("segments: %+v", segs)
	}
	if segs[0].BaseSeq != nil || segs[1].BaseSeq == nil || *segs[1].BaseSeq != 0 || segs[1].BaseHash != segs[0].HeadHash {
		t.Fatalf("segment chain positions: %+v", segs)
	}
	total := 0
	for _, s := range segs {
		total += s.Records
	}

	pin := "genesis"
	records := 0
	for i, s := range segs {
		code, bundle := do(t, f.h, "GET", "/v2/export?project=p1&month="+s.Month, "")
		if code != http.StatusOK {
			t.Fatalf("export %s (%d): %s", s.Month, code, bundle)
		}
		r := parseSegReport(t, f.c.VerifyBundleWith(bundle, f.pins(fmt.Sprintf(`,"segment_base_checkpoint_hash":%q`, pin))))
		if !r.OK {
			t.Fatalf("%s does not verify offline: %v", s.Month, r.Issues)
		}
		if r.Segment == nil || r.Segment.Month != s.Month || r.Records != s.Records {
			t.Fatalf("%s segment report: %+v records=%d", s.Month, r.Segment, r.Records)
		}
		wantLink := "base_pinned"
		if i == 0 {
			wantLink = "genesis"
		}
		if r.Segment.Link != wantLink {
			t.Fatalf("%s link = %s", s.Month, r.Segment.Link)
		}
		if r.Segment.HeadHash != s.HeadHash {
			t.Fatalf("%s head %s != listed %s", s.Month, r.Segment.HeadHash, s.HeadHash)
		}
		records += r.Records
		if r.Segment.HeadCount != records {
			t.Fatalf("%s head count %d != running total %d", s.Month, r.Segment.HeadCount, records)
		}
		if i > 0 && (r.Broker != "assumed" || len(r.Segment.NotEvaluated) != 2) {
			t.Fatalf("%s must report the grant log as not evaluated: broker_trust=%s %v", s.Month, r.Broker, r.Segment.NotEvaluated)
		}
		if i == 2 {
			if r.Segment.EarlierRefs != 1 {
				t.Fatalf("August's use-outcome names July's intent from before its base: earlier refs = %d", r.Segment.EarlierRefs)
			}
			// ... and the outcome is listed as unresolved, not as a violation and not as a match
			if len(r.Segment.Unresolved) != 1 || r.Segment.Unresolved[0].Kind != "use_outcome" {
				t.Fatalf("August must list July's intent as unresolved: %+v", r.Segment.Unresolved)
			}
		} else if len(r.Segment.Unresolved) != 0 {
			t.Fatalf("%s lists unresolved references: %+v", s.Month, r.Segment.Unresolved)
		}

		// the server's own self-view answers per month too
		_, self := do(t, f.h, "GET", "/v2/verify?project=p1&month="+s.Month, "")
		if sr := parseSegReport(t, self); !sr.OK || sr.Segment == nil || sr.Segment.Month != s.Month {
			t.Fatalf("self-verify %s: ok=%v issues=%v", s.Month, sr.OK, sr.Issues)
		}
		pin = r.Segment.HeadHash
	}
	if records != total {
		t.Fatalf("months hold %d records, listing says %d", records, total)
	}
	// the whole-history count: 2 plain + grant + use | grant + intent + plain | outcome + plain
	if records != 4+3+2 {
		t.Fatalf("unexpected record total %d", records)
	}

	// a month cannot be verified against another month's head
	_, june := do(t, f.h, "GET", "/v2/export?project=p1&month=2026-08", "")
	if r := parseSegReport(t, f.c.VerifyBundleWith(june, f.pins(fmt.Sprintf(`,"segment_base_checkpoint_hash":%q`, segs[0].HeadHash)))); r.OK {
		t.Fatal("August verified against June's head: the chain skips July")
	}
}

func TestMonthEndpointsFailClosed(t *testing.T) {
	f := buildThreeMonths(t)
	for path, want := range map[string]int{
		"/v2/export?project=p1&month=2026-09":    http.StatusNotFound,
		"/v2/export?project=p1&month=2026-13":    http.StatusBadRequest,
		"/v2/export?project=p1&month=junk":       http.StatusBadRequest,
		"/v2/verify?project=p1&month=2026-09":    http.StatusNotFound,
		"/v2/verify?project=p1&month=2026-6":     http.StatusBadRequest,
		"/v2/export?project=other&month=2026-06": http.StatusNotFound,
	} {
		code, body := do(t, f.h, "GET", path, "")
		if code != want {
			t.Errorf("%s = %d (want %d): %s", path, code, want, body)
		}
	}
	// a month export carries only its own records: another month's record id is absent
	_, aug := do(t, f.h, "GET", "/v2/export?project=p1&month=2026-08", "")
	if strings.Contains(aug, `"record_id":"r-a"`) || !strings.Contains(aug, `"record_id":"r-d"`) {
		t.Fatalf("August export holds the wrong records")
	}
}

// With revocation configured the self-view has no anchor to date the signed revocation_list, so whole-history
// self-verification already reports it (a standing property of the self-view, not of segments). A month must
// behave the same, and with anchors and the issuer pinned offline a month verifies clean.
func TestMonthSegmentWithRevocationBehavesLikeWholeHistory(t *testing.T) {
	f := buildThreeMonthsOpt(t, true)
	_, whole := do(t, f.h, "GET", "/v2/verify?project=p1", "")
	_, month := do(t, f.h, "GET", "/v2/verify?project=p1&month=2026-08", "")
	w, m := parseSegReport(t, whole), parseSegReport(t, month)
	if strings.Join(w.Issues, "|") != strings.Join(m.Issues, "|") || w.OK != m.OK {
		t.Fatalf("self-view differs: whole ok=%v %v, month ok=%v %v", w.OK, w.Issues, m.OK, m.Issues)
	}

	tsa := testTSAKey()
	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(revocationKey().Public().(ed25519.PublicKey))
	for _, month := range []string{"2026-06", "2026-08"} {
		_, bundle := do(t, f.h, "GET", "/v2/export?project=p1&month="+month, "")
		anchored := attachTestAnchor(t, bundle, tsa)
		opts := f.pins(fmt.Sprintf(`,"tsa_keys":[%q],"revocation_keys":[%q]`, tsaPubEncoded(tsa), revPub))
		r := parseSegReport(t, f.c.VerifyBundleWith(anchored, opts))
		if !r.OK {
			t.Fatalf("%s with anchors and the revocation issuer pinned: %v", month, r.Issues)
		}
	}
}
