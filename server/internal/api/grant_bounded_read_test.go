package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/store"
)

// readEntryStore reports when a handler enters a project read. The underlying
// pool has one connection, held by the test, so cancellation must bound the
// acquisition wait for both committed retries and authenticated denials.
type readEntryStore struct {
	store.Store
	entered chan struct{}
}

func (s *readEntryStore) WithProjectRead(ctx context.Context, projectID string, fn func(store.Store) error) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	return s.Store.WithProjectRead(ctx, projectID, fn)
}

func TestGrantReadProbesCancelWhilePoolIsHeld(t *testing.T) {
	_, admin := newVoidTestPostgres(t)
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer setupCancel()
	dsn, err := url.Parse(admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("pool_max_conns", "1")
	dsn.RawQuery = q.Encode()
	limited, err := store.NewPostgres(setupCtx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	sharedContent := content.NewMemStore()
	initial := api.New(mustCore(t), limited, "k0").WithContent(sharedContent).WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	grant := grantBody("idem-bounded", "read:orders", ak, ak)
	if code, body := do(t, initial, http.MethodPost, "/v2/grants", grant); code != http.StatusCreated {
		t.Fatalf("initial grant: %d %s", code, body)
	}

	probe := &readEntryStore{Store: limited, entered: make(chan struct{}, 1)}
	h := api.New(mustCore(t), probe, "k0").WithContent(sharedContent).WithBroker(brokerIssuingKey()).Routes()
	holdCtx, holdCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer holdCancel()
	locked := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	holder := make(chan error, 1)
	go func() {
		holder <- limited.WithProjectRead(holdCtx, "p1", func(store.Store) error {
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-holder:
		t.Fatalf("holder failed before acquiring pool connection: %v", err)
	case <-holdCtx.Done():
		t.Fatal(holdCtx.Err())
	}

	for _, tc := range []struct {
		name, body string
	}{
		{"exact committed retry", grant},
		{"authenticated forbidden-scope denial", signedDenialBody(ak, "idem-denial-probe", "s1", "db.query:orders-ro", "orders-db", "iam:reset", 60, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, "/v2/grants", strings.NewReader(tc.body)).WithContext(requestCtx)
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				response <- rec
			}()
			select {
			case <-probe.entered:
			case <-holdCtx.Done():
				t.Fatal("grant did not reach its read probe while pool connection was held")
			}
			cancel()
			select {
			case rec := <-response:
				if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "idempotency lookup") {
					t.Fatalf("canceled read did not fail closed: %d %s", rec.Code, rec.Body.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("canceled grant read remained blocked on pool acquisition")
			}
		})
	}
	close(release)
	released = true
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, h, http.MethodPost, "/v2/grants", grant); code != http.StatusCreated || !strings.Contains(body, `"created":false`) {
		t.Fatalf("exact retry after pool release: %d %s", code, body)
	}
}
