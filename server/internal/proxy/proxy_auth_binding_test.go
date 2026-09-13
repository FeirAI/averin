package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
)

// These tests invoke handlers directly; every client has an injected transport.
// They exercise request construction and middleware, not a real ingestion server.
type authBindingTransport func(*http.Request) (*http.Response, error)

func (f authBindingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func authBindingResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestAuthBindingRecorderURLAndBody(t *testing.T) {
	cases := []struct {
		name, base, project, escapedPath string
	}{
		{"ordinary", "http://recorder.invalid", "p1", "/v2/records"},
		{"prefix", "https://recorder.invalid/root///", "p1", "/root/v2/records"},
		{"query", "https://recorder.invalid/root?project=wrong&project=other&keep=a&keep=b", "p&?= +/", "/root/v2/records"},
		{"encoded", "https://recorder.invalid/a%2Fb/c%20d", "p1", "/a%2Fb/c%20d/v2/records"},
		{"encoded-trailing-slash", "https://recorder.invalid/a%2F/", "p1", "/a%2F/v2/records"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			body := map[string]any{"project_id": tc.project, "idempotency_key": "fixed", "note": "unchanged"}
			client := &http.Client{Transport: authBindingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.EscapedPath() != tc.escapedPath {
					t.Fatalf("unexpected method/path: %s %s", r.Method, r.URL.EscapedPath())
				}
				q := r.URL.Query()
				if !reflect.DeepEqual(q["project"], []string{tc.project}) {
					t.Fatalf("project query: %#v", q)
				}
				if tc.name == "query" {
					if len(q) != 2 || !reflect.DeepEqual(q["keep"], []string{"a", "b"}) {
						t.Fatalf("query values lost or injected: %#v", q)
					}
				} else if len(q) != 1 {
					t.Fatalf("unexpected query fields: %#v", q)
				}
				if r.Header.Get("X-Api-Key") != "record-key" {
					t.Fatal("recorder API key missing")
				}
				var got map[string]any
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, body) {
					t.Fatalf("body changed: %#v", got)
				}
				return authBindingResponse(http.StatusCreated, "{}"), nil
			})}
			err := (&HTTPRecorder{URL: tc.base, Token: "record-key", Client: client}).Record(body)
			if err != nil || calls != 1 {
				t.Fatalf("record error=%v calls=%d", err, calls)
			}
			if !reflect.DeepEqual(body, map[string]any{"project_id": tc.project, "idempotency_key": "fixed", "note": "unchanged"}) {
				t.Fatal("caller fields changed")
			}
		})
	}
}

func TestAuthBindingRecorderMiddleware(t *testing.T) {
	cases := []struct {
		name, token, project, rewriteProject string
		wantStatus, wantTerminal             int
	}{
		{"valid", "valid-key", "p1", "", 201, 1},
		{"missing-key", "", "p1", "", 401, 0},
		{"wrong-key", "wrong", "p1", "", 401, 0},
		{"unknown-project", "valid-key", "other", "", 401, 0},
		{"body-query-mismatch", "valid-key", "p1", "p2", 403, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, terminal, status := 0, 0, 0
			ks := auth.NewMapStore(map[string][]string{"p1": {"valid-key"}, "p2": {"valid-key"}})
			gate := auth.Middleware(ks, "project")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				terminal++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				// Synthetic terminal check, not a claim about real API-handler execution.
				if body["project_id"] != r.URL.Query().Get("project") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusCreated)
			}))
			client := &http.Client{Transport: authBindingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if tc.rewriteProject != "" {
					q := r.URL.Query()
					q.Set("project", tc.rewriteProject)
					r.URL.RawQuery = q.Encode()
				}
				w := httptest.NewRecorder()
				gate.ServeHTTP(w, r)
				status = w.Code
				return w.Result(), nil
			})}
			err := (&HTTPRecorder{URL: "http://recorder.invalid", Token: tc.token, Client: client}).Record(map[string]any{"project_id": tc.project})
			if calls != 1 || terminal != tc.wantTerminal || status != tc.wantStatus || (err != nil) != (tc.wantStatus != 201) {
				t.Fatalf("calls=%d terminal=%d status=%d err=%v", calls, terminal, status, err)
			}
		})
	}
}

func TestAuthBindingRecorderRejectsBeforeTransport(t *testing.T) {
	cases := []struct {
		name, base string
		body       map[string]any
	}{
		{"nil", "http://recorder.invalid", nil},
		{"missing", "http://recorder.invalid", map[string]any{}},
		{"nonstring", "http://recorder.invalid", map[string]any{"project_id": 1}},
		{"empty", "http://recorder.invalid", map[string]any{"project_id": ""}},
		{"whitespace", "http://recorder.invalid", map[string]any{"project_id": " \t"}},
		{"marshal", "http://recorder.invalid", map[string]any{"project_id": "p1", "bad": make(chan int)}},
	}
	for _, base := range []string{"", "/relative", "http://", "http://[bad", "http://recorder.invalid/%zz", "http://recorder.invalid?bad=%zz", "http://recorder.invalid?a=1;bad=2", "http://user:synthetic-secret@recorder.invalid", "http://recorder.invalid/#fragment", "ftp://recorder.invalid", "http:opaque"} {
		cases = append(cases, struct {
			name, base string
			body       map[string]any
		}{"bad-base-" + base, base, map[string]any{"project_id": "p1"}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: authBindingTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, fmt.Errorf("unexpected transport")
			})}
			err := (&HTTPRecorder{URL: tc.base, Client: client}).Record(tc.body)
			if err == nil || calls != 0 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
			if strings.Contains(err.Error(), "synthetic-secret") || (tc.base != "" && strings.Contains(err.Error(), tc.base)) {
				t.Fatal("validation error echoed supplied base or credential")
			}
		})
	}
}

func TestAuthBindingRecorderIdempotencyRetry(t *testing.T) {
	body := map[string]any{"project_id": "p1", "note": "unchanged"}
	var keys []string
	client := &http.Client{Transport: authBindingTransport(func(r *http.Request) (*http.Response, error) {
		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		key, ok := got["idempotency_key"].(string)
		if !ok || key == "" || got["project_id"] != "p1" || got["note"] != "unchanged" {
			t.Fatalf("unexpected request body: %#v", got)
		}
		keys = append(keys, key)
		return authBindingResponse(http.StatusServiceUnavailable, "synthetic retry"), nil
	})}
	rec := &HTTPRecorder{URL: "http://recorder.invalid", Client: client}
	for i := 0; i < 2; i++ {
		if err := rec.Record(body); err == nil {
			t.Fatal("non-2xx must remain an error")
		}
	}
	if len(keys) != 2 || keys[0] != keys[1] || body["idempotency_key"] != keys[0] || len(body) != 3 {
		t.Fatalf("idempotency changed: %#v %#v", keys, body)
	}
}

type authBindingRecorder struct {
	calls int
	err   error
}

func (r *authBindingRecorder) Record(map[string]any) error {
	r.calls++
	return r.err
}

func TestAuthBindingProxyCredentialSeparation(t *testing.T) {
	cases := []struct {
		name, configured, xToken, bearer, wantAuth string
		wantStatus, wantCalls                     int
	}{
		{"bearer", "proxy-key", "", "Bearer proxy-key", "", 200, 1},
		{"bearer-case-space", "proxy-key", " \t", "bEaReR   proxy-key  ", "", 200, 1},
		{"separate", "proxy-key", " proxy-key ", "Bearer upstream-key", "Bearer upstream-key", 200, 1},
		{"x-only", "proxy-key", "proxy-key", "", "", 200, 1},
		{"x-precedence", "proxy-key", "wrong", "Bearer proxy-key", "", 401, 0},
		{"missing", "proxy-key", "", "", "", 401, 0},
		{"wrong-bearer", "proxy-key", "", "Bearer wrong", "", 401, 0},
		{"wrong-scheme", "proxy-key", "", "Basic proxy-key", "", 401, 0},
		{"open", "", "ignored", "Bearer upstream-key", "Bearer upstream-key", 200, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &authBindingRecorder{}
			calls := 0
			p := New("http://upstream.invalid", "p1", rec).WithInboundAuth(tc.configured)
			p.client = &http.Client{Transport: authBindingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != tc.wantAuth {
					t.Fatal("wrong upstream Authorization disposition")
				}
				for k := range r.Header {
					if strings.HasPrefix(strings.ToLower(k), "x-averin-") {
						t.Fatal("proxy control header forwarded")
					}
				}
				return authBindingResponse(http.StatusOK, `{"choices":[]}`), nil
			})}
			req := httptest.NewRequest(http.MethodPost, "http://proxy.invalid/v1/chat/completions", strings.NewReader(`{"model":"synthetic"}`))
			req.Header.Set("X-Averin-Proxy-Token", tc.xToken)
			req.Header.Set("X-Averin-Session-Id", "synthetic-session")
			req.Header.Set("Authorization", tc.bearer)
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != tc.wantStatus || calls != tc.wantCalls || rec.calls != tc.wantCalls {
				t.Fatalf("status=%d upstream=%d recorder=%d", w.Code, calls, rec.calls)
			}
			if req.Header.Get("Authorization") != tc.bearer {
				t.Fatal("caller request header mutated")
			}
		})
	}
}

func TestAuthBindingProxyHealthRemainsOpen(t *testing.T) {
	rec := &authBindingRecorder{}
	p := New("http://upstream.invalid", "p1", rec).WithInboundAuth("proxy-key")
	calls := 0
	p.client = &http.Client{Transport: authBindingTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected transport")
	})}
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://proxy.invalid/healthz", nil))
	if w.Code != 200 || w.Body.String() != "ok" || calls != 0 || rec.calls != 0 {
		t.Fatal("health request was gated, relayed or recorded")
	}
}

func TestAuthBindingRecordingFailureLoggedWithoutFailingUpstream(t *testing.T) {
	var logs bytes.Buffer
	oldWriter, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	}()
	rec := &authBindingRecorder{err: fmt.Errorf("synthetic recorder rejection")}
	p := New("http://upstream.invalid", "p1", rec).WithInboundAuth("proxy-key")
	calls := 0
	p.client = &http.Client{Transport: authBindingTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return authBindingResponse(http.StatusOK, `{"choices":[]}`), nil
	})}
	req := httptest.NewRequest(http.MethodPost, "http://proxy.invalid/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("X-Averin-Proxy-Token", "proxy-key")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != `{"choices":[]}` || calls != 1 || rec.calls != 1 {
		t.Fatal("recording failure changed upstream result or call count")
	}
	if !strings.Contains(logs.String(), "synthetic recorder rejection") || !strings.Contains(logs.String(), "NOT in the evidence trail") {
		t.Fatal("recording failure not reported")
	}
}
