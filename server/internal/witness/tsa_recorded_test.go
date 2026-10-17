package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// The fixtures in testdata are responses recorded from live timestamp authorities on 2026-10-15
// (FreeTSA, DigiCert, Sectigo) for the SHA-256 of message.txt. The matching *.tsq is the request
// openssl built for that exchange; each authority accepted it.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The client's own request must be byte-identical to the one the real authorities accepted. A change to
// BuildTimeStampReq that breaks that equivalence fails here.
func TestBuildTimeStampReqMatchesRequestRealTSAsAccepted(t *testing.T) {
	msg := readFixture(t, "message.txt")
	sum := sha256.Sum256(msg)
	got, err := BuildTimeStampReq(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"freetsa", "digicert", "sectigo"} {
		if want := readFixture(t, name+".tsq"); !bytes.Equal(got, want) {
			t.Fatalf("%s: request differs from the accepted one\n got %x\nwant %x", name, got, want)
		}
	}
}

// Each recorded TimeStampResp, served over HTTP, must come out of HTTPTSA.Stamp as the bare token that the
// verifier (core/tests/fixtures/tsa/*.token.der, same bytes) verifies.
func TestHTTPTSAUnwrapsRecordedRealResponses(t *testing.T) {
	msg := readFixture(t, "message.txt")
	sum := sha256.Sum256(msg)
	for _, name := range []string{"freetsa", "digicert", "sectigo"} {
		resp := readFixture(t, name+".tsr")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			if !bytes.Equal(body, readFixture(t, name+".tsq")) {
				t.Errorf("%s: server saw a request unlike the recorded one", name)
			}
			w.Write(resp)
		}))
		tok, err := (&HTTPTSA{URL: srv.URL}).Stamp(context.Background(), sum[:])
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile("../../../core/tests/fixtures/tsa/" + name + ".token.der")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(tok, want) {
			t.Fatalf("%s: unwrapped token differs from the recorded bare token (%d vs %d bytes)", name, len(tok), len(want))
		}
	}
}

func TestHTTPTSASendsConfiguredAuthorization(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write(readFixture(t, "digicert.tsr"))
	}))
	defer srv.Close()
	imp := sha256.Sum256([]byte("x"))
	if _, err := (&HTTPTSA{URL: srv.URL, Authorization: "Basic dXNlcjpwdw=="}).Stamp(context.Background(), imp[:]); err != nil {
		t.Fatal(err)
	}
	if got != "Basic dXNlcjpwdw==" {
		t.Fatalf("Authorization = %q", got)
	}
	got = "unset"
	if _, err := (&HTTPTSA{URL: srv.URL}).Stamp(context.Background(), imp[:]); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("Authorization sent without configuration: %q", got)
	}
}

func TestTSAPresets(t *testing.T) {
	p, err := LookupTSAPreset(" FreeTSA ")
	if err != nil || p.URL != "https://freetsa.org/tsr" || p.SPKIB64 == "" {
		t.Fatalf("freetsa preset: %+v %v", p, err)
	}
	if _, err := LookupTSAPreset("nope"); err == nil {
		t.Fatal("unknown preset accepted")
	}
}
