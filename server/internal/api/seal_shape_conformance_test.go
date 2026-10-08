package api_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/feirai/averin/server/internal/core"
)

// SB-29 producer conformance. Every record the server emits goes through (*Server).sealAndStore and
// then the cgo core's SealRecord, which now refuses a body that verify_sealed would reject on shape,
// domain or canon_version. This TestMain records every body the WHOLE api test suite seals through the
// real cgo path (the suite drives each producer: generic ingest, grants, denials, use receipts,
// two-phase use, introspection, void, delegation, ...), so TestMain can fail the run if any producer
// was refused, and TestSealShapeProducerKinds can show which kinds were exercised.

var (
	sealObsMu   sync.Mutex
	sealObsKind = map[string]int{}
	sealObsBad  []string
)

func kindOf(body string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return "unparseable"
	}
	ev, _ := m["event_type"].(string)
	rk, _ := m["record_kind"].(string)
	act, _ := m["action"].(string)
	if i := strings.IndexAny(act, ":"); i > 0 {
		act = act[:i]
	}
	return fmt.Sprintf("event_type=%s record_kind=%s action_family=%s", ev, rk, act)
}

func TestMain(m *testing.M) {
	core.SetSealObserver(func(body string, err error) {
		sealObsMu.Lock()
		defer sealObsMu.Unlock()
		sealObsKind[kindOf(body)]++
		if err != nil && strings.Contains(err.Error(), "seal error:") && shapeRefusal(err.Error()) {
			sealObsBad = append(sealObsBad, kindOf(body)+": "+err.Error())
		}
	})
	code := m.Run()
	sealObsMu.Lock()
	bad := append([]string(nil), sealObsBad...)
	sealObsMu.Unlock()
	if len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "SB-29 conformance: a producer emitted a body seal refuses on shape/domain/canon_version:\n  %s\n", strings.Join(bad, "\n  "))
		code = 1
	}
	if os.Getenv("AVERIN_PRINT_SEALED_KINDS") != "" {
		sealObsMu.Lock()
		for k, n := range sealObsKind {
			fmt.Fprintf(os.Stderr, "SEALED %d %s\n", n, k)
		}
		sealObsMu.Unlock()
	}
	// On a full run (no -run filter) every producer family must have been reached, so a green run cannot
	// mean "the suite stopped exercising that producer". Substrings of kindOf's rendering.
	if f := flag.Lookup("test.run"); f == nil || f.Value.String() == "" {
		sealObsMu.Lock()
		var all []string
		for k := range sealObsKind {
			all = append(all, k)
		}
		sealObsMu.Unlock()
		joined := strings.Join(all, "\n")
		for _, want := range []string{
			"event_type=credential_grant ", "event_type=credential_grant_denied", "event_type=credential_grant_void",
			"event_type=tool_call", "action_family=use_outcome", "event_type=decision", "event_type=handoff",
			"event_type=spawn_child", "event_type=incomplete", "record_kind=budget-exhausted", "record_kind=chargeback-posted",
		} {
			if !strings.Contains(joined, want) {
				fmt.Fprintf(os.Stderr, "SB-29 conformance: the suite no longer seals any record of kind %q through the real core\n", want)
				code = 1
			}
		}
	}
	if v := core.SealShapeViolations(); v != 0 {
		fmt.Fprintf(os.Stderr, "SB-29 conformance: %d bodies were sealed in shadow mode despite failing the shape check\n", v)
		code = 1
	}
	os.Exit(code)
}

// shapeRefusal says whether a seal error is one of the SB-29 shape, domain or canon_version refusals.
func shapeRefusal(msg string) bool {
	for _, p := range []string{"missing required field", "unknown top-level field", "domain mismatch", "canon_version mismatch", "is not a JSON object"} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
