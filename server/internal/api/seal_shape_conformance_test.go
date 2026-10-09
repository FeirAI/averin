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
// domain or canon_version. Every checkpoint goes through createCheckpointTx and the core's
// SealCheckpoint, which refuses a body that verify_checkpoint_sealed would reject on domain or
// canon_version. This TestMain records every body the WHOLE api test suite seals through the real cgo
// path (the suite drives each producer: generic ingest, grants, denials, use receipts, two-phase use,
// introspection, void, delegation, checkpoints with and without per-broker grant heads, ...), so
// TestMain can fail the run if any producer was refused, and AVERIN_PRINT_SEALED_KINDS=1 prints which
// kinds were exercised.

var (
	sealObsMu   sync.Mutex
	sealObsKind = map[string]int{}
	sealObsBad  []string
)

func kindOf(kind core.SealKind, body string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return string(kind) + " unparseable"
	}
	if kind == core.SealKindCheckpoint {
		// The one server checkpoint producer (createCheckpointTx) builds two shapes: with the per-broker
		// broker_grant_heads map (WithBrokerID) and without it.
		_, fed := m["broker_grant_heads"]
		_, head := m["broker_grant_head"]
		return fmt.Sprintf("checkpoint broker_grant_head=%t broker_grant_heads=%t", head, fed)
	}
	ev, _ := m["event_type"].(string)
	rk, _ := m["record_kind"].(string)
	act, _ := m["action"].(string)
	if i := strings.IndexAny(act, ":"); i > 0 {
		act = act[:i]
	}
	// The producer site is told apart by authority.grant_type and authority.enforcement_point as well,
	// so e.g. the native oauth-scope grant and the ID-JAG grant, or the introspection receipt and the
	// use receipt, are separate families that must each be reached.
	var gt, ep string
	if a, ok := m["authority"].(map[string]any); ok {
		gt, _ = a["grant_type"].(string)
		ep, _ = a["enforcement_point"].(string)
	}
	var bk string
	if x, ok := m["extensions"].(map[string]any); ok {
		if b, ok := x["broker"].(map[string]any); ok {
			bk, _ = b["kind"].(string)
		}
	}
	return fmt.Sprintf("event_type=%s record_kind=%s action_family=%s grant_type=%s enforcement_point=%s broker_kind=%s", ev, rk, act, gt, ep, bk)
}

func TestMain(m *testing.M) {
	core.SetSealObserver(func(kind core.SealKind, body string, err error) {
		sealObsMu.Lock()
		defer sealObsMu.Unlock()
		sealObsKind[kindOf(kind, body)]++
		if err != nil && strings.Contains(err.Error(), "seal error:") && shapeRefusal(err.Error()) {
			sealObsBad = append(sealObsBad, kindOf(kind, body)+": "+err.Error())
		}
	})
	code := m.Run()
	sealObsMu.Lock()
	bad := append([]string(nil), sealObsBad...)
	sealObsMu.Unlock()
	if len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "SB-29 conformance: a producer emitted a record or checkpoint body seal refuses on shape/domain/canon_version:\n  %s\n", strings.Join(bad, "\n  "))
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
		joined := strings.Join(all, "\n") + "\n"
		for _, want := range []string{
			// One entry per producer site (kindOf adds authority and broker kind to the family).
			"event_type=credential_grant record_kind= action_family=db.query grant_type=id-jag enforcement_point=credential_broker broker_kind=grant",
			"event_type=credential_grant record_kind= action_family=db.query grant_type=oauth-scope enforcement_point=credential_broker broker_kind=grant",
			"event_type=credential_grant_denied",
			"broker_kind=grant_void",
			"broker_kind=use_intent", "broker_kind=use_outcome", "broker_kind=use\n",
			"broker_kind=introspection_transcript",
			"event_type=decision record_kind= action_family=approve grant_type= enforcement_point=sdk",
			"event_type=handoff", "event_type=spawn_child", "event_type=incomplete",
			"record_kind=budget-exhausted", "record_kind=chargeback-posted",
			// Both shapes of the server's checkpoint producer (createCheckpointTx).
			"checkpoint broker_grant_head=true broker_grant_heads=false",
			"checkpoint broker_grant_head=true broker_grant_heads=true",
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
	for _, p := range []string{"missing required field", "unknown top-level field", "domain mismatch", "canon_version mismatch", "is not a JSON object", "is not a string"} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
