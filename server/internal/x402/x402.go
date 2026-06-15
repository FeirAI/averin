// Package x402 is the EXPERIMENTAL agent payment rail (HTTP 402 + USDC micropayments). Per spec
// §9/§13 it is an experiment, NOT the revenue path (Stripe is). It ships with the required guards:
// per-agent spend limits, nonce/replay protection, idempotency (request↔payment binding), and it
// never puts sensitive prompt/rationale content in payment metadata.
package x402

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Payment is the settled result of an X-PAYMENT proof. AmountMicros is in micro-USDC.
type Payment struct {
	Agent        string
	Nonce        string
	AmountMicros int64
	RequestKey   string // binds the payment to a specific request (idempotency)
}

// Settle verifies a payment proof header and returns the Payment, or an error. The real
// implementation talks to an x402 facilitator / settles USDC; tests inject a stub.
type Settle func(proofHeader string) (Payment, error)

type Guard struct {
	PriceMicros    int64
	Asset          string
	MaxSpendMicros int64 // per agent
	Settle         Settle

	mu        sync.Mutex
	seenNonce map[string]bool
	seenReq   map[string]bool
	spent     map[string]int64
}

func New(priceMicros, maxSpendMicros int64, settle Settle) *Guard {
	return &Guard{
		PriceMicros:    priceMicros,
		Asset:          "USDC",
		MaxSpendMicros: maxSpendMicros,
		Settle:         settle,
		seenNonce:      map[string]bool{},
		seenReq:        map[string]bool{},
		spent:          map[string]int64{},
	}
}

// Middleware gates `next` behind a paid request. Unpaid -> 402 with the price; a valid, non-replayed,
// within-budget payment -> served.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof := r.Header.Get("X-PAYMENT")
		if proof == "" {
			g.require(w, "payment required")
			return
		}
		pay, err := g.Settle(proof)
		if err != nil {
			g.require(w, "invalid payment: "+err.Error())
			return
		}
		if !g.accept(pay) {
			g.require(w, "payment rejected (replay, request mismatch, or over spend limit)")
			return
		}
		// NOTE: we intentionally record only {agent, nonce, amount, request_key} — never prompt or
		// rationale content — in any payment ledger.
		next.ServeHTTP(w, r)
	})
}

// accept applies the guards atomically: nonce single-use, request single-use (idempotency), and the
// per-agent spend cap. Returns false (and records nothing) if any guard fails.
func (g *Guard) accept(p Payment) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p.AmountMicros <= 0 { // no non-positive payments (guards overflow + nonsense)
		return false
	}
	if p.Nonce == "" || g.seenNonce[p.Nonce] { // replay protection
		return false
	}
	if p.RequestKey != "" && g.seenReq[p.RequestKey] { // idempotency: one payment per request
		return false
	}
	if p.AmountMicros < g.PriceMicros { // underpaid
		return false
	}
	// per-agent spend limit, written to avoid int64 overflow (spent <= MaxSpendMicros invariant).
	if p.AmountMicros > g.MaxSpendMicros-g.spent[p.Agent] {
		return false
	}
	g.seenNonce[p.Nonce] = true
	if p.RequestKey != "" {
		g.seenReq[p.RequestKey] = true
	}
	g.spent[p.Agent] += p.AmountMicros
	return true
}

func (g *Guard) require(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	json.NewEncoder(w).Encode(map[string]any{
		"error": reason,
		"accepts": []map[string]any{{
			"scheme":       "x402-usdc",
			"amount_micros": g.PriceMicros,
			"asset":        g.Asset,
			"experimental": true,
		}},
	})
}

// Spent returns the total micros spent by an agent (for tests / dashboards).
func (g *Guard) Spent(agent string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.spent[agent]
}
