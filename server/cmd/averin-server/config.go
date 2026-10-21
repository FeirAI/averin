package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/api"
)

// boolFromEnv parses 1/true/0/false (case-insensitive); empty is false.
func boolFromEnv(name, raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("%s must be 1/true/0/false (got %q)", name, raw)
}

// devModeFromEnv parses AVERIN_DEV_MODE. It is the only switch that permits an open API, the volatile
// store and the dev seed.
func devModeFromEnv(raw string) (bool, error) { return boolFromEnv("AVERIN_DEV_MODE", raw) }

// contentDirRefusal is the startup guard for durable records with volatile disclosure content. When records are
// durable (AVERIN_DATABASE_URL set) but AVERIN_CONTENT_DIR is unset, the raw values behind selective disclosure
// would live only in memory: lost on every restart while the records stay, and (before the dev cap) growing
// without bound. Outside dev mode that combination is refused; dev mode keeps the in-memory store (capped).
func contentDirRefusal(devMode bool, databaseURL, contentDir string) error {
	if devMode || strings.TrimSpace(databaseURL) == "" || contentDir != "" {
		return nil
	}
	return fmt.Errorf("AVERIN_DATABASE_URL is set (records are durable) but AVERIN_CONTENT_DIR is not: the raw input/output/rationale values behind selective disclosure would be held in memory only, lost on every restart while their records remain, so disclosures would silently stop working. Set AVERIN_CONTENT_DIR (and AVERIN_CONTENT_MASTER_KEY) to a durable directory, or set AVERIN_DEV_MODE=1 for development (which keeps a volatile, size-capped in-memory store)")
}

// contentMemMaxBytesFromEnv parses AVERIN_CONTENT_MEM_MAX_BYTES, the byte cap of the dev in-memory content store.
// Empty is the default (content.DefaultMemMaxBytes, returned as 0 for "use the default"); it must be positive.
func contentMemMaxBytesFromEnv(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("AVERIN_CONTENT_MEM_MAX_BYTES must be a positive integer (got %q)", raw)
	}
	return n, nil
}

// requireProdSecretsFromEnv decides the production gate (AVE-06). Unset: on, unless dev mode. Explicit 1:
// on. Explicit 0: off, but only inside dev mode, so a stray 0 cannot turn the gate off in production.
func requireProdSecretsFromEnv(raw string, devMode bool) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return !devMode, nil
	}
	v, err := boolFromEnv("AVERIN_REQUIRE_PROD_SECRETS", raw)
	if err != nil {
		return false, err
	}
	if !v && !devMode {
		return false, fmt.Errorf("AVERIN_REQUIRE_PROD_SECRETS=0 is refused outside development: the production gate is on by default and is turned off only with AVERIN_DEV_MODE=1")
	}
	return v, nil
}

// requireBodyBoundFromEnv decides strict body-bound approval proofs (AVE-06). Unset: on, unless dev mode.
// An explicit value always wins, so a migration can still opt out with 0 (logged loudly by the caller).
func requireBodyBoundFromEnv(raw string, devMode bool) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return !devMode, nil
	}
	return boolFromEnv("AVERIN_REQUIRE_BODY_BOUND_AUTHORITY", raw)
}

// nonNegativeIntFromEnv parses a count; empty is 0 (off).
func nonNegativeIntFromEnv(name, raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer (got %q)", name, raw)
	}
	return n, nil
}

type budgetJSON struct {
	PerProjectPerSec float64 `json:"per_project_per_sec"`
	PerProjectBurst  int     `json:"per_project_burst"`
	GlobalPerSec     float64 `json:"global_per_sec"`
	GlobalBurst      int     `json:"global_burst"`
	MaxProjects      int     `json:"max_projects"`
}

// parseBudget reads "" / "0" / "false" (off, nil), "1" / "true" (on, defaults) or a JSON object. Unknown
// fields and negative values are errors, so a typo cannot silently leave a limit unset.
func parseBudget(name, raw string) (*budgetJSON, error) {
	t := strings.TrimSpace(raw)
	switch strings.ToLower(t) {
	case "", "0", "false":
		return nil, nil
	case "1", "true":
		return &budgetJSON{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(t)))
	dec.DisallowUnknownFields()
	var b budgetJSON
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%s must be 0, 1 or a JSON object of per_project_per_sec, per_project_burst, global_per_sec, global_burst, max_projects: %v", name, err)
	}
	if b.PerProjectPerSec < 0 || b.PerProjectBurst < 0 || b.GlobalPerSec < 0 || b.GlobalBurst < 0 || b.MaxProjects < 0 {
		return nil, fmt.Errorf("%s: values must not be negative", name)
	}
	return &b, nil
}

// ingestBudgetFromEnv returns the ingest rate limit for AVERIN_INGEST_BUDGET, or nil when off.
func ingestBudgetFromEnv(raw string) (*api.IngestBudget, error) {
	b, err := parseBudget("AVERIN_INGEST_BUDGET", raw)
	if err != nil || b == nil {
		return nil, err
	}
	return &api.IngestBudget{PerProjectPerSec: b.PerProjectPerSec, PerProjectBurst: b.PerProjectBurst,
		GlobalPerSec: b.GlobalPerSec, GlobalBurst: b.GlobalBurst, MaxProjects: b.MaxProjects}, nil
}

// deniedGrantBudgetFromEnv returns the denial-seal budget; unset or 0/1 gives the defaults.
func deniedGrantBudgetFromEnv(raw string) (api.DenialBudget, error) {
	b, err := parseBudget("AVERIN_DENIED_GRANT_BUDGET", raw)
	if err != nil || b == nil {
		return api.DenialBudget{}, err
	}
	return api.DenialBudget{PerProjectPerSec: b.PerProjectPerSec, PerProjectBurst: b.PerProjectBurst,
		GlobalPerSec: b.GlobalPerSec, GlobalBurst: b.GlobalBurst, MaxProjects: b.MaxProjects}, nil
}

type approverBindingPolicy struct {
	on    bool
	since string
}

// requireApproverBindingFromEnv decides AVE-10. Unset: on, unless dev mode. An explicit value wins. since
// must be a canonical timestamp and needs the policy on.
func requireApproverBindingFromEnv(raw, since string, devMode bool) (approverBindingPolicy, error) {
	on := !devMode
	if strings.TrimSpace(raw) != "" {
		v, err := boolFromEnv("AVERIN_REQUIRE_APPROVER_BINDING", raw)
		if err != nil {
			return approverBindingPolicy{}, err
		}
		on = v
	}
	since = strings.TrimSpace(since)
	if since != "" {
		t, err := time.Parse("2006-01-02T15:04:05.000Z", since)
		if err != nil || t.UTC().Format("2006-01-02T15:04:05.000Z") != since {
			return approverBindingPolicy{}, fmt.Errorf("AVERIN_APPROVER_BINDING_SINCE must be a canonical timestamp YYYY-MM-DDTHH:MM:SS.mmmZ (got %q)", since)
		}
		if !on {
			return approverBindingPolicy{}, fmt.Errorf("AVERIN_APPROVER_BINDING_SINCE needs AVERIN_REQUIRE_APPROVER_BINDING on")
		}
	}
	return approverBindingPolicy{on: on, since: since}, nil
}
