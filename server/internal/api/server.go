// Package api is the averin ingestion + app HTTP server. It assigns server-controlled fields,
// derives the causal DAG links and the frontier, and routes all canonicalize/seal/verify work
// through the Rust core (the single source of truth). The store is append-only.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/meter"
	"github.com/feirai/averin/server/internal/metrics"
	"github.com/feirai/averin/server/internal/otel"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/witness"
)

// Sealer is the subset of the Rust core the API needs.
type Sealer interface {
	SealRecord(bodyJSON string) (string, error)
	SealCheckpoint(bodyJSON string) (string, error)
	VerifyBundle(bundleJSON string) string
	// VerifyBundleWithAuthority pins authority keys (the broker recording key) so credential-broker
	// grants elevate to gateway_enforced (Level 3 Tier-A grant accountability).
	VerifyBundleWithAuthority(bundleJSON string, authorityPubKeys []string) string
	// VerifyBundleWithRoles pins broker + resource recording keys separately (ADR 0003 R2), so a
	// grant elevates only under a broker key and a use receipt only under a resource key.
	VerifyBundleWithRoles(bundleJSON string, brokerKeys, resourceKeys []string) string
	// VerifyBundleWith pins the FULL role-disjoint trust set from a JSON opts object (broker/resource/
	// revocation/attestation/cosig/federation/tsa) — used by the self-verify endpoint to evaluate every mode
	// the server can attest to, not only grant/use.
	VerifyBundleWith(bundleJSON, optsJSON string) string
	PubKey() string
	// content commitments (RCP §9.3): mint a nonce and commit a low-entropy field at ingest.
	RandomNonce() (string, error)
	Commit(domain string, value []byte, nonceHex string) (string, error)
	// authority evidence: the credential broker signs a gateway_enforced grant (RCP §11).
	SignEvidence(source, projectID, recordID, evidenceHash string) (string, error)
	// RcpEvidenceHash derives evidence_hash = sha256(RCP-canonicalize(payload)) so the verifier can
	// re-derive it from the embedded grant_evidence (ADR 0003 R1).
	RcpEvidenceHash(payloadJSON string) (string, error)
}

type Server struct {
	core      Sealer
	st        store.Store
	content   content.Store // raw low-entropy values (committed at ingest, revealed on disclosure)
	meter     meter.Meter
	auth      auth.KeyStore      // nil = no per-project auth (dev/single-tenant)
	witness   witness.Witness    // nil = no external witness configured
	tsa       witness.TSA        // nil = no external timestamp anchoring configured
	brokerKey ed25519.PrivateKey // nil = credential broker (/v2/grants) disabled
	// M4 (ADR 0005): this broker's federation identity. When set, every grant this server issues is tagged with
	// grant_evidence.broker_id, and each checkpoint ALSO carries a per-broker_id `broker_grant_heads` map (in
	// addition to the legacy single `broker_grant_head`), so its bundles verify under `federated_broker_keys` and
	// can be combined with OTHER brokers' bundles without one broker's grants masking another's. "" = single-broker
	// (legacy byte-identical path — no broker_id, no map).
	brokerID string
	// brokerSeqVoidMinAge is the safety age a reserved broker_seq must reach before POST /v2/broker-seq/void may
	// fill it with a grant_void tombstone (AVERIN_BROKER_SEQ_VOID_MIN_AGE; DefaultBrokerSeqVoidMinAge).
	brokerSeqVoidMinAge time.Duration
	// seqAttempts is the void's second age input: the app-clock time of the LATEST attempt (allocate or settle) of
	// each grant_id that allocated/reused a broker_seq on THIS process, keyed project\x00grant_id. The store's
	// allocated_at is stamped only on the fresh insert (Postgres cannot refresh it — broker_seq is insert-only), so
	// without this a retry at T0+59m whose commit is still in flight would not stop a void at T0+60m. Entries older
	// than brokerSeqVoidMinAge can no longer block a void and are pruned (see noteSeqAttempt). Guarded by
	// seqAttemptsMu. Process-local: a multi-instance deployment is closed only by the UNIQUE record_id index.
	seqAttemptsMu      sync.Mutex
	seqAttempts        map[string]time.Time
	seqAttemptsPruneAt int
	// processStart is the BOOT FLOOR of the void's age: seqAttempts is in-memory, so after a restart it has
	// forgotten every attempt made by the previous process (a retry whose commit may still be in flight). The age
	// is therefore measured from max(allocated_at, latest attempt, processStart). Stamped from the server's clock
	// at construction (New) and re-stamped by WithClock, so a test clock drives it too.
	processStart time.Time
	// M5 (ADR 0005): the revocation authority key (role-separated from broker/resource/signing/attestation/TSA).
	// When set, POST /v2/revoke records a grant_id as revoked, and each /v2/export carries a signed, time-bounded
	// revocation_list over the project's revoked set (the verifier blocks any use of a revoked grant). nil =
	// revocation disabled. `revoked` is the in-memory READ cache; when `durable` is set (AVERIN_DATABASE_URL),
	// every revoke is persisted to Postgres FIRST (fail-closed) and the cache is rehydrated from it at boot —
	// see WithDurable. With no durable store configured it stays in-memory only, as before.
	revocationKey ed25519.PrivateKey
	revoked       map[string]map[string]struct{} // projectID -> IMMUTABLE set of revoked grant_ids (copy-on-write)
	// revokedMu guards the top-level `revoked` map ONLY — it is never held across the durable Revoke() Postgres
	// round-trip. Each per-project set is IMMUTABLE once published: handleRevoke builds a new set (old ∪ {id})
	// and swaps it in under revokedMu, so readers (isRevoked on the /v2/use path, the export) take ONLY
	// revokedMu for a pointer read and then range the snapshot lock-free. The cap-check-then-persist-then-publish
	// for a SINGLE project must still stay atomic (finding C), so handleRevoke serializes per-project via
	// revokeLocks, which IS held across the durable round-trip — but no reader ever takes revokeLocks, so a slow
	// revoke can never stall /v2/use (which runs under the process-wide ingestMu).
	revokedMu          sync.Mutex
	revokeLocks        keyedMutex
	revokeCapWarnAt    time.Time // throttles the at-capacity WARNING (guarded by revokeLocks, keyed by project_id)
	revocationValidity time.Duration
	revocationCap      int
	denyLog            bool // B11: seal a denied-grant record on a POLICY denial (opt-in, off by default)
	// #47: optional rate limit on best-effort B11 denial seals so a varying-scope/PoP-brute-force sweep cannot
	// inflate stored records without bound (the prerequisite for default-on). nil = unbounded (prior behavior).
	denialBudget *denialBudget
	// averin#20: optional coarse per-project + global token bucket on state-mutating POST /v2/* ingest, so a
	// leaked token (or an unauthenticated default deploy) cannot drive unbounded billable, append-only DB growth.
	// Reuses the denial_budget.go two-level bucket. nil = unlimited (the prior behavior — this is opt-in
	// defense-in-depth; a reverse-proxy/gateway limit remains the PRIMARY, HARD control, see CONFIGURATION.md).
	ingestBudget *denialBudget
	// T7 (ADR 0002 / coverage-limits #4): pinned EXTERNAL authority verifying keys, keyed by
	// (project, source). When a generic record carries a matching source plus an authority evidence_sig
	// that verifies under the key pinned for THAT (project, source), it is stamped with that elevated
	// source (else forced to caller_declared). An empty map = Phase-1 default (every generic authority is
	// caller_declared). Each external authority holds the private half OUT of this server. Distinct
	// sources MAY be served by distinct keys (e.g. the policy engine signs policy_engine_signed, a
	// separate human-approval service signs human_signed) so a record signed by the matching key elevates
	// to ITS source — exactly the verifier's per-source trusted_authority_keys model.
	//
	// PROJECT SCOPING (F1). A pin with project=="" is the GLOBAL default (the historical, single-key
	// behavior). A pin with a non-empty project applies to THAT project only and WINS over the global
	// default. This exists because the upstream authority (govder) derives its signing key per
	// (tenant, role) and govder's tenant IS the averin project — so a single global key per source can
	// only ever elevate ONE tenant's records. Every other tenant's policy_engine_signed / human_signed /
	// delegate_signed records failed key verification and were silently sealed at the forgeable
	// caller_declared. A global-only pin is also authoritative in EVERY project, so the project_id bound
	// into the authority preimage stopped a signed block being COPIED across projects but did not stop
	// the holder of one tenant's key from minting a fresh, valid block for another tenant's project.
	policyEngineKeys map[authorityPin]ed25519.PublicKey
	// Tier-B resource side (ADR 0003): the resource recording key signs use-receipt authority evidence
	// (role-separated from the broker key, R2); resourceID is this resource's audience.
	// The project Store transaction owns consume-before-act claims. nil disables /v2/use.
	resourceCore Sealer
	resourceID   string
	// M3 (ADR 0005 — Native/STS): the RAW resource recording key (the same key resourceCore wraps). The
	// introspection-transcript producer needs it to sign the structured averin.resource.introspection.v1 challenge
	// (over raw bytes), which the FFI core's tagged SignEvidence cannot do. nil = POST /v2/introspection disabled.
	resourceRawKey ed25519.PrivateKey
	// D7.2 (ADR 0004): the deployment-attestation issuing key (role-separated from broker/resource/TSA).
	// nil = no attestation emitted on export (a bundle then verifies attestation_status:"unevaluated").
	attestKey ed25519.PrivateKey
	// attestIssuedSkew / attestValidity define the attestation freshness window around the latest
	// checkpoint's created_ts (the verifier checks the anchored TSA genTime against it, NOT export time).
	// Set by WithAttestation; overridable via WithAttestationWindow.
	attestIssuedSkew time.Duration
	attestValidity   time.Duration
	// externalVerifyAttestationKeys / externalVerifyTSASPKI are PUBLIC, operator-pinned auditor
	// roots used by the product-facing /v2/verify view. They are deliberately separate from the
	// producer's private attestation key and TSA client: without both external roots configured,
	// selfVerifyOpts leaves D7 unevaluated exactly as before.
	externalVerifyAttestationKeys []ed25519.PublicKey
	externalVerifyTSASPKI         [][]byte
	// D4/D8 operation-taxonomy roots used by the product-facing self-view. The signed
	// artifact and every pin are operator/auditor supplied; the producer never derives
	// them from observed records (which would make the coverage claim self-validating).
	externalVerifyTaxonomy        json.RawMessage
	externalVerifyTaxonomyKeys    []ed25519.PublicKey
	externalVerifyTaxonomyDigest  string
	externalVerifyTaxonomyVersion int64
	// T6/D8 (ADR 0004): the operator-declared coverage_manifest (raw JSON, e.g. a side_effect_closure).
	// Emitted verbatim in every export bundle, and its RCP-canonical digest is bound into the
	// deployment_attestation subject so the two cannot diverge. Empty = no manifest (capstone stays at most
	// claimed_over_manifest). This is a DECLARATION, never auto-derived from what happened.
	coverageManifest string
	signingKeyID     string
	keyValidFrom     string
	now              func() time.Time // injectable clock for tests
	// M6/M2 (ADR 0005) — the ONLINE two-phase grant flow (/v2/grants/prepare + /v2/grants/finalize). A
	// cosigned/delegated grant is inherently two-phase: the cosig/delegation challenge binds the broker-MINTED
	// credential_binding/exp, so an approver/delegator can only sign AFTER the broker prepares + reveals it.
	// `pending` holds the minted-but-uncommitted broker.Prepared between the two phases, keyed by project:idem,
	// WITHOUT a broker_seq (the seq is allocated at FINALIZE, under ingestMu, so the seq order == the record
	// commit order and the D6 grant log stays a gapless prefix). `pending` is the in-memory READ cache; when
	// `durable` is set (AVERIN_DATABASE_URL), every fresh mint is persisted to Postgres FIRST (fail-closed)
	// before it is cached, and the cache is rehydrated from it at boot — see WithDurable. With no durable
	// store configured it stays in-memory only, as before: a restart mid-approval loses the pending mint. With
	// a durable store, a same-idem-key mint race across REPLICAS sharing one AVERIN_DATABASE_URL is now also
	// coordinated: pgdurable.PutPending detects the conflict and the loser serves the winner's durable
	// challenge instead of its own (see handleGrantPrepare) — but WITHIN a single process, same-key prepares
	// still fully serialize via pendingKeyLocks below, and different instances still mint independently rather
	// than negotiating who mints at all (only the after-the-fact conflict is resolved, not prevented).
	// cosigApprovers/cosigThreshold are the SERVER-pinned M-of-N policy a finalize's cosignatures are
	// validated against (never client-supplied).
	pending map[string]*pendingGrant
	// pendingMu guards STRUCTURAL access to `pending` ONLY (lookup/insert/delete) — it is never held across
	// the durable PutPending Postgres round-trip. The idempotent-mint-check-then-persist-then-cache for a
	// SINGLE idem key must still stay atomic (finding C), so handleGrantPrepare instead serializes per-idem-key
	// via pendingKeyLocks, which IS held across that round-trip; different idem keys' prepares run fully
	// concurrently under it (a slow/degraded Postgres no longer stalls every prepare process-wide).
	pendingMu       sync.Mutex
	pendingKeyLocks keyedMutex
	cosigThreshold  int
	cosigApprovers  []ed25519.PublicKey
	// durable optionally backs `revoked` and `pending` with Postgres (AVERIN_DATABASE_URL) — see WithDurable.
	// nil = both stay in-memory only (dev/single-process), matching the pre-durability behavior exactly.
	durable durableWriter
	// ingestMu serializes the heads->seal->put critical section so concurrent ingests cannot read
	// a stale frontier and fork the DAG (the Postgres store will do this in a serializable tx).
	ingestMu sync.Mutex
	// checkpointMu serializes checkpoint creation so concurrent calls cannot read the same
	// NextCheckpointSeq and fork the checkpoint chain.
	checkpointMu sync.Mutex

	// requirePinnedAuthority (AVERIN_REQUIRE_PINNED_AUTHORITY, default ON since F3) makes an
	// authority-BEARING record whose CLAIMED elevation (policy_engine_signed / human_signed /
	// delegate_signed) FAILS key verification REJECT the ingest (fail-closed) instead of silently sealing it
	// downgraded to the forgeable caller_declared. Off restores the Phase-1 silent downgrade — an explicit,
	// logged fail-OPEN opt-out.
	//
	// The default lives in New() (NOT in the zero value) and is ON, so an embedder and the shipped
	// averin-server binary get the SAME posture — a test suite running fail-open while production runs
	// fail-closed would be testing a different server than the one that ships. See normalizeAuthority.
	requirePinnedAuthority bool
	// authorityDowngradeLogAt throttles the WARNING that names a failed authority elevation (a govder/averin
	// key misalignment can otherwise spam it on every ingest). Guarded by ingestMu: normalizeAuthority — its
	// only writer — is only ever called from ingestOne while ingestMu is held, so it needs no extra lock.
	authorityDowngradeLogAt time.Time
	// bundleSem caps concurrent whole-project bundle builds (GET /v2/export + /v2/verify). Each buildBundle
	// materializes the project's full record+checkpoint history in RAM (see docs/dev/LIMITATIONS.md), so a
	// burst of large exports could otherwise exhaust memory. A full-scan build under this cap is also lifted
	// off the server's finite WriteTimeout (per-handler deadline) so a large-but-legitimate export is not
	// hard-killed mid-write. Buffered to maxConcurrentBundleReads; a saturated cap yields 503.
	bundleSem chan struct{}
	// verifyFlights coalesces concurrent self-verifications for the same project and trust-root configuration.
	// It deliberately has no completed-result cache: writes can land at any time, so a later request must build
	// and verify fresh project state. A flight's work continues independently if one HTTP caller disconnects;
	// otherwise cancellation by one waiter could strand every other waiter or leave an unverified response cached.
	verifyFlights verifyFlightGroup

	// readiness is the set of dependencies GET /readyz probes (each with a short per-request timeout)
	// before reporting 200 — see WithReadiness. Empty (dev / in-memory store, no Postgres configured)
	// means /readyz has nothing to be unready about and always reports ready.
	readiness []readinessTarget

	// metrics is the hand-rolled Prometheus-text registry served at GET /metrics (no
	// prometheus/client_golang — averin stays pgx-only). Never nil (set in New).
	metrics              *metrics.Registry
	mRecordsSealed       *metrics.Counter
	mRecordsSealFailed   *metrics.Counter
	mCheckpointsSealed   *metrics.Counter
	mWitnessFailures     *metrics.Counter
	mAnchorFailures      *metrics.Counter
	mAuthorityDowngrades *metrics.Counter
	mDenialBudgetDrops   *metrics.Counter
	mUseOutcome          *metrics.CounterVec // labeled "outcome": allow | deny
}

// Pinger is a short-timeout dependency health check for GET /readyz (e.g. a pgx pool's Ping).
// Implemented by store.Postgres, pgdurable.Store, and pgledger.Ledger.
type Pinger interface {
	Ping(ctx context.Context) error
}

// readinessTarget names one dependency /readyz probes.
type readinessTarget struct {
	name string
	ping Pinger
}

func New(core Sealer, st store.Store, signingKeyID string) *Server {
	reg := metrics.NewRegistry()
	return &Server{
		core:          core,
		st:            st,
		content:       content.NewMemStore(), // in-memory by default; WithContent for a durable store
		meter:         meter.NewMem(),
		signingKeyID:  signingKeyID,
		keyValidFrom:  "2026-01-01T00:00:00.000Z",
		now:           time.Now,
		processStart:  time.Now(), // the void's boot floor (re-stamped by WithClock)
		revocationCap: maxRevokedPerProject,
		pending:       make(map[string]*pendingGrant), // M6/M2 online two-phase grant flow
		// D6 operator remediation (POST /v2/broker-seq/void): a conservative default safety age.
		brokerSeqVoidMinAge: DefaultBrokerSeqVoidMinAge,
		bundleSem:           make(chan struct{}, maxConcurrentBundleReads),
		// F3: fail-CLOSED authority posture by default. A record CLAIMING an elevated source that averin
		// cannot verify under a pinned key is REJECTED, never silently sealed at the forgeable
		// caller_declared. WithRequirePinnedAuthority(false) is the explicit opt-out.
		requirePinnedAuthority: true,

		metrics: reg,
		mRecordsSealed: reg.Counter("averin_records_sealed_total",
			"Total records successfully sealed by the Rust core (generic ingest, grants, denials, use receipts)."),
		mRecordsSealFailed: reg.Counter("averin_records_seal_failed_total",
			"Total record seal attempts that failed at the Rust core."),
		mCheckpointsSealed: reg.Counter("averin_checkpoints_sealed_total",
			"Total checkpoints successfully sealed."),
		mWitnessFailures: reg.Counter("averin_witness_append_failures_total",
			"Total checkpoint witness-append failures (checkpoint stored un-witnessed, backfillable)."),
		mAnchorFailures: reg.Counter("averin_checkpoint_anchor_failures_total",
			"Total TSA anchor failures (checkpoint stored un-anchored, backfillable)."),
		mAuthorityDowngrades: reg.Counter("averin_authority_downgrades_total",
			"Total records whose caller-claimed elevated authority source (policy_engine_signed/human_signed/"+
				"delegate_signed) was forced back to caller_declared — an unpinned source or a key-misalignment "+
				"(evidence_sig failed to verify under the pinned key)."),
		mDenialBudgetDrops: reg.Counter("averin_denial_budget_drops_total",
			"Total best-effort B11 denied-grant seals dropped by the per-project/global denial budget."),
		mUseOutcome: reg.CounterVec("averin_use_requests_total",
			"Total POST /v2/use (and /v2/use-intent) requests by capability-authorization outcome.", "outcome"),
	}
}

// WithContent swaps in a durable content store (e.g. content.NewFSStore) for the raw low-entropy
// values committed at ingest. Defaults to in-memory.
func (s *Server) WithContent(c content.Store) *Server {
	s.content = c
	return s
}

// WithMeter swaps in a usage meter (e.g. a Stripe reporter). Returns the server for chaining. When m
// is a *meter.StripeReporter, its best-effort async-queue drop count is also exposed on GET /metrics
// (a nonzero, growing rate means billable events — and thus revenue — are being silently lost).
func (s *Server) WithMeter(m meter.Meter) *Server {
	s.meter = m
	if sr, ok := m.(*meter.StripeReporter); ok {
		s.metrics.CounterFunc("averin_meter_queue_drops_total",
			"Total usage-metering events dropped from the async reporter queue under back-pressure.",
			sr.Dropped)
		// averin#15: a delivery failure (transport error or non-2xx, most often an unmapped
		// project→stripe_customer_id) is not retried, so a growing count is silent under-billing.
		s.metrics.CounterFunc("averin_meter_post_failures_total",
			"Total usage-metering events whose Stripe delivery failed (transport error or non-2xx response); not retried.",
			sr.PostFailures)
	}
	return s
}

// WithReadiness registers a named dependency that GET /readyz probes (each with a short per-request
// timeout) before reporting ready. Call once per real out-of-process dependency (a Postgres-backed
// store/ledger/durable-state pool). p == nil is a no-op (so a caller can pass a possibly-nil pointer
// without an extra guard). A deployment that registers none (in-memory store, dev/single-process) has
// nothing to be unready about — /readyz always reports 200 in that case.
func (s *Server) WithReadiness(name string, p Pinger) *Server {
	if p == nil {
		return s
	}
	s.readiness = append(s.readiness, readinessTarget{name: name, ping: p})
	return s
}

// WithGauge registers a named Prometheus-text gauge on GET /metrics backed by fn, read fresh on every
// scrape (e.g. a pgx pool's live connection counts via PoolStat).
func (s *Server) WithGauge(name, help string, fn func() float64) *Server {
	s.metrics.GaugeFunc(name, help, fn)
	return s
}

// WithClock replaces the server's clock (default time.Now) — for tests that must drive time-dependent paths such as
// the broker_seq void's safety age. Pair it with the store's clock (store.Mem.WithClock) when both must agree.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.now = now
	s.processStart = now() // construction-time boot floor, taken from the injected clock (see processStart)
	return s
}

// WithAuth gates the /v2/* routes behind project-scoped API-key auth.
func (s *Server) WithAuth(ks auth.KeyStore) *Server {
	s.auth = ks
	return s
}

// WithWitness appends every sealed checkpoint to a customer-controlled append-only witness
// (out-of-vendor-control) so omitting/rewriting it later is detectable (threats #1/#15).
func (s *Server) WithWitness(w witness.Witness) *Server {
	s.witness = w
	return s
}

// WithBroker enables the credential broker (POST /v2/grants) with the given Ed25519 issuing key
// (which signs the capabilities it mints; its public half is the descriptor kid). The recording key
// that signs the grant's gateway_enforced evidence is the server's own signing key (core). For the
// Tier-A prototype that is broker_trust: assumed — issuing and recording keys are NOT split into a
// reduced TCB (ADR 0002). Nil/unset disables the endpoint.
func (s *Server) WithBroker(issuingKey ed25519.PrivateKey) *Server {
	// R2 (ADR 0003): mirror of WithResource's disjointness check, so a broker/resource key overlap is caught
	// REGARDLESS of call order. WithResource's broker-overlap check is gated on s.brokerKey being set, so
	// calling WithResource BEFORE WithBroker would skip it; this reciprocal check (against an already-set
	// resource key) closes that order dependence — F12 must fail CLOSED on the broker axis, not only the
	// signing axis. The offline verifier also rejects the overlap as a fatal config error; this is the
	// producer fail-fast. A key collision is a programming error -> panic.
	if s.resourceCore != nil {
		if rpub, err := decodePubKey(s.resourceCore.PubKey()); err == nil &&
			bytes.Equal(issuingKey.Public().(ed25519.PublicKey), rpub) {
			panic("WithBroker: broker issuing key must differ from the resource recording key (R2 role separation)")
		}
	}
	s.brokerKey = issuingKey
	return s
}

// WithBrokerID sets this broker's federation identity (ADR 0005 M4). When set, grants this server issues carry
// grant_evidence.broker_id, and checkpoints carry a per-broker_id `broker_grant_heads` map — so the bundle
// verifies under `federated_broker_keys[brokerID]` and is combinable with other brokers' bundles. Requires the
// broker (WithBroker). A single configured broker_id gets the project's gapless [1..N] broker_seq as its own
// partition (the global counter == the one broker's counter); a multi-broker_id deployment would need per-broker
// sequence allocation (not yet — one server = one broker_id).
func (s *Server) WithBrokerID(brokerID string) *Server {
	if s.brokerKey == nil {
		panic("WithBrokerID requires WithBroker (broker_id tags the grants this broker issues)")
	}
	s.brokerID = brokerID
	return s
}

// WithDeniedGrantLog (B11, ADR 0002 open Q4) makes the broker SEAL a `grant_denied` record when it
// refuses a well-formed grant request on policy (forbidden scope, over-cap TTL, failed proof-of-possession)
// — so a metadata-oracle probe leaves tamper-evident evidence instead of an invisible 400. Malformed input
// is never logged (no policy signal). OPT-IN / default OFF: a probing attacker who varies the scope can
// otherwise inflate stored (billable) records; deterministic-id dedup collapses retries of the SAME probe,
// and WithDeniedGrantBudget (#47) bounds the volume of DISTINCT-probe seals — the safeguard a default-on
// posture needs.
func (s *Server) WithDeniedGrantLog() *Server {
	s.denyLog = true
	return s
}

// WithRequirePinnedAuthority (AVERIN_REQUIRE_PINNED_AUTHORITY) sets the fail-closed authority posture: when
// on, a record that CLAIMS an elevated authority source (policy_engine_signed / human_signed / delegate_signed)
// whose evidence does NOT verify under the key pinned for its (project, source) — or whose source is UNPINNED
// for that project — is REJECTED (a retryable ingest error) rather than silently sealed downgraded to
// caller_declared. It is ON by default (New); passing false is the explicit fail-OPEN opt-out that restores the
// Phase-1 silent downgrade. Ordinary caller_declared traffic is never affected either way (it claims no
// elevation to fail). See normalizeAuthority.
func (s *Server) WithRequirePinnedAuthority(v bool) *Server {
	s.requirePinnedAuthority = v
	return s
}

// authorityPin identifies ONE pinned external authority key: the averin project it is authoritative for
// and the authority source it vouches for. Project "" is the GLOBAL default pin (authoritative in any
// project that has no project-scoped pin for the same source) — the historical single-key behavior.
type authorityPin struct {
	project string
	source  string
}

// authorityKeyFor resolves the pinned verifying key for (project, source): the project-scoped pin wins,
// then the global (project=="") default. A miss means the source is UNPINNED for this project, which is a
// FAILED elevation (downgrade, or reject under requirePinnedAuthority) — never a silent pass.
//
// This is the F1 fix: govder derives its authority key per (tenant, role) and govder's tenant is the
// averin project, so a lookup keyed by source ALONE could only ever elevate one tenant.
func (s *Server) authorityKeyFor(project, source string) (ed25519.PublicKey, bool) {
	if key, ok := s.policyEngineKeys[authorityPin{project: project, source: source}]; ok {
		return key, true
	}
	key, ok := s.policyEngineKeys[authorityPin{source: source}]
	return key, ok
}

// WithPolicyEngineKey (T7) pins an EXTERNAL authority's published verifying key + the authority source it
// vouches for ("policy_engine_signed", "human_signed", or "delegate_signed") as the GLOBAL default for
// every project. Use WithProjectAuthorityKey to pin a key for ONE project (multi-tenant: the upstream
// authority derives a distinct key per tenant). It may be called ONCE PER SOURCE: pin the policy engine's
// key for policy_engine_signed AND (separately) a human-approval service's key for human_signed AND a
// delegate-agent authority's key for delegate_signed, so a record signed by the matching key elevates to
// ITS source. At ingest, a generic record whose authority carries a pinned source plus a
// {evidence_hash, evidence_sig} that verifies under that source's key over the canonical authority
// preimage is elevated to that source (so an offline verifier pinning the SAME keys as authority_keys reads
// it as `verified`); anything else — an unpinned source, or a mismatched/forged key — falls back to forgeable
// `caller_declared` (threat #4). Model: each authority signs with its OWN key off-box and the server only
// VERIFIES — keeping those authorities out of the server TCB. Every pinned key MUST be role-separated (the
// verifier does not fold authority_keys into its disjointness check, so we reject the obvious overlaps: the
// server's own signing key, and re-using one key across two authority sources).
func (s *Server) WithPolicyEngineKey(source string, key ed25519.PublicKey) *Server {
	return s.WithProjectAuthorityKey("", source, key)
}

// WithProjectAuthorityKey pins an external authority verifying key for ONE project (F1). It is the
// multi-tenant form of WithPolicyEngineKey: govder derives its authority signing key per (tenant, role) and
// its tenant is the averin project, so a deployment recording more than one tenant MUST pin that tenant's
// key against that tenant's project. A project-scoped pin WINS over the global default for the same source;
// a project with no scoped pin still falls back to the global default (back-compat), and a project with
// neither leaves the source UNPINNED — a failed elevation, never a silent pass.
//
// project "" pins the global default (exactly what WithPolicyEngineKey does).
func (s *Server) WithProjectAuthorityKey(project, source string, key ed25519.PublicKey) *Server {
	// The offline verifier only elevates these three generic authority sources; pinning any other source would
	// make the server stamp records the verifier reads as `declared`, not `verified` (gateway_enforced is the
	// broker's own source, not a generic policy-engine one).
	switch source {
	case "policy_engine_signed", "human_signed", "delegate_signed":
	default:
		panic("WithPolicyEngineKey: source must be policy_engine_signed, human_signed, or delegate_signed")
	}
	if serverPub, err := decodePubKey(s.core.PubKey()); err == nil && key.Equal(serverPub) {
		panic("WithPolicyEngineKey: the authority key must be role-separated from the server signing key")
	}
	if s.policyEngineKeys == nil {
		s.policyEngineKeys = make(map[authorityPin]ed25519.PublicKey, 2)
	}
	pin := authorityPin{project: project, source: source}
	if _, dup := s.policyEngineKeys[pin]; dup {
		panic("WithPolicyEngineKey: source " + source + " already pinned for project " + strconv.Quote(project) + " (pin at most one key per project+source)")
	}
	// Reuse of ONE key across two authority SOURCES would let a record signed for one source be re-labeled with
	// the other's source by a caller (the verifier binds source into the preimage, so this is only a
	// defense-in-depth guard, but it keeps the pinned set as cleanly role-separated as the verifier expects).
	// Re-using one key across two PROJECTS for the SAME source is allowed: the preimage binds project_id, and a
	// single-tenant authority legitimately serves several averin projects.
	for existing, existingKey := range s.policyEngineKeys {
		if existing.source != source && existingKey.Equal(key) {
			panic("WithPolicyEngineKey: this key is already pinned for source " + existing.source + " (one key per source)")
		}
	}
	s.policyEngineKeys[pin] = key
	return s
}

// WithResource enables the Tier-B resource gateway (POST /v2/use) for resourceID, signing use-receipt
// authority evidence with resourceCore's key — which MUST be DISTINCT from the server signing key and
// the broker key (R2 role separation; the verifier rejects a broker/resource key-set overlap). It
// requires the broker to be enabled (the resource verifies capabilities under the broker issuing
// key). The configured project Store supplies consume-before-act claims in the
// same transaction as each receipt. Nil resourceCore disables /v2/use.
func (s *Server) WithResource(resourceCore Sealer, resourceID string) *Server {
	// R2 (ADR 0003): the resource recording key MUST be disjoint from the server signing key and the
	// broker issuing key, else a grant could forge its own use receipt. The offline verifier rejects an
	// overlap as a fatal config error and averin-server checks it at startup — this fail-fasts an embedder
	// that constructs a Server directly. Compares the keys set so far (call WithBroker first for the
	// broker check). A key collision here is a programming error, so it panics.
	if rpub, err := decodePubKey(resourceCore.PubKey()); err == nil {
		if cpub, e := decodePubKey(s.core.PubKey()); e == nil && bytes.Equal(rpub, cpub) {
			panic("WithResource: resource recording key must differ from the server signing key (R2 role separation)")
		}
		if s.brokerKey != nil && bytes.Equal(rpub, s.brokerKey.Public().(ed25519.PublicKey)) {
			panic("WithResource: resource recording key must differ from the broker issuing key (R2 role separation)")
		}
	}
	s.resourceCore = resourceCore
	s.resourceID = resourceID
	return s
}

// WithAttestation enables the D7.2 deployment-attestation export: every /v2/export bundle carries a
// top-level `deployment_attestation` signed by `key` (the attestation issuer, role-separated from
// broker/resource/TSA), binding this bundle's project / latest checkpoint + grant-head / authority key
// ids / resource ids. A verifier that pins this key (out of band) elevates `attestation_status` toward
// `attested_claims`; the attestation asserts a CLAIM exists, never runtime enforcement (ADR 0004 D7).
func (s *Server) WithAttestation(key ed25519.PrivateKey) *Server {
	pub := key.Public().(ed25519.PublicKey)
	if cpub, err := decodePubKey(s.core.PubKey()); err == nil && bytes.Equal(pub, cpub) {
		panic("WithAttestation: attestation key must differ from the server signing key (role separation)")
	}
	if s.brokerKey != nil && bytes.Equal(pub, s.brokerKey.Public().(ed25519.PublicKey)) {
		panic("WithAttestation: attestation key must differ from the broker issuing key (role separation)")
	}
	if s.resourceCore != nil {
		if rpub, err := decodePubKey(s.resourceCore.PubKey()); err == nil && bytes.Equal(pub, rpub) {
			panic("WithAttestation: attestation key must differ from the resource recording key (role separation)")
		}
	}
	if s.revocationKey != nil && bytes.Equal(pub, s.revocationKey.Public().(ed25519.PublicKey)) {
		panic("WithAttestation: attestation key must differ from the revocation key (role separation)")
	}
	s.attestKey = key
	if s.attestIssuedSkew == 0 {
		s.attestIssuedSkew = time.Hour // small skew below the checkpoint time for TSA/clock jitter
	}
	if s.attestValidity == 0 {
		// Window above the checkpoint time. Widened from the original 24h so a slow/queued anchor whose
		// genTime lands hours-to-days after the seal still falls inside (D7.2 residual). A wide not_after
		// is safe: the subject binds the exact checkpoint_hash + frontier coverage, so a stale attestation
		// cannot be replayed onto a moved-on bundle regardless of window width.
		s.attestValidity = 7 * 24 * time.Hour
	}
	return s
}

// WithCoverageManifest sets the operator-declared coverage_manifest (raw JSON) emitted in every export
// bundle. Its primary content is a `side_effect_closure` — the operator's AFFIRMATIVE declaration of the
// (resource_id, action) pairs the deployment may touch (T6 / ADR 0002 Q1). The verifier checks the
// brokered surface stayed WITHIN this closure; a manifest is REQUIRED to reach the
// attested_complete_over_brokered_surface capstone (D8). The manifest's RCP digest is bound into the
// deployment_attestation, so the closure cannot be swapped without breaking the attestation.
func (s *Server) WithCoverageManifest(manifestJSON string) *Server {
	s.coverageManifest = manifestJSON
	return s
}

// WithAttestationWindow overrides the deployment-attestation freshness window: issuedSkew is how far
// BELOW the latest checkpoint's created_ts issued_at sits (clock/anchor jitter), validity is how far
// ABOVE it not_after sits (must exceed the worst-case anchor latency). Call after WithAttestation.
func (s *Server) WithAttestationWindow(issuedSkew, validity time.Duration) *Server {
	if issuedSkew <= 0 {
		issuedSkew = time.Hour // a non-positive skew would degenerate issued_at to the checkpoint time
	}
	if validity <= 0 {
		validity = 7 * 24 * time.Hour // ...and a non-positive validity would fail every anchored genTime closed
	}
	s.attestIssuedSkew = issuedSkew
	s.attestValidity = validity
	return s
}

// WithExternalVerificationRoots installs PUBLIC trust roots pinned by the deployment operator for
// the product-facing /v2/verify view. Supplying both an attestation issuer and an RFC 3161 TSA SPKI
// makes D7 independently evaluable: the verifier checks the deployment-attestation signature and
// the externally timestamped checkpoint it binds. A partial pair is intentionally ignored here;
// averin-server rejects partial environment configuration at startup.
func (s *Server) WithExternalVerificationRoots(attestationKeys []ed25519.PublicKey, tsaSPKI [][]byte) *Server {
	s.externalVerifyAttestationKeys = append([]ed25519.PublicKey(nil), attestationKeys...)
	s.externalVerifyTSASPKI = make([][]byte, len(tsaSPKI))
	for i, spki := range tsaSPKI {
		s.externalVerifyTSASPKI[i] = append([]byte(nil), spki...)
	}
	return s
}

// WithExternalTaxonomy installs the signed D4 operation taxonomy and its independent
// auditor pins for the product-facing /v2/verify view. The complete pinning tuple is
// required: artifact, issuer key(s), canonical digest, and positive version. The
// verifier re-checks the signature/digest/version and rejects role overlap; this setter
// validates the deployment shape before accepting it.
func (s *Server) WithExternalTaxonomy(taxonomyJSON []byte, keys []ed25519.PublicKey, digest string, version int64) *Server {
	if len(taxonomyJSON) == 0 || len(keys) == 0 || digest == "" || version <= 0 {
		panic("WithExternalTaxonomy: artifact, issuer keys, digest, and positive version are all required")
	}
	var parsed any
	if err := json.Unmarshal(taxonomyJSON, &parsed); err != nil {
		panic("WithExternalTaxonomy: taxonomy artifact must be valid JSON")
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		panic("WithExternalTaxonomy: taxonomy digest must be canonical sha256:<64hex>")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		panic("WithExternalTaxonomy: taxonomy digest must be canonical sha256:<64hex>")
	}
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			panic("WithExternalTaxonomy: taxonomy issuer key must be 32-byte Ed25519")
		}
		if cpub, err := decodePubKey(s.core.PubKey()); err == nil && bytes.Equal(key, cpub) {
			panic("WithExternalTaxonomy: taxonomy issuer key must differ from the server/broker key")
		}
		if s.brokerKey != nil && bytes.Equal(key, s.brokerKey.Public().(ed25519.PublicKey)) {
			panic("WithExternalTaxonomy: taxonomy issuer key must differ from the broker issuing key")
		}
		if s.resourceCore != nil {
			if rpub, err := decodePubKey(s.resourceCore.PubKey()); err == nil && bytes.Equal(key, rpub) {
				panic("WithExternalTaxonomy: taxonomy issuer key must differ from the resource recording key")
			}
		}
		if s.attestKey != nil && bytes.Equal(key, s.attestKey.Public().(ed25519.PublicKey)) {
			panic("WithExternalTaxonomy: taxonomy issuer key must differ from the attestation key")
		}
		if s.revocationKey != nil && bytes.Equal(key, s.revocationKey.Public().(ed25519.PublicKey)) {
			panic("WithExternalTaxonomy: taxonomy issuer key must differ from the revocation key")
		}
		for _, approver := range s.cosigApprovers {
			if bytes.Equal(key, approver) {
				panic("WithExternalTaxonomy: taxonomy issuer key must differ from every cosign approver key")
			}
		}
		for _, attest := range s.externalVerifyAttestationKeys {
			if bytes.Equal(key, attest) {
				panic("WithExternalTaxonomy: taxonomy issuer key must differ from every attestation issuer key")
			}
		}
	}
	s.externalVerifyTaxonomy = append(json.RawMessage(nil), taxonomyJSON...)
	s.externalVerifyTaxonomyKeys = append([]ed25519.PublicKey(nil), keys...)
	s.externalVerifyTaxonomyDigest = digest
	s.externalVerifyTaxonomyVersion = version
	return s
}

func decodePubKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "ed25519pub:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not an ed25519pub key: %q", encoded)
	}
	return ed25519.PublicKey(raw), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resourceIDsOf returns the resource_id(s) a record names via its signed grant_evidence / use_evidence —
// the same fields the verifier folds into the attestation-subject resource_id set.
func resourceIDsOf(recordJSON string) []string {
	var probe struct {
		Extensions struct {
			Broker struct {
				GrantEvidence struct {
					ResourceID string `json:"resource_id"`
				} `json:"grant_evidence"`
				UseEvidence struct {
					ResourceID string `json:"resource_id"`
				} `json:"use_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(recordJSON), &probe) != nil {
		return nil
	}
	var out []string
	if r := probe.Extensions.Broker.GrantEvidence.ResourceID; r != "" {
		out = append(out, r)
	}
	if r := probe.Extensions.Broker.UseEvidence.ResourceID; r != "" {
		out = append(out, r)
	}
	return out
}

// signTagged signs `contentHash` under a domain `tag` exactly as the Rust core's sign::sign does:
// ed25519(sk, LP4(tag) ‖ utf8(contentHash)), returning "ed25519:<base64url-no-pad>". (RCP §9.2.)
func signTagged(tag, contentHash string, sk ed25519.PrivateKey) string {
	pre := make([]byte, 0, 4+len(tag)+len(contentHash))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(tag)))
	pre = append(pre, lp[:]...)
	pre = append(pre, tag...)
	pre = append(pre, contentHash...)
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, pre))
}

// attestFallbackSkew is the (wide) lower-bound skew used when a checkpoint carries no parseable created_ts,
// so an honest attestation over a legacy/externally-produced checkpoint is not failed CLOSED (its anchored
// TSA genTime may predate now()-issuedSkew). not_after still bounds the window; subject binding prevents replay.
const attestFallbackSkew = 30 * 24 * time.Hour

// attestationWindow computes the [issued_at, not_after] freshness window for a deployment attestation.
// The offline verifier checks the latest ANCHORED checkpoint's TSA genTime (≈ the checkpoint's createdTS)
// against this window — it has no wall clock of its own — so the window is bracketed on createdTS, NOT on
// export time. Anchoring to export now() fails whenever a checkpoint is exported after its seal (adversarial review D7.2).
// When createdTS is missing/unparseable we cannot bracket the real anchor time, so issued_at is widened to
// attestFallbackSkew below export time rather than fail an honest attestation closed.
func attestationWindow(createdTS string, now time.Time, issuedSkew, validity time.Duration) (string, string) {
	base := now
	if t, err := time.Parse("2006-01-02T15:04:05.000Z", createdTS); err == nil {
		base = t
	} else if issuedSkew < attestFallbackSkew {
		issuedSkew = attestFallbackSkew
	}
	return ts(base.Add(-issuedSkew)), ts(base.Add(validity))
}

// buildDeploymentAttestation assembles the D7.2 attestation over the project's latest checkpoint. The
// signed `subject` binds project_id / coverage_manifest_digest / latest checkpoint_hash +
// broker_grant_head_root / the authority key-id set / the resource-id set; the digest is the verifier's
// (sha256 of RCP-canonical attestation minus sig), signed under "averin.attestation.v1".
func (s *Server) buildDeploymentAttestation(projectID string, recs []store.Record, checks []store.Checkpoint, revocationDigest string) (map[string]any, error) {
	if len(checks) == 0 {
		return nil, nil // nothing anchored to attest over yet
	}
	latest := checks[len(checks)-1]
	var cp struct {
		CheckpointHash  string `json:"checkpoint_hash"`
		CreatedTS       string `json:"created_ts"`
		BrokerGrantHead struct {
			CumulativeRoot string `json:"cumulative_root"`
		} `json:"broker_grant_head"`
	}
	if err := json.Unmarshal([]byte(latest.JSON), &cp); err != nil {
		return nil, fmt.Errorf("parse latest checkpoint: %w", err)
	}
	headRoot := cp.BrokerGrantHead.CumulativeRoot
	if headRoot == "" {
		headRoot = broker.EmptyGrantHeadRoot()
	}
	// authority key ids = the kids of the broker (server) + resource recording keys — exactly the set the
	// verifier derives from its pinned broker+resource authority keys. The taxonomy issuer is NOT an
	// authority over this deployment's grants/uses (it is validated separately via taxonomy_status), and
	// the producer holds no taxonomy key, so it is deliberately excluded here and in the verifier.
	kids := map[string]bool{}
	if pk, err := decodePubKey(s.core.PubKey()); err == nil {
		kids[broker.KeyID(pk)] = true
	}
	if s.resourceCore != nil {
		if pk, err := decodePubKey(s.resourceCore.PubKey()); err == nil {
			kids[broker.KeyID(pk)] = true
		}
	}
	authorityKids := sortedKeys(kids)
	// resource ids = every resource named by a grant_evidence / use_evidence in the bundle.
	resIDs := map[string]bool{}
	for _, r := range recs {
		for _, rid := range resourceIDsOf(r.JSON) {
			resIDs[rid] = true
		}
	}
	resourceIDs := sortedKeys(resIDs)

	// Bind the coverage_manifest the bundle carries: digest == sha256(RCP-canonical(manifest)), exactly
	// what the verifier recomputes from bundle.coverage_manifest. Empty when no manifest is declared.
	manifestDigest := ""
	if s.coverageManifest != "" {
		d, e := s.core.RcpEvidenceHash(s.coverageManifest)
		if e != nil {
			return nil, fmt.Errorf("coverage_manifest digest: %w", e)
		}
		manifestDigest = d
	}
	subject := map[string]any{
		"project_id":               projectID,
		"coverage_manifest_digest": manifestDigest,
		"checkpoint_hash":          cp.CheckpointHash,
		"broker_grant_head_root":   headRoot,
		"authority_kids":           authorityKids,
		"resource_ids":             resourceIDs,
		// #3: bind the digest of the revocation_list this export carries ("" when none) so the strip-downgrade
		// (deleting the soft-tier revocation_list to read `absent`) breaks this signed subject match → !ok.
		"revocation_digest": revocationDigest,
	}
	issuedAt, notAfter := attestationWindow(cp.CreatedTS, s.now(), s.attestIssuedSkew, s.attestValidity)
	att := map[string]any{
		"issuer_kid":  broker.KeyID(s.attestKey.Public().(ed25519.PublicKey)),
		"issued_at":   issuedAt,
		"not_after":   notAfter,
		"claim_types": []string{"sandbox_isolation", "egress_policy", "key_non_transferability"},
		"subject":     subject,
	}
	// digest = sha256(RCP-canonical(attestation minus sig)) — exactly what the verifier recomputes.
	bodyJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}
	digest, err := s.core.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("attestation digest: %w", err)
	}
	att["sig"] = signTagged("averin.attestation.v1", digest, s.attestKey)
	return att, nil
}

// WithTSA anchors every sealed checkpoint to a third-party RFC 3161 timestamp authority, attaching
// the returned token so a verifier can prove the checkpoint (and its causal ancestors) existed by
// the TSA-attested time (threat #3 backdating). Best-effort: a TSA failure stores the checkpoint
// un-anchored (reported), never wedging the chain.
func (s *Server) WithTSA(t witness.TSA) *Server {
	s.tsa = t
	return s
}

func healthz(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }

// readyzTimeout bounds the WHOLE /readyz probe (all registered dependencies), not just one — so a
// short timeout still holds even as more Postgres-backed components (store/durable/ledger) are
// registered. Short and fixed so a degraded dependency fails the probe fast (fail-closed) rather than
// hanging the readiness check or flapping the whole pod out of rotation on a slow-but-alive blip.
const readyzTimeout = 3 * time.Second

// readyz reports 200 only once every registered dependency answers a cheap Ping within
// readyzTimeout; the first failing dependency reports 503 naming itself, so an operator/alert can
// tell WHICH component is unready without guessing. Deliberately: (1) never fails open — a Ping
// error or a ctx deadline is reported not-ready, never swallowed into 200; (2) never probes the full
// dependency graph — only the direct pool Pings registered via WithReadiness (cheap liveness, not a
// downstream health cascade), so one blip cannot flap an entire tier out of rotation; (3) an
// in-memory (dev, no Postgres configured) deployment registers nothing and is always ready — there is
// no dependency to be unready about.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyzTimeout)
	defer cancel()
	for _, t := range s.readiness {
		if err := t.ping.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":    "not-ready",
				"component": t.name,
				"error":     err.Error(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) Routes() http.Handler {
	// Role separation (T7, adversarial review): every pinned authority key must be disjoint from the RESOURCE key too —
	// checked HERE (not only in WithPolicyEngineKey) so it holds regardless of option order (WithResource can
	// be called after WithPolicyEngineKey). Else a resource key could sign a generic record's evidence_sig and
	// have the server stamp it `verified` — exactly what the offline verifier's authority_keys disjointness
	// check now also fatals on. Fail fast at setup, like the other WithPolicyEngineKey guards.
	if len(s.policyEngineKeys) > 0 && s.resourceCore != nil {
		if rpub, err := decodePubKey(s.resourceCore.PubKey()); err == nil {
			for pin, key := range s.policyEngineKeys {
				if key.Equal(rpub) {
					panic("the " + pin.source + " authority key must be role-separated from the resource key")
				}
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("POST /v2/records", s.handleRecords)
	mux.HandleFunc("GET /v2/records", s.handleListRecords)
	mux.HandleFunc("POST /v2/grants", s.handleGrant)
	mux.HandleFunc("POST /v2/grants/prepare", s.handleGrantPrepare)   // M6/M2 online two-phase: phase 1 (mint+reveal)
	mux.HandleFunc("POST /v2/grants/finalize", s.handleGrantFinalize) // M6/M2 online two-phase: phase 2 (attach+commit)
	mux.HandleFunc("POST /v2/introspection", s.handleIntrospection)   // M3 native/STS: record a resource introspection transcript
	mux.HandleFunc("POST /v2/revoke", s.handleRevoke)                 // M5: mark a grant_id revoked (export carries a signed revocation_list)
	mux.HandleFunc("POST /v2/broker-seq/void", s.handleBrokerSeqVoid) // D6 remediation: fill a reserved, never-recorded broker_seq with a signed tombstone
	mux.HandleFunc("POST /v2/use", s.handleUse)
	mux.HandleFunc("POST /v2/use-intent", s.handleUseIntent)
	mux.HandleFunc("POST /v2/use-outcome", s.handleUseOutcome)
	mux.HandleFunc("POST /v2/otel/traces", s.handleOTel)
	mux.HandleFunc("POST /v2/checkpoints", s.handleCheckpoint)
	mux.HandleFunc("GET /v2/sessions", s.handleSessions)
	mux.HandleFunc("GET /v2/dag", s.handleDAG)
	mux.HandleFunc("GET /v2/verify", s.handleVerify)
	mux.HandleFunc("GET /v2/export", s.handleExport)
	mux.HandleFunc("GET /v2/usage", s.handleUsage)

	// averin#20: an opt-in coarse ingest rate limit wraps the mux INNERMOST (so in the guarded path it runs
	// AFTER auth — an unauthenticated request is 401, not 429 — and applies in the dev/no-auth path too). Unset
	// (the default) leaves the routes unlimited, exactly as before.
	var handler http.Handler = mux
	if s.ingestBudget != nil {
		handler = s.rateLimitIngest(mux)
	}
	if s.auth == nil || auth.IsOpen(s.auth) {
		return rejectNULParams(handler) // dev/single-tenant: no per-project auth (documented Phase-1/dev posture)
	}
	// gate every /v2/* route behind project-scoped auth; /healthz, /readyz, /metrics stay open (health/
	// observability endpoints are unauthenticated by design, matching /healthz's existing posture).
	gate := auth.Middleware(s.auth, "project")
	guarded := http.NewServeMux()
	guarded.HandleFunc("GET /healthz", healthz)
	guarded.HandleFunc("GET /readyz", s.readyz)
	guarded.HandleFunc("GET /metrics", s.metrics.Handler())
	guarded.Handle("/v2/", gate(handler))
	return rejectNULParams(guarded)
}

// rateLimitIngest wraps h with the opt-in per-project + global ingest token bucket (averin#20). It governs ONLY
// state-mutating POST /v2/* requests (record/grant/use/checkpoint ingest — the routes that grow the append-only
// store and bill); GET reads pass through untouched. A saturated per-project or global bucket answers 429 with a
// Retry-After so a leaked token cannot drive unbounded billable DB growth. The project is read from the same
// ?project= param auth scopes on. Drop logging is bucket-throttled (denialBudget.allow) so a sweep cannot turn
// each 429 into a log write.
func (s *Server) rateLimitIngest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			project := r.URL.Query().Get("project")
			if ok, logDrop := s.ingestBudget.allow(project); !ok {
				if logDrop {
					log.Printf("WARNING: ingest rate limit throttling project %q (429); a reverse-proxy/gateway limit is the primary control", project)
				}
				w.Header().Set("Retry-After", "1")
				writeErr(w, http.StatusTooManyRequests, "ingest rate limit exceeded for this project; retry shortly")
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// decode preserves integer literals (json.Number) so cost_micros_usd etc. never round-trip through
// float64 (RCP forbids floats; the Rust core would reject a re-emitted exponent/precision-loss).
func decode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

// ---- ingestion ----

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// accept a single record object or a batch array
	var items []json.RawMessage
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := decode(trimmed, &items); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid batch: "+err.Error())
			return
		}
	} else {
		items = []json.RawMessage{trimmed}
	}
	if len(items) == 0 {
		writeErr(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Validate the WHOLE batch up front so a malformed item cannot partially persist the earlier ones
	// (F14: batch ingest is all-or-nothing on a deterministic 400). This runs EVERY deterministic 400-class
	// check the per-item ingest does — JSON decodability, the project_id binding (with auth, a token for
	// project A must not write to project B via the body's project_id), the idempotency-key requirement,
	// and the reserved-field checks (via validateGenericRecordItem, shared with ingestOne) — before any
	// item is sealed. Only a rarer non-deterministic failure (a commit/seal/store error AFTER this pass)
	// can still partial-persist, and that is self-healing: every record is idempotency-keyed, so a
	// whole-batch retry collapses the already-sealed items rather than duplicating them.
	queryProject := r.URL.Query().Get("project")
	headerIdem := r.Header.Get("Idempotency-Key")
	// F5: within ONE batch, two items that resolve to the SAME (project_id, idempotency_key) would collapse
	// in the store — PutRecord returns the FIRST item's row for the second, created=false, and the second
	// item's DISTINCT evidence is silently DISCARDED while the 201 response still lists a record for it. That
	// is evidence loss in an append-only flight recorder, and it is the default outcome for a multi-item batch
	// posted with only an `Idempotency-Key` HEADER (every item inherits the one key). Reject the WHOLE batch
	// up front (deterministic 400, nothing sealed) rather than silently dropping records: a batch of distinct
	// records needs a distinct idempotency_key per item.
	batchIdem := make(map[string]struct{}, len(items))
	batchRecordIDs := make(map[string]struct{}, len(items))
	for _, raw := range items {
		var probe map[string]any
		if decode(raw, &probe) != nil {
			writeErr(w, http.StatusBadRequest, "invalid record in batch")
			return
		}
		if queryProject != "" && stringField(probe, "project_id") != queryProject {
			writeErr(w, http.StatusForbidden, "a record's project_id does not match the authorized ?project=")
			return
		}
		idem := stringField(probe, "idempotency_key")
		if idem == "" {
			idem = headerIdem
		}
		if idem == "" {
			writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header)")
			return
		}
		if reservedIdem(idem) {
			writeErr(w, http.StatusBadRequest, reservedIdemMsg)
			return
		}
		if err := rejectNUL("idempotency_key", idem); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// F5: the store dedups per (project_id, idempotency_key), so two items in one batch under the same
		// pair collapse and the later item's evidence is dropped. Reject before anything is sealed.
		if len(items) > 1 {
			dedupKey := stringField(probe, "project_id") + "\x00" + idem
			if _, dup := batchIdem[dedupKey]; dup {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf(
					"two records in this batch share idempotency_key %q under the same project_id — they would collapse "+
						"onto one stored record and silently DROP the later record's evidence; give each batch item its own "+
						"idempotency_key (an Idempotency-Key HEADER applies to every item, so it cannot key a multi-item batch)", idem))
				return
			}
			batchIdem[dedupKey] = struct{}{}
		}
		if err := s.validateGenericRecordItem(probe); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// record_id is unique per project (store.ErrRecordIDConflict → 409). Reject a collision — within this
		// batch, or with an already-stored record — HERE, before any item is sealed, so a later item's conflict
		// cannot leave the earlier items committed. An idempotent replay (its idempotency_key already bound)
		// collapses onto its stored row and is exempt. PutRecord remains the authoritative check.
		if rid := stringField(probe, "record_id"); rid != "" {
			pid := stringField(probe, "project_id")
			ridKey := pid + "\x00" + rid
			if _, dup := batchRecordIDs[ridKey]; dup {
				writeErr(w, http.StatusConflict, fmt.Sprintf("two records in this batch share record_id %q under the same project_id (record_id is unique per project)", rid))
				return
			}
			batchRecordIDs[ridKey] = struct{}{}
			var replay, taken bool
			err := s.st.WithProjectRead(r.Context(), pid, func(st store.Store) error {
				_, found, err := st.RecordByIdem(pid, idem)
				if err != nil {
					return err
				}
				replay = found
				if !replay {
					taken, err = st.HasRecordID(pid, rid)
				}
				return err
			})
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "idempotency lookup: "+err.Error())
				return
			}
			if !replay && taken {
				writeErr(w, http.StatusConflict, fmt.Sprintf("%v: %q", store.ErrRecordIDConflict, rid))
				return
			}
		}
		// With AVERIN_REQUIRE_PINNED_AUTHORITY on, a failed authority elevation makes ingestOne REJECT the item —
		// a deterministic outcome for a given body + pinned keys, so a later item failing it would otherwise leave
		// the earlier items committed (and the retry fail identically). Dry-run the SAME decision here
		// (checkAuthority is pure) and reject the whole batch before anything is sealed, with the same retryable
		// 500 + metric/WARNING ingestOne would produce. A record with no record_id cannot verify either way
		// (ingestOne would assign a fresh random one), so the dry-run's verdict matches.
		if _, isMap := probe["authority"].(map[string]any); isMap && s.requirePinnedAuthority {
			if v := s.checkAuthority(probe); v.failedElevation {
				s.ingestMu.Lock() // onFailedElevation's log throttle is guarded by ingestMu
				s.mAuthorityDowngrades.Inc()
				err := s.onFailedElevation(v.claimed, v.keyID)
				s.ingestMu.Unlock()
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		// F14: the seal RCP-canonicalizes the record and HARD-rejects floats, out-of-range integers, and
		// interior NULs (canon.rs) — deterministic 400s the shallow checks above miss. Without this dry-run a
		// bad field in a LATER batch item would fail only at seal time, AFTER earlier items are already stored
		// (a partial commit that is NOT self-healing: the failure is deterministic, so a retry fails identically
		// while the earlier item stays persisted). Batch records chain in the session DAG (each seal reads the
		// frontier the prior item updated), so "seal all then store all" is not possible; instead canonicalize
		// here over the fields that reach the seal VERBATIM — idempotency_key is dropped and input/output/
		// rationale are commitment-replaced before sealing, so strip them to avoid a false reject; the
		// server-stamped fields are always canonical. RcpEvidenceHash runs the SAME RCP parse the seal does.
		probeForCanon := canonProbe(probe)
		probeJSON, _ := json.Marshal(probeForCanon)
		if _, err := s.core.RcpEvidenceHash(string(probeJSON)); err != nil {
			writeErr(w, http.StatusBadRequest, "record is not RCP-canonical (a float, out-of-range integer, or NUL in a signed field rejects the whole batch): "+err.Error())
			return
		}
	}

	results := make([]map[string]any, 0, len(items))
	for _, raw := range items {
		sealed, created, err := s.ingestOne(r.Context(), raw, headerIdem)
		if err != nil {
			// A rejected authority elevation (AVERIN_REQUIRE_PINNED_AUTHORITY) is an infrastructure/config
			// fail-closed, not caller-bad-input: surface it as a retryable 500 (idempotency makes the retry
			// safe once the operator aligns the pinned key), distinct from the deterministic 400-class
			// validation errors ingestOne returns for a malformed record.
			if errors.Is(err, errAuthorityRejected) {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			// A different record already holds this record_id (a race past the pre-pass): nothing persisted.
			if errors.Is(err, store.ErrRecordIDConflict) {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		results = append(results, map[string]any{"created": created, "record": json.RawMessage(sealed)})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"results": results})
}

// denialIdemPrefix namespaces the broker's best-effort denied-grant log: sealGrantDenial stores each denial
// under denialIdemPrefix+denialID. NO caller-supplied idempotency key may use this prefix at ANY endpoint
// (/v2/records, /v2/otel, /v2/grants, /v2/use, /v2/use-intent, /v2/use-outcome) — else a pre-seeded
// grant/use/record under a denial's deterministic key would make the later denial's PutRecord collapse onto
// it and SILENTLY suppress the B11 evidence (the denial seal is best-effort). Only sealGrantDenial writes
// here, via sealAndStore, which bypasses these handler guards.
const denialIdemPrefix = "denial:"

// reservedIdemMsg is the 400 every caller-facing entry point returns for a reserved idempotency_key prefix.
const reservedIdemMsg = `idempotency_key prefixes "denial:" and "grant-void:" are reserved for the broker (denied-grant log, grant_void tombstones)`

// reservedIdem also covers grantVoidIdemPrefix: a record pre-seeded under grant-void:<seq> would make the operator's
// tombstone for that seq collapse onto it (and never fill the seq).
func reservedIdem(idem string) bool {
	return strings.HasPrefix(idem, denialIdemPrefix) || strings.HasPrefix(idem, grantVoidIdemPrefix)
}

// rejectNUL returns an error naming the first (name, value) pair whose value contains U+0000. project_id,
// idempotency_key and record_id feed NUL-DELIMITED derivations — the deterministic grant/use/outcome/introspection
// ids (uuidV5Shaped hashes namespace‖0‖project‖0‖idem), the two-phase pendingKey, the batch dedup keys and the
// verify cache key — so (project "a", idem "b\x00c") and (project "a\x00b", idem "c") would derive the SAME id
// and pending key across projects. The RCP parser accepts an escaped \u0000, so reject it at every entry point.
func rejectNUL(pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if strings.IndexByte(pairs[i+1], 0) >= 0 {
			return fmt.Errorf("%s must not contain a NUL (U+0000) character", pairs[i])
		}
	}
	return nil
}

// rejectNULParams is the outermost handler: it refuses a NUL in the ?project= query parameter or the
// Idempotency-Key header on EVERY route (the same 400 whether or not auth is enabled), before auth scoping,
// rate limiting or any handler derives a key from them. Body fields are checked by each handler (rejectNUL).
func rejectNULParams(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := rejectNUL("project", r.URL.Query().Get("project"), "Idempotency-Key", r.Header.Get("Idempotency-Key")); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		h.ServeHTTP(w, r)
	})
}

// canonProbe projects a decoded record down to exactly the fields whose CALLER-supplied value reaches the
// seal verbatim, so the batch pre-pass (F14) can dry-run the RCP canonicalizer and reject a deterministic
// seal-time failure (float / out-of-range int / interior NUL) UP FRONT — without false-rejecting a batch the
// seal would accept. It mirrors ingestOne+sealAndScore field disposition exactly:
//   - DROPPED: idempotency_key (deleted), input/output/rationale (commitment-replaced), and the
//     unconditionally server-overwritten fields (schema_version, canon_version, domain, received_ts,
//     display_seq, causal_prev_hashes, key) — their caller value never reaches the seal.
//   - CONDITIONALLY-DEFAULTED (agent_id/agent_version/event_type/action/observed_via/status, agent_ts,
//     record_id, span_id): setDefault/stringField overwrite a NON-string or EMPTY value, so the caller value
//     reaches the seal ONLY when it is a non-empty string — keep it then (so an interior NUL is still
//     caught), drop it otherwise (else a non-string like agent_id:1.5 would false-reject a batch the seal
//     accepts by overwriting it with "unknown").
//   - authority: normalizeAuthority overwrites only authority.source (and only for a map); every other
//     sub-key reaches the seal verbatim, so canon-check authority minus a map's `source`.
//   - everything else (project_id/session_id, extensions, parent_span_id, arbitrary caller fields like
//     "cost"): reaches the seal verbatim — canon-check it.
func canonProbe(probe map[string]any) map[string]any {
	out := make(map[string]any, len(probe))
	for k, v := range probe {
		switch k {
		case "idempotency_key", "input", "output", "rationale",
			"schema_version", "canon_version", "domain", "received_ts",
			"display_seq", "causal_prev_hashes", "key":
			// dropped / commitment-replaced / unconditionally server-overwritten before the seal
		case "agent_id", "agent_version", "event_type", "action", "observed_via", "status",
			"agent_ts", "record_id", "span_id":
			if sv, ok := v.(string); ok && sv != "" {
				out[k] = v // a non-empty string reaches the seal verbatim; check it (catches interior NUL)
			}
		case "authority":
			if m, ok := v.(map[string]any); ok {
				cp := make(map[string]any, len(m))
				for ak, av := range m {
					if ak != "source" { // normalizeAuthority overwrites source; the rest reaches the seal
						cp[ak] = av
					}
				}
				out[k] = cp
			} else {
				out[k] = v // a non-map authority is left as-is by normalizeAuthority -> reaches the seal
			}
		default:
			out[k] = v
		}
	}
	return out
}

// uuidV5Pattern matches exactly the lowercase UUIDv5 shape uuidV5Shaped emits — the form of every
// deterministic grant_id (deterministicGrantID) and introspection record_id.
var uuidV5Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// reservedRecordID reports whether a CALLER-supplied record_id falls in a namespace the broker/resource
// endpoints derive their own ids from. record_id is unique per project (store.ErrRecordIDConflict), so a
// generic record pre-seeded under one of these ids would squat it: the later grant/use/outcome/denial/
// introspection whose deterministic id it is (grant ids are PUBLIC functions of project + idempotency key)
// would then be refused. Reserved: the use-/outcome-/denial- prefixes, the introspection-/revocation- prefixes
// ADR 0005 §7 reserves, and the lowercase UUIDv5 shape of deterministic grant/introspection ids. Server-assigned
// ids (newUUID) are v4, so a record with no caller record_id is never affected.
func reservedRecordID(rid string) bool {
	for _, p := range []string{"use-", "outcome-", "denial-", "introspection-", "revocation-"} {
		if strings.HasPrefix(rid, p) {
			return true
		}
	}
	return uuidV5Pattern.MatchString(rid)
}

// maxRecordIDBytes caps a caller-supplied record_id (see validateGenericRecordItem; documented in docs/dev/API.md).
// Every server-derived id (UUIDs, use-/outcome-/denial- ids) is far below it.
const maxRecordIDBytes = 256

// validateGenericRecordItem runs the deterministic, body-only validations the generic /v2/records path
// rejects with a 400. It is shared by ingestOne and the batch up-front pre-pass (F14: a malformed item
// must reject the WHOLE batch before any earlier item is sealed) so the two cannot diverge. It does NOT
// mutate the record (the caller assigns record_id / normalizes authority after).
func (s *Server) validateGenericRecordItem(rec map[string]any) error {
	if stringField(rec, "project_id") == "" || stringField(rec, "session_id") == "" {
		return fmt.Errorf("project_id and session_id are required")
	}
	if err := rejectNUL("project_id", stringField(rec, "project_id"), "record_id", stringField(rec, "record_id")); err != nil {
		return err
	}
	if err := s.validateDelegationEvidence(rec); err != nil {
		return err
	}
	// The "use-"/"outcome-"/"denial-" prefixes are RESERVED for the resource-gateway / denial endpoints
	// (deterministic ids from the idempotency key): a generic caller must not pre-seed one, else a later
	// /v2/use[-intent|-outcome] retry with the matching idempotency key could short-circuit to the
	// pre-seeded record and SKIP PoP validation / consume-before-act (a forged-capability use as success).
	// record_id is capped (bytes): it is indexed (the store's per-project uniqueness backstop) and echoed in every
	// export, so an unbounded caller-chosen id is both an index-row-limit hazard and an amplification vector. The
	// check is here — before any store — so Mem and Postgres reject an overlong id identically (400).
	if rid := stringField(rec, "record_id"); len(rid) > maxRecordIDBytes {
		return fmt.Errorf("record_id is %d bytes; the maximum is %d", len(rid), maxRecordIDBytes)
	}
	if rid := stringField(rec, "record_id"); reservedRecordID(rid) {
		return fmt.Errorf("record_id %q is in a namespace reserved for the broker/resource endpoints (use-/outcome-/denial-/introspection-/revocation- prefixes and the deterministic UUIDv5 grant/introspection ids)", rid)
	}
	// credential_grant_denied is the B11 denied-grant marker the verifier counts (denied_grants) by
	// event_type alone. A denial is sealed by the server signing key like every record, so the verifier
	// cannot cryptographically tell a broker-produced denial from a generic-forged one — the ONLY defense
	// is to reserve the marker at ingest, so only the opt-in broker denial path can produce it (else any
	// project writer could fabricate B11 evidence with arbitrary claimed pubkeys in tamper-evident records).
	if stringField(rec, "event_type") == "credential_grant_denied" {
		return fmt.Errorf("event_type \"credential_grant_denied\" is reserved for the broker denied-grant log")
	}
	// record_kind is OPTIONAL but its value-set is CLOSED (schema enum). The Rust closed-key gate only
	// admits the KEY (so a record carrying it verifies), not the value — so enforce the enum here at
	// ingest, else an off-enum kind would seal AND verify yet be invisible to / mis-classified by a
	// record_kind-filtered export. Absent record_kind is fine (it is not required).
	if rk, present := rec["record_kind"]; present {
		rks, ok := rk.(string)
		if !ok || !validRecordKind(rks) {
			return fmt.Errorf("record_kind must be one of {budget-exhausted, chargeback-posted}")
		}
	}
	// extensions.broker is RESERVED for the broker/resource lifecycle endpoints, which build their own
	// records — a GENERIC caller must not set it. Otherwise a forged extensions.broker.kind="grant" +
	// authority.enforcement_point="credential_broker" would be folded into the D6 grant-transparency head
	// by the producer (which cannot check the broker evidence_sig the offline verifier requires), so the
	// producer's grant set would diverge from the verifier's and poison/DoS the anchored cumulative_root
	// (ADR 0004 D6). Reject (not silently strip) so the caller sees it.
	if ext, ok := rec["extensions"].(map[string]any); ok {
		if _, reserved := ext["broker"]; reserved {
			return fmt.Errorf("extensions.broker is reserved for the broker/resource endpoints and must not be set on a generic record")
		}
		if _, reserved := ext["broker_denial"]; reserved {
			return fmt.Errorf("extensions.broker_denial is reserved for the broker denied-grant log and must not be set on a generic record")
		}
	}
	return nil
}

// validateDelegationEvidence makes a carried govder delegation hop load-bearing:
// the signature must verify and its delegator must be this project's pinned
// policy-engine authority key. A self-signed attacker-selected root is rejected.
func (s *Server) validateDelegationEvidence(rec map[string]any) error {
	ext, _ := rec["extensions"].(map[string]any)
	gov, _ := ext["govder"].(map[string]any)
	// govder's payload-envelope mapper carries the normalized body under
	// extensions.govder.BODY (internal/averin/mapper.go: gov["body"]=decoded), NOT
	// "payload". Reading the wrong key made the delegation_hop always look absent,
	// so EVERY real sub-agent-handoff seal was rejected ("requires a signed
	// delegation_hop") even though govder signed + carried it — the delegation path
	// was only ever tested with hand-built "payload" records, never real govder output.
	payload, _ := gov["body"].(map[string]any)
	hopValue, present := payload["delegation_hop"]
	if !present {
		claimsDelegation := stringField(rec, "event_type") == "handoff" ||
			stringField(rec, "event_type") == "sub-agent-handoff" ||
			stringField(payload, "artifact_type") == "delegation-attestation" ||
			stringField(payload, "handoff_kind") == "sub-agent-spawn"
		if claimsDelegation {
			return errors.New("delegation evidence requires a signed delegation_hop")
		}
		return nil
	}
	id := stringField(payload, "grant_id")
	if id == "" {
		id = stringField(payload, "handoff_id")
	}
	if id == "" {
		return errors.New("delegation_hop requires grant_id or handoff_id")
	}
	raw, err := json.Marshal(hopValue)
	if err != nil {
		return fmt.Errorf("delegation_hop: %w", err)
	}
	var hop broker.DelegationHop
	if err := json.Unmarshal(raw, &hop); err != nil {
		return fmt.Errorf("delegation_hop: %w", err)
	}
	delegator, err := broker.VerifyDelegationHop(id, 0, hop)
	if err != nil {
		return fmt.Errorf("delegation_hop verification failed: %w", err)
	}
	// Plan 031 D8: a delegation_hop is pinned to its record's authority source. A sub-agent-handoff /
	// delegation-attestation (sealed by govder's policy-engine key) pins to policy_engine_signed; a record whose
	// authority is delegate_signed (carrying a delegate-agent decision) pins to the delegate key — so a
	// policy-engine-level compromise cannot forge a delegate decision's hop, and vice versa. An unpinned source
	// is rejected closed (a self-signed attacker-selected root never passes).
	claimedSrc, _ := rec["authority"].(map[string]any)
	claimedSource, _ := claimedSrc["source"].(string)
	pinnedSource := "policy_engine_signed"
	if claimedSource == "delegate_signed" {
		pinnedSource = "delegate_signed"
	}
	// F1: resolve the pin for THIS record's project (project-scoped pin first, then the global default) —
	// a global-only lookup would accept tenant A's delegator on a tenant-B record.
	pinned, _ := s.authorityKeyFor(stringField(rec, "project_id"), pinnedSource)
	if len(pinned) != ed25519.PublicKeySize || !pinned.Equal(delegator) {
		return fmt.Errorf("delegation_hop delegator is not the pinned %s authority", pinnedSource)
	}
	if hop.Exp != 0 && time.Now().Unix() >= hop.Exp {
		return errors.New("delegation_hop is expired at ingest")
	}
	if stringField(payload, "handoff_id") != "" {
		from := stringField(payload, "from_agent_id")
		to := stringField(payload, "to_agent_id")
		if from == "" || to == "" || hop.Action != "spawn_child" || hop.ResourceID != from+"->"+to {
			return errors.New("delegation_hop does not bind the carried parent->child edge")
		}
		expected, err := delegationEvidenceScopeDigest(map[string]any{
			"from_agent_id": from, "to_agent_id": to,
			"delegated_scope": payload["delegated_scope"],
		})
		if err != nil || hop.Scope != expected {
			return errors.New("delegation_hop does not bind the complete carried handoff scope")
		}
	} else {
		delegate := stringField(payload, "delegate_agent_id")
		if delegate == "" || hop.Action != "delegate-approval" || hop.ResourceID != delegate {
			return errors.New("delegation_hop does not bind the carried delegation grant")
		}
		expected, err := delegationEvidenceScopeDigest(map[string]any{
			"delegator":         stringField(payload, "delegator"),
			"delegate_agent_id": delegate,
			"scope":             payload["scope"],
		})
		if err != nil || hop.Scope != expected {
			return errors.New("delegation_hop does not bind the complete carried grant scope")
		}
	}
	return nil
}

func delegationEvidenceScopeDigest(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var canonical any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&canonical); err != nil {
		return "", err
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *Server) ingestOne(ctx context.Context, raw []byte, headerIdem string) (string, bool, error) {
	var rec map[string]any
	if err := decode(raw, &rec); err != nil {
		return "", false, fmt.Errorf("invalid record: %w", err)
	}
	idem := stringField(rec, "idempotency_key")
	if idem == "" {
		idem = headerIdem
	}
	if idem == "" {
		return "", false, fmt.Errorf("idempotency_key is required (field or Idempotency-Key header)")
	}
	if reservedIdem(idem) { // see denialIdemPrefix: no caller may squat the denied-grant log namespace
		return "", false, errors.New(reservedIdemMsg)
	}
	if err := rejectNUL("idempotency_key", idem); err != nil {
		return "", false, err
	}
	delete(rec, "idempotency_key") // not part of the signed record

	// The deterministic body validations the generic path rejects with a 400 — shared with the batch
	// up-front pre-pass (F14) so a malformed item rejects the WHOLE batch before any item is sealed.
	if err := s.validateGenericRecordItem(rec); err != nil {
		return "", false, err
	}
	projectID := stringField(rec, "project_id")
	sessionID := stringField(rec, "session_id")
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID()
	}
	// authority is declared by default — never silently presented as verified (threat #4). With
	// AVERIN_REQUIRE_PINNED_AUTHORITY on, a claimed elevation that fails key verification returns
	// errAuthorityRejected here (fail-closed) rather than sealing downgraded to caller_declared.
	s.ingestMu.Lock() // guards only the authority warning throttle
	authErr := s.normalizeAuthority(rec)
	s.ingestMu.Unlock()
	if err := authErr; err != nil {
		return "", false, err
	}

	// Replace any raw input/output/rationale with a hiding commitment (RCP §9.3, threat #6); the
	// plaintext goes to the content store and never enters the signed body. The disclosure secrets
	// ride along on the Record so PutRecord persists them ATOMICALLY with the record (and only when
	// it creates it), so a committed field can never be sealed with no way to disclose it.
	disclosures, err := s.commitLowEntropyFields(rec, stringField(rec, "record_id"))
	if err != nil {
		return "", false, fmt.Errorf("commit fields: %w", err)
	}

	var sealed string
	var created bool
	err = s.withProjectWrite(ctx, projectID, func(st store.Store) error {
		var e error
		sealed, created, e = s.sealAndStore(st, projectID, sessionID, idem, rec, disclosures)
		return e
	})
	return sealed, created, err
}

// sealAndStore stamps recorder fields, reads the transaction-bound frontier and
// display sequence, seals the record, and inserts it with disclosures. The caller
// MUST pass the project-bound Store from WithProjectWrite and prepare authority
// handling and commitments before calling — so both
// the generic ingest path (normalizeAuthority + commitLowEntropyFields) and the credential broker
// (its own gateway_enforced authority + input_commit) share these DAG/seal/store mechanics without
// the broker's verified authority being clobbered back to caller_declared.
func (s *Server) sealAndStore(st store.Store, projectID, sessionID, idem string, rec map[string]any, disclosures []store.DisclosureSecret) (string, bool, error) {
	now := s.now()
	// server-controlled fields (override anything the caller sent)
	rec["schema_version"] = "2"
	rec["canon_version"] = "rcp-1"
	rec["domain"] = "flightrecorder.record.v2"
	rec["received_ts"] = ts(now)
	if stringField(rec, "agent_ts") == "" {
		rec["agent_ts"] = ts(now) // agent clock untrusted; default to receipt if absent
	}
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID() // safety net; callers normally set it before committing fields
	}
	if stringField(rec, "span_id") == "" {
		rec["span_id"] = "span-" + newUUID()
	}
	if _, ok := rec["parent_span_id"]; !ok {
		rec["parent_span_id"] = nil
	}
	// FAIL-CLOSED on the frontier reads: this store is append-only + signed, so a record sealed against a
	// silently-defaulted frontier is a permanent defect. A NextDisplaySeq error must abort (never seal with a
	// bogus display_seq), mirroring createCheckpoint's fail-closed snapshot reads. Callers treat a sealAndStore
	// error as a retryable 5xx and idempotency makes the retry safe (a released credential re-validates).
	seq, err := st.NextDisplaySeq(projectID, sessionID)
	if err != nil {
		return "", false, fmt.Errorf("seal: read display seq: %w", err)
	}
	rec["display_seq"] = seq

	// sensible defaults for required semantic fields so a minimal record is still valid
	setDefault(rec, "agent_id", "unknown")
	setDefault(rec, "agent_version", "unknown")
	setDefault(rec, "event_type", "decision")
	setDefault(rec, "action", "")
	setDefault(rec, "observed_via", "sdk")
	setDefault(rec, "status", "ok")

	// feir_evidence lineage/authority are stamped HERE — after the span_id/observed_via
	// defaults above — so the sealed evidence block can never disagree with the record's
	// own top-level fields (the commit pass runs before these defaults exist).
	if extensions, _ := rec["extensions"].(map[string]any); extensions != nil {
		if evidence, _ := extensions["feir_evidence"].(map[string]any); evidence != nil {
			evidence["capture_authority"] = rec["observed_via"]
			evidence["lineage"] = map[string]any{
				"session_id": rec["session_id"], "span_id": rec["span_id"],
				"parent_span_id": rec["parent_span_id"],
			}
		}
	}

	// causal DAG links = the session's current heads (server-derived, never client-trusted).
	// Heads, seal inputs and insert share the project write transaction.
	// FAIL-CLOSED (security-load-bearing): a swallowed Heads() error would leave heads=nil → parents=[] →
	// the record sealed as a DETACHED, parentless DAG root — permanently forging a break in the causal
	// chain the verifier relies on. A read failure MUST abort the seal, never manufacture a detached root.
	heads, err := st.Heads(projectID, sessionID)
	if err != nil {
		return "", false, fmt.Errorf("seal: read session heads: %w", err)
	}
	// A caller (the use_outcome producer) may pre-set causal_prev_hashes to FORCE a parent edge that must
	// persist even when the target is no longer a session head — the outcome MUST link to its intent so the
	// verifier's before-act DAG-consistency check holds even if a record was appended between the two phases.
	// UNION the forced parents with the current heads (dedup, byte-sorted), so a normal record (no forced
	// parents) still links to exactly the heads.
	forced, _ := rec["causal_prev_hashes"].([]string)
	seen := map[string]bool{}
	parents := []string{}
	for _, h := range append(append([]string{}, forced...), heads...) {
		if h != "" && !seen[h] {
			seen[h] = true
			parents = append(parents, h)
		}
	}
	sort.Strings(parents)
	rec["causal_prev_hashes"] = parents

	// signing key block
	rec["key"] = map[string]any{
		"signing_key_id": s.signingKeyID,
		"key_epoch":      0,
		"key_valid_from": s.keyValidFrom,
		"key_status":     "active",
	}

	bodyJSON, err := json.Marshal(rec)
	if err != nil {
		return "", false, err
	}
	sealed, err := s.core.SealRecord(string(bodyJSON))
	if err != nil {
		s.mRecordsSealFailed.Inc()
		return "", false, fmt.Errorf("seal: %w", err)
	}
	s.mRecordsSealed.Inc()

	ch, parents, sess := recordMeta(sealed)
	stored, created, err := st.PutRecord(projectID, idem, store.Record{
		JSON: sealed, ContentHash: ch, SessionID: sess, Parents: parents, Disclosures: disclosures,
	})
	if err != nil {
		// Propagate the store error AS-IS: the store flags only a genuinely commit-AMBIGUOUS failure (a fresh
		// insert whose commit outcome is unknown) with store.ErrCommitAmbiguous; every other store/seal/marshal
		// failure persists nothing, so a caller that consumed an irreversible resource releases on those.
		return "", false, err
	}
	return stored.JSON, created, nil
}

// ---- credential broker (Level 3 Tier-A: gateway_enforced grants, ADR 0002) ----

// grantRequest is the POST /v2/grants wire shape.
type grantRequest struct {
	IdempotencyKey   string   `json:"idempotency_key"`
	PoPVersion       int      `json:"pop_version"`
	IssuedAt         int64    `json:"issued_at"`
	RequestExpiresAt int64    `json:"request_expires_at"`
	ProjectID        string   `json:"project_id"`
	SessionID        string   `json:"session_id"`
	AgentID          string   `json:"agent_id"`
	Action           string   `json:"action"`
	Resource         string   `json:"resource"`
	Scope            string   `json:"scope"`
	ScopeClass       string   `json:"scope_class"`
	UseLimit         int      `json:"use_limit"` // bounded_reuse only (ADR 0005 M1): the cap N (>= 1)
	AgentPubKey      string   `json:"agent_pubkey"`
	AgentSig         string   `json:"agent_sig"`
	Principal        string   `json:"authorizing_principal"`
	DelegationChain  []string `json:"delegation_chain"`
	Justification    string   `json:"justification"`
	TTLSeconds       int      `json:"ttl_seconds"`
	// M3 (ADR 0005 — Native/STS): when Mode == "token_exchange", this is a NATIVE grant for an externally
	// minted (IdP/STS) credential — no broker credential_binding / cnf PoP (agent_pubkey/agent_sig are not
	// required). LeaseID is the external credential reference a later introspection transcript must match.
	Mode    string `json:"mode"`
	LeaseID string `json:"lease_id"`
}

// uuidV5Shaped derives a DETERMINISTIC, UUIDv5-shaped id from (namespace, project, idempotency_key),
// so an honest retry re-derives the SAME id and collapses in the store. namespace domain-separates id
// spaces (grants vs uses) so they can never collide.
func uuidV5Shaped(namespace, projectID, idem string) string {
	sum := sha256.Sum256([]byte(namespace + "\x00" + projectID + "\x00" + idem))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 (name-based)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// deterministicGrantID is the grant's UUIDv5-shaped id — re-derived on retry so a lost-response grant
// never mints a second live credential (ADR 0002 idempotency).
func deterministicGrantID(projectID, idem string) string {
	return uuidV5Shaped("averin.grant.id.v1", projectID, idem)
}

// handleGrant issues a credential-broker grant: it RECORDS a signed gateway_enforced grant (sealed
// into the agent's session DAG) BEFORE returning the minted, sender-constrained, single-use
// capability — so a credential never exists without a durable, anchored grant (record-before-issue).
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled (set AVERIN_BROKER_ISSUING_SEED)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var gr grantRequest
	if err := decode(body, &gr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid grant request: "+err.Error())
		return
	}
	// With auth enabled the project is bound by ?project= (middleware); a body project_id must match.
	if qp := r.URL.Query().Get("project"); qp != "" {
		if gr.ProjectID != "" && gr.ProjectID != qp {
			writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
			return
		}
		gr.ProjectID = qp
	}
	if gr.ProjectID == "" || gr.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	// Idempotency is REQUIRED for issuance: without it a lost-response retry would mint a SECOND live
	// single-use credential. The key (body or Idempotency-Key header) deterministically fixes the
	// grant_id, so a retry collapses to the original grant + capability.
	idem, idemErr := grantIdem(gr, r)
	if idemErr != nil {
		writeErr(w, http.StatusBadRequest, idemErr.Error())
		return
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot double-issue a credential")
		return
	}
	if reservedIdem(idem) { // a grant under denial:<denialID> would later collapse a denial and suppress it
		writeErr(w, http.StatusBadRequest, reservedIdemMsg)
		return
	}
	if err := rejectNUL("project_id", gr.ProjectID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	grantID := deterministicGrantID(gr.ProjectID, idem) // also the credential jti + record_id

	// M3 (ADR 0005 — Native/STS): a token_exchange grant is for an EXTERNALLY-minted credential — no broker
	// credential_binding, no cnf PoP — so it takes the separate native path (no agent_sig required, no minted
	// capability). Its use is later accountable ONLY via a resource-signed introspection transcript (/v2/introspection).
	if gr.Mode == "token_exchange" {
		// M6 fail-closed (averin#0): a native/token_exchange grant carries NO cosignatures and
		// there is no cosigned two-phase path for native issuance (prepare/finalize is built
		// entirely around broker-minted capabilities). So while an M-of-N cosig policy is pinned,
		// a project-token holder self-issuing a token_exchange grant would silently bypass the
		// independent-approval gate the operator required. Refuse it. Gated on >0 so a no-cosig
		// deployment (the default) is unaffected. This needs its OWN message: the two-phase flow
		// the brokered-path error below points at cannot serve a native grant.
		if s.cosigThreshold > 0 {
			writeErr(w, http.StatusBadRequest, "this broker pins an M-of-N cosig policy — native (token_exchange) grants cannot be cosigned (there is no cosigned native issuance path), so they are refused while a cosig policy is pinned; issue a brokered grant via the two-phase POST /v2/grants/prepare + POST /v2/grants/finalize flow instead")
			return
		}
		s.handleNativeGrant(r.Context(), w, gr, idem, grantID)
		return
	}

	// M6 (ADR 0005): when this broker pins an M-of-N cosig policy, a single-phase brokered grant would mint a
	// credential with NO cosignatures (the verifier only requires cosig on a grant that DECLARES cosig_threshold,
	// which single-phase issuance never sets) — silently bypassing the policy. Require the two-phase
	// prepare/finalize flow, which is the ONLY path that stamps cosig_threshold + binds the approver signatures.
	if s.cosigThreshold > 0 {
		writeErr(w, http.StatusBadRequest, "this broker pins an M-of-N cosig policy — brokered grants must be issued via the two-phase POST /v2/grants/prepare + POST /v2/grants/finalize flow (single-phase issuance would bypass cosig)")
		return
	}

	if gr.Mode != "" && gr.Mode != "capability" || gr.LeaseID != "" {
		writeErr(w, http.StatusBadRequest, "brokered grants require capability mode and no lease_id")
		return
	}
	if gr.TTLSeconds <= 0 || int64(gr.TTLSeconds) > (1<<63-1)/int64(time.Second) {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be positive and fit the server duration")
		return
	}
	gr.IdempotencyKey = idem
	req := grantRequestToBroker(gr)
	req.BrokerID = s.brokerID
	if req.PoPVersion != 2 {
		writeErr(w, http.StatusBadRequest, "online brokered grants require grant PoP v2")
		return
	}
	// Validate the request — proof-of-possession (agent_sig) + forbidden-scope — BEFORE anything else, so
	// a malformed / unsigned / forbidden request can NEVER retrieve a stored capability by reusing a known
	// idempotency key (every response is gated on PoP + scope, not just brand-new grants). req.Validate
	// verifies the Ed25519 agent_sig, so a caller that cannot sign the challenge is rejected here.
	if e := req.Validate(); e != nil {
		if errors.Is(e, broker.ErrTTLExceeded) {
			s.rejectAuthenticatedGrantPolicy(w, gr, req, idem, "ttl_exceeded", e)
			return
		}
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	if _, e := broker.ClassifyScope(req.Scope, req.ScopeClass); e != nil {
		if errors.Is(e, broker.ErrForbiddenScope) {
			s.rejectAuthenticatedGrantPolicy(w, gr, req, idem, "forbidden_scope", e)
			return
		}
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	// A committed exact retry remains readable after its signed request window.
	// Check before staging the descriptor: staging a fresh candidate would both
	// reject the expired proof and leave an unnecessary content-store write.
	if existing, found, e := s.st.RecordByIdem(gr.ProjectID, idem); e != nil {
		writeErr(w, http.StatusInternalServerError, "idempotency lookup: "+e.Error())
		return
	} else if found {
		if same, e := storedGrantMatchesRequest(existing.JSON, req); e != nil || !same {
			writeErr(w, http.StatusConflict, "idempotency_key already used for a different record or grant request")
			return
		}
		s.respondGrant(w, gr.ProjectID, grantID, existing.JSON, false, "")
		return
	}
	if e := req.ValidateAt(s.now()); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	// Stage the immutable credential descriptor before taking the project guard.
	// Its bytes do not depend on broker_seq; the authoritative prepare below
	// replaces only the sequence inside signed grant evidence.
	issuedAt := s.now()
	staged, err := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, issuedAt, s.brokerKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	credentialAddr, err := s.content.Put(content.WithTenant(r.Context(), gr.ProjectID), staged.DescriptorBytes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store credential descriptor: "+err.Error())
		return
	}

	// Mint + record-before-issue, all UNDER the project transaction (ADR 0004 D6): broker.Prepare validates the
	// request (proof-of-possession + forbidden scopes) and mints the capability + canonical evidence; its
	// allocSeq callback assigns the gapless broker_seq ONLY after validation passes (a rejected grant
	// never burns a seq) AND inside the same critical section as the record insert — so the broker_seq
	// allocation ORDER equals the record/anchor ORDER, and the recorded grant log is always a gapless
	// prefix [1..N] (a higher seq can never be recorded before a lower one). The lock is released via
	// defer (panic-safe). A validation failure is the caller's (400); a build/store failure is a 500.
	var prepared broker.Prepared
	var sealed string
	var created bool
	var validationErr error // set => 400 (request rejected by Prepare's validation, before allocation)
	var allocErr error      // set => 500 (broker_seq store/allocation failure, NOT caller-bad-input)
	var conflictErr error   // set => 409 (idem key reused with a DIFFERENT grant request)
	err = s.withProjectWrite(r.Context(), gr.ProjectID, func(st store.Store) error {
		var e error
		// Idempotent retry (or a pre-D6 legacy grant under this idem key): the record already exists, so
		// DO NOT allocate a broker_seq (a replay must never burn a seq, ADR 0004 D6). The response metadata
		// is derived from the SEALED record below (same for create and retry), so a retry's expires_at/
		// scope_class match the original grant; the original capability is reconstructed from the descriptor.
		if existing, found, le := st.RecordByIdem(gr.ProjectID, idem); le != nil {
			return le
		} else if found {
			// Idempotency CONFLICT: a reused idem key MUST carry the SAME grant request. A different (even
			// validly-signed) request must be rejected — otherwise a caller who knows/guesses another grant's
			// idem key could retrieve its capability descriptor. Compare the identity + authorization fields
			// against the stored grant_evidence (the request's cnf is its agent_pubkey's key id).
			same, pe := storedGrantMatchesRequest(existing.JSON, req)
			if pe != nil {
				return pe
			}
			if !same {
				conflictErr = fmt.Errorf("idempotency_key already used for a different grant request (agent/action/resource/scope/cnf mismatch)")
				return nil
			}
			sealed, created = existing.JSON, false
			return nil
		}
		// New grant: allocate (after validation, inside the lock), build, seal+store. Roll back the seq on
		// ANY failure after allocation but before the record commits, so an uncommitted grant never burns a
		// number (the rollback is safe under ingestMu — no other grant allocates in between).
		if e = req.ValidateAt(s.now()); e != nil {
			validationErr = e
			return e
		}
		prepared, e = broker.Prepare(req, grantID, func() (int64, error) {
			s.noteSeqAttempt(gr.ProjectID, grantID)
			seq, _, aerr := st.AllocateBrokerSeq(gr.ProjectID, grantID)
			if aerr == nil && seq < 1 {
				// a store-contract violation (non-positive seq with no error) is a 500 dependency bug,
				// NOT caller-bad-input — synthesize an error so it routes to allocErr (500), not 400.
				aerr = fmt.Errorf("store returned non-positive broker_seq %d", seq)
			}
			if aerr != nil {
				allocErr = aerr // a dependency failure, not a 400 — surfaced as 500 below
			}
			return seq, aerr
		}, issuedAt, s.brokerKey)
		if e != nil {
			if allocErr == nil {
				validationErr = e
			} else {
				allocErr = e
			}
			return e // rollback the whole transaction, including any allocated sequence
		}
		if !bytes.Equal(prepared.DescriptorBytes, staged.DescriptorBytes) {
			return errors.New("credential descriptor changed between staging and transaction")
		}
		rec, disclosures, e := s.buildGrantRecord(grantID, gr, req, prepared, credentialAddr.Digest)
		if e != nil {
			return e
		}
		sealed, created, e = s.sealAndStore(st, gr.ProjectID, gr.SessionID, idem, rec, disclosures)
		if e != nil {
			return e
		}
		if !created {
			// defensive: a brand-new grant collapsed (impossible — content is unique). The record exists, so
			// do NOT release the seq (a durable record holds it); surface the anomaly.
			return fmt.Errorf("grant %s unexpectedly collapsed to an existing record (broker_seq left reserved)", grantID)
		}
		return nil
	})
	if errors.Is(err, store.ErrCommitAmbiguous) {
		// COMMIT may have succeeded while its acknowledgement was lost. Only
		// this exact idempotency identity may recover the committed grant.
		reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
		defer cancel()
		_ = s.st.WithProjectRead(reconcileCtx, gr.ProjectID, func(st store.Store) error {
			existing, found, lookupErr := st.RecordByIdem(gr.ProjectID, idem)
			if lookupErr != nil || !found {
				return lookupErr
			}
			if same, matchErr := storedGrantMatchesRequest(existing.JSON, req); matchErr == nil && same {
				sealed, created, err = existing.JSON, false, nil
			}
			return nil
		})
	}
	if conflictErr != nil {
		writeErr(w, http.StatusConflict, conflictErr.Error())
		return
	}
	if allocErr != nil {
		if isVoidedGrant(allocErr) {
			writeErr(w, http.StatusConflict, allocErr.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, "allocate broker_seq: "+allocErr.Error())
		return
	}
	if validationErr != nil {
		writeErr(w, http.StatusBadRequest, validationErr.Error())
		return
	}
	if err != nil {
		if msg := grantIDTakenMsg(err, grantID); msg != "" {
			writeErr(w, http.StatusConflict, msg)
			return
		}
		writeErr(w, http.StatusInternalServerError, "store grant: "+err.Error())
		return
	}

	s.respondGrant(w, gr.ProjectID, grantID, sealed, created, prepared.Capability)
}

func (s *Server) respondGrant(w http.ResponseWriter, projectID, grantID, sealed string, created bool, capability string) {
	var err error
	if !created {
		// Idempotent retry: the grant already exists. Return the ORIGINAL capability, reconstructed
		// deterministically from the stored descriptor, NOT this call's freshly-timed one.
		capability, err = s.reconstructCapability(projectID, grantID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "reconstruct capability: "+err.Error())
			return
		}
	}

	// Derive expires_at/scope_class from the SEALED record's signed grant_evidence (same source for both
	// create and retry), so the response always matches the grant the capability is bound to — never a
	// fresh, request-time value that could outlast the (original) capability on an idempotent replay.
	exp, scopeClass, perr := storedGrantFields(sealed)
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, perr.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"grant_id":    grantID,
		"capability":  capability, // the agent presents this to the resource
		"expires_at":  ts(time.Unix(exp, 0)),
		"scope_class": scopeClass,
		"created":     created,
		"record":      json.RawMessage(sealed),
	})
}

// reconstructCapability re-mints the original capability for an existing grant from its stored
// credential descriptor (the bytes committed at issue), so an idempotent retry returns the SAME
// token rather than a new one. ed25519 signing is deterministic, so the re-mint is byte-identical.
func (s *Server) reconstructCapability(projectID, grantID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var secrets []store.DisclosureSecret
	err := s.st.WithProjectRead(ctx, projectID, func(st store.Store) error {
		var e error
		secrets, e = st.Disclosures(projectID)
		return e
	})
	if err != nil {
		return "", err
	}
	for _, d := range secrets {
		if d.RecordID == grantID && d.Field == "credential" {
			raw, err := s.content.Get(content.WithTenant(ctx, projectID), d.ValueDigest)
			if err != nil {
				return "", err
			}
			return broker.MintCapability(raw, s.brokerKey), nil
		}
	}
	return "", fmt.Errorf("no stored credential descriptor for grant %s", grantID)
}

// rejectAuthenticatedGrantPolicy checks idempotency before policy evidence.
// A validly re-signed different request under an existing grant key is a 409,
// never a new denial record. The denial writer repeats this lookup under its
// project transaction to close a concurrent grant/denial race.
func (s *Server) rejectAuthenticatedGrantPolicy(w http.ResponseWriter, gr grantRequest, req broker.Request, idem, reason string, policyErr error) {
	if e := req.FreshAt(s.now()); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	if _, found, e := s.st.RecordByIdem(gr.ProjectID, idem); e != nil {
		writeErr(w, http.StatusInternalServerError, "idempotency lookup: "+e.Error())
		return
	} else if found {
		writeErr(w, http.StatusConflict, "idempotency_key already used for a different record or grant request")
		return
	}
	if s.denyLog && s.sealGrantDenial(gr, req, reason, policyErr.Error()) {
		writeErr(w, http.StatusConflict, "idempotency_key already used for a different record or grant request")
		return
	}
	writeErr(w, http.StatusBadRequest, policyErr.Error())
}

// sealGrantDenial seals a B11 denied-grant record for an authenticated POLICY refusal (forbidden
// scope / over-cap TTL). It deliberately classifies to BrokerRole::None in the verifier — event_type
// credential_grant_denied (so it is never counted as a grant), authority.enforcement_point
// credential_broker_denied and extensions.broker.kind grant_denied (so it matches no grant-role tuple) —
// and carries NO broker_seq / grant_evidence / capability: nothing was issued, so the gapless D6 grant
// sequence is untouched. It records the REQUESTED scope metadata (the probe target). A deterministic
// record_id collapses retries of the same probe. Best-effort: a seal failure is logged and never changes
// the caller's 400. Caller must NOT already hold ingestMu (this takes it for the seal critical section).
func (s *Server) sealGrantDenial(gr grantRequest, req broker.Request, reason, detail string) (conflict bool) {
	// #47: bound the best-effort denial log. A drop changes NOTHING the caller sees — every call site invokes
	// this from inside the denial branch and writes the same 4xx immediately after it returns, regardless of
	// whether a seal happened — it only declines to seal one more best-effort record once a sweep exceeds the
	// budget. The check runs BEFORE taking ingestMu, so a rate-limited probe never enters the seal critical section.
	if s.denialBudget != nil {
		if ok, logDrop := s.denialBudget.allow(gr.ProjectID); !ok {
			s.mDenialBudgetDrops.Inc()
			if logDrop {
				log.Printf("WARNING: B11 denial seals are being dropped — per-project/global denial budget exhausted (varying-scope sweep DoS bound; this log is throttled to ~1/sec)")
			}
			return false
		}
	}
	now := ts(s.now())
	requested := map[string]any{
		"action": req.Action, "resource_id": req.Resource, "scope": req.Scope,
		"scope_class": string(req.ScopeClass), "agent_id": req.AgentID,
	}
	// Both policy denials reach this point only after the agent signature verifies.
	if kid := agentCnfKid(req.AgentPubKey); kid != "" {
		requested["cnf_kid"] = kid
	}
	// Derive the id from the FULL denied request identity, NOT a hand-picked field subset: a probe that
	// reuses one idem key while varying ANY distinguishing field (session_id, ttl_seconds, principal,
	// delegation, justification, ...) is a DISTINCT denial and must be logged separately — else a sweep that
	// varies, e.g., ttl_seconds or session_id collapses onto the first record and suppresses the rest of the
	// B11 log. Marshal the WHOLE grantRequest (canonical, declaration-order-stable) so every recognized field
	// is included and no future field is silently omitted, with the idempotency_key cleared (NOT part of the
	// probe identity — that is the point) and agent_sig cleared (a derived value; sig-only variation is the
	// same probe). The outer JSON array is unambiguous framing (each element quoted + escaped), so a field
	// boundary cannot be forged by an embedded delimiter.
	idReq := gr
	idReq.IdempotencyKey = "" // the idempotency key is the retry key, NOT part of the probe identity
	// Canonicalize the base64 identity fields: the broker's base64 decode is non-strict, so re-encode the
	// decoded bytes — otherwise alternate spellings of the SAME pubkey/signature bytes would yield distinct
	// denial ids and let a caller inflate denied_grants without a distinct key/proof. A field that does not
	// decode is left as-is (a malformed value is itself part of the identity; the denial still logs).
	if pub, err := base64.RawURLEncoding.DecodeString(idReq.AgentPubKey); err == nil {
		idReq.AgentPubKey = base64.RawURLEncoding.EncodeToString(pub)
	}
	// agent_sig is part of the probe identity ONLY for pop_failed: there each DISTINCT failed proof is a
	// distinct attempt the B11 log must COUNT (a PoP brute-force should leave one record per attempt; volume
	// is bounded by the per-project denial budget, not by hiding attempts). For forbidden_scope/ttl the sig
	// is incidental — and since a key-OWNER can craft many distinct VALID ed25519 sigs over one challenge
	// (Verify accepts any canonical sig, not just the deterministic one), keeping it would let them inflate
	// one logical operation into N denials; so it is excluded there. When kept, canonicalize it the same way.
	if reason == "pop_failed" {
		if sig, err := base64.RawURLEncoding.DecodeString(idReq.AgentSig); err == nil {
			idReq.AgentSig = base64.RawURLEncoding.EncodeToString(sig)
		}
	} else {
		idReq.AgentSig = ""
	}
	reqJSON, _ := json.Marshal(idReq)
	// ROOT defense against pre-seeding (C2b–C2e): mix a SERVER SECRET into the id so a caller can never
	// precompute denial:<denialID> and squat the key in ANY version. The salt is a deterministic ed25519
	// signature under the broker private key over a fixed domain string — secret (it needs the private key),
	// stable across restarts (Ed25519 is deterministic, so genuine retries still dedup), and one-way through
	// the sha256-based uuidV5Shaped (observed record_ids never reveal it). The namespace reservation + the
	// foreign-collision recovery remain as defense-in-depth.
	salt := ed25519.Sign(s.brokerKey, []byte("averin.denial.salt.v1"))
	probe, _ := json.Marshal([]string{base64.RawURLEncoding.EncodeToString(salt), string(reqJSON), reason})
	denialID := "denial-" + uuidV5Shaped("averin.denial.id.v1", gr.ProjectID, string(probe))
	rec := map[string]any{
		"record_id":     denialID,
		"project_id":    gr.ProjectID,
		"session_id":    gr.SessionID,
		"agent_id":      req.AgentID,
		"agent_version": "averin-broker",
		"event_type":    "credential_grant_denied", // NOT credential_grant -> the verifier never counts it as a grant
		"observed_via":  "broker",
		"action":        req.Action,
		"status":        "denied",
		// NO authority block (nothing was authorized) and NO extensions.broker.kind: a record that CARRIES
		// extensions.broker.kind but classifies to no recognized (kind, enforcement_point) role fails the
		// verifier CLOSED (R2 rule 4). The denial therefore rides under a SIBLING key, extensions.broker_denial,
		// so it stays a generic BrokerRole::None record — integrity-bound + anchored, but never grant-counted
		// and never a D6 broker-seq member.
		"extensions": map[string]any{
			"broker_denial": map[string]any{
				"kind":          "grant_denied",
				"denial_reason": reason,
				"denial_detail": detail,
				"requested":     requested,
				"denied_at":     now,
			},
		},
	}
	err := s.withProjectWrite(context.Background(), gr.ProjectID, func(st store.Store) error {
		if _, found, e := st.RecordByIdem(gr.ProjectID, gr.IdempotencyKey); e != nil {
			return e
		} else if found {
			conflict = true
			return nil
		}
		stored, created, e := s.sealAndStore(st, gr.ProjectID, gr.SessionID, denialIdemPrefix+denialID, rec, nil)
		if e != nil {
			return e
		}
		if created {
			return nil
		}
		var existing struct {
			RecordID  string `json:"record_id"`
			EventType string `json:"event_type"`
		}
		_ = json.Unmarshal([]byte(stored), &existing)
		if existing.RecordID == denialID && existing.EventType == "credential_grant_denied" {
			return nil
		}
		log.Printf("WARNING: B11 grant-denial %s collided with foreign record %q; sealing recovery record", denialID, existing.RecordID)
		_, fresh, e := s.sealAndStore(st, gr.ProjectID, gr.SessionID, denialIdemPrefix+"recovery-"+newUUID(), rec, nil)
		if e != nil {
			return e
		}
		if !fresh {
			return errors.New("denial recovery record unexpectedly collapsed")
		}
		return nil
	})
	if err != nil {
		log.Printf("WARNING: B11 grant-denial record %s failed to seal (denial NOT recorded): %v", denialID, err)
	}
	return conflict
}

// agentCnfKid returns the broker key-id of a base64url-no-pad ed25519 agent public key, or "" if malformed.
func agentCnfKid(agentPubKeyB64 string) string {
	pub, err := base64.RawURLEncoding.DecodeString(agentPubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return broker.KeyID(ed25519.PublicKey(pub))
}

// buildGrantRecord assembles the unsealed grant Decision Record: gateway_enforced authority with a
// broker-signed evidence_sig, a hiding commitment over the credential descriptor (revealable via
// selective disclosure), and the broker lifecycle fields under extensions.broker.
func (s *Server) buildGrantRecord(grantID string, gr grantRequest, req broker.Request, p broker.Prepared, descriptorDigest string) (map[string]any, []store.DisclosureSecret, error) {
	// Derive evidence_hash = sha256(RCP-canonicalize(grant_evidence)) via the Rust core (ADR 0003 R1).
	// json.Marshal here only produces the bytes we hand to the core; the canonical hash is computed by
	// RCP inside RcpEvidenceHash (NOT from these Go-marshaled bytes), so the offline verifier re-derives
	// the SAME hash from the grant_evidence embedded below and confirms the signed hash commits to the
	// canonical match fields. The grant_evidence payload is carried verbatim under
	// extensions.broker.grant_evidence.
	evidenceJSON, err := json.Marshal(p.Evidence)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal grant evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("derive grant evidence_hash: %w", err)
	}
	// Sign the gateway_enforced evidence (record_id-bound) — this is what the verifier elevates.
	evidenceSig, err := s.core.SignEvidence("gateway_enforced", gr.ProjectID, grantID, evidenceHash)
	if err != nil {
		return nil, nil, fmt.Errorf("sign grant evidence: %w", err)
	}
	// Commit the credential descriptor (hiding) under the dedicated `credential` domain (ADR 0004 D1 —
	// a grant no longer overloads `input`): store the bytes content-addressed, mint a nonce, and commit.
	// Selective disclosure can later reveal the descriptor to prove the grant↔credential binding
	// without publishing it in the signed body.
	nonce, err := s.core.RandomNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	commitment, err := s.core.Commit("credential", p.DescriptorBytes, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("commit credential descriptor: %w", err)
	}

	delegation := gr.DelegationChain
	if delegation == nil {
		delegation = []string{}
	}
	rec := map[string]any{
		"record_id":     grantID,
		"project_id":    gr.ProjectID,
		"session_id":    gr.SessionID,
		"agent_id":      req.AgentID,
		"agent_version": "averin-broker",
		"event_type":    "credential_grant",
		"observed_via":  "broker",
		"action":        req.Action,
		"status":        "ok",
		"authority": map[string]any{
			"source":                "gateway_enforced",
			"enforcement_point":     "credential_broker",
			"grant_type":            broker.GrantTypeIDJAG,
			"grant_id":              grantID,
			"authorizing_principal": req.Principal,
			"delegation_chain":      delegation,
			"evidence_hash":         evidenceHash,
			"evidence_sig":          evidenceSig,
			"evaluated_at":          p.EvaluatedAt,
			"expires_at":            p.ExpiresAt,
		},
		"credential_commit": map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				// kind is the R2 role discriminator (with authority.enforcement_point=credential_broker
				// it classifies this record to the BROKER role; ADR 0003 R2).
				"kind":               "grant",
				"issuance_status":    "recorded",
				"scope_class":        string(p.ScopeClass),
				"conformance_level":  p.ConformanceLevel,
				"credential_binding": p.CredentialBinding,
				// The canonical grant_evidence the verifier re-derives evidence_hash from (ADR 0003 R1).
				"grant_evidence": p.Evidence,
			},
		},
	}
	disclosures := []store.DisclosureSecret{
		{RecordID: grantID, Field: "credential", ValueDigest: descriptorDigest, NonceHex: nonce},
	}
	return rec, disclosures, nil
}

// ---- credential broker (Level 3 Tier-B: resource use receipts, ADR 0003) ----

// useRequest is the POST /v2/use wire shape: the agent presents the minted capability + a
// proof-of-possession (use_sig over the resource-bound PoP challenge) for an operation.
type useRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	ProjectID      string `json:"project_id"`
	SessionID      string `json:"session_id"`
	Capability     string `json:"capability"`   // the minted, sender-constrained token
	UseSig         string `json:"use_sig"`      // base64url ed25519 PoP signature (signed with the cnf key)
	Action         string `json:"action"`       // the operation to perform (must equal the grant's action)
	Params         string `json:"params"`       // raw operation parameters (committed + PoP-bound)
	Nonce          string `json:"nonce"`        // the one-time PoP freshness nonce
	ParamsNonce    string `json:"params_nonce"` // 64-hex nonce hiding the params commitment the PoP binds (D2)
	// UseSequenceNumber (ADR 0005 M1, bounded_reuse only): the 1-based exercise index in [1, use_limit].
	// Ignored for other scope classes; the shim validates it against the capability's use_limit.
	UseSequenceNumber int `json:"use_sequence_number"`
}

// deterministicUseID derives a stable use-receipt id from (project, idempotency_key), so an honest
// retry collapses in the store rather than sealing a second receipt (and re-consuming the credential).
func deterministicUseID(projectID, idem string) string {
	return "use-" + uuidV5Shaped("averin.use.id.v1", projectID, idem)
}

// handleUse records a Tier-B USE RECEIPT: the resource validates a presented capability + PoP at use
// time (resourceshim: capability sig, validity window, audience/action, PoP, consume-before-act), then
// seals a resource-signed receipt whose authority evidence the offline verifier joins to the grant.
// handleUse records a ONE-PHASE ADR-0003 use receipt (kind=use). handleUseIntent records the FIRST phase
// of a two-phase use (kind=use_intent, ADR 0004 D5) — recorded BEFORE the resource performs the side effect;
// it is completed by POST /v2/use-outcome. Both share the same validate+consume+seal path.
func (s *Server) handleUse(w http.ResponseWriter, r *http.Request) { s.handleUsePhase(w, r, "use") }
func (s *Server) handleUseIntent(w http.ResponseWriter, r *http.Request) {
	s.handleUsePhase(w, r, "use_intent")
}

func (s *Server) handleUsePhase(w http.ResponseWriter, r *http.Request, brokerKind string) {
	if s.resourceCore == nil || s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "resource gateway not enabled (set the resource recording key + broker issuing key)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var ur useRequest
	if err := decode(body, &ur); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid use request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && ur.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if ur.ProjectID == "" || ur.SessionID == "" {
		// A use must land in the grant's session DAG; an unknown/empty session is malformed (ADR 0003
		// resolved open question 2).
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	idem := ur.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot re-consume the credential")
		return
	}
	if reservedIdem(idem) { // a use under denial:<denialID> would later collapse a denial and suppress it
		writeErr(w, http.StatusBadRequest, reservedIdemMsg)
		return
	}
	if err := rejectNUL("project_id", ur.ProjectID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	useID := deterministicUseID(ur.ProjectID, idem)

	// D2 (ADR 0004): the PoP binds a HIDING params commitment (the agent's params_nonce) which is ALSO
	// the receipt's input_commit — so the offline verifier reconstructs the PoP challenge from
	// input_commit.commitment and re-runs Ed25519 without the raw params leaking. The resource RECOMPUTES
	// the commitment from (params, params_nonce); the PoP only verifies if the agent signed over THIS
	// exact value, so the agent cannot bind params different from those it sends (MF4 recompute-or-reject).
	rawParams := []byte(ur.Params)
	paramsCommitment, err := s.core.Commit("input", rawParams, ur.ParamsNonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid params/params_nonce (need a 64-hex nonce): "+err.Error())
		return
	}
	// A committed exact retry can return its original receipt even after the
	// capability expires. Resolve it from a bounded project snapshot before the
	// pure preflight and before staging content; the write session below repeats
	// the lookup for a concurrent first commit.
	var priorUse store.Record
	var priorFound bool
	if err := s.st.WithProjectRead(r.Context(), ur.ProjectID, func(st store.Store) error {
		var e error
		priorUse, priorFound, e = st.RecordByIdem(ur.ProjectID, idem)
		return e
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "use idempotency lookup: "+err.Error())
		return
	}
	if priorFound {
		if gid, same := s.priorUseMatchesRequest(priorUse.JSON, useID, ur, brokerKind, paramsCommitment); same {
			s.mUseOutcome.WithLabelValue("allow").Inc()
			writeJSON(w, http.StatusCreated, map[string]any{
				"use_id": useID, "grant_id": gid,
				"record": json.RawMessage(priorUse.JSON), "idempotent": true,
			})
			return
		}
		writeErr(w, http.StatusConflict, "use rejected: idempotency_key is already bound to a different record in this project (a key cannot be reused across operations, phases, or sessions)")
		return
	}
	trustedProject := r.URL.Query().Get("project")
	if trustedProject == "" {
		trustedProject = ur.ProjectID // no-auth local mode only
	}
	op := resourceshim.Op{Action: ur.Action, ParamsCommitment: paramsCommitment, UseSequenceNumber: ur.UseSequenceNumber}
	// Reject malformed, wrong-project, or bad-PoP uses before staging even an
	// erasable content blob. ValidateUse repeats this pure check inside the
	// project transaction before revocation, ledger claims, and receipt sealing.
	preflight := resourceshim.New(s.brokerKey.Public().(ed25519.PublicKey), s.resourceID, nil).WithProject(trustedProject)
	if err := preflight.PreflightUse(ur.Capability, ur.UseSig, op, ur.Nonce, s.now()); err != nil {
		s.mUseOutcome.WithLabelValue("deny").Inc()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	paramsAddr, err := s.content.Put(content.WithTenant(r.Context(), ur.ProjectID), rawParams)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store use params: "+err.Error())
		return
	}

	// The idempotency resolution, the capability validation+consume, and the seal run as ONE critical
	// section. Idempotency is keyed on `idem` — the SAME key sealAndStore→PutRecord dedupes on — resolved
	// up front via RecordByIdem, NOT by scanning the session for useID. The by-id scan was unsafe: a prior
	// /v2/records row OR the OTHER use phase can already occupy this idem key with a different record_id or
	// kind that the scan misses; ValidateUse would then burn the nonce/jti and PutRecord would silently
	// COLLAPSE the seal onto that prior row (created=false) → an action with no persisted receipt (and a
	// foreign record echoed back). So: a retry under this key that ALSO matches the stored receipt's OPERATION
	// (action/nonce/params-commitment/use_sig — storedUseMatchesRequest) is an honest retry (return it,
	// skipping the credential-consuming ValidateUse — concurrent retries also see it under the lock); ANY other
	// record under this key — including a DIFFERENT use reusing the key — is a conflict → 409 BEFORE consuming.
	// validateErr (caller's 400) and conflictErr (caller's 409) are distinguished from a store error (500).
	var sealed, grantID string
	var idempotent bool
	var validateErr, conflictErr error
	storeErr := s.withProjectWrite(r.Context(), ur.ProjectID, func(st store.Store) error {
		prior, found, le := st.RecordByIdem(ur.ProjectID, idem)
		if le != nil {
			// FAIL CLOSED on an ambiguous idempotency lookup: a transient store error must abort BEFORE
			// ValidateUse, which consumes the single-use nonce/jti — otherwise a read-path failure burns the
			// credential and leaves no persisted receipt (action without a receipt). Surface as 500.
			return le
		}
		if found {
			// EXACT-request match (adversarial review): (record_id, session, kind) is NOT sufficient — useID is derived from
			// (project, idem) so it always matches on key reuse. A reused idem key carrying a DIFFERENT use
			// (capability/action/params/nonce/use_sig) must NOT collapse onto this receipt and return 201 while
			// SKIPPING ValidateUse (which is what authorizes + consumes the credential), so also require the
			// operation itself to match the signed receipt; anything else is a 409 BEFORE any side effect.
			if gid, same := s.priorUseMatchesRequest(prior.JSON, useID, ur, brokerKind, paramsCommitment); same {
				sealed, grantID, idempotent = prior.JSON, gid, true
				return nil
			}
			conflictErr = fmt.Errorf("idempotency_key is already bound to a different record in this project (a key cannot be reused across operations, phases, or sessions)")
			return nil
		}
		shim := resourceshim.New(s.brokerKey.Public().(ed25519.PublicKey), s.resourceID, st).WithProject(trustedProject)
		// The callback receives the signature-verified JTI. A database read
		// failure rejects the request before ledger consumption, never falling
		// back to this replica's boot-time revoked cache.
		shim.WithRevocationCheckErr(func(id string) (bool, error) {
			return st.IsRevoked(trustedProject, id)
		})
		ev, e := shim.ValidateUse(ur.Capability, ur.UseSig, op, ur.Nonce, s.now())
		if errors.Is(e, resourceshim.ErrRevocationCheck) {
			return e
		}
		if e != nil {
			validateErr = e // a forged/expired/replayed/wrong-scope use — the caller's fault
			return nil
		}
		grantID = ev.GrantID
		rec, disclosures, e := s.buildUseRecord(useID, ur, ev, paramsAddr.Digest, paramsCommitment, brokerKind)
		if e != nil {
			// Receipt construction failed BEFORE any record was written and the caller never acted (it gets a
			// 500). ValidateUse already consumed the single-use nonce/jti, so RELEASE them — otherwise a
			// transient build error (e.g. the content store) burns the credential with no receipt. Safe: nothing
			// persisted, the caller did not act, and a successful path never releases.
			shim.RollbackUse(ev)
			return e
		}
		var created bool
		sealed, created, e = s.sealAndStore(st, ur.ProjectID, ur.SessionID, idem, rec, disclosures)
		if e == nil && !created {
			// PutRecord COLLAPSED onto an already-stored row (a same-key insert that raced past the RecordByIdem
			// check above, e.g. another instance): THIS receipt was not persisted. Answer with that row only if it
			// is this exact operation; otherwise it is another record's receipt — returning it as ours would report
			// an action that has no receipt of its own. Nothing of ours persisted and the caller has not acted, so
			// release the consumed credential and 409.
			if _, same := s.priorUseMatchesRequest(sealed, useID, ur, brokerKind, paramsCommitment); same {
				idempotent = true
				return nil
			}
			shim.RollbackUse(ev)
			sealed, grantID = "", ""
			conflictErr = fmt.Errorf("idempotency_key is already bound to a different record in this project (a key cannot be reused across operations, phases, or sessions)")
			return nil
		}
		if e != nil {
			if errors.Is(e, store.ErrRecordIDConflict) {
				// A different record already holds this deterministic use id (persisted nothing): a conflict, not
				// an infra failure — release the credential (the caller has not acted) and 409.
				shim.RollbackUse(ev)
				conflictErr = e
				return nil
			}
			// The transaction owns both ledger claims and the receipt. Returning
			// an error rolls all three back; a COMMIT error is classified only
			// by withProjectWrite after this callback returns successfully.
			return e
		}
		return nil
	})
	if conflictErr != nil {
		writeErr(w, http.StatusConflict, "use rejected: "+conflictErr.Error())
		return
	}
	if validateErr != nil {
		// The actual capability-authorization decision (a forged/expired/replayed/wrong-scope use) —
		// as opposed to conflictErr (a reused idempotency key, no authorization performed) or storeErr
		// (an infra failure), neither of which is an allow/deny outcome.
		s.mUseOutcome.WithLabelValue("deny").Inc()
		writeErr(w, http.StatusBadRequest, "use rejected: "+validateErr.Error())
		return
	}
	if storeErr != nil {
		writeErr(w, http.StatusInternalServerError, "store use receipt: "+storeErr.Error())
		return
	}
	s.mUseOutcome.WithLabelValue("allow").Inc()
	writeJSON(w, http.StatusCreated, map[string]any{
		"use_id":     useID,
		"grant_id":   grantID,
		"record":     json.RawMessage(sealed),
		"idempotent": idempotent,
	})
}

// priorUseMatchesRequest is the single exact-retry rule for both the bounded
// read-only fast path and the guarded write path.
func (s *Server) priorUseMatchesRequest(recordJSON, useID string, ur useRequest, brokerKind, paramsCommitment string) (grantID string, same bool) {
	rid, sessionID, kind, grantID := useReceiptIdentity(recordJSON)
	return grantID, rid == useID && sessionID == ur.SessionID && kind == brokerKind && s.storedUseMatchesRequest(recordJSON, ur, paramsCommitment)
}

// useReceiptIdentity extracts the identity tuple of a stored broker/resource record — its record_id,
// session_id, broker `kind` (use|use_intent|use_outcome) and authority.grant_id. It decides whether a
// record found under an idempotency key is an EXACT idempotent retry of the current request (matching
// record_id + session_id + kind) or a CONFLICTING reuse of that key. A generic /v2/records row carries no
// extensions.broker.kind, so it returns kind == "" and can never match a use phase (kind is non-empty).
func useReceiptIdentity(recJSON string) (recordID, sessionID, kind, grantID string) {
	var probe struct {
		RecordID  string `json:"record_id"`
		SessionID string `json:"session_id"`
		Authority struct {
			GrantID string `json:"grant_id"`
		} `json:"authority"`
		Extensions struct {
			Broker struct {
				Kind string `json:"kind"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	_ = json.Unmarshal([]byte(recJSON), &probe)
	return probe.RecordID, probe.SessionID, probe.Extensions.Broker.Kind, probe.Authority.GrantID
}

// storedUseMatchesRequest permits a committed exact retry without applying the
// capability's CURRENT expiry, revocation, or replay state. It still verifies
// the PRESENTED capability under this server's configured issuer key and
// recomputes its descriptor-bound PoP challenge against the signed receipt.
// This rejects changed tokens or use sequences even if the caller copies the
// original use_sig; no raw capability has to be retained in the receipt.
func (s *Server) storedUseMatchesRequest(recordJSON string, ur useRequest, paramsCommitment string) bool {
	if s.brokerKey == nil {
		return false
	}
	claims, err := broker.VerifyCapability(ur.Capability, s.brokerKey.Public().(ed25519.PublicKey))
	if err != nil {
		return false
	}
	var p struct {
		ProjectID   string `json:"project_id"`
		InputCommit struct {
			Commitment string `json:"commitment"`
		} `json:"input_commit"`
		Extensions struct {
			Broker struct {
				UseEvidence struct {
					GrantID           string `json:"grant_id"`
					JTI               string `json:"jti"`
					ResourceID        string `json:"resource_id"`
					Action            string `json:"action"`
					Nonce             string `json:"nonce"`
					UseSig            string `json:"use_sig"`
					CnfPub            string `json:"cnf_pub"`
					PopChallengeHash  string `json:"pop_challenge_hash"`
					UseSequenceNumber int    `json:"use_sequence_number"`
				} `json:"use_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(recordJSON), &p) != nil || claims.Version != 2 ||
		p.ProjectID != ur.ProjectID || claims.ProjectID != p.ProjectID {
		return false
	}
	ue := p.Extensions.Broker.UseEvidence
	if ue.Action != ur.Action || ue.Nonce != ur.Nonce || ue.UseSequenceNumber != ur.UseSequenceNumber ||
		p.InputCommit.Commitment != paramsCommitment ||
		claims.Jti == "" || claims.Jti != ue.GrantID || claims.Jti != ue.JTI ||
		claims.Aud != s.resourceID || claims.Aud != ue.ResourceID || claims.Act != ue.Action ||
		claims.Cnf == "" || claims.Cnf != ue.CnfPub {
		return false
	}
	useSig, err := base64.RawURLEncoding.DecodeString(ur.UseSig)
	if err != nil || len(useSig) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(useSig) != ue.UseSig {
		return false
	}
	cnfPub, err := base64.RawURLEncoding.DecodeString(claims.Cnf)
	if err != nil || len(cnfPub) != ed25519.PublicKeySize {
		return false
	}
	binding, err := resourceshim.CredentialBinding(ur.Capability)
	if err != nil {
		return false
	}
	challenge := resourceshim.UsePoPChallenge(claims.Jti, ue.ResourceID, ue.Action, paramsCommitment, binding, ur.Nonce)
	return ue.PopChallengeHash == "sha256:"+hex.EncodeToString(challenge) && ed25519.Verify(ed25519.PublicKey(cnfPub), challenge, useSig)
}

// storedOutcomeMatchesRequest reports whether the stored use_outcome receipt completes the SAME intent with
// the SAME status — so a reused outcome idem key carrying a different intent_ref/status is a 409, not a 201
// echoing an unrelated outcome (adversarial review convergence).
func storedOutcomeMatchesRequest(recordJSON, intentRef, status string) bool {
	var p struct {
		Extensions struct {
			Broker struct {
				UseOutcome struct {
					IntentRef string `json:"intent_ref"`
					Status    string `json:"status"`
				} `json:"use_outcome"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(recordJSON), &p) != nil {
		return false
	}
	uo := p.Extensions.Broker.UseOutcome
	return uo.IntentRef == intentRef && uo.Status == status
}

// intentAndOutcome resolves, in ONE pass over the session's records, (a) the broker/resource record whose record_id
// is intentRef (the use_intent an outcome completes) and (b) the record_id of a use_outcome that already completes
// intentRef, read from the SIGNED use_outcome payload the verifier pairs on (not the unsigned extensions.broker
// sibling). /v2/use-outcome runs under the process-wide ingestMu, so it scans the session once, not once per question.
// A read error propagates (fail closed → retryable 500). Caller holds ingestMu.
//
// A matching record must be a real broker/resource record (it carries extensions.broker.kind). A generic record can
// never set extensions.broker (reserved), so a pre-seeded generic record with a matching record_id is NOT treated as
// the intent — the gateway validation (PoP, consume-before-act) is never skipped on a spoofed record. (Reserved
// record_id prefixes also block the pre-seed.)
func (s *Server) intentAndOutcome(st store.Store, projectID, sessionID, intentRef string) (intentJSON string, intentFound bool, outcomeID string, outcomeFound bool, err error) {
	recs, err := st.SessionRecords(projectID, sessionID)
	if err != nil {
		// FAIL CLOSED (averin#14): a SessionRecords read error is NOT "intent not found" — propagate it so the
		// caller answers a retryable 500, not a 400 that makes the client abandon the outcome (breaking the
		// intent→outcome pairing and leaving a permanent intent_without_outcome).
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

// buildUseRecord assembles the unsealed use-receipt Decision Record: a tool_gateway-role authority
// with a RESOURCE-signed evidence_sig over the re-derivable use_evidence (R1/R2), a hiding commitment
// over the operation params, and the use lifecycle under extensions.broker (kind=use → resource role).
func (s *Server) buildUseRecord(useID string, ur useRequest, ev resourceshim.UseEvidence, paramsDigest, commitment, brokerKind string) (map[string]any, []store.DisclosureSecret, error) {
	// D5 (ADR 0004): brokerKind is "use" (one-phase ADR-0003) or "use_intent" (two-phase, recorded BEFORE
	// the side effect). use_evidence.kind MUST equal the extensions.broker.kind discriminator (the verifier
	// rejects divergence), so stamp it onto the evidence before hashing.
	ev.Kind = brokerKind
	// evidence_hash = sha256(RCP-canonicalize(use_evidence)) via the core (R1), signed by the RESOURCE
	// key (R2) and record_id-bound to this receipt.
	evidenceJSON, err := json.Marshal(ev)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal use evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("derive use evidence_hash: %w", err)
	}
	evidenceSig, err := s.resourceCore.SignEvidence("gateway_enforced", ur.ProjectID, useID, evidenceHash)
	if err != nil {
		return nil, nil, fmt.Errorf("sign use evidence (resource key): %w", err)
	}
	// Store the raw params content-addressed for selective disclosure. D2: input_commit IS the agent's
	// PoP-bound hiding commitment (over (params, params_nonce)) — the SAME value the offline verifier
	// reconstructs the PoP challenge from. The disclosure opens it with the agent's params_nonce.
	nonce := ur.ParamsNonce

	// use_evidence is carried verbatim (the verifier re-derives evidence_hash from it). Round-trip the
	// typed struct through JSON into a generic map so it embeds as a JSON object in the record body.
	var useEvidence map[string]any
	if err := json.Unmarshal(evidenceJSON, &useEvidence); err != nil {
		return nil, nil, fmt.Errorf("use evidence to map: %w", err)
	}

	rec := map[string]any{
		"record_id":     useID,
		"project_id":    ur.ProjectID,
		"session_id":    ur.SessionID,
		"agent_id":      "averin-resource",
		"agent_version": "averin-resource",
		"event_type":    "tool_call",
		"observed_via":  "broker",
		"action":        ev.Action,
		"status":        "ok",
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "tool_gateway",
			"grant_id":          ev.GrantID,
			"evidence_hash":     evidenceHash,
			"evidence_sig":      evidenceSig,
			"evaluated_at":      ts(s.now()),
		},
		"input_commit": map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				// kind (use | use_intent) + enforcement_point=tool_gateway classifies this to the RESOURCE
				// role (R2); the verifier requires use_evidence.kind == this discriminator.
				"kind":         brokerKind,
				"grant_id":     ev.GrantID,
				"resource_id":  ev.ResourceID,
				"use_evidence": useEvidence,
			},
		},
	}
	disclosures := []store.DisclosureSecret{
		{RecordID: useID, Field: "input", ValueDigest: paramsDigest, NonceHex: nonce},
	}
	return rec, disclosures, nil
}

func deterministicOutcomeID(projectID, idem string) string {
	return "outcome-" + uuidV5Shaped("averin.use_outcome.id.v1", projectID, idem)
}

type useOutcomeRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	ProjectID      string `json:"project_id"`
	SessionID      string `json:"session_id"`
	IntentRecordID string `json:"intent_record_id"` // the use_intent's record_id (from POST /v2/use-intent)
	Status         string `json:"status"`           // outcome status, default "ok"
}

// handleUseOutcome records the SECOND phase of a two-phase use (ADR 0004 D5) — recorded AFTER the side
// effect, completing the use_intent named by intent_record_id. No new PoP/consumption (the intent already
// consumed the credential before acting); this just anchors the completion so a crash-after-act leaves a
// detectable intent_without_outcome rather than an invisible action.
func (s *Server) handleUseOutcome(w http.ResponseWriter, r *http.Request) {
	if s.resourceCore == nil || s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "resource gateway not enabled (set the resource recording key + broker issuing key)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var or useOutcomeRequest
	if err := decode(body, &or); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid use-outcome request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && or.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if or.ProjectID == "" || or.SessionID == "" || or.IntentRecordID == "" {
		writeErr(w, http.StatusBadRequest, "project_id, session_id and intent_record_id are required")
		return
	}
	idem := or.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header)")
		return
	}
	if reservedIdem(idem) { // an outcome under denial:<denialID> would later collapse a denial and suppress it
		writeErr(w, http.StatusBadRequest, reservedIdemMsg)
		return
	}
	if err := rejectNUL("project_id", or.ProjectID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	status := or.Status
	if status == "" {
		status = "ok"
	}
	outcomeID := deterministicOutcomeID(or.ProjectID, idem)

	var sealed string
	var idempotent bool
	var clientErr, conflictErr error
	storeErr := s.withProjectWrite(r.Context(), or.ProjectID, func(st store.Store) error {
		// Outcome idempotency is keyed on `idem` (the PutRecord dedupe key), resolved up front: a retry that
		// matches (record_id, session_id, kind) AND completes the SAME intent_ref/status
		// (storedOutcomeMatchesRequest) is an honest retry; any other record under this key is a conflict → 409
		// (else PutRecord would later collapse the outcome onto a foreign row and echo it).
		prior, found, le := st.RecordByIdem(or.ProjectID, idem)
		if le != nil {
			return le // fail closed on an ambiguous idempotency lookup (mirror handleUsePhase) — no partial outcome
		}
		if found {
			rid, sess, kind, _ := useReceiptIdentity(prior.JSON)
			// EXACT-request match (adversarial review): also require the stored outcome to complete the SAME intent with the
			// SAME status, so a reused idem key carrying a different intent_ref/status is a 409, not a 201 that
			// echoes an unrelated outcome.
			if rid == outcomeID && sess == or.SessionID && kind == "use_outcome" && storedOutcomeMatchesRequest(prior.JSON, or.IntentRecordID, status) {
				sealed, idempotent = prior.JSON, true
				return nil
			}
			conflictErr = fmt.Errorf("idempotency_key is already bound to a different record in this project (a key cannot be reused across operations, phases, or sessions)")
			return nil
		}
		// resolve the intent this outcome completes: it must be a use_intent recorded in this session, and
		// we read its content_hash to bind the before-act ordering into the resource-signed payload.
		intentJSON, ok, priorOutcome, outcomeDone, re := s.intentAndOutcome(st, or.ProjectID, or.SessionID, or.IntentRecordID)
		if re != nil {
			return re // FAIL CLOSED (averin#14): a SessionRecords read error → retryable 500, not a 400 "not found"
		}
		if !ok {
			clientErr = fmt.Errorf("intent_record_id %q not found in this session", or.IntentRecordID)
			return nil
		}
		var probe struct {
			ContentHash string `json:"content_hash"`
			Extensions  struct {
				Broker struct {
					Kind string `json:"kind"`
					// read grant_id from the SIGNED use_evidence (what the verifier matches), not the
					// unsigned extensions.broker.grant_id sibling, so the outcome binds the same grant the
					// resource signed into the intent.
					UseEvidence struct {
						GrantID string `json:"grant_id"`
					} `json:"use_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		}
		if e := json.Unmarshal([]byte(intentJSON), &probe); e != nil {
			return fmt.Errorf("parse intent record: %w", e)
		}
		if probe.Extensions.Broker.Kind != "use_intent" {
			clientErr = fmt.Errorf("record %q is not a use_intent (kind=%q)", or.IntentRecordID, probe.Extensions.Broker.Kind)
			return nil
		}
		// An intent has EXACTLY ONE outcome: a second use_outcome for the same intent (e.g. "ok" then "failed"
		// under a different idempotency key) would make the anchored bundle fail verification. The honest retry
		// of the SAME outcome was already answered above via its idempotency key, so any other outcome already
		// completing this intent is a conflict → 409, checked under ingestMu so two racing outcomes cannot both land.
		if outcomeDone {
			conflictErr = fmt.Errorf("intent %q already has a recorded use_outcome (%s); an intent is completed exactly once", or.IntentRecordID, priorOutcome)
			return nil
		}
		rec, be := s.buildUseOutcomeRecord(outcomeID, or.ProjectID, or.SessionID, probe.Extensions.Broker.UseEvidence.GrantID, or.IntentRecordID, probe.ContentHash, status)
		if be != nil {
			return be // 500: never seal an outcome whose evidence could not be hashed/signed
		}
		stored, created, se := s.sealAndStore(st, or.ProjectID, or.SessionID, idem, rec, nil)
		if errors.Is(se, store.ErrRecordIDConflict) {
			conflictErr = se // a different record already holds this deterministic outcome id; nothing persisted
			return nil
		}
		if se != nil {
			return se
		}
		if !created {
			// PutRecord COLLAPSED onto an already-stored row (a same-key insert that raced past the RecordByIdem
			// check above): this outcome was not persisted. Only the SAME outcome may be echoed back; anything
			// else is another record's receipt → 409 (mirrors the up-front idempotency check).
			if rid, sess, kind, _ := useReceiptIdentity(stored); rid == outcomeID && sess == or.SessionID && kind == "use_outcome" && storedOutcomeMatchesRequest(stored, or.IntentRecordID, status) {
				sealed, idempotent = stored, true
				return nil
			}
			conflictErr = fmt.Errorf("idempotency_key is already bound to a different record in this project (a key cannot be reused across operations, phases, or sessions)")
			return nil
		}
		sealed = stored
		return nil
	})
	if conflictErr != nil {
		writeErr(w, http.StatusConflict, "use-outcome rejected: "+conflictErr.Error())
		return
	}
	if clientErr != nil {
		writeErr(w, http.StatusBadRequest, "use-outcome rejected: "+clientErr.Error())
		return
	}
	if storeErr != nil {
		writeErr(w, http.StatusInternalServerError, "store use outcome: "+storeErr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"outcome_id": outcomeID,
		"intent_ref": or.IntentRecordID,
		"record":     json.RawMessage(sealed),
		"idempotent": idempotent,
	})
}

// buildUseOutcomeRecord assembles a use_outcome record. The SIGNED use_outcome payload binds the join
// (grant_id, intent_ref) AND the before-act ordering (intent_hash = the intent's content_hash) to the
// RESOURCE evidence signature — the verifier reads these from the signed payload, never the unsigned
// extensions.broker siblings, so a relay holding only the record-signing key cannot redirect or backfill.
func (s *Server) buildUseOutcomeRecord(outcomeID, projectID, sessionID, grantID, intentRef, intentHash, status string) (map[string]any, error) {
	payload := map[string]any{
		"grant_id":    grantID,
		"intent_hash": intentHash,
		"intent_ref":  intentRef,
		"kind":        "use_outcome",
		"status":      status,
	}
	payloadJSON, _ := json.Marshal(payload)
	evidenceHash, err := s.core.RcpEvidenceHash(string(payloadJSON))
	if err != nil {
		return nil, fmt.Errorf("use-outcome evidence hash: %w", err)
	}
	// Do NOT seal an outcome carrying an unsigned/invalid evidence_sig into the append-only log: propagate a
	// sign failure so the caller gets a 500 and can retry. The intent is already recorded, so a missing valid
	// outcome surfaces as intent_without_outcome — never a permanently-unverifiable record (adversarial review).
	evidenceSig, err := s.resourceCore.SignEvidence("gateway_enforced", projectID, outcomeID, evidenceHash)
	if err != nil {
		return nil, fmt.Errorf("use-outcome evidence sign: %w", err)
	}
	return map[string]any{
		"record_id": outcomeID,
		// FORCE the causal edge to the intent (unioned with session heads in sealAndStore) so the outcome
		// links to its intent even if a record was appended between the two phases — the verifier requires
		// the outcome's causal_prev to include the intent content_hash.
		"causal_prev_hashes": []string{intentHash},
		"project_id":         projectID,
		"session_id":         sessionID,
		"agent_id":           "averin-resource",
		"agent_version":      "averin-resource",
		"event_type":         "tool_call",
		"observed_via":       "broker",
		"action":             "use_outcome",
		"status":             status,
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "tool_gateway",
			"grant_id":          grantID,
			"evidence_hash":     evidenceHash,
			"evidence_sig":      evidenceSig,
			"evaluated_at":      ts(s.now()),
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":        "use_outcome",
				"grant_id":    grantID,
				"intent_ref":  intentRef,
				"use_outcome": payload,
			},
		},
	}, nil
}

// commitLowEntropyFields replaces each raw input/output/rationale field in rec with a hiding
// commitment {alg, commitment, low_entropy}, storing the raw value content-addressed and minting a
// fresh nonce. It returns the disclosure secrets (bound to recordID) to persist atomically with the
// record. The plaintext is deleted from rec so it never enters the signed body (and would otherwise
// be rejected by the closed schema).
func (s *Server) commitLowEntropyFields(rec map[string]any, recordID string) ([]store.DisclosureSecret, error) {
	var out []store.DisclosureSecret
	for _, field := range []string{"input", "output", "rationale"} {
		v, ok := rec[field]
		if !ok {
			continue
		}
		raw, err := rawValueBytes(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		projectID, _ := rec["project_id"].(string)
		addr, err := s.content.Put(content.WithTenant(context.Background(), projectID), raw)
		if err != nil {
			return nil, fmt.Errorf("store %s content: %w", field, err)
		}
		nonce, err := s.core.RandomNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		commitment, err := s.core.Commit(field, raw, nonce)
		if err != nil {
			return nil, fmt.Errorf("commit %s: %w", field, err)
		}
		rec[field+"_commit"] = map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		}
		// The encrypted raw blob may be deleted by retention, but the hiding commitment,
		// lineage and capture authority remain inside the signed record. This makes the
		// post-retention proof independently auditable without pretending the raw payload
		// is still available for disclosure. The retained reference is the NONCE'D
		// commitment, never the plain content digest: an unsalted sha256 of a low-entropy
		// value in the always-exported body would be dictionary-reversible (threat #6),
		// undoing exactly what the commitment above hides. The plain digest lives only in
		// the server-private disclosure store. (lineage/capture_authority are stamped by
		// sealAndStore, after the server defaults for span_id/observed_via exist.)
		extensions, _ := rec["extensions"].(map[string]any)
		if extensions == nil {
			extensions = map[string]any{}
			rec["extensions"] = extensions
		}
		evidence, _ := extensions["feir_evidence"].(map[string]any)
		if evidence == nil {
			evidence = map[string]any{}
			extensions["feir_evidence"] = evidence
		}
		payloads, _ := evidence["payloads"].(map[string]any)
		if payloads == nil {
			payloads = map[string]any{}
			evidence["payloads"] = payloads
		}
		payloads[field] = map[string]any{
			"commitment": commitment, "payload_reference": "averin-commit:" + commitment,
			"retention_class": "raw_payload",
		}
		delete(rec, field)
		out = append(out, store.DisclosureSecret{
			RecordID: recordID, Field: field, ValueDigest: addr.Digest, NonceHex: nonce,
		})
	}
	return out, nil
}

// rawValueBytes is the byte form of a low-entropy field that gets committed: a string verbatim, any
// other JSON value as its marshaled bytes (so the disclosed value round-trips exactly what was sent).
func rawValueBytes(v any) ([]byte, error) {
	if s, ok := v.(string); ok {
		return []byte(s), nil
	}
	return json.Marshal(v)
}

// errAuthorityRejected is returned by normalizeAuthority when AVERIN_REQUIRE_PINNED_AUTHORITY is on and a
// record's CLAIMED elevated authority (an authority-bearing kill/approval/policy/delegation claim) fails key
// verification. Rather than silently sealing it downgraded to the forgeable caller_declared (the default,
// back-compat behavior), the ingest is REJECTED so a govder/averin key MISALIGNMENT surfaces loudly instead of
// permanently recording a kill/audit at forgeable authority. Callers map it to a retryable 500 — idempotency
// makes the retry safe, and once the operator aligns the pinned key the same record elevates and seals.
var errAuthorityRejected = errors.New("authority elevation rejected (AVERIN_REQUIRE_PINNED_AUTHORITY): claimed source failed key verification")

// authorityDowngradeLogInterval throttles the failed-elevation WARNING so a persistent key misalignment
// (which fires on every ingest) cannot flood the log; the metrics counter carries the exact count.
const authorityDowngradeLogInterval = time.Minute

// normalizeAuthority enforces honest authority labeling. The server never labels authority as an elevated
// source on the client's say-so: a claimed policy_engine_signed / human_signed / delegate_signed elevates only
// if its evidence_sig verifies under the key pinned FOR THAT source (T7); otherwise the source is unpinned or
// the evidence fails, which is a FAILED elevation. On a failed elevation the default (back-compat) behavior is
// to downgrade to the forgeable caller_declared and seal anyway; with AVERIN_REQUIRE_PINNED_AUTHORITY on it
// instead REJECTS the ingest (fail-closed) so a key MISALIGNMENT never permanently records an authority-bearing
// record at forgeable authority. A record with no elevated claim (empty/caller_declared) is untouched by either
// mode. (spec §11; coverage-limits.md)
func (s *Server) normalizeAuthority(rec map[string]any) error {
	a, ok := rec["authority"].(map[string]any)
	if !ok {
		return nil
	}
	v := s.checkAuthority(rec)
	if v.elevate {
		a["source"] = v.claimed // verified; evidence_hash/evidence_sig retained for the offline verifier
		rec["authority"] = a
		return nil
	}
	if v.failedElevation {
		s.mAuthorityDowngrades.Inc()
		if err := s.onFailedElevation(v.claimed, v.keyID); err != nil {
			return err
		}
	}
	a["source"] = "caller_declared"
	rec["authority"] = a
	return nil
}

// authorityVerdict is checkAuthority's side-effect-free decision for one record's authority block.
type authorityVerdict struct {
	claimed         string // the caller-claimed authority.source
	keyID           string // the pinned key's log-safe id, or "unpinned"
	elevate         bool   // the claim verified under the key pinned for (project, source): seal it as claimed
	failedElevation bool   // an elevation was attempted and FAILED (normalizeAuthority downgrades or rejects it)
}

// checkAuthority is the PURE core of normalizeAuthority — no metric, no log, no mutation — so the batch pre-pass
// can dry-run it (a deterministic authority rejection must reject the WHOLE batch before any item is sealed).
// rec must carry a map authority.
func (s *Server) checkAuthority(rec map[string]any) authorityVerdict {
	a, _ := rec["authority"].(map[string]any)
	claimed, _ := a["source"].(string)
	// A record with no elevated claim at all (empty, or already caller_declared) has nothing to
	// downgrade FROM — only an ATTEMPTED elevation that fails counts toward mAuthorityDowngrades
	// (the silent key-misalignment signal), so ordinary caller_declared traffic does not swamp it, and the
	// fail-closed toggle never rejects plain caller_declared Phase-1 traffic.
	attemptedElevation := claimed != "" && claimed != "caller_declared"
	// Phase-1 default, or a source with no pinned key: authority is forgeable -> caller_declared (threat #4).
	// Looking the key up BY (project, claimed source) is what lets policy_engine_signed AND human_signed
	// coexist — each elevates only under the key pinned for that exact source — AND what makes a multi-tenant
	// deployment work: the upstream authority derives its key per (tenant, role) and its tenant is the averin
	// project, so a source-only lookup could elevate exactly ONE tenant and silently downgraded the rest (F1).
	recProjectID, _ := rec["project_id"].(string)
	key, pinned := s.authorityKeyFor(recProjectID, claimed)
	if !pinned {
		return authorityVerdict{claimed: claimed, keyID: "unpinned", failedElevation: attemptedElevation}
	}
	// T7 model (b): elevate to the claimed source ONLY if the caller-supplied evidence_sig verifies under that
	// source's pinned key over the canonical authority preimage; else fall back to caller_declared.
	recordID, _ := rec["record_id"].(string)
	eh, _ := a["evidence_hash"].(string)
	es, _ := a["evidence_sig"].(string)
	if verifyAuthorityEvidence(claimed, recProjectID, recordID, eh, es, key) {
		return authorityVerdict{claimed: claimed, elevate: true}
	}
	// A source IS pinned but the evidence failed to verify under it — a genuine key-misalignment
	// (wrong signature, wrong preimage, or a forged claim), not just an unconfigured source.
	return authorityVerdict{claimed: claimed, keyID: authorityKeyID(key), failedElevation: true}
}

// onFailedElevation is the companion to the mAuthorityDowngrades counter: it emits a rate-limited WARNING that
// NAMES the claimed source and the pinned-key id (or "unpinned") — so a silent govder/averin key misalignment
// is visible in logs, not only in metrics — and, when AVERIN_REQUIRE_PINNED_AUTHORITY is on, returns
// errAuthorityRejected so the caller REJECTS the ingest instead of sealing the record downgraded to
// caller_declared. The reject is NOT rate-limited (every failing record must fail closed); only the log line is.
// Called under ingestMu (via normalizeAuthority ← ingestOne), so authorityDowngradeLogAt needs no extra lock.
func (s *Server) onFailedElevation(claimed, keyID string) error {
	now := s.now()
	if now.Sub(s.authorityDowngradeLogAt) >= authorityDowngradeLogInterval {
		s.authorityDowngradeLogAt = now
		disposition := "downgraded to forgeable caller_declared and sealed"
		if s.requirePinnedAuthority {
			disposition = "REJECTED (AVERIN_REQUIRE_PINNED_AUTHORITY on)"
		}
		log.Printf("WARNING: authority elevation FAILED key verification (claimed source=%q, pinned_key=%s) — record %s. A govder/averin authority-key MISALIGNMENT can affect every kill/approval/policy record; verify the pinned authority pubkey. (count: averin_authority_downgrades_total)", claimed, keyID, disposition)
	}
	if s.requirePinnedAuthority {
		return fmt.Errorf("%w: source %q, pinned_key %s", errAuthorityRejected, claimed, keyID)
	}
	return nil
}

// authorityKeyID renders a short, log-safe fingerprint of a pinned authority verifying key (a base64url
// prefix), so a WARNING can name WHICH pinned key an elevation was checked against without dumping the key.
func authorityKeyID(key ed25519.PublicKey) string {
	enc := base64.RawURLEncoding.EncodeToString(key)
	if len(enc) > 12 {
		return enc[:12] + "..."
	}
	return enc
}

// verifyAuthorityEvidence checks an authority evidence_sig exactly as the offline verifier does (core
// authority.rs): ed25519 over LP4("averin.authority.v2") ‖ LP4(source) ‖ LP4(project_id) ‖ LP4(record_id) ‖
// utf8(evidence_hash), under `key`, with a well-formed sha256 evidence_hash and a non-empty project_id +
// record_id (so a record the server stamps will actually elevate to `verified` offline, not `failed`).
// project_id binds the evidence to its tenant so a verified triple cannot be replayed cross-project (adversarial review).
func verifyAuthorityEvidence(source, projectID, recordID, evidenceHash, evidenceSig string, key ed25519.PublicKey) bool {
	if projectID == "" || recordID == "" || !strings.HasPrefix(evidenceSig, "ed25519:") || !strings.HasPrefix(evidenceHash, "sha256:") {
		return false
	}
	// evidence_hash must be CANONICAL lowercase sha256:<64hex>: the offline verifier's parse_sha256 rejects
	// uppercase/non-canonical hex, so a record the server stamped over a non-canonical hash would read
	// `failed`, not `verified`. Re-encoding the decoded bytes and comparing enforces canonical lowercase.
	hexPart := strings.TrimPrefix(evidenceHash, "sha256:")
	hb, err := hex.DecodeString(hexPart)
	if err != nil || len(hb) != 32 || hex.EncodeToString(hb) != hexPart {
		return false
	}
	// evidence_sig must be CANONICAL base64url too (the verifier's strict decoder rejects non-canonical bits).
	sigPart := strings.TrimPrefix(evidenceSig, "ed25519:")
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != sigPart {
		return false
	}
	var pre []byte
	lp := func(str string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(str)))
		pre = append(pre, b[:]...)
		pre = append(pre, str...)
	}
	lp("averin.authority.v2")
	lp(source)
	lp(projectID)
	lp(recordID)
	pre = append(pre, evidenceHash...)
	return ed25519.Verify(key, pre, sig)
}

// handleOTel ingests an OTLP/JSON trace export. The project comes from ?project= (NEVER the OTLP
// payload), each span becomes a sealed record (observed_via=otel).
func (s *Server) handleOTel(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if project == "" {
		writeErr(w, http.StatusBadRequest, "project query param required")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	bodies, err := otel.MapSpansToRecords(body, project)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ingested, failed := 0, 0
	var errs []string
	for _, b := range bodies {
		raw, err := json.Marshal(b)
		if err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		// content-addressed idempotency key (passed as the header arg so we marshal once and don't
		// mutate the body): a re-sent identical span collapses (#8), but two distinct spans — even
		// sharing a span_id across traces — never collide. A per-span failure does not abort the
		// rest (idempotency makes a whole-export retry safe), so partial success is reported honestly.
		sum := sha256.Sum256(raw)
		if _, _, err := s.ingestOne(r.Context(), raw, "otel-"+hex.EncodeToString(sum[:])); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		ingested++
	}
	code := http.StatusCreated
	if ingested == 0 && failed > 0 {
		code = http.StatusBadRequest
	}
	writeJSON(w, code, map[string]any{"ingested": ingested, "failed": failed, "errors": errs})
}

// ---- checkpoints ----

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	if projectID == "" {
		writeErr(w, http.StatusBadRequest, "project query param required")
		return
	}
	sealed, witnessWarn, err := s.createCheckpoint(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"checkpoint": json.RawMessage(sealed)}
	if witnessWarn != nil {
		resp["warning"] = witnessWarn.Error() // checkpoint created; witnessing is pending (backfill)
	}
	writeJSON(w, http.StatusCreated, resp)
}

// createCheckpoint seals the current frontier and stores it, then best-effort appends it to the
// witness. Returns (sealed, witnessWarning, fatalErr). Serialized so concurrent calls cannot read
// the same NextCheckpointSeq and fork the chain. Store-before-witness with a monotonic seq means a
// witness failure does NOT re-seal the same seq on retry (seq has already advanced) — so it can
// never wedge checkpointing; the un-witnessed checkpoint is reported via the warning and is
// storedGrantFields reads the response metadata (exp unix-seconds, scope_class) from a STORED grant
// record's signed grant_evidence, so an idempotent retry returns the ORIGINAL grant's expiry/scope_class
// (matching the reconstructed original capability) rather than fresh, request-time values.
func storedGrantFields(recordJSON string) (exp int64, scopeClass string, err error) {
	var parsed struct {
		Extensions struct {
			Broker struct {
				GrantEvidence struct {
					Exp        int64  `json:"exp"`
					ScopeClass string `json:"scope_class"`
				} `json:"grant_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if e := json.Unmarshal([]byte(recordJSON), &parsed); e != nil {
		return 0, "", fmt.Errorf("read stored grant fields: %w", e)
	}
	return parsed.Extensions.Broker.GrantEvidence.Exp, parsed.Extensions.Broker.GrantEvidence.ScopeClass, nil
}

// storedGrantMatchesRequest reports whether `req` is the SAME grant request that produced the stored
// grant record — by comparing the identity + authorization fields (agent_id, action, resource_id, scope,
// and the cnf key id derived from the request's agent_pubkey) against the signed grant_evidence. Used to
// reject an idempotency-key reuse that carries a DIFFERENT request (which must not retrieve this grant's
// capability). A malformed request pubkey cannot match a stored canonical cnf_kid → not a match.
func storedGrantMatchesRequest(recordJSON string, req broker.Request) (bool, error) {
	var p struct {
		Extensions struct {
			Broker struct {
				Kind          string `json:"kind"`
				GrantEvidence struct {
					PopVersion      int      `json:"pop_version"`
					ProjectID       string   `json:"project_id"`
					RequestHash     string   `json:"request_hash"`
					AgentID         string   `json:"agent_id"`
					Action          string   `json:"action"`
					ResourceID      string   `json:"resource_id"`
					Scope           string   `json:"scope"`
					ScopeClass      string   `json:"scope_class"`
					UseLimit        int      `json:"use_limit"`
					CnfKid          string   `json:"cnf_kid"`
					AuthzPrincipal  string   `json:"authorizing_principal"`
					DelegationChain []string `json:"delegation_chain"`
					IssuedAt        int64    `json:"issued_at"`
					Exp             int64    `json:"exp"`
				} `json:"grant_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if e := json.Unmarshal([]byte(recordJSON), &p); e != nil {
		return false, fmt.Errorf("read stored grant match fields: %w", e)
	}
	if p.Extensions.Broker.Kind != "grant" {
		return false, nil // not a grant record (e.g. a use/denial/generic row under this key): never a match
	}
	ge := p.Extensions.Broker.GrantEvidence
	if req.PoPVersion == 2 {
		if ge.PopVersion != 2 || ge.ProjectID != req.ProjectID {
			return false, nil
		}
		h, err := req.SemanticHash()
		return err == nil && ge.RequestHash == h, err
	}
	if ge.PopVersion != 0 {
		return false, nil // a historical proof cannot retrieve a v2 capability
	}
	pub, e := base64.RawURLEncoding.DecodeString(req.AgentPubKey)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return false, nil
	}
	// Compare EVERY field that shapes the grant/capability — not just identity — so a reused idem key with
	// a different scope_class (single_use!), TTL (exp!), principal, or delegation chain is a 409 conflict,
	// not a silent collapse onto a semantically-different stored capability. scope_class is the CLASSIFIED
	// result (ClassifyScope keys off both scope AND the requested class), and TTL is exp-issued_at.
	wantClass, ce := broker.ClassifyScope(req.Scope, req.ScopeClass)
	if ce != nil {
		return false, nil // an unclassifiable request can't match a stored (validly classified) grant
	}
	return ge.AgentID == req.AgentID &&
		ge.Action == req.Action &&
		ge.ResourceID == req.Resource &&
		ge.Scope == req.Scope &&
		ge.ScopeClass == string(wantClass) &&
		// M1: a retry with a different bounded_reuse cap is a 409, not a collapse. Gate on the class so a
		// non-bounded retry that carries a stray use_limit in its body (which Prepare drops, storing 0)
		// does not spuriously 409 against the stored 0.
		(wantClass != broker.ScopeBoundedReuse || ge.UseLimit == req.UseLimit) &&
		ge.CnfKid == broker.KeyID(ed25519.PublicKey(pub)) &&
		ge.AuthzPrincipal == req.Principal &&
		ge.Exp-ge.IssuedAt == int64(req.TTL.Seconds()) &&
		stringSlicesEqual(ge.DelegationChain, normalizeDelegation(req.DelegationChain)), nil
}

// normalizeDelegation maps a nil delegation chain to an empty slice, mirroring broker.Prepare's
// normalization so a retry with nil vs [] does not spuriously 409.
func normalizeDelegation(d []string) []string {
	if d == nil {
		return []string{}
	}
	return d
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// grantLog extracts the D6 grant-transparency log — each grant record's (broker_seq, content_hash) —
// sorted by broker_seq. A record is a grant iff the tuple (extensions.broker.kind == "grant",
// authority.enforcement_point == "credential_broker") matches; its broker_seq is read from the signed
// extensions.broker.grant_evidence.broker_seq. The producer ALWAYS assigns a broker_seq >= 1, so a record
// with seq < 1 is a legacy (pre-D6) grant: it is SKIPPED here (never folded with a bogus seq, which would
// corrupt the head's [1..N] prefix). Skipping is NOT silent acceptance — under strict D6 the offline
// verifier's seq-less guard rejects any committed broker grant that lacks a broker_seq once D6 is active,
// so an un-backfilled legacy grant fails verification rather than being quietly dropped (the demonstrator
// is built fresh and has none).
func grantLog(records []store.Record) ([]broker.GrantSeqHash, error) {
	var log []broker.GrantSeqHash
	for _, r := range records {
		var parsed struct {
			Authority struct {
				EnforcementPoint string `json:"enforcement_point"`
			} `json:"authority"`
			Extensions struct {
				Broker struct {
					Kind          string `json:"kind"`
					GrantEvidence struct {
						BrokerSeq int64 `json:"broker_seq"`
					} `json:"grant_evidence"`
					VoidEvidence struct {
						BrokerSeq int64 `json:"broker_seq"`
					} `json:"void_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		}
		if err := json.Unmarshal([]byte(r.JSON), &parsed); err != nil {
			return nil, fmt.Errorf("grant log: parse record %s: %w", r.ContentHash, err)
		}
		// A grant_void tombstone (POST /v2/broker-seq/void) fills its seq in the log EXACTLY as a grant would — the
		// verifier's committed_broker_log folds it identically — so an operator-voided reservation closes the gap.
		if parsed.Extensions.Broker.Kind == "grant_void" && parsed.Authority.EnforcementPoint == "credential_broker" {
			if seq := parsed.Extensions.Broker.VoidEvidence.BrokerSeq; seq >= 1 {
				log = append(log, broker.GrantSeqHash{Seq: seq, ContentHash: r.ContentHash})
			}
			continue
		}
		// Identify a grant EXACTLY as the offline verifier's classify_role does — the tuple
		// (extensions.broker.kind=="grant", authority.enforcement_point=="credential_broker"). MEMBERSHIP
		// CONTRACT (the verifier's D6 cumulative_root re-derivation MUST use the identical rule): the
		// transparency log includes every RECORDED grant by this tuple, NOT gated on whether its
		// evidence_sig verifies — a broker must not be able to omit a grant from the log by under-signing
		// it (that would BE suppression). Per-grant trust (evidence_sig under a pinned broker key) is a
		// separate axis (grant_verified), independent of transparency-log membership. Generic ingest
		// cannot set these markers (reserved above), so only /v2/grants produces them.
		if parsed.Extensions.Broker.Kind != "grant" || parsed.Authority.EnforcementPoint != "credential_broker" {
			continue
		}
		// STRICT D6: the head folds only grants that CARRY a broker_seq>=1, and the producer ALWAYS assigns
		// one (allocated under ingestMu in /v2/grants). The seq<1 skip below therefore only ever fires on a
		// LEGACY grant recorded before D6 — which strict D6 does NOT treat as benign: the verifier requires
		// every tuple-classified grant the DAG commits to carry a broker_seq, and down-ranks broker_trust to
		// `assumed` on any committed seq-less broker grant (a seq-less grant is indistinguishable from one
		// SMUGGLED out of the log). So a legacy grant must be BACKFILLED with a broker_seq before the first
		// D6 checkpoint; folding it here without a seq would instead corrupt the [1..N] prefix. The
		// demonstrator is built fresh and has none. We skip-not-fold so we never put a seq<1 entry in the
		// log; the verifier's seq-less guard — not this fold — is what rejects the un-backfilled bundle.
		if parsed.Extensions.Broker.GrantEvidence.BrokerSeq < 1 {
			continue
		}
		log = append(log, broker.GrantSeqHash{Seq: parsed.Extensions.Broker.GrantEvidence.BrokerSeq, ContentHash: r.ContentHash})
	}
	sort.Slice(log, func(i, j int) bool { return log[i].Seq < log[j].Seq })
	return log, nil
}

// checkGaplessGrantLog reports an error unless the seq-sorted grant log is exactly [1..N] AND the store's
// allocated max broker_seq equals N — i.e. every allocated seq is held by exactly one recorded grant.
func checkGaplessGrantLog(gl []broker.GrantSeqHash, maxAllocated int64) error {
	for i := 1; i < len(gl); i++ {
		if gl[i].Seq == gl[i-1].Seq {
			return fmt.Errorf("broker_seq %d is held by two recorded entries (%s, %s) — duplicate seq", gl[i].Seq, gl[i-1].ContentHash, gl[i].ContentHash)
		}
	}
	for i, g := range gl {
		if g.Seq != int64(i+1) {
			return fmt.Errorf("recorded grant broker_seq set is not a gapless [1..N] prefix (position %d holds seq %d)", i+1, g.Seq)
		}
	}
	if n := int64(len(gl)); maxAllocated != n {
		return fmt.Errorf("allocated broker_seq max %d != %d recorded grants (a reserved or orphaned seq has no recorded grant; retry that grant before checkpointing, or void the seq with POST /v2/broker-seq/void once it is older than AVERIN_BROKER_SEQ_VOID_MIN_AGE)", maxAllocated, n)
	}
	return nil
}

// priorGrantHeadRoot returns the cumulative_root of the LATEST stored checkpoint's broker_grant_head, to
// chain the next head to it (ADR 0004 D6). A project with no checkpoint yet — or whose latest checkpoint
// predates D6 (no head) — chains from the empty-log root.
func (s *Server) priorGrantHeadRoot(st store.Store, projectID string) (string, error) {
	cps, err := st.Checkpoints(projectID)
	if err != nil {
		return "", fmt.Errorf("prior grant head: %w", err)
	}
	if len(cps) == 0 {
		return broker.EmptyGrantHeadRoot(), nil
	}
	var parsed struct {
		BrokerGrantHead struct {
			CumulativeRoot string `json:"cumulative_root"`
		} `json:"broker_grant_head"`
	}
	if err := json.Unmarshal([]byte(cps[len(cps)-1].JSON), &parsed); err != nil {
		return "", fmt.Errorf("prior grant head: parse latest checkpoint: %w", err)
	}
	if parsed.BrokerGrantHead.CumulativeRoot == "" {
		return broker.EmptyGrantHeadRoot(), nil // pre-D6 checkpoint
	}
	return parsed.BrokerGrantHead.CumulativeRoot, nil
}

// priorFedHeadRoot returns the cumulative_root of `brokerID`'s entry in the LATEST stored checkpoint's
// `broker_grant_heads` MAP (M4), so the next federated head chains per-broker. A project with no checkpoint yet —
// or whose latest carries no map / no entry for this broker (the first federated checkpoint, or a pre-federation
// checkpoint) — chains from the empty-log root (this broker's federated log starts fresh).
func (s *Server) priorFedHeadRoot(st store.Store, projectID, brokerID string) (string, error) {
	cps, err := st.Checkpoints(projectID)
	if err != nil {
		return "", fmt.Errorf("prior fed head: %w", err)
	}
	if len(cps) == 0 {
		return broker.EmptyGrantHeadRoot(), nil
	}
	var parsed struct {
		BrokerGrantHeads map[string]struct {
			CumulativeRoot string `json:"cumulative_root"`
		} `json:"broker_grant_heads"`
	}
	if err := json.Unmarshal([]byte(cps[len(cps)-1].JSON), &parsed); err != nil {
		return "", fmt.Errorf("prior fed head: parse latest checkpoint: %w", err)
	}
	if h, ok := parsed.BrokerGrantHeads[brokerID]; ok && h.CumulativeRoot != "" {
		return h.CumulativeRoot, nil
	}
	return broker.EmptyGrantHeadRoot(), nil
}

// backfillable. A deterministic checkpoint_id keeps the body reproducible for a given seq.
func (s *Server) createCheckpointTx(st store.Store, projectID string) (store.Checkpoint, error) {
	heads, headsErr := st.ProjectHeads(projectID)
	count, countErr := st.RecordCount(projectID)
	grantRecs, recErr := st.GrantRecords(projectID)
	// The allocated max broker_seq is read in the SAME snapshot: every allocate→seal→insert runs under ingestMu,
	// so outside it an allocated seq with no recorded grant is never "in flight" — it is a reserved
	// (commit-ambiguous) or orphaned (failed release) seq, i.e. a real gap the fail-closed check below refuses.
	maxAlloc, maxAllocErr := st.MaxBrokerSeq(projectID)
	// Surface any snapshot-read error: signing a checkpoint with an empty frontier (heads=nil) while the
	// grant head folds a non-empty grant set would anchor a frontier that disagrees with the grant set it
	// commits, so a store-read failure must abort the checkpoint, not silently degrade it.
	seq, seqErr := st.NextCheckpointSeq(projectID)
	prev, hasPrev, prevErr := st.LatestCheckpointHash(projectID)
	// Surface ANY snapshot/chain read error: signing a checkpoint with a defaulted frontier/seq/prev (e.g.
	// seq silently 0, or prev_checkpoint_hash omitted while broker_grant_head.prior_head_hash still points
	// at the prior head) would anchor a broken/forked checkpoint, so a read failure must abort, not degrade.
	for _, e := range []error{headsErr, countErr, recErr, maxAllocErr, seqErr, prevErr} {
		if e != nil {
			return store.Checkpoint{}, fmt.Errorf("checkpoint: read project snapshot: %w", e)
		}
	}
	if heads == nil {
		heads = []string{}
	}
	var prevVal any
	if hasPrev {
		prevVal = prev
	}
	// D6 (ADR 0004 / MF2): anchor the grant-transparency head into the signed, fork-detected checkpoint.
	// The cumulative_root folds every recorded grant's (broker_seq, content_hash) in seq order, chained
	// to the previous checkpoint's cumulative_root — so a dropped/renumbered/forked grant fails the
	// verifier's re-derivation.
	gl, err := grantLog(grantRecs)
	if err != nil {
		return store.Checkpoint{}, err
	}
	// FAIL CLOSED on a broker_seq gap (ADR 0004 D6): checkpoints are append-only, so a head signed over a
	// recorded set that is not exactly [1..N] — or while an allocated seq above N has no recorded grant — would
	// anchor a PERMANENT "not a gapless [1..N] prefix" verifier failure. Refuse to sign instead; the gap closes
	// when the reserved grant is retried (its deterministic grant_id reclaims the seq) or the orphan is released.
	if err := checkGaplessGrantLog(gl, maxAlloc); err != nil {
		return store.Checkpoint{}, fmt.Errorf("checkpoint refused: %w", err)
	}
	prior, err := s.priorGrantHeadRoot(st, projectID)
	if err != nil {
		return store.Checkpoint{}, err
	}
	grantHead := broker.BrokerGrantHead(gl, prior)

	body := map[string]any{
		"schema_version":       "2",
		"canon_version":        "rcp-1",
		"domain":               "flightrecorder.checkpoint.v2",
		"checkpoint_id":        fmt.Sprintf("cp-%s-%d", projectID, seq), // deterministic per seq
		"project_id":           projectID,
		"checkpoint_seq":       seq,
		"prev_checkpoint_hash": prevVal,
		"frontier":             heads,
		"record_count":         count,
		"broker_grant_head":    grantHead,
		"created_ts":           ts(s.now()),
		"key": map[string]any{
			"signing_key_id": s.signingKeyID,
			"key_epoch":      0,
			"key_valid_from": s.keyValidFrom,
			"key_status":     "active",
		},
	}
	// M4 (ADR 0005): when this broker has a federation id, ALSO emit the per-broker_id `broker_grant_heads` MAP.
	// A single configured broker_id owns the project's whole gapless [1..N] log, so its partition == the flat
	// `gl`. The legacy single `broker_grant_head` above stays (the verifier IGNORES it once federation is active
	// — it dispatches to the per-broker partition — and it keeps the single-broker + D7 attestation paths intact).
	if s.brokerID != "" {
		priorFed, ferr := s.priorFedHeadRoot(st, projectID, s.brokerID)
		if ferr != nil {
			return store.Checkpoint{}, ferr
		}
		body["broker_grant_heads"] = broker.BrokerGrantHeads(
			map[string][]broker.GrantSeqHash{s.brokerID: gl},
			map[string]string{s.brokerID: priorFed},
		)
	}
	bodyJSON, _ := json.Marshal(body)
	sealed, err := s.core.SealCheckpoint(string(bodyJSON))
	if err != nil {
		return store.Checkpoint{}, err
	}
	var cp struct {
		CheckpointHash string `json:"checkpoint_hash"`
		Seq            int64  `json:"checkpoint_seq"`
	}
	_ = json.Unmarshal([]byte(sealed), &cp)

	// Store the sealed checkpoint (un-anchored). Anchoring is DECOUPLED: the token is stored
	// separately (anchors table) and joined into the checkpoint's `anchor` block at export time, so
	// the third-party TSA network call happens OUTSIDE this global checkpoint lock and a checkpoint
	// that failed to anchor can be back-anchored later (the checkpoints table is append-only).
	if err := st.PutCheckpoint(projectID, store.Checkpoint{JSON: sealed, CheckpointHash: cp.CheckpointHash, Seq: cp.Seq}); err != nil {
		return store.Checkpoint{}, err
	}
	return store.Checkpoint{JSON: sealed, CheckpointHash: cp.CheckpointHash, Seq: cp.Seq}, nil
}

func (s *Server) createCheckpoint(ctx context.Context, projectID string) (string, error, error) {
	var cp store.Checkpoint
	err := s.withProjectWrite(ctx, projectID, func(st store.Store) error {
		var e error
		cp, e = s.createCheckpointTx(st, projectID)
		return e
	})
	if err != nil {
		return "", nil, err
	}
	sealed := cp.JSON
	s.mCheckpointsSealed.Inc()
	var warns []string
	// best-effort witness append (bounded so a hung witness can't block); a failure leaves the
	// checkpoint stored-but-un-witnessed (reported, backfillable) rather than wedging the chain.
	if s.witness != nil {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := s.witness.Append(wctx, projectID, []byte(sealed)); err != nil {
			warns = append(warns, fmt.Sprintf("witness append failed (backfill needed): %v", err))
			s.mWitnessFailures.Inc()
			// Also LOG (not only return to the HTTP caller): an un-witnessed checkpoint is an operational gap
			// an operator must backfill, and the /v2/checkpoints response is often not watched.
			log.Printf("WARNING: checkpoint %s (project %s) stored UN-WITNESSED — witness append failed, backfill needed: %v", cp.CheckpointHash, projectID, err)
		}
		cancel()
	}

	if s.tsa != nil {
		if err := s.anchorCheckpoint(ctx, projectID, cp.Seq, cp.CheckpointHash); err != nil {
			warns = append(warns, fmt.Sprintf("checkpoint stored un-anchored (TSA failed, backfillable): %v", err))
			s.mAnchorFailures.Inc()
			// Also LOG: an un-anchored checkpoint has no third-party timestamp (threat #3 backdating window)
			// until back-anchored; surface it beyond the (often-unwatched) HTTP warning.
			log.Printf("WARNING: checkpoint %s (project %s) stored UN-ANCHORED — TSA stamp failed, back-anchor needed: %v", cp.CheckpointHash, projectID, err)
		}
	}

	var warn error
	if len(warns) > 0 {
		warn = fmt.Errorf("checkpoint created; %s", strings.Join(warns, "; "))
	}
	return sealed, warn, nil
}

// anchorCheckpoint stamps a checkpoint_hash at a third-party RFC 3161 TSA and stores the returned
// token (keyed by seq) for the export to join. The TSA timestamps the SHA-256 of the checkpoint_hash
// STRING (what the verifier re-imprints). Runs OUT of the checkpoint critical section.
func (s *Server) anchorCheckpoint(ctx context.Context, projectID string, seq int64, checkpointHash string) error {
	imprint := sha256.Sum256([]byte(checkpointHash))
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	der, err := s.tsa.Stamp(tctx, imprint[:])
	if err != nil {
		return err
	}
	// base64url-no-pad to match the Rust verifier's token decoder.
	return s.st.WithProjectWrite(tctx, projectID, func(st store.Store) error {
		return st.PutAnchor(projectID, seq, base64.RawURLEncoding.EncodeToString(der))
	})
}

// ---- app / verify / export ----

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	var sessions []string
	err := s.st.WithProjectRead(r.Context(), projectID, func(st store.Store) error {
		var e error
		sessions, e = st.Sessions(projectID)
		return e
	})
	if err != nil {
		// FAIL CLOSED (averin#3): surface a store read error as 500 rather than an empty 200 that would let a
		// caller read "no sessions" during a transient outage.
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	u := s.meter.Usage(projectID)
	billRecords, billExports := meter.Billable(u)
	writeJSON(w, http.StatusOK, map[string]any{
		"usage":            u,
		"free_tier":        meter.FreeTierRecords,
		"billable_records": billRecords,
		"billable_exports": billExports,
	})
}

// handleDAG returns a session's sealed records (the causal DAG) for the trace-waterfall view.
//
// PHASE-1 AUTHZ LIMIT: the app API has NO per-project authentication/authorization yet (RBAC/SSO is
// explicitly Phase 2, spec §3). A deployment MUST put averin behind its own auth (or run it single-
// tenant) until the authz layer lands — any caller who can reach this endpoint can read any
// project's data. Documented in docs/coverage-limits.md.
// handleListRecords returns a tenant's sealed records newest-first with truncation honesty.
func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	if projectID == "" {
		writeErr(w, http.StatusBadRequest, "project query param is required")
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > 1000 {
			n = 1000
		}
		limit = n
	}
	// Optional offset for paging deeper than the newest page (default 0 keeps the prior behavior byte-for-byte).
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		n, err := strconv.Atoi(offsetStr)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	// Page IN THE STORE (SQL LIMIT/OFFSET on Postgres) rather than loading the whole project history into RAM
	// and slicing — a large tenant no longer materializes every record per list call. RecordsPage returns
	// newest-first; RecordCount is a cheap indexed count for the truncation-honesty total.
	var total int
	var page []store.Record
	err := s.st.WithProjectRead(r.Context(), projectID, func(st store.Store) error {
		var e error
		total, e = st.RecordCount(projectID)
		if e != nil {
			return e
		}
		page, e = st.RecordsPage(projectID, limit, offset)
		return e
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]json.RawMessage, len(page))
	for i, rec := range page {
		out[i] = json.RawMessage(rec.JSON) // already newest-first
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records":   out,
		"total":     total,
		"truncated": offset+len(page) < total,
	})
}

func (s *Server) handleDAG(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	sessionID := r.URL.Query().Get("session")
	if projectID == "" || sessionID == "" {
		writeErr(w, http.StatusBadRequest, "project and session query params are required")
		return
	}
	var recs []store.Record
	err := s.st.WithProjectRead(r.Context(), projectID, func(st store.Store) error {
		var e error
		recs, e = st.SessionRecords(projectID, sessionID)
		return e
	})
	if err != nil {
		// FAIL CLOSED (averin#3): surface a store read error as 500 rather than an empty 200 that would let a
		// caller read "no records" (an apparently-empty DAG) during a transient outage.
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]json.RawMessage, len(recs))
	for i, rec := range recs {
		out[i] = json.RawMessage(rec.JSON)
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	setBundleWriteDeadline(w)
	projectID := r.URL.Query().Get("project")
	// The work is coalesced before taking a bundle slot. A Telegram/browser refresh storm for one project
	// therefore consumes one build slot, not one slot per waiting HTTP request.
	report, err := s.verifyProject(r.Context(), projectID)
	if err != nil {
		if errors.Is(err, errVerifyOverloaded) {
			writeErr(w, http.StatusServiceUnavailable, "too many concurrent verification requests; retry shortly")
			return
		}
		// A disconnected client cannot receive an error response. The shared verification is intentionally
		// allowed to finish for the remaining waiters; do not turn one cancellation into a failed flight.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(report))
}

// verifyProject builds and self-verifies one project's current bundle. The coordinator key includes the
// project and the trust-root options, so requests from different tenants (or with different verifier
// configuration) can never share a result. The result is shared only while the work is in flight; errors and
// integrity-failure reports are never retained as a reassuring answer for a later request.
func (s *Server) verifyProject(ctx context.Context, projectID string) (string, error) {
	verifyOpts := s.selfVerifyOpts()
	key := verificationKey(projectID, verifyOpts)
	return s.verifyFlights.run(ctx, key, func() (string, error) {
		// Unlike acquireBundleSlot, this worker has no ResponseWriter. It waits for capacity so a burst of
		// unrelated exports cannot cause a duplicate verification or make the first request fail spuriously.
		s.bundleSem <- struct{}{}
		defer func() { <-s.bundleSem }()

		bundle, err := s.buildBundle(projectID, false)
		if err != nil {
			return "", err
		}
		// Self-verify under the trust roots this server holds that are MEANINGFUL without the externally-held TSA
		// key — broker (or per-broker federation), resource, revocation, and cosig — so every such mode is
		// EVALUATED rather than read as a benign `absent`/`unevaluated` (false comfort). This is the server's
		// SELF-VIEW; an INDEPENDENT auditor pins all roles INCLUDING the RFC3161 TSA out-of-band (the real check).
		// Attestation remains unevaluated unless both public D7 roots are configured; see selfVerifyOpts.
		return s.core.VerifyBundleWith(bundle, verifyOpts), nil
	})
}

func verificationKey(projectID, verifyOpts string) string {
	return projectID + "\x00" + fmt.Sprintf("%x", sha256.Sum256([]byte(verifyOpts)))
}

// selfVerifyOpts builds the pinned-trust-root opts JSON from the server's configured keys, for the self-verify
// endpoint. Role-disjoint by construction (the With* setters enforce it). It pins ONLY the roles whose verdict is
// meaningful WITHOUT the external RFC3161 TSA key (which this server does not hold): broker/federation and resource
// elevation (no temporal dependency), revocation (the membership gate blocks a revoked use independent of list
// currency — see verify.rs M5), and cosig (a signature, no anchor dependency).
//
// The attestation role is excluded by default. It is included only when the operator explicitly installs BOTH
// public out-of-band roots via WithExternalVerificationRoots: an attestation issuer and an RFC 3161 TSA SPKI.
// This keeps the default self-view from self-pinning a producer key while allowing the product view to surface a
// real auditor-pinned D7 verdict when the deployment has actually configured the full trust path.
func (s *Server) selfVerifyOpts() string {
	enc := func(pub ed25519.PublicKey) string {
		return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(pub)
	}
	opts := map[string]any{}
	if s.brokerID != "" {
		opts["federated_broker_keys"] = map[string]any{s.brokerID: []string{s.core.PubKey()}}
	} else {
		opts["broker_authority_keys"] = []string{s.core.PubKey()}
	}
	if s.resourceCore != nil {
		opts["resource_authority_keys"] = []string{s.resourceCore.PubKey()}
	}
	if s.revocationKey != nil {
		opts["revocation_keys"] = []string{enc(s.revocationKey.Public().(ed25519.PublicKey))}
	}
	if len(s.cosigApprovers) > 0 {
		ak := make([]string, len(s.cosigApprovers))
		for i, a := range s.cosigApprovers {
			ak[i] = enc(a)
		}
		opts["cosig_approver_keys"] = ak
	}
	if len(s.externalVerifyAttestationKeys) > 0 && len(s.externalVerifyTSASPKI) > 0 {
		ak := make([]string, len(s.externalVerifyAttestationKeys))
		for i, key := range s.externalVerifyAttestationKeys {
			ak[i] = enc(key)
		}
		spki := make([]string, len(s.externalVerifyTSASPKI))
		for i, der := range s.externalVerifyTSASPKI {
			spki[i] = base64.RawURLEncoding.EncodeToString(der)
		}
		opts["attestation_keys"] = ak
		opts["tsa_spki_b64"] = spki
	}
	if len(s.externalVerifyTaxonomy) > 0 && len(s.externalVerifyTaxonomyKeys) > 0 {
		tk := make([]string, len(s.externalVerifyTaxonomyKeys))
		for i, key := range s.externalVerifyTaxonomyKeys {
			tk[i] = enc(key)
		}
		opts["taxonomy"] = s.externalVerifyTaxonomy
		opts["taxonomy_keys"] = tk
		opts["taxonomy_digest"] = s.externalVerifyTaxonomyDigest
		opts["taxonomy_version"] = s.externalVerifyTaxonomyVersion
	}
	b, _ := json.Marshal(opts)
	return string(b)
}

// validRecordKind is the closed value-set for the optional typed `record_kind` field (kebab-case
// per averin convention), mirroring spec/decision-record.schema.json and core/src/record.rs. leria
// seals spend-governance evidence under these kinds; a board/GRC pack filters /v2/export by them
// without parsing `extensions`.
func validRecordKind(k string) bool {
	switch k {
	case "budget-exhausted", "chargeback-posted":
		return true
	default:
		return false
	}
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	release, ok := s.acquireBundleSlot(w)
	if !ok {
		return
	}
	defer release()
	projectID := r.URL.Query().Get("project")
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "proof_only"
	}
	// Optional record_kind filter: a board pulls "all budget-exhausted this quarter" (or chargebacks)
	// without parsing `extensions`. Reject an unknown value (vs. silently returning everything) so a
	// caller's typo cannot masquerade as "no matching evidence". Works in proof_only AND full_evidence.
	recordKind := r.URL.Query().Get("record_kind")
	if recordKind != "" && !validRecordKind(recordKind) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown record_kind %q (allowed: budget-exhausted, chargeback-posted)", recordKind))
		return
	}
	bundle, snapshotDisclosures, err := s.buildBundleWithSnapshot(projectID, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.meter.ExportIssued(projectID) // billable per export
	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(bundle), &obj)
	obj["mode"], _ = jsonRaw(mode)

	// record_kind filtering surfaces a typed VIEW alongside the canonical bundle. The full `records`/
	// `checkpoints` arrays are left INTACT (the DAG + checkpoint chain verify over the WHOLE set — pruning
	// records would break causal-parent / frontier resolution), so the bundle still verifies as-is; the
	// filter only adds `filtered_records` (the matching sealed records, each individually verifiable) plus
	// a `record_kind_filter` echo. In a disclosing mode the disclosures are also pruned to the matching
	// records, so a board view does not over-disclose unrelated evidence.
	matchedRecordIDs := map[string]struct{}{}
	if recordKind != "" {
		filtered := filterRecordsByKind(obj["records"], recordKind, matchedRecordIDs)
		obj["filtered_records"], _ = jsonRaw(filtered)
		obj["record_kind_filter"], _ = jsonRaw(recordKind)
	}

	// For a disclosing mode, attach the (value, nonce) for every committed field so an offline
	// verifier can confirm each disclosure against its record's commitment (RCP §9.3). proof_only
	// ships commitments only.
	rawAvailable := false
	// The bundle itself is the authority for the completeness wording.  A D8-capable
	// deployment may now prove the strongest bounded verdict, so the old unconditional
	// "not claimed" sentence would contradict the verifier.  Re-run the same pinned
	// verifier used by /v2/verify and change the line only when the complete capstone is
	// actually present.  The wording retains the two load-bearing bounds: brokered surface
	// (not every action an agent might take) and assumed-truthful resource reporting.
	verificationReport := s.core.VerifyBundleWith(bundle, s.selfVerifyOpts())
	gaps := []string{completenessGapLine(verificationReport)}
	if mode == "selective_disclosure" || mode == "full_evidence" {
		disclosures, err := s.buildDisclosures(projectID, snapshotDisclosures)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// When a record_kind filter is active, restrict disclosures to the matching records so a typed
		// board view (full_evidence + record_kind) does not over-disclose unrelated evidence's raw fields.
		if recordKind != "" {
			pruned := disclosures[:0]
			for _, d := range disclosures {
				if rid, _ := d["record_id"].(string); rid != "" {
					if _, ok := matchedRecordIDs[rid]; ok {
						pruned = append(pruned, d)
					}
				}
			}
			disclosures = pruned
		}
		obj["disclosures"], _ = jsonRaw(disclosures)
		rawAvailable = len(disclosures) > 0
		if !rawAvailable {
			gaps = append(gaps, "no committed low-entropy fields were recorded for this project, so there is nothing to disclose")
		}
	}
	obj["gap_report"], _ = jsonRaw(map[string]any{
		"mapped_fields":         []string{"record integrity", "checkpoint chain", "declared authority"},
		"customer_supplied":     []string{"raw input/output/rationale blobs (content store)"},
		"gaps":                  gaps,
		"raw_content_available": rawAvailable,
	})
	out, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

const completenessNotClaimed = "Level-2 observation scope is per-record; Level-3 completeness not claimed"
const completenessBrokeredSurface = "Level-3 completeness is attested over the brokered surface only (resource trust is assumed truthful); actions outside that surface are not claimed"

// completenessGapLine projects the verifier's bounded D8 verdict into the export's
// human-readable gap report.  It deliberately requires the whole conjunction visible
// at this boundary: the report must be OK, name the brokered-surface capstone, and carry
// the irreducible resource-TCB qualifier.  Malformed, partial, or future-unknown reports
// retain the conservative pre-D8 sentence.
func completenessGapLine(reportJSON string) string {
	var report struct {
		OK                 bool   `json:"ok"`
		ActionCompleteness string `json:"action_completeness"`
		ResourceTrust      string `json:"resource_trust"`
	}
	if json.Unmarshal([]byte(reportJSON), &report) == nil &&
		report.OK &&
		report.ActionCompleteness == "attested_complete_over_brokered_surface" &&
		report.ResourceTrust == "assumed_truthful" {
		return completenessBrokeredSurface
	}
	return completenessNotClaimed
}

// filterRecordsByKind returns the subset of the bundle's sealed records whose signed top-level
// `record_kind` equals kind, preserving each record's canonical bytes verbatim (so a filtered_records
// entry stays individually verifiable). It records the matching records' record_ids into matched (for
// pruning disclosures). The canonical `records` array is never mutated — this is a typed VIEW only.
func filterRecordsByKind(recordsRaw json.RawMessage, kind string, matched map[string]struct{}) []json.RawMessage {
	var recs []json.RawMessage
	_ = json.Unmarshal(recordsRaw, &recs)
	out := make([]json.RawMessage, 0, len(recs))
	for _, r := range recs {
		var m map[string]json.RawMessage
		if json.Unmarshal(r, &m) != nil {
			continue
		}
		var rk string
		if raw, ok := m["record_kind"]; ok {
			_ = json.Unmarshal(raw, &rk)
		}
		if rk != kind {
			continue
		}
		out = append(out, r)
		var rid string
		if raw, ok := m["record_id"]; ok {
			_ = json.Unmarshal(raw, &rid)
		}
		if rid != "" {
			matched[rid] = struct{}{}
		}
	}
	return out
}

// buildDisclosures turns the project's stored disclosure secrets into the bundle's `disclosures`
// array: {record_id, field, value_b64, nonce_hex}. The raw value is fetched from the content store
// (which re-verifies its digest on read) and re-encoded base64url-no-pad for the verifier. Never nil.
func (s *Server) buildDisclosures(projectID string, secrets []store.DisclosureSecret) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(secrets))
	for _, d := range secrets {
		raw, err := s.content.Get(content.WithTenant(context.Background(), projectID), d.ValueDigest)
		if errors.Is(err, content.ErrNotFound) {
			// Retention intentionally removes the opening material. The signed
			// record still carries the digest/reference added at ingest, so omit
			// only this optional disclosure rather than failing the whole bundle.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("disclose %s/%s: %w", d.RecordID, d.Field, err)
		}
		out = append(out, map[string]any{
			"record_id": d.RecordID,
			"field":     d.Field,
			"value_b64": base64.RawURLEncoding.EncodeToString(raw),
			"nonce_hex": d.NonceHex,
		})
	}
	return out, nil
}

// maxConcurrentBundleReads caps concurrent whole-project bundle builds (GET /v2/export + /v2/verify). Each
// build materializes the project's full record + checkpoint history in RAM (see docs/dev/LIMITATIONS.md), so
// an unbounded burst of large exports could exhaust memory; a saturated cap returns 503 (retryable).
const maxConcurrentBundleReads = 4

// bundleWriteTimeout is the per-handler write deadline used for /v2/export + /v2/verify, replacing the
// server's global 60s WriteTimeout for JUST these two long-response routes (main.go keeps the finite timeout
// for every other route, preserving Slowloris protection). Generous so a large-but-legitimate export is not
// hard-killed mid-write; a full cursor-streaming export (constant memory, no whole-history materialization) is
// a DEFERRED design item — see docs/dev/LIMITATIONS.md.
const bundleWriteTimeout = 10 * time.Minute

// acquireBundleSlot admits a whole-project bundle build (export/verify) under maxConcurrentBundleReads and
// lifts the finite WriteTimeout for this response (via a per-handler deadline). Returns ok=false — having
// already written a 503 — when the cap is saturated. The caller MUST defer release() when ok.
func (s *Server) acquireBundleSlot(w http.ResponseWriter) (release func(), ok bool) {
	select {
	case s.bundleSem <- struct{}{}:
	default:
		writeErr(w, http.StatusServiceUnavailable, "too many concurrent export/verify requests; retry shortly")
		return nil, false
	}
	setBundleWriteDeadline(w)
	return func() { <-s.bundleSem }, true
}

// setBundleWriteDeadline lifts the server's finite WriteTimeout for a verify/export response. Verify work may
// be performed by a background coalesced flight, but the eventual waiter still needs the same long response
// deadline that the pre-coalescing handler had.
func setBundleWriteDeadline(w http.ResponseWriter) {
	// http.ResponseController plumbs the deadline to the underlying conn; the error (e.g. httptest recorders
	// that do not support deadlines) is best-effort and safely ignored.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(bundleWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Printf("WARNING: could not extend write deadline for a bundle response: %v", err)
	}
}

// buildBundle assembles the export/verify bundle: published key, all sealed records, and the full
// checkpoint history.
func (s *Server) buildBundle(projectID string, _ bool) (string, error) {
	bundle, _, err := s.buildBundleWithSnapshot(projectID, false)
	return bundle, err
}

func (s *Server) buildBundleWithSnapshot(projectID string, includeDisclosures bool) (string, []store.DisclosureSecret, error) {
	// One repeatable-read snapshot prevents an export from combining a new
	// checkpoint with an older record set, or a fresh revocation list with a
	// different anchor/record cutoff. The complete uncheckpointed tail remains.
	var checks []store.Checkpoint
	var anchors map[int64]string
	var recs []store.Record
	var revokedIDs []string
	var secrets []store.DisclosureSecret
	err := s.st.WithProjectRead(context.Background(), projectID, func(st store.Store) error {
		var err error
		if checks, err = st.Checkpoints(projectID); err != nil {
			return err
		}
		if anchors, err = st.Anchors(projectID); err != nil {
			return err
		}
		if recs, err = st.AllRecords(projectID); err != nil {
			return err
		}
		if s.revocationKey != nil {
			revokedIDs, err = st.RevokedGrantIDs(projectID)
			if err != nil {
				return err
			}
		}
		if includeDisclosures {
			secrets, err = st.Disclosures(projectID)
		}
		return err
	})
	if err != nil {
		return "", nil, err
	}
	records := make([]json.RawMessage, len(recs))
	for i, r := range recs {
		records[i] = json.RawMessage(r.JSON)
	}
	checkpoints := make([]json.RawMessage, len(checks))
	for i, c := range checks {
		// Join the decoupled anchor (if any) into the checkpoint's `anchor` block. The anchor is
		// excluded from the checkpoint_hash/sig, so attaching it here does not affect verification.
		if tok, ok := anchors[c.Seq]; ok {
			withAnchor, err := attachAnchor(c.JSON, tok)
			if err != nil {
				return "", nil, fmt.Errorf("attach anchor to checkpoint %d: %w", c.Seq, err)
			}
			checkpoints[i] = json.RawMessage(withAnchor)
		} else {
			checkpoints[i] = json.RawMessage(c.JSON)
		}
	}
	keyEntry := map[string]any{
		"signing_key_id": s.signingKeyID,
		"key_epoch":      0,
		"public_key":     s.core.PubKey(),
		"key_status":     "active",
	}
	bundle := map[string]any{
		"bundle_version": "1",
		"project_id":     projectID,
		"keys":           []any{keyEntry},
		"records":        records,
		"checkpoints":    checkpoints,
	}
	// T6/D8: emit the operator-declared coverage_manifest verbatim. Its digest is bound into the
	// deployment_attestation (above), so the closure the verifier checks is the one the operator attested.
	if s.coverageManifest != "" {
		bundle["coverage_manifest"] = json.RawMessage(s.coverageManifest)
	}
	// M5 (ADR 0005): emit a signed, time-bounded revocation_list over the project's revoked grant_ids whenever a
	// revocation authority key is configured — EMPTY when nothing is revoked, because a verifier pinning that key
	// reads a bundle with no list as `missing` (blocks the capstone). Its freshness window is
	// derived from the latest checkpoint's created_ts (same anchor the attestation uses), so the verifier reads
	// it `fresh` for this bundle and `stale` for a much-later one. Built BEFORE the attestation so the
	// attestation can bind its digest (#3 strip-downgrade defense).
	revocationDigest := ""
	if s.revocationKey != nil {
		rl, e := s.buildRevocationListForExportIDs(revokedIDs, checks)
		if e != nil {
			return "", nil, e
		}
		if rl != nil {
			bundle["revocation_list"] = rl
			rlJSON, e := json.Marshal(rl)
			if e != nil {
				return "", nil, fmt.Errorf("marshal revocation_list: %w", e)
			}
			d, e := s.core.RcpEvidenceHash(string(rlJSON))
			if e != nil {
				return "", nil, fmt.Errorf("revocation_list digest: %w", e)
			}
			revocationDigest = d
		}
	}
	// D7.2: emit a deployment_attestation binding this bundle's latest checkpoint + authority/resource set
	// (+ the revocation_list digest), when an attestation issuing key is configured (else the bundle verifies
	// attestation_status:unevaluated).
	if s.attestKey != nil {
		att, e := s.buildDeploymentAttestation(projectID, recs, checks, revocationDigest)
		if e != nil {
			return "", nil, e
		}
		if att != nil {
			bundle["deployment_attestation"] = att
		}
	}
	out, err := json.Marshal(bundle)
	return string(out), secrets, err
}

// attachAnchor adds an `anchor` block to a sealed checkpoint JSON. The anchor is excluded from the
// checkpoint_hash/sig (the verifier strips it and re-canonicalizes the body), so re-serializing here
// is safe — the body's RawMessage fields are preserved byte-for-byte.
func attachAnchor(checkpointJSON, tokenB64 string) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(checkpointJSON), &obj); err != nil {
		return "", fmt.Errorf("parse checkpoint: %w", err)
	}
	anchor, err := json.Marshal(map[string]any{"scheme": "rfc3161", "token_b64": tokenB64})
	if err != nil {
		return "", err
	}
	obj["anchor"] = anchor
	out, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ---- helpers ----

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 8<<20)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func stringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func setDefault(m map[string]any, k, val string) {
	if s, ok := m[k].(string); !ok || s == "" {
		m[k] = val
	}
}

func jsonRaw(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

func recordMeta(sealed string) (contentHash string, parents []string, session string) {
	var m struct {
		ContentHash string   `json:"content_hash"`
		Parents     []string `json:"causal_prev_hashes"`
		SessionID   string   `json:"session_id"`
	}
	_ = json.Unmarshal([]byte(sealed), &m)
	return m.ContentHash, m.Parents, m.SessionID
}
