# Deployment & infra readiness (Tier-2)

These are the **Tier-2** items: they need real infrastructure, hardware, an external IdP, or operator
action, so they cannot be *finished* as a self-contained repo diff. This doc records, for each, the
production design, what is already **scaffolded in-repo** (a hook/interface you wire up), what **external
infra** must provide, the **readiness checklist**, and the explicit **operator action**. It is the honest
boundary between "averin ships this" and "your deployment provides this."

| Item | In-repo today | Needs (external) | Status |
|------|---------------|------------------|--------|
| 1. Per-project authn/authz (Phase 2) | API-key auth (`auth.KeyStore` + `Middleware`, wired) | IdP (SSO/SAML/OIDC), secrets store, RBAC/scoped-token layer | **Phase-1 done; Phase-2 layered design** |
| 2. HSM/TPM sender-key (B12) | raw ed25519 keys + PoP binding (theft-fails-PoP test) | HSM/TPM/KMS + agent secure element | **Needs a `Signer` interface + hardware** |
| 3. Multi-instance `broker_seq` lock (D6) | per-project `pg_advisory_xact_lock` for seq | shared Postgres + ingest-path distributed lock | **Seq-lock done; ingest-lock design** |
| 4. TEE/remote-attestation enforcement (D7) | signed `deployment_attestation` claim | TEE hardware + attestation service + quote-verify lib | **Assertion today; hardware-root design** |
| 5. git remote + push | clean tree, `.gitignore` hardened | remote URL + push credentials | **Repo push-ready; operator action** |
| 6. Durable consume-before-act ledger (R5) | Postgres-backed `internal/pgledger` (auto-injected when `AVERIN_DATABASE_URL` is set) | shared Postgres | **Done** — survives restart + serializes across instances (`a9c4b9c`) |

---

## 1. Per-project authentication / authorization (Phase 2)

**Current state.** `server/internal/auth/auth.go` ships a fail-closed, constant-time `KeyStore`
(`ValidFor(project, token) bool`) + `MapStore` + an `auth.Middleware(ks, "project")`, and it IS wired:
`Routes()` (`server.go:422-426`) applies the middleware to `/v2/*` whenever a `KeyStore` is configured via
`WithAuth`. The **default is open** (no `KeyStore` → dev/single-tenant), documented in `coverage-limits.md`.
So Phase-1 — "is this token valid for this project?" — exists. What's deferred (Phase 2, per the `auth.go`
header) is **RBAC, SSO, scoped/expiring tokens, and per-route permissions**.

**Production design.**
- **Scoped + expiring tokens.** Replace the static token set with short-lived tokens (JWT/PASETO) carrying
  `{project, role, exp}`. averin validates the signature + `exp` + audience instead of a string-set lookup.
- **RBAC.** Gate routes by role: `reader` (`/v2/export`, `/v2/verify`, `/v2/dag`), `writer` (`/v2/records`,
  `/v2/grants`, `/v2/use*`), `admin` (`/v2/checkpoints`). The middleware already binds the request to the
  named `project`; add a per-route role requirement.
- **SSO/SAML/OIDC.** An external IdP issues the tokens; averin is a resource server that validates them
  (verify the IdP's JWT signature + claims). No password handling in averin.

**In-repo preparation (buildable now, no external dependency).**
- An `Authorizer` interface that *extends* `KeyStore` to return `{project, role, exp}` instead of a bool, and
  a per-route `RequireRole` wrapper — both behind the existing `WithAuth` hook (the wiring point is done).
- A JWT/OIDC `KeyStore`/`Authorizer` impl (signature + `exp` + audience validation) — no IdP needed to *write
  and unit-test* it against a local signing key.
- Tests: a writer token rejected on a reader-only route; an expired token rejected; a token for project A
  rejected on project B (the cross-project bind already exists — extend it).

**External infra.** An IdP (SSO/SAML/OIDC) to issue tokens; a secrets store (KMS/Vault) for any static keys.

**Readiness checklist.** Auth ON in prod (never the open default); every `/v2/*` route requires a token;
roles enforced; tokens expire; project-bind holds; 401/403 bodies are generic (no token echo).

**Operator action.** Choose the model (static keys vs. OIDC); provision the IdP; configure per-project
keys/roles; **set `WithAuth` in the production wiring** (the open default is dev-only).

---

## 2. HSM/TPM/measured-boot sender-key non-exportability (threat B12)

**Current state.** All signing keys are **raw, software-held ed25519**: the server/broker/resource seeds
(`core.Core` holds `seedHex`; `SignEvidence`/`PubKey` derive from it) and the agent's `cnf` private key (the
agent signs the PoP challenge). The PoP *binding* is sound — `resourceshim_test.go::TestTokenTheftFailsPoP`
proves a stolen capability + a different key fails PoP — but the keys themselves are **exportable software
keys**, so a host compromise can exfiltrate them.

**Production design.** Make the private keys **non-exportable** and bound to hardware:
- **Server/broker/resource keys** → a `Signer` backed by a PKCS#11 HSM, AWS/GCP KMS, or a TPM: averin asks the
  device to sign; the key never leaves the device.
- **Agent `cnf` key** → bound to a TPM / Secure Enclave / mobile secure element, non-exportable, so a stolen
  capability token cannot be exercised without the hardware. Attest the binding (TPM EK / platform attestation)
  so the verifier knows the `cnf` key is hardware-resident, not a copyable software key.

**In-repo preparation.**
- A `core.Signer` interface (`Sign(msg) (sig, error)` + `PubKey()`) abstracting the raw-seed signing in
  `core.go`, so a KMS/HSM/TPM implementation drops in without touching call sites. The current seed-backed
  signer becomes the default impl.
- Extend the **bypass test** (`TestTokenTheftFailsPoP`) into an explicit "token-without-key cannot use" suite
  documenting the property the hardware must enforce.

**External infra.** An HSM / TPM / cloud KMS for the server keys; a secure element (TPM / Secure Enclave) on
each agent host for the `cnf` key.

**Readiness checklist.** No private seed material on disk or in env in prod; every signature goes through the
device; the agent `cnf` key is provably hardware-resident; the bypass test passes against the hardware-backed
signer.

**Operator action.** Provision the HSM/KMS; deploy agents on hosts with secure elements; configure the
`Signer` to the device.

---

## 3. Multi-instance distributed per-project lock for gapless `broker_seq` (ADR 0004 D6)

**Current state.** Gaplessness of `broker_seq` is **already cross-instance-safe for the allocation step**:
`Postgres.AllocateBrokerSeq` (`postgres.go:482`) takes a per-project `pg_advisory_xact_lock(hashtext(project))`
inside its transaction, so two instances cannot mint the same seq; a grant that fails after allocation deletes
its `broker_seq` row, so the durable max only advances for recorded grants (no manufactured gap). What is
**single-instance only** is the *broader* ingest critical section — the `heads → seal → put` frontier read in
`server.go` is serialized by the **in-process** `ingestMu`/`checkpointMu` mutexes, which do not coordinate
across processes.

**Production design.** For multiple server instances behind a shared Postgres:
- The `broker_seq` allocation lock already serializes cross-instance — no change.
- The **ingest path** (read frontier → seal → put record, and checkpoint creation) must also serialize per
  project across instances, or two instances could read the same DAG frontier and fork it. Two equivalent
  options: (a) hold a **per-project `pg_advisory_xact_lock`** around the whole read-seal-put within one txn
  (extends the `AllocateBrokerSeq` pattern), or (b) run the put under a **serializable** Postgres txn that
  fails-and-retries on a frontier conflict. The in-memory `Mem` store is single-instance only and cannot back
  a multi-instance deployment.

**In-repo preparation.**
- Document the **single-writer-per-project** invariant and that `ingestMu` is an in-process optimization, not
  a multi-instance guarantee.
- Add a `DistributedLock`/per-project lock seam at the ingest entry (the wiring point), defaulting to the
  in-process mutex and pluggable to the Postgres advisory lock.
- A concurrency test (`TestConcurrentCheckpointsDoNotFork` already covers the single-instance case) extended
  to the Postgres-backed cross-connection case (the parity CI lane added in T10 can host it).

**External infra.** A shared Postgres (the lock authority) and a multi-instance deployment topology.

**Readiness checklist.** Two instances ingesting the same project concurrently produce one gapless DAG +
gapless `broker_seq` (no fork, no duplicate seq); `Mem` is rejected for multi-instance; the advisory lock is
the single serialization point.

**Operator action.** Deploy with Postgres (not `Mem`); run behind the per-project lock.

---

## 4. TEE / remote-attestation runtime enforcement for D7

**Current state.** D7.2 deployment attestation is a **signed claim**: `WithAttestation(attestKey)` emits a
top-level `deployment_attestation` on `/v2/export`, role-separated from broker/resource/TSA keys; the verifier
(`verify.rs::evaluate_attestation`) checks the signature, the freshness window (against the anchored TSA
genTime), and the bound subject (project / checkpoint / head-root / authority kids / resource_ids). This proves
*an attestation issuer asserted this deployment state* — it is **assertion, not a hardware root of trust**.

**Production design.** Upgrade the attestation from operator-asserted to **hardware-attested**:
- The attestation carries a real **remote-attestation quote** — Intel SGX/TDX, AMD SEV-SNP, or AWS Nitro —
  binding the **measured boot + the running binary measurement** to the attestation key.
- The verifier **verifies the quote** against the platform vendor's roots (e.g. Intel DCAP/PCCS), so a reader
  trusts the *hardware* attested the running code, not the operator's signature over a claim.

**In-repo preparation.**
- An `Attester` interface that produces the attestation evidence and, when available, an embedded quote — so a
  TEE-quote implementation drops in; the current sign-a-claim path is the default impl.
- A reserved `deployment_attestation.quote` schema field + a **feature-gated** verifier quote-verification hook
  (mirroring the `rfc3161` feature: off by default to keep the lean/WASM verifier free of the heavy ASN.1 +
  vendor-root machinery; native CLI builds it).
- Document the trust upgrade (assertion → hardware root) in `coverage-limits.md` so the current attestation is
  never read as a hardware guarantee.

**External infra.** TEE hardware (SGX/TDX/SEV-SNP/Nitro); the platform attestation service (PCCS/DCAP or cloud
equivalent); a quote-verification library.

**Readiness checklist.** The attestation carries a verifiable quote; the verifier rejects a quote whose
measurement doesn't match the pinned binary; the trust label distinguishes "attested by hardware" from
"asserted by issuer."

**Operator action.** Deploy on TEE hardware; configure the attestation service; pin the platform roots and the
expected binary measurement.

---

## 5. git remote + push

**Current state.** Local-only: **no remote configured**, branch `main`, working tree clean. `.gitignore`
already excludes build artifacts (`target/`, `node_modules`, `dist`, `*.test`) and secrets (`.env`, `.env.*`,
`*.pem`, `*.key`, with a deliberate `!spec/**/*.key` exception for the deterministic, non-secret test vectors).
The one gap — now closed in this change — was `.claude/` (Claude Code harness state: scheduled-task locks,
plans, transcripts), which was untracked but not ignored, so a `git add -A` would have staged it.

**Readiness / in-repo preparation.**
- **`.gitignore` now ignores `.claude/`** (this change) so harness state can never be committed/pushed.
- No real secrets are tracked: the only key material under version control is `spec/**` deterministic test
  vectors (intentional, non-secret); production keys come from env/KMS (ignored).

**External / operator action (this one is genuinely yours).**
- Provide a **remote URL** and **push credentials** (SSH key or token) — averin cannot push to a remote it has
  no address or auth for.
- Choose the **branch strategy**: push `main`, or cut a feature branch and open a PR. The session's commits are
  on `main`; if you want a PR flow, branch before pushing.

**Readiness checklist.** `git status` clean; `.claude/` and build artifacts ignored; no secrets in
`git ls-files`; remote set; branch decided.

---

## What is buildable in-repo now (no external dependency)

These are the safe scaffolds the items above identify — design-ready, implementable without infra, and the
natural next commits when this umbrella is picked up:

1. **`core.Signer` interface** abstracting raw-seed signing (item 2) — unblocks an HSM/KMS drop-in.
2. **`Authorizer` interface + `RequireRole`** extending the auth middleware (item 1) — unblocks RBAC/OIDC.
3. **`Attester` interface + reserved `quote` field + feature-gated quote-verify hook** (item 4).
4. **Per-project ingest lock seam** defaulting to `ingestMu`, pluggable to the Postgres advisory lock (item 3).
5. **`.gitignore` for `.claude/`** (item 5) — done in this change.

Items 2–4's interfaces are pure refactors (extract a seam; the existing behavior becomes the default impl), so
they can land + be tested with zero external dependency, leaving only the hardware/IdP impls for deployment.
