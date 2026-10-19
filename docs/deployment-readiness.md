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
| 3. Multi-instance project writes (D6) | persisted project guard, bound transactions, authenticated capability-project binding, tenant and resource scoped nonce claims, a bounded sequence-recovery fence, and a two-process failure matrix with a trace monitor run on every pull request (`multiwriter` job) | a content store shared by the replicas, the per-replica ingest budget, and an optional object-storage witness | **Database write path exercised under two-process faults; replicas still gated on the shared content store and ingest budget** |
| 4. TEE/remote-attestation enforcement (D7) | signed `deployment_attestation` claim | TEE hardware + attestation service + quote-verify lib | **Assertion today; hardware-root design** |
| 5. git remote + push | GitHub remote configured, `.gitignore` hardened | nothing further | **Done** |
| 6. Durable consume-before-act ledger (R5) | project Store claims and receipt share one transaction; nonce and JTI claims are scoped by project and resource (migration `0006`); `pgledger` sweeps; one use of a capability across two processes is part of the failure matrix | shared Postgres | **Done for the Postgres store** |

---

## 1. Per-project authentication / authorization (Phase 2)

**Current state.** `server/internal/auth` ships a fail-closed, constant-time `MapStore` that holds, per
project, tokens with a role (`read`, `write`, `admin`) and an optional expiry, and `auth.MiddlewareRoles`
applies a per-route role requirement (`api/auth_roles.go`; anything unclassified needs `admin`). It IS wired:
`Routes()` applies it to `/v2/*`. A server with no auth store refuses every request, and `averin-server` refuses
to start without `AVERIN_API_KEYS` unless `AVERIN_DEV_MODE=1`. What is still not built is SSO/OIDC and
short-lived signed tokens; static keys with `not_after` are the shipped model.

**Production design.**
- **Scoped + expiring tokens.** Replace the static token set with short-lived tokens (JWT/PASETO) carrying
  `{project, role, exp}`. averin validates the signature + `exp` + audience instead of a string-set lookup.
- **RBAC.** Already enforced (see Current state): `read` for every GET/HEAD, `write` for the evidence-adding
  POST routes listed in `api/auth_roles.go`, `admin` for everything else, including `/v2/checkpoints` and
  `/v2/revoke`. What remains is carrying the role in IdP-issued short-lived tokens.
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

**Readiness checklist.** Auth ON in prod (there is no open default outside `AVERIN_DEV_MODE=1`); every `/v2/*`
route requires a token; roles enforced; tokens expire (set `not_after`); project-bind holds; 401/403 bodies are
generic (no token echo).

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

## 3. Multi-instance project serialization and remaining readiness gates

**Current state.** The database now serializes each project's authoritative
frontier, allocation, pending, revocation, ledger and checkpoint writes with an
exact `project_write_guard` row. Each callback uses one transaction and
connection; a separate project can proceed while a guard is held. The
`record_id` UNIQUE index is checked before unsafe writes. Export uses one
repeatable-read snapshot. Independent-pool tests cover these seams.

**Failure matrix.** The `multiwriter` job runs two or three real `averin-server`
processes on one Postgres schema and injects, one leg at a time: one nonce used
by eight racing requests over two processes; one use request sent six times; a
revoke (prospective and total) against a use that has already read the
revocation state; a use against a revoke that has not committed; `kill -9` while
a prepare or a finalize transaction is open (a request waiting on the other
process then proceeds); stranded `broker_seq` recovery while the other process
writes, and a recovery process killed between its fence and its terminal
transaction; a lost COMMIT acknowledgment cut before and after the server
committed, for finalize, use and revoke, retried on both processes; and
checkpoints from both processes at once. A trace monitor then checks the
recorded run and the committed state against the invariants of
`formal/tla/ProjectTx.tla` (no use after an acknowledged revoke, one
consumption per nonce, no session fork, a numbered checkpoint chain whose last
checkpoint equals the committed frontier, no receipt at or after its cutoff, a
gapless `broker_seq` log, every acknowledged operation durable). Faults are
injected by a store wrapper in the test binary and an in-test TCP proxy in front
of Postgres (not toxiproxy), so the shipped server has no fault points. Two
semantic mutants (the guard row not locked, a revocation answer ignored on use)
must make the matrix fail.

**Deployment policy.** Keep one writer per project for now. The matrix shows
the database write path holds under these faults; it does not cover a content
store shared by replicas (each replica reads its own content directory today),
the per-replica ingest budget, an object-storage witness, Postgres failover, or
more than two concurrent writers. On DB outage, writes fail closed rather than
remaining available.

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

**Current state.** Done: the repository has a GitHub remote (`FeirAI/averin`), and `main` is its default branch. `.gitignore`
already excludes build artifacts (`target/`, `node_modules`, `dist`, `*.test`) and secrets (`.env`, `.env.*`,
`*.pem`, `*.key`, with a deliberate `!spec/**/*.key` exception for the deterministic, non-secret test vectors).
The one gap — now closed in this change — was `.claude/` (AI coding-assistant harness state: scheduled-task locks,
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
4. **Project transaction contract** — implemented with the persisted guard row; retain the deployment policy above until the remaining protocol gates pass.
5. **`.gitignore` for `.claude/`** (item 5) — done in this change.

Items 2–4's interfaces are pure refactors (extract a seam; the existing behavior becomes the default impl), so
they can land + be tested with zero external dependency, leaving only the hardware/IdP impls for deployment.
