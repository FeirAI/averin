# Security policy

averin is alpha software. Its assurance claims are bounded by
[`docs/coverage-limits.md`](docs/coverage-limits.md) and the threat model in
[`docs/dev/SECURITY.md`](docs/dev/SECURITY.md). Reading those first will help
you tell an intended limit from a defect, but if you are unsure, report it.

## Reporting a vulnerability

Report privately to **security@feir.ai**. Do not open a public issue for
anything exploitable.

Include what you can of: the affected component (`core/`, `server/`,
`verifier/`, `web/`, `sdk/`), the commit or tag, steps to reproduce, and the
impact you believe it has on the record-integrity, event-observation, or
action-accountability claims.

You will get an acknowledgement within 7 days.
There is no bug bounty.

## What we especially want to hear about

- A documented limit that does not hold the way the documents say it does.
- Any way to bypass a guard, including the production-secrets gate that is
  enabled by setting `AVERIN_REQUIRE_PROD_SECRETS` to `1` or `true`, or any
  way a globally-known development value is accepted while that gate is on.
- Unexpected impact from a behaviour that is documented as a non-goal.

## What is out of scope

Reports that solely restate a limit already documented in
`docs/coverage-limits.md` or under "What averin deliberately does NOT do" in
`docs/dev/SECURITY.md`, with no new impact. The development signing seed in
`spec/golden-vectors/sign-vectors.json` is public by construction; a report that it is usable as a
key is expected, a report that it is accepted while the production-secrets
gate is on is not.

Do not run denial-of-service or load tests against instances you do not
operate. Availability weaknesses found without such testing are welcome.

## Supported versions

Only the latest tagged release and the `main` branch
receive fixes.
