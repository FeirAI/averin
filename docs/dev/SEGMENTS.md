# Month segments: checking a long history one month at a time

A project's whole history used to travel as one export, built in memory, and the verifier refuses any file
over 256 MiB. A project that keeps recording therefore reached a size where nothing could be checked. A
**month segment** is the answer: the history is cut into one bundle per month, each chained to the previous
month's last checkpoint. A month export and a month check are bounded by the month, not by the history. The
chain's cross-month verdict is different: it needs the concatenation in memory and under the 256 MiB cap (see "Verifying").

A whole-history export still works and is still the only way to evaluate the grant-log transparency chain (see
"What a month does not check"). It is refused with HTTP 413 once it would exceed the cap, and the response
points here.

## The format

A segment is an ordinary bundle plus a `segment` block:

```json
"segment": {
  "format": "averin.segment.v1",
  "month": "2026-09",
  "base_seq": 12,
  "base_checkpoint_hash": "sha256:...",
  "base_record_count": 480
}
```

- `checkpoints` carries the **base checkpoint** first (a real, signed, possibly anchored checkpoint: the last
  one of the previous segment), then the checkpoints created in `month`.
- `records` carries only the records those checkpoints commit beyond the base: the range
  `(base_record_count, last_checkpoint.record_count]` in insertion order.
- The **first month** has no base: `base_seq` and `base_checkpoint_hash` are `null` and `base_record_count` is
  `0`. It verifies exactly like a whole-history bundle that stops at that month's last checkpoint.
- A month is the UTC month of the checkpoint's signed `created_ts`. Every checkpoint after the base falls in
  `month`; the base falls before it. A month with no checkpoint has no segment; its records belong to the segment
  of the next month that has one.
- A checkpoint is the cut, not the clock: records written after a month's last checkpoint are in no
  segment until the next checkpoint commits them.

## Getting segments

Server:

| Route | What |
|---|---|
| `GET /v2/segments?project=<id>` | The months that exist: record range, checkpoint range, head hash, base. Reads checkpoints only. |
| `GET /v2/export?project=<id>&month=YYYY-MM` | One month's bundle (all the usual `mode` and `record_kind` options apply). `404` if no checkpoint was created in that month, `400` for a malformed month. |
| `GET /v2/verify?project=<id>&month=YYYY-MM` | The server's self-view of one month. |

A month export reads only that month's records from the store (`RecordsPage`), so its memory is bounded by the
month, not by the history. A month whose records alone exceed 256 MiB is refused (413): no verifier would
accept it. Checkpoint more often and the cut moves with the checkpoints, but the month label does not split.

Offline, from an old whole-history bundle: `averin-verify split <bundle.json> <outdir>` writes
`<project>-<YYYY-MM>.json` per month. A `revocation_list` and `deployment_attestation` bind the whole bundle's latest
checkpoint and cannot be re-issued offline for an earlier month, so split copies them into the last month only (its
head is the whole history's head). The server re-issues both for every month it serves.

## Verifying

One month:

```
averin-verify bundle 2026-09.json opts.json
```

prints a `segment:` line and checks, on top of everything a bundle check does:

1. the base checkpoint is carried, has the stated seq, hash and record count, and its signature, key and
   anchor are checked like every other checkpoint;
2. the chain starts at the base (not at seq 0) and has at least one checkpoint after it;
3. every checkpoint falls in the month, the base before it;
4. the latest checkpoint's frontier equals the segment's heads (a base head that no record references is still a
   head), its `record_count` equals the base's count plus the records carried, and no carried record is a member of
   the base checkpoint's frontier (an earlier month owns those);
5. a parent that is a base head resolves; a parent older than that is counted as `earlier_parent_refs`, listed by
   hash in `earlier_parent_ref_hashes`, and left to the chain check.

**What one month proves about its own record set.** When `earlier_parent_refs` is 0, the checks above force the
carried set to equal the records reachable from the latest frontier minus those reachable from the base frontier, so
a dropped or substituted record fails. When it is above 0, a record dropped from the month can be replaced by an
earlier month's record without changing the count, the heads or the signatures, and one month cannot tell. The
report then lists `record_completeness` in `segment.not_evaluated` and the CLI says so; only `averin-verify chain`,
which knows every earlier month, closes it (it refuses a parent that names no record in this or any earlier month).

`opts.json` may carry `segment_base_checkpoint_hash`: `"genesis"` for the first month, otherwise the previous
month's `segment.head_checkpoint_hash`. Then the link is a checked fact (`link: base_pinned`); a different base,
or a pin on a bundle that is not a segment, fails. Without it the report says `link: base_unpinned`: the month is
consistent, and nobody has said which month it follows.

All months:

```
averin-verify chain --opts opts.json 2026-06.json 2026-07.json 2026-08.json
```

verifies each month pinned to the previous month's head (`genesis` for the first), then checks what no single
month can: months strictly increase, the project is the same, each base count equals the previous head count,
every parent a month points before its base exists in an earlier month, and every grant or intent that a use or
outcome names across a month boundary is held by an earlier month (and an outcome binds the earlier `use_intent` it
names: same grant, `intent_hash` equal to that intent's content hash). It also refuses a month that carries a record
(by content hash or by record id) an earlier month already holds: months partition the history, no record is reused.

Then it puts the months back together and verifies the result as one whole-history bundle, with the options in
`opts.json` and no segment pin. The chain word is that whole history's own claim word for the requested claim (FAIL,
INSUFFICIENT, CONSISTENT or PASS), and the RESULT line names the claim. So a violation that spans months reaches the
word exactly as it does in one export: a use whose grant no month holds, a second use of a single-use grant, an
outcome no intent closes. The rule is a test: verifying the months in sequence gives the same word as verifying the
concatenated history (core/tests/segments_cross_month.rs), for the default claim and for `authorized`. `PASS` needs
pinned signing keys; without them the word is `CONSISTENT`, as for a single bundle.

The rebuilt history is what a whole-history export would carry: every record and checkpoint, every month's
disclosures, and the latest month's `revocation_list` and `deployment_attestation` (they bind its head, which is the
concatenation's head). A revocation that lands on a grant an earlier month issued therefore reaches the word too.

The cost is memory: the chain holds every month's records and checkpoints, and the concatenation must fit the
verifier's 256 MiB cap. The chain adds up the serialized size as it takes each month; once the total passes the cap it
stops holding records and does not rebuild the history. When it does not fit (the very case months exist for), the
cross-month rules are not run, the RESULT line says so, and the word is capped at INSUFFICIENT. A history over the cap
can therefore never PASS here, and a cross-month double use in it is not reported as FAIL. Each month and every link
were still checked.

**A month with a base never passes alone.** A month with a base lists `cross_month_uses` in `segment.not_evaluated`,
because one month cannot rule out a second use of a single-use grant, a replayed PoP nonce or ledger commitment, a
use of a grant no month holds, or a revocation that lands on an earlier month's grant. So every month with a base,
and any month whose base is not the pinned previous head (`link: base_unpinned`) or whose `not_evaluated` lists
`record_completeness`, gets the headline INSUFFICIENT and exit code 1 from `averin-verify bundle`, the browser
verifier and the web app, whatever the claim says. Only the first month (no base) can pass alone. The CLI prints the
number of unresolved cross-month references in its `segment:` block. Only the chain closes the rest.

## What a month does not check

A month reports these as not evaluated rather than as passed (`segment.not_evaluated`):

- **The grant-log transparency chain** (`broker_trust`, D6) and the **federation heads**. They chain every
  grant since the project began, so a month that starts after a base cannot re-derive them. A month reports
  `broker_trust: assumed`, and the capstone claims stay unsatisfied for it. The first month and a whole-history
  bundle evaluate them. The chain command rebuilds the whole history from the months, so it evaluates them
  whenever the months carry the grant-log members and the history fits the verifier's cap.
- **A use or outcome whose grant or intent was sealed in an earlier month.** It is listed in
  `segment.unresolved_cross_month`, never counted as matched and never as a violation (the counterpart is not in
  the bundle). A month with one reports the `authorized` claim as insufficient (a whole-history bundle would count an
  unconsumed outcome as a violation). The chain command checks that the named record exists in an earlier month, and
  then the use-to-grant match runs where both records are, in the concatenated history it verifies as one bundle
  (scope, expiry, key binding and single use included), unless that history is over the verifier's cap.

- **Uniqueness and revocation across months** (`cross_month_uses`): a second use of a single-use grant, a replayed PoP
  nonce or ledger commitment, a use of a grant no month holds, and the use of a grant an earlier month issued that a
  later list revokes. One month blocks a use of an earlier month's grant that its own signed `revocation_list` names as
  revoked, but cannot see the rest. The chain closes them on the concatenated history.

Everything else a bundle check does applies to a month: record integrity and signatures, key rotation, the DAG,
the checkpoint chain, anchors and backdating, disclosures, the deployment attestation and revocation list the server
re-issues for the month, and the claims contract. A month with a base is still capped below PASS by the items above.

## What the link proves, and what it does not

The base checkpoint is signed (and, if anchored, timestamped), and the chain after it is hash-linked, so a month
cannot start from a checkpoint the recorder never produced, and a month cannot be spliced onto a different
predecessor without the hash changing. It does not prove the earlier months are intact: only the chain command
over all of them, or a pinned head from a month you verified, does. A recorder that equivocates, showing
different histories to different auditors, is caught only by external anchoring, exactly as for a whole-history
bundle.
