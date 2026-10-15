# Month segments: checking a long history one month at a time

A project's whole history used to travel as one export, built in memory, and the verifier refuses any file
over 256 MiB. A project that keeps recording therefore reached a size where nothing could be checked. A
**month segment** is the answer: the history is cut into one bundle per month, each chained to the previous
month's last checkpoint, so no single export, and no single verification, has to hold all of it.

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
`<project>-<YYYY-MM>.json` per month. A `revocation_list` and `deployment_attestation` are not copied (they bind
the whole bundle's latest checkpoint and cannot be re-issued offline).

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
   head) and its `record_count` equals the base's count plus the records carried, so a dropped or added
   record fails;
5. a parent that is a base head resolves; a parent older than that is counted as `earlier_parent_refs` and left to
   the chain check.

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
outcome names across a month boundary is held by an earlier month. It reads one file at a time. `PASS` needs
pinned signing keys; without them the word is `CONSISTENT`, as for a single bundle.

## What a month does not check

A month reports these as not evaluated rather than as passed (`segment.not_evaluated`):

- **The grant-log transparency chain** (`broker_trust`, D6) and the **federation heads**. They chain every
  grant since the project began, so a month that starts after a base cannot re-derive them. A month reports
  `broker_trust: assumed`, and the capstone claims stay unsatisfied for it. The first month and a whole-history
  bundle evaluate them. The chain command does not evaluate them across months either.
- **A use or outcome whose grant or intent was sealed in an earlier month.** It is listed in
  `segment.unresolved_cross_month`, never counted as matched and never as a violation (the counterpart is not in
  the bundle). The chain command checks that the named record exists in an earlier month. It does not re-run the
  use-to-grant match across months: scope, expiry and key binding are checked in the month that holds both
  records.

Everything else a bundle check does applies to a month: record integrity and signatures, key rotation, the DAG,
the checkpoint chain, anchors and backdating, disclosures, the deployment attestation and revocation list the server
re-issues for the month, and the claims contract.

## What the link proves, and what it does not

The base checkpoint is signed (and, if anchored, timestamped), and the chain after it is hash-linked, so a month
cannot start from a checkpoint the recorder never produced, and a month cannot be spliced onto a different
predecessor without the hash changing. It does not prove the earlier months are intact: only the chain command
over all of them, or a pinned head from a month you verified, does. A recorder that equivocates, showing
different histories to different auditors, is caught only by external anchoring, exactly as for a whole-history
bundle.
