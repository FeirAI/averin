# Rotating averin's recording key

averin signs every record and checkpoint with one Ed25519 key (`AVERIN_SIGNING_SEED`). This page is the
runbook for replacing it without breaking the checkability of the history it already signed. The design
reasons are in [ADR 0008](../decisions/0008-privacy-commitments-and-recording-key-rotation.md).

## What a rotation produces

- A **retired-key entry** (`AVERIN_RETIRED_SIGNING_KEYS_FILE`): id, epoch, public key, status
  (`retired` or `compromised`) and the time the status took effect.
- A **signed rotation statement** (`AVERIN_KEY_ROTATIONS_FILE`) that links the old key to the new one:
  `{kind: "key_rotation", old_key, new_key, rotated_at, reason, sig_new[, sig_old]}`, signed under the
  domain `averin.key_rotation.v1`.
- A new **epoch**: new records and checkpoints carry `key.key_epoch` = the epoch you set in
  `AVERIN_SIGNING_KEY_EPOCH`.

Every export then carries the current key first, every retired key with its status, and the statements in
`key_rotations`. `averin-server` refuses to start when the lineage does not hold together (a retired key
with no statement, a statement that does not verify, a chain that does not end at the current key).

## Scheduled rotation (the old key is still in your hands)

1. Write the new seed to an owner-only file (`openssl rand -hex 32 > new.seed; chmod 600 new.seed`).
2. Create a checkpoint for every project under the old key (`POST /v2/checkpoints?project=...`) and, if you
   anchor to a timestamp authority, let the anchor land. This pins the old history to a time.
3. Record the rotation:

   ```
   averin-keyrotate --reason scheduled --rotated-at 2026-11-01T00:00:00.000Z \
     --old-id k0 --old-epoch 0 --old-seed-file old.seed \
     --new-id k1 --new-epoch 1 --new-seed-file new.seed \
     --rotations-file rotations.json --retired-file retired.json
   ```

   Both keys sign the statement. The tool checks its own output the way the server will.
4. Restart `averin-server` with `AVERIN_SIGNING_SEED_FILE` = the new seed, `AVERIN_SIGNING_KEY_ID=k1`,
   `AVERIN_SIGNING_KEY_EPOCH=1`, `AVERIN_RETIRED_SIGNING_KEYS_FILE` and `AVERIN_KEY_ROTATIONS_FILE`.
5. Tell auditors the new public key (printed by the tool). An auditor who pinned only the old key still
   verifies everything: the verifier follows the signed statement from the pinned old key to the new one
   (`key_rotations_chain_trusted` in the report). Auditors who prefer to pin both can.
6. Destroy the old seed once nothing needs it. A further rotation uses the same files: the tool appends.

The same files accumulate across rotations (k0 to k1, k1 to k2); the chain must end at the key in use.

## Compromise (the old key is stolen or lost)

```
averin-keyrotate --reason compromise --rotated-at <earliest possible misuse, canonical UTC> \
  --old-id k0 --old-epoch 0 --old-public-key ed25519pub:... \
  --new-id k1 --new-epoch 1 --new-seed-file new.seed \
  --rotations-file rotations.json --retired-file retired.json
```

Only the new key signs. A stolen key proves nothing, so the statement **extends no trust**: auditors must
pin the new key themselves, and they should pin the old key as `compromised` with a `status_changed_at`
(see [operator-verification.md](../operator-verification.md)). Old records then stay trusted only when a
verified timestamp anchor shows they existed before `status_changed_at`; anything the thief signed after
that does not elevate. Choose `--rotated-at` as the earliest time the key could have been misused, not the
time you noticed.

## What the verifier does and does not establish

- It establishes that each statement carries valid signatures (both keys for `scheduled`, the new key for
  `compromise`), names keys the bundle lists, and, for a **pinned** old key that is neither revoked nor
  compromised (by your pin or by the bundle), that the new key is trusted for the records it signed. A
  bundle can only withdraw trust this way, never add it: marking a key `compromised` in the bundle outweighs
  the pin.
- It does not establish that the old key stopped signing at `rotated_at`. A holder of the old key can still
  sign records that claim the old key; for a scheduled rotation you rely on destroying the old seed, for a
  compromise on the anchor rule above.
- Statements are not records in the project chain; the chain does not prove the rotation happened at the
  stated time. A timestamp anchor taken before and after (step 2) bounds it.
- A statement whose old key is not pinned extends nothing. Without any pinned keys the report is internal
  consistency only, as before.
