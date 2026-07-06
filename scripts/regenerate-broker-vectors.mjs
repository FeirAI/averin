#!/usr/bin/env node

// Regenerate the shared Go/Rust broker preimage vectors after an intentional
// domain-separation change. The int64 minimum sentinel keeps JSON parsing exact.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const path = new URL("../spec/golden-vectors/broker-preimages.json", import.meta.url);
const i64min = "__I64_MIN__";
const raw = await readFile(path, "utf8");
const vectors = JSON.parse(raw.replaceAll("-9223372036854775808", `"${i64min}"`));

const sha = (value) => createHash("sha256").update(value).digest();
const hex = (value) => Buffer.from(value).toString("hex");
const prefixed = (value) => `sha256:${hex(sha(value))}`;
const lp4 = (value) => {
  const body = Buffer.from(value, "utf8");
  const size = Buffer.alloc(4);
  size.writeUInt32BE(body.length);
  return Buffer.concat([size, body]);
};
const be8 = (value) => {
  let integer = value === i64min ? -(1n << 63n) : BigInt(value);
  integer = BigInt.asUintN(64, integer);
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(integer);
  return bytes;
};
const digest = (...parts) => sha(Buffer.concat(parts));

for (const item of vectors.ledger_commitment) {
  item.expect = prefixed(Buffer.concat([
    lp4("averin.broker.use.ledger.v1"), lp4(item.jti), lp4(item.nonce), be8(item.used_at),
  ]));
}
for (const item of vectors.grant_head_root) {
  const tag = "averin.broker.grant_head.v1";
  let accumulator = sha(lp4(tag));
  for (const grant of item.grants) {
    accumulator = digest(lp4(tag), accumulator, be8(grant.seq), lp4(grant.content_hash));
  }
  item.expect = `sha256:${hex(accumulator)}`;
}
for (const item of vectors.use_pop_challenge) {
  item.expect_hex = hex(digest(
    lp4("averin.broker.use.pop.v1"), lp4(item.grant_id), lp4(item.resource_id),
    lp4(item.action), lp4(item.params_commitment), lp4(item.credential_binding), lp4(item.nonce),
  ));
}
for (const item of vectors.cosig_approval_challenge) {
  item.expect_hex = hex(digest(
    lp4("averin.broker.cosig.approval.v1"), lp4(item.grant_id), lp4(item.approver_kid),
    lp4(item.credential_binding), be8(item.threshold_m), be8(item.exp),
  ));
}
for (const item of vectors.delegation_hop_challenge) {
  item.expect_hex = hex(digest(
    lp4("averin.broker.delegation.hop.v1"), lp4(item.grant_id), be8(item.hop_index),
    lp4(item.delegator_kid), lp4(item.delegate_kid), lp4(item.scope), lp4(item.action),
    lp4(item.resource_id), be8(item.exp),
  ));
}
for (const item of vectors.introspection_transcript_challenge) {
  item.expect_hex = hex(digest(
    lp4("averin.resource.introspection.v1"), lp4(item.grant_id), lp4(item.credential_ref),
    lp4(item.effective_scope), lp4(item.resource_id), be8(item.introspected_at), be8(item.effective_exp),
  ));
}
for (const item of vectors.federation_cert_challenge) {
  item.expect_hex = hex(digest(
    lp4("averin.broker.federation.cert.v1"), lp4(item.issuer_broker_id),
    lp4(item.subject_broker_id), lp4(item.subject_kid), lp4(item.scope),
    lp4(item.resource_id), be8(item.not_after),
  ));
}

const revocationLeaf = (grantID) => digest(lp4("averin.broker.revocation.leaf.v1"), lp4(grantID));
for (const item of vectors.revocation_leaf) item.expect_hex = hex(revocationLeaf(item.grant_id));

const leafHash = (value) => digest(Buffer.from([0]), value);
const nodeHash = (left, right) => digest(Buffer.from([1]), left, right);
const merkleRoot = (grantIDs) => {
  const values = grantIDs.map(revocationLeaf).sort(Buffer.compare);
  let level = [Buffer.alloc(32), ...values, Buffer.alloc(32, 0xff)].map(leafHash);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return `sha256:${hex(level[0])}`;
};
for (const item of vectors.revocation_merkle_root) item.expect = merkleRoot(item.revoked);

const output = `${JSON.stringify(vectors, null, 2).replaceAll(`"${i64min}"`, "-9223372036854775808")}\n`;
await writeFile(path, output);
console.log(`updated ${path.pathname}`);
