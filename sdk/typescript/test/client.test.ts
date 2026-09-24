import { test, expect } from "bun:test";
import { buildRecord, stringify, Client, AverinError, prepareV3AuthoritySubject } from "../src/index";

test("v3 prepared fixture is exactly the submitted semantic record", async () => {
  const fixture = await Bun.file(new URL("../../../spec/golden-vectors/authority-sdk-v3.json", import.meta.url)).json();
  const draft = fixture.draft_record as Record<string, unknown>;
  const before = stringify(draft);
  const prepared = prepareV3AuthoritySubject(draft);
  expect(prepared).toEqual(fixture.prepared_record);
  expect(stringify(draft)).toBe(before);
  const authority = prepared.authority as Record<string, unknown>;
  authority.subject_digest = fixture.subject_digest;
  authority.evidence_sig = "ed25519:external-approver-proof";
  const signedSemantics = stringify(prepared);
  let submitted: Record<string, unknown> = {};
  const transport = async (_url: string, _headers: Record<string, string>, body: string) => {
    const sent = JSON.parse(body) as Record<string, unknown>;
    expect(sent.idempotency_key).toBe("sdk-v3-fixed");
    delete sent.idempotency_key;
    submitted = sent;
    return JSON.stringify({ results: [{ record: { content_hash: "sha256:sealed" } }] });
  };
  await new Client("http://localhost:8080", "p1", { transport }).submit(prepared, "sdk-v3-fixed");
  expect(submitted).toEqual(JSON.parse(signedSemantics));
  expect(stringify(prepared)).toBe(signedSemantics);
});

test("v3 prepare rejects incomplete or server-rewritten subjects", async () => {
  const fixture = await Bun.file(new URL("../../../spec/golden-vectors/authority-sdk-v3.json", import.meta.url)).json();
  for (const change of [
    { record_id: "" }, { agent_ts: "" }, { schema_version: "3" },
    { idempotency_key: "inside-subject" }, { input: "raw secret" },
  ]) {
    expect(() => prepareV3AuthoritySubject({ ...fixture.draft_record, ...change })).toThrow();
  }
});

test("buildRecord basics + bigint cost", () => {
  const rec = buildRecord("p1", "s1", "db.query", { eventType: "tool_call", costMicrosUsd: 18000n });
  expect(rec.project_id).toBe("p1");
  expect(rec.event_type).toBe("tool_call");
  expect(rec.cost_micros_usd).toBe(18000n);
  expect(rec.agent_ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
});

test("stringify emits bigint as a raw integer token (no precision loss, no quotes)", () => {
  const big = 9007199254740993n; // 2^53 + 1, not representable as a JS number
  expect(stringify({ cost_micros_usd: big })).toBe('{"cost_micros_usd":9007199254740993}');
  expect(stringify({ a: 1n, b: [2n, 3n] })).toBe('{"a":1,"b":[2,3]}');
});

test("stringify renders undefined array elements as null (valid JSON, never [1,,2])", () => {
  expect(stringify([1, undefined, 2])).toBe("[1,null,2]");
  expect(JSON.parse(stringify({ a: [undefined] }))).toEqual({ a: [null] });
});

test("cost_micros_usd is range-checked to signed 64-bit", () => {
  expect(() => buildRecord("p", "s", "a", { costMicrosUsd: 2n ** 63n })).toThrow();
  // i64 max is fine
  expect(buildRecord("p", "s", "a", { costMicrosUsd: 2n ** 63n - 1n }).cost_micros_usd).toBe(2n ** 63n - 1n);
});

test("floats and bad event types are rejected at the SDK", () => {
  expect(() => buildRecord("p", "s", "a", { costMicrosUsd: 1.5 })).toThrow();
  // @ts-expect-error invalid event type
  expect(() => buildRecord("p", "s", "a", { eventType: "nonsense" })).toThrow();
});

test("client submits with idempotency key and returns the record", async () => {
  let captured: any = {};
  const transport = async (url: string, headers: Record<string, string>, body: string) => {
    captured = { url, headers, body: JSON.parse(body) };
    return JSON.stringify({ results: [{ created: true, record: { content_hash: "sha256:abc" } }] });
  };
  const c = new Client("http://localhost:8080/", "p1", { transport });
  const out = await c.record("s1", "db.query", { idempotencyKey: "fixed", rationale: "why" });

  expect(captured.url).toBe("http://localhost:8080/v2/records");
  expect(captured.headers["Idempotency-Key"]).toBe("fixed");
  expect(captured.body.idempotency_key).toBe("fixed");
  expect((captured.body.extensions as any).content_preview.rationale).toBe("why");
  expect(out.content_hash).toBe("sha256:abc");
});

test("transport preserves opaque identity bytes for server validation", async () => {
  let sent = "";
  const transport = async (_url: string, _headers: Record<string, string>, body: string) => {
    sent = body;
    return JSON.stringify({ error: "project_id must be NFC-normalized" });
  };
  const c = new Client("http://x", "e\u0301", { transport });
  await expect(c.record("s", "read", { idempotencyKey: "k" })).rejects.toThrow(/NFC/);
  expect(JSON.parse(sent).project_id).toBe("e\u0301");
});

test("a server rejection is THROWN, never returned as a sealed record", async () => {
  // A custom transport that does not check status returns the {"error":...} body. The SDK must NOT hand that
  // back as if a record were sealed (the agent would believe unrecorded evidence exists).
  const errBody = async () => JSON.stringify({ error: "unauthorized" });
  const c = new Client("http://x", "p1", { transport: errBody });
  await expect(c.record("s1", "a")).rejects.toThrow(AverinError);
  await expect(c.record("s1", "a")).rejects.toThrow(/unauthorized/);
});

test("an unexpected (no sealed record) response is rejected", async () => {
  const empty = async () => JSON.stringify({ results: [] });
  const c = new Client("http://x", "p1", { transport: empty });
  await expect(c.record("s1", "a")).rejects.toThrow(/did not contain a sealed record/);

  const garbage = async () => "not json at all";
  const c2 = new Client("http://x", "p1", { transport: garbage });
  await expect(c2.record("s1", "a")).rejects.toThrow(/non-JSON/);
});

test("fetchTransport throws on a non-2xx HTTP status (surfacing the server error)", async () => {
  const realFetch = globalThis.fetch;
  // cast via unknown: a minimal stub does not satisfy the full `typeof fetch` surface (e.g. `preconnect`).
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ error: "idempotency_key is required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch;
  try {
    const c = new Client("http://x", "p1"); // default fetchTransport
    await expect(c.record("s1", "a")).rejects.toThrow(AverinError);
    await expect(c.record("s1", "a")).rejects.toThrow(/HTTP 400.*idempotency_key/s);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("auto idempotency keys are unique", async () => {
  const keys = new Set<string>();
  const transport = async (_u: string, h: Record<string, string>) => {
    keys.add(h["Idempotency-Key"]);
    return JSON.stringify({ results: [{ created: true, record: {} }] });
  };
  const c = new Client("http://x", "p1", { transport });
  await c.record("s1", "a");
  await c.record("s1", "a");
  expect(keys.size).toBe(2);
});
