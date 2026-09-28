/**
 * averin — flight recorder SDK for AI agents (TypeScript).
 *
 * Submits records to a averin server, where the integrity core seals them. Integer money/token
 * fields are `bigint` so a value above 2^53 never loses precision through a JS `number` (RCP
 * forbids floats and uses i64); we serialize bigints as raw JSON integer tokens.
 */

export type EventType =
  | "llm_call"
  | "tool_call"
  | "decision"
  | "approval_gate"
  | "handoff"
  | "spawn_child"
  | "incomplete"
  | "credential_grant"; // credential-broker grant record (Level 3, ADR 0002)

const EVENT_TYPES: ReadonlySet<string> = new Set([
  "llm_call",
  "tool_call",
  "decision",
  "approval_gate",
  "handoff",
  "spawn_child",
  "incomplete",
  "credential_grant",
]);

/** Finalize server semantic defaults before an external authority signs v3 evidence.
 * Sign this returned structured record, attach subject_digest/evidence_sig to its authority,
 * then submit that same object. The idempotency key is supplied separately at submit time.
 */
export function prepareV3AuthoritySubject(draft: Record<string, unknown>): Record<string, unknown> {
  const rec = structuredClone(draft);
  if ("idempotency_key" in rec) throw new Error("supply idempotency_key to Client.submit");
  for (const field of ["input", "output", "rationale"]) {
    if (field in rec) throw new Error(`v3 requires a preapproved ${field}_commit, not raw ${field}`);
  }
  const profile: Record<string, string> = {
    schema_version: "2", canon_version: "rcp-1", domain: "flightrecorder.record.v2",
  };
  for (const [field, value] of Object.entries(profile)) {
    if (field in rec && rec[field] !== value) throw new Error(`v3 requires ${field}=${value}`);
    rec[field] = value;
  }
  const defaults: Record<string, string> = {
    agent_id: "unknown", agent_version: "unknown", event_type: "decision",
    action: "", observed_via: "sdk", status: "ok",
  };
  for (const [field, value] of Object.entries(defaults)) {
    if (!(field in rec)) rec[field] = value;
  }
  if (!("parent_span_id" in rec)) rec.parent_span_id = null;
  for (const field of ["project_id", "record_id", "session_id", "span_id", "agent_ts",
    "agent_id", "agent_version", "event_type", "action", "observed_via", "status"]) {
    if (typeof rec[field] !== "string" || (field !== "action" && rec[field] === "")) {
      throw new Error(`v3 requires final string ${field} before signing`);
    }
  }
  if (rec.parent_span_id !== null && typeof rec.parent_span_id !== "string") {
    throw new Error("v3 parent_span_id must be a string or null");
  }
  const authority = rec.authority;
  if (authority === null || typeof authority !== "object" || Array.isArray(authority)) {
    throw new Error("v3 requires a pinned external authority block");
  }
  const proof = authority as Record<string, unknown>;
  if (!["policy_engine_signed", "human_signed", "delegate_signed"].includes(String(proof.source))) {
    throw new Error("v3 requires a policy, human, or delegate authority source");
  }
  if (typeof proof.evidence_hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(proof.evidence_hash)) {
    throw new Error("v3 requires a canonical evidence_hash");
  }
  if ("subject_digest" in proof || "evidence_sig" in proof) {
    throw new Error("v3 subject must be prepared before attaching its proof");
  }
  const projection = "averin.authority.subject.v1";
  if (("proof_version" in proof && proof.proof_version !== "v3") ||
      ("subject_projection" in proof && proof.subject_projection !== projection)) {
    throw new Error("unsupported v3 authority proof profile");
  }
  proof.proof_version = "v3";
  proof.subject_projection = projection;
  if ("extensions" in rec && rec.extensions !== null) {
    const extensions = rec.extensions;
    if (typeof extensions !== "object" || Array.isArray(extensions)) {
      throw new Error("v3 extensions must be an object");
    }
    const ext = extensions as Record<string, unknown>;
    if ("content_preview" in ext) throw new Error("v3 requires commitments instead of raw content_preview");
    if ("feir_evidence" in ext && ext.feir_evidence !== null) {
      const evidence = ext.feir_evidence;
      if (typeof evidence !== "object" || Array.isArray(evidence)) {
        throw new Error("v3 feir_evidence must be an object");
      }
      const feir = evidence as Record<string, unknown>;
      feir.capture_authority = rec.observed_via;
      feir.lineage = {
        session_id: rec.session_id, span_id: rec.span_id, parent_span_id: rec.parent_span_id,
      };
    }
  }
  return rec;
}

export interface RecordOpts {
  eventType?: EventType;
  status?: string;
  observedVia?: string;
  rationale?: string;
  input?: unknown;
  output?: unknown;
  authority?: Record<string, unknown>;
  costMicrosUsd?: bigint | number;
  tokensIn?: bigint | number;
  tokensOut?: bigint | number;
  parentSpanId?: string;
  framework?: string;
  extensions?: Record<string, unknown>;
}

const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

function asInt(name: string, v: bigint | number | undefined): bigint | undefined {
  if (v === undefined) return undefined;
  let b: bigint;
  if (typeof v === "bigint") b = v;
  else if (typeof v === "number" && Number.isInteger(v)) b = BigInt(v);
  else throw new Error(`${name} must be an integer (no floats in signed records)`);
  if (b < I64_MIN || b > I64_MAX) throw new Error(`${name} out of signed 64-bit range (RCP)`);
  return b;
}

function nowMs(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export function buildRecord(
  projectId: string,
  sessionId: string,
  action: string,
  opts: RecordOpts = {},
): Record<string, unknown> {
  const eventType = opts.eventType ?? "tool_call";
  if (!EVENT_TYPES.has(eventType)) throw new Error(`invalid eventType: ${eventType}`);

  const rec: Record<string, unknown> = {
    project_id: projectId,
    session_id: sessionId,
    action,
    event_type: eventType,
    status: opts.status ?? "ok",
    observed_via: opts.observedVia ?? "sdk",
    agent_ts: nowMs(),
  };
  if (opts.parentSpanId !== undefined) rec.parent_span_id = opts.parentSpanId;
  const cost = asInt("costMicrosUsd", opts.costMicrosUsd);
  if (cost !== undefined) rec.cost_micros_usd = cost;
  const tin = asInt("tokensIn", opts.tokensIn);
  const tout = asInt("tokensOut", opts.tokensOut);
  if (tin !== undefined || tout !== undefined) {
    rec.tokens = { in: tin ?? 0n, out: tout ?? 0n };
  }
  const content: Record<string, unknown> = {};
  if (opts.input !== undefined) content.input = opts.input;
  if (opts.output !== undefined) content.output = opts.output;
  if (opts.rationale !== undefined) content.rationale = opts.rationale;
  if (Object.keys(content).length) rec.extensions = { content_preview: content };
  if (opts.authority) rec.authority = { ...opts.authority };
  if (opts.framework) rec.framework = opts.framework;
  if (opts.extensions) rec.extensions = { ...(rec.extensions as object), ...opts.extensions };
  return rec;
}

/** JSON.stringify that emits `bigint` as a raw integer token (JSON.stringify throws on bigint). */
export function stringify(value: unknown): string {
  if (typeof value === "bigint") return value.toString();
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) {
    // JSON.stringify renders undefined/function/symbol array elements as null — match that so the
    // output is always valid JSON (never `[1,,2]`).
    return "[" + value.map((v) => stringify(v)).join(",") + "]";
  }
  const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
  return "{" + entries.map(([k, v]) => JSON.stringify(k) + ":" + stringify(v)).join(",") + "}";
}

export type Transport = (url: string, headers: Record<string, string>, body: string) => Promise<string>;

/**
 * Thrown when the server REJECTS a submission (non-2xx) or returns a response that is not a sealed record.
 * This SDK records tamper-evident evidence: a rejected submission must surface as an error, never be returned
 * as if a record were sealed — otherwise an agent would believe evidence exists when the server stored none.
 */
export class AverinError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: string,
  ) {
    super(message);
    this.name = "AverinError";
  }
}

const fetchTransport: Transport = async (url, headers, body) => {
  const resp = await fetch(url, { method: "POST", headers, body });
  const text = await resp.text();
  if (!resp.ok) {
    // Do NOT let a 4xx/5xx body (e.g. {"error":"unauthorized"}) flow back as a "record" — surface the rejection.
    let msg = `averin server returned HTTP ${resp.status}`;
    try {
      const e = (JSON.parse(text) as { error?: unknown })?.error;
      if (typeof e === "string") msg += `: ${e}`;
    } catch {
      // non-JSON error body; the status alone is the signal.
    }
    throw new AverinError(msg, resp.status, text);
  }
  return text;
};

export class Client {
  private baseUrl: string;
  constructor(
    baseUrl: string,
    private projectId: string,
    private opts: { apiKey?: string; transport?: Transport } = {},
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async record(
    sessionId: string,
    action: string,
    opts: RecordOpts & { idempotencyKey?: string } = {},
  ): Promise<Record<string, unknown>> {
    const { idempotencyKey, ...rest } = opts;
    return this.submit(buildRecord(this.projectId, sessionId, action, rest), idempotencyKey);
  }

  async submit(recordBody: Record<string, unknown>, idempotencyKey?: string): Promise<Record<string, unknown>> {
    const idem = idempotencyKey ?? crypto.randomUUID();
    const payload = { ...recordBody, idempotency_key: idem };
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Idempotency-Key": idem,
    };
    if (this.opts.apiKey) headers["Authorization"] = `Bearer ${this.opts.apiKey}`;
    const transport = this.opts.transport ?? fetchTransport;
    const resp = await transport(`${this.baseUrl}/v2/records`, headers, stringify(payload));
    let parsed: { results?: Array<{ record?: Record<string, unknown> }>; error?: unknown };
    try {
      parsed = JSON.parse(resp);
    } catch {
      throw new AverinError("averin server returned a non-JSON response", undefined, resp);
    }
    // Backstop for a custom transport that does NOT check HTTP status (the built-in fetchTransport throws on
    // non-2xx already): an {"error":...} body or a missing sealed record is a REJECTION, not a sealed record.
    // The previous `?? parsed` fallback returned the error body AS the record — silently masking the rejection.
    if (typeof parsed.error === "string") {
      throw new AverinError(`averin server rejected the record: ${parsed.error}`, undefined, resp);
    }
    const record = parsed.results?.[0]?.record;
    if (record == null) {
      throw new AverinError("averin server response did not contain a sealed record", undefined, resp);
    }
    return record;
  }
}
