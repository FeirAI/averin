/**
 * feir — flight recorder SDK for AI agents (TypeScript).
 *
 * Submits records to a feir server, where the integrity core seals them. Integer money/token
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
  | "incomplete";

const EVENT_TYPES: ReadonlySet<string> = new Set([
  "llm_call",
  "tool_call",
  "decision",
  "approval_gate",
  "handoff",
  "spawn_child",
  "incomplete",
]);

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

const fetchTransport: Transport = async (url, headers, body) => {
  const resp = await fetch(url, { method: "POST", headers, body });
  return await resp.text();
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
    const parsed = JSON.parse(resp);
    return parsed.results?.[0]?.record ?? parsed;
  }
}
