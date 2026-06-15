// Pure trace-waterfall construction (no DOM) — unit-tested. The primary run view is an indented
// waterfall by causal depth (spec §13: no graph-layout dependency), not a 2D/3D graph.

export interface Rec {
  content_hash: string;
  causal_prev_hashes?: string[];
  display_seq: number;
  span_id?: string;
  record_id?: string;
  event_type: string;
  action: string;
  status: string;
  observed_via: string;
  session_id?: string;
}

export interface Row {
  rec: Rec;
  depth: number;
}

/** Causal depth of a record = longest chain of causal parents (0 for a root). Computed iteratively
 * (an explicit stack, not recursion) so a session thousands of records deep cannot overflow the JS
 * call stack. O(V+E) via memoization; cycles (which the core rejects anyway) and missing parents are
 * guarded. */
export function buildWaterfall(records: Rec[]): Row[] {
  const byHash = new Map(records.map((r) => [r.content_hash, r]));
  const depthCache = new Map<string, number>();

  for (const start of records) {
    const stack: string[] = [start.content_hash];
    const onPath = new Set<string>();
    while (stack.length) {
      const h = stack[stack.length - 1];
      if (depthCache.has(h)) {
        stack.pop();
        continue;
      }
      const r = byHash.get(h);
      const parents = (r?.causal_prev_hashes ?? []).filter((p) => byHash.has(p));
      const unresolved = parents.filter((p) => !depthCache.has(p) && !onPath.has(p));
      if (unresolved.length > 0) {
        onPath.add(h);
        for (const p of unresolved) stack.push(p);
      } else {
        // a parent still on the current path is a cycle → treated as depth 0
        const d = parents.length ? 1 + Math.max(...parents.map((p) => depthCache.get(p) ?? 0)) : 0;
        depthCache.set(h, d);
        onPath.delete(h);
        stack.pop();
      }
    }
  }

  return [...records]
    .sort((a, b) => a.display_seq - b.display_seq)
    .map((rec) => ({ rec, depth: depthCache.get(rec.content_hash) ?? 0 }));
}

/** Short label for a record in the waterfall. */
export function recLabel(r: Rec): string {
  return `${r.event_type} · ${r.action || "—"}`;
}
