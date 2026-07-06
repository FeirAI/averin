// Thin client for the averin app API. The web app is rendered against this; the server routes all
// canonicalize/seal/verify through the Rust core.
import type { Rec } from "./trace";

async function getJSON(path: string): Promise<any> {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`${path}: ${resp.status}`);
  return resp.json();
}

export async function listSessions(project: string): Promise<string[]> {
  const j = await getJSON(`/v2/sessions?project=${encodeURIComponent(project)}`);
  return j.sessions ?? [];
}

export async function sessionDAG(project: string, session: string): Promise<Rec[]> {
  const j = await getJSON(
    `/v2/dag?project=${encodeURIComponent(project)}&session=${encodeURIComponent(session)}`,
  );
  return j.records ?? [];
}

export async function verifyProject(project: string): Promise<any> {
  return getJSON(`/v2/verify?project=${encodeURIComponent(project)}`);
}

export function exportURL(project: string, mode: string): string {
  return `/v2/export?project=${encodeURIComponent(project)}&mode=${encodeURIComponent(mode)}`;
}
