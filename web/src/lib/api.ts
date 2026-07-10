// Thin client for the averin app API. The web app is rendered against this; the server routes all
// canonicalize/seal/verify through the Rust core.
import type { Rec } from "./trace";

// --- Auth -----------------------------------------------------------------------------------------
// The app API is UNAUTHENTICATED only in dev. The documented production posture sets AVERIN_API_KEYS,
// after which every /v2 route requires a project-scoped token, presented as `Authorization: Bearer
// <token>` (server/internal/auth accepts Bearer, else X-Api-Key). Without a token field here, an
// auth-ON server would 401 every request and brick this dashboard — pushing operators to run the API
// authless (full cross-project read + export) just to keep the UI working (averin#19). So we hold the
// token in memory (optionally persisted to localStorage for this browser) and attach it to every call.
const TOKEN_KEY = "averin.apiToken";
let apiToken = "";
try {
  apiToken = globalThis.localStorage?.getItem(TOKEN_KEY) ?? "";
} catch {
  // localStorage may be unavailable (private mode / disabled) — degrade to in-memory only.
}

export function getToken(): string {
  return apiToken;
}

/** Set the API token used for every subsequent request. Empty clears it (dev / authless server). */
export function setToken(token: string): void {
  apiToken = token.trim();
  try {
    if (apiToken) globalThis.localStorage?.setItem(TOKEN_KEY, apiToken);
    else globalThis.localStorage?.removeItem(TOKEN_KEY);
  } catch {
    // ignore persistence failures; the in-memory token still applies for this session.
  }
}

function authHeaders(): Record<string, string> {
  // Only send the header when a token is set, so the authless dev path keeps working unchanged.
  return apiToken ? { Authorization: `Bearer ${apiToken}` } : {};
}

async function getJSON(path: string): Promise<any> {
  const resp = await fetch(path, { headers: authHeaders() });
  if (resp.status === 401) {
    throw new Error(
      `${path}: 401 unauthorized — set a valid API token (the server has AVERIN_API_KEYS auth on)`,
    );
  }
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

/**
 * Download an export bundle. Goes through fetch (not a bare `<a href>` navigation) so the
 * Authorization header is attached — a link navigation cannot carry it, and would 401 whenever the
 * server has auth on. The response is streamed to a blob and saved as a file (averin#19).
 */
export async function downloadExport(project: string, mode: string): Promise<void> {
  const resp = await fetch(exportURL(project, mode), { headers: authHeaders() });
  if (resp.status === 401) {
    throw new Error("export: 401 unauthorized — set a valid API token");
  }
  if (!resp.ok) throw new Error(`export: ${resp.status}`);
  const blob = await resp.blob();
  const objUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objUrl;
  a.download = `averin-${project}-${mode}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objUrl);
}
