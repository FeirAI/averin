<script lang="ts">
  import {
    listSessions,
    sessionDAG,
    verifyProject,
    downloadExport,
    getToken,
    setToken,
  } from "./lib/api";
  import { buildWaterfall, recLabel, type Rec } from "./lib/trace";

  let project = $state("proj-001");
  // API token for AVERIN_API_KEYS-authenticated servers. Empty = authless dev server (averin#19).
  let token = $state(getToken());
  let sessions = $state<string[]>([]);
  let selected = $state<string | null>(null);
  let rows = $state<ReturnType<typeof buildWaterfall>>([]);
  let report = $state<any>(null);
  let error = $state<string>("");

  function applyToken() {
    setToken(token);
  }

  async function doExport(mode: string) {
    error = "";
    try {
      await downloadExport(project, mode);
    } catch (e) {
      error = String(e);
    }
  }

  async function loadSessions() {
    error = "";
    report = null;
    selected = null;
    rows = [];
    try {
      sessions = await listSessions(project);
    } catch (e) {
      error = String(e);
    }
  }

  async function openSession(s: string) {
    selected = s;
    error = "";
    try {
      const recs = (await sessionDAG(project, s)) as Rec[];
      rows = buildWaterfall(recs);
    } catch (e) {
      error = String(e);
    }
  }

  async function verify() {
    error = "";
    try {
      report = await verifyProject(project);
    } catch (e) {
      error = String(e);
    }
  }

  const trustMark = (s: string) => (s === "ok" ? "✓" : s === "incomplete" ? "▍" : "✗");
</script>

<main>
  <header>
    <h1>averin</h1>
    <p class="tag">verifiable incident reconstruction for production agents</p>
  </header>

  <section class="bar">
    <input bind:value={project} placeholder="project id" />
    <input
      class="token"
      type="password"
      bind:value={token}
      oninput={applyToken}
      placeholder="API token (if auth on)"
      title="Sent as Authorization: Bearer on every request. Leave blank for an authless dev server. Stored in this browser only (averin#19)."
    />
    <button onclick={loadSessions}>Load sessions</button>
    <button onclick={verify}>Verify project</button>
    <button onclick={() => doExport("proof_only")}>Export (proof_only)</button>
    <button onclick={() => doExport("full_evidence")}>Export (full)</button>
  </section>

  {#if error}<p class="err">{error}</p>{/if}

  {#if report}
    <section class="panel verdict {report.ok ? 'pass' : 'fail'}">
      <strong>{report.ok ? "PASS" : "FAIL"}</strong>
      {report.records_proven}/{report.records_total} records proven ·
      DAG {report.dag_ok ? "ok" : "INVALID"} ·
      checkpoints {report.checkpoints_verified}/{report.checkpoints_total}
      ({report.checkpoints_anchors_attached ?? report.checkpoints_anchored} anchors attached,
      {report.checkpoints_anchored} verified-anchored) ·
      chain {report.chain_ok ? "ok" : "BROKEN"}
      {#if report.record_trust?.some((r: any) => r.authority === "legacy_unbound")}
        <div class="lvl">Historical authority signatures verify, but do not bind their record bodies.</div>
      {/if}
      {#if report.first_broken_link}<div class="broken">{report.first_broken_link}</div>{/if}
      {#if !report.keys_externally_pinned}
        <div class="lvl">Keys are bundle-supplied (not externally pinned): this proves internal
          consistency under the bundle's own key claims, not authenticity against an out-of-band
          trust root.</div>
      {/if}
      <div class="lvl">Proves integrity/provenance (Level 1), not completeness (Level 3).</div>
    </section>
  {/if}

  <div class="cols">
    <aside>
      <h2>Sessions</h2>
      {#each sessions as s}
        <button class="sess {selected === s ? 'on' : ''}" onclick={() => openSession(s)}>{s}</button>
      {:else}
        <p class="muted">No sessions loaded.</p>
      {/each}
    </aside>

    <div class="trace">
      {#if selected}
        <h2>{selected} — trace waterfall</h2>
        {#each rows as { rec, depth }}
          <div class="row" style="padding-left:{depth * 22}px">
            <span class="mark {rec.status}">{trustMark(rec.status)}</span>
            <span class="label">{recLabel(rec)}</span>
            <span class="via">{rec.observed_via}</span>
            <span class="hash">{rec.content_hash?.slice(7, 19)}</span>
          </div>
        {/each}
      {:else}
        <p class="muted">Select a session to view its trace.</p>
      {/if}
    </div>
  </div>
</main>

<style>
  :global(body) { margin: 0; background: #0f1115; color: #e6e9ef;
    font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; }
  main { max-width: 1000px; margin: 0 auto; padding: 28px 20px 80px; }
  h1 { margin: 0; font-size: 24px; }
  .tag { color: #9aa4b2; margin: 2px 0 18px; }
  .bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  input { background: #171a21; border: 1px solid #262b35; color: #e6e9ef; border-radius: 8px; padding: 8px 12px; }
  .token { min-width: 190px; }
  button { background: #7c9cff; color: #0b0d12; border: 0; border-radius: 8px; padding: 8px 14px;
    font-weight: 600; cursor: pointer; text-decoration: none; font-size: 14px; }
  .err { color: #f87171; font-family: ui-monospace, monospace; }
  .panel { background: #171a21; border: 1px solid #262b35; border-radius: 12px; padding: 14px; margin: 18px 0; }
  .verdict strong { font-size: 18px; margin-right: 8px; }
  .pass strong { color: #34d399; } .fail strong { color: #f87171; }
  .broken { color: #f87171; font-family: ui-monospace, monospace; font-size: 13px; margin-top: 6px; }
  .lvl { color: #9aa4b2; font-size: 12px; margin-top: 6px; }
  .cols { display: grid; grid-template-columns: 220px 1fr; gap: 18px; margin-top: 12px; }
  aside h2, .trace h2 { font-size: 15px; color: #9aa4b2; }
  .sess { display: block; width: 100%; text-align: left; background: #171a21; color: #e6e9ef;
    border: 1px solid #262b35; margin-bottom: 6px; font-weight: 400; }
  .sess.on { border-color: #7c9cff; }
  .muted { color: #9aa4b2; }
  .row { display: flex; gap: 10px; align-items: center; padding-top: 5px; padding-bottom: 5px;
    border-top: 1px solid #1c2029; font-family: ui-monospace, monospace; font-size: 13px; }
  .mark.ok { color: #34d399; } .mark.error, .mark.blocked { color: #f87171; } .mark.incomplete { color: #fbbf24; }
  .label { flex: 1; } .via { color: #9aa4b2; } .hash { color: #7c9cff; }
</style>
