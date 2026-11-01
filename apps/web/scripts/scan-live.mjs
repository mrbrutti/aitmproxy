// LIVE PROOF of the v2 Scan surface (track T8): a real `aitm web` on a real core, the real
// `aitm-testtarget-serve` as the target, the real web UI driven in headless Chrome with real input
// events only (Input.dispatchMouseEvent / dispatchKeyEvent / insertText — never synthetic DOM
// events, never app functions), and a SECOND operator bus connection kept as the **witness**:
// every value the UI renders is cross-checked against what the witness reads from the core.
//
//   node scripts/scan-live.mjs [--keep] [--json]
//
// --keep leaves aitm and Chrome running and prints the UI URL.
// --json sends the human log to stderr so stdout carries exactly one line: the result JSON
//        `{ pass, fail, gap, shots, results }` (T10's test_t8_web_live.py wraps that).
//
// Every step takes a screenshot into apps/web/.cua-shots/scan/ and the witness's whole
// conversation (call, reply, error, push) is appended to .cua-shots/scan/bus-transcript.jsonl.
// Exit 1 on any FAIL. No step reads a fixture. Node >= 22, no dependencies.
import { appendFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, sleep, startAitm, startTestTarget, waitFor } from './live-env.mjs';
import { launchChrome, makeDriver } from './cua-driver.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-shots/scan');
const TRANSCRIPT = join(SHOTS, 'bus-transcript.jsonl');
const KEEP = process.argv.includes('--keep');
const JSON_MODE = process.argv.includes('--json');
const W = 1600;
const H = 1000;

// ------------------------------------------------------------------------------------------
// Selectors — fixed by the plan (T8 tasks 10-14); nothing here is invented.
// ------------------------------------------------------------------------------------------
const SIDEBAR = 'aside[aria-label="Sources"]';
const GRID = '[role=grid][aria-label="Flows"]';
const SCANNER = 'section[aria-label="Scanner"]';
const TABLIST = `${SCANNER} [role=tablist][aria-label="Scan views"]`;
const PROFILES = '[role=listbox][aria-label="Profiles"]';
const JOBS = '[role=listbox][aria-label="Jobs"]';
const SITEMAP = '[role=listbox][aria-label="Site map"]';
const STRIP = `${SCANNER} [role=region][aria-label="Selected job"]`;
const FINDINGS_ROWS = '[role=listbox][aria-label="Findings"]';

// The plan (task 11) pins the button name `Add L4 target` and the row's fields (ip/port/proto/
// grammar) but NOT their aria-labels, so step 8b probes the labels that follow the origin picker's
// convention and records a GAP — never a FAIL — when none of them is present: an unpinned selector
// is a hole in the plan's selector contract, not evidence of a UI defect.
const L4_LABELS = {
  ip: ['L4 target IP', 'L4 target ip', 'Target IP', 'L4 IP', 'IP'],
  port: ['L4 target port', 'Target port', 'L4 port'],
  proto: ['L4 target proto', 'Target proto', 'L4 proto', 'Proto', 'Transport'],
};

const TERMINAL = new Set(['done', 'cancelled', 'failed']); // JobState, crates/aitm-scan-model/src/job.rs
// The store polls scan.status every 1000 ms (D10), so a witness read taken this long before the DOM
// read is guaranteed to precede the poll the rendered number came from: that is what makes the
// bracket `status_before.sent <= rendered <= status_after.sent` a sound assertion and not a race.
const BRACKET_LEAD_MS = 1300;

// ------------------------------------------------------------------------------------------
// Results
// ------------------------------------------------------------------------------------------
const results = [];
const out = (m) => (JSON_MODE ? console.error(m) : console.log(m));
function record(status, step, detail) {
  results.push({ status, step, detail: detail ?? null });
  out(`${status.padEnd(4)} ${step}${detail ? ` — ${detail}` : ''}`);
}
const pass = (step, detail) => record('PASS', step, detail);
const fail = (step, detail) => record('FAIL', step, detail);
const gap = (step, detail) => record('GAP', step, detail);
const note = (step, detail) => record('NOTE', step, detail);
const expect = (cond, okMsg, badMsg) => (cond ? pass(okMsg) : fail(okMsg, badMsg));

// ------------------------------------------------------------------------------------------
// Witness bus: a second operator connection whose whole conversation is transcribed
// ------------------------------------------------------------------------------------------
mkdirSync(SHOTS, { recursive: true });
for (const f of readdirSync(SHOTS)) if (f.endsWith('.png')) rmSync(join(SHOTS, f));
writeFileSync(TRANSCRIPT, '');

function tx(entry) {
  appendFileSync(TRANSCRIPT, JSON.stringify({ t: new Date().toISOString(), ...entry }) + '\n');
}

async function witness(busUrl, token, conn) {
  const b = await connectBus(busUrl, token);
  let seen = 0;
  const drain = () => {
    while (seen < b.notifications.length) tx({ dir: 'push', conn, line: b.notifications[seen++] });
  };
  const timer = setInterval(drain, 200);
  timer.unref?.();
  const call = async (name, args = {}) => {
    const t0 = Date.now();
    tx({ dir: 'call', conn, name, args });
    try {
      const result = await b.call(name, args);
      tx({ dir: 'reply', conn, name, ms: Date.now() - t0, result });
      drain();
      return result;
    } catch (e) {
      tx({ dir: 'error', conn, name, ms: Date.now() - t0, error: e.message });
      drain();
      throw e;
    }
  };
  const tools = async () => {
    const t = await b.tools();
    tx({ dir: 'reply', conn, name: 'tools/list', result: t.map((x) => x.name) });
    return t;
  };
  return {
    call,
    tools,
    drain,
    close: () => {
      clearInterval(timer);
      drain();
      b.close();
    },
  };
}

// ------------------------------------------------------------------------------------------
// Main
// ------------------------------------------------------------------------------------------
let target, env, bus, cdp, d;
let jobId = null;
let nodeId = null;
let engineOk = false;
const j = JSON.stringify;
const log = (m) => out(m);

/** Runs one step: PASS unless the body throws or records a non-NOTE result; always screenshots. */
async function step(name, body) {
  log(`\n== ${name}`);
  const before = results.length;
  try {
    await body();
    if (!results.slice(before).some((r) => r.status !== 'NOTE')) pass(name);
  } catch (e) {
    fail(name, e.message.split('\n')[0]);
  } finally {
    try {
      const f = await d.shot(name);
      if (f) log(`  shot ${f}`);
    } catch (e) {
      log(`  (screenshot failed: ${e.message})`);
    }
  }
}

/** waitFor that yields null instead of throwing, for "is it there?" questions. */
const soft = async (fn, timeoutMs = 5000) => {
  try {
    return await waitFor(fn, { timeoutMs, everyMs: 200, what: 'condition' });
  } catch {
    return null;
  }
};

// --- read-only page queries (no DOM writes beyond the driver's scrollIntoView) ---------------
const countOf = (sel) => d.ev(`document.querySelectorAll(${j(sel)}).length`);
const attr = (sel, name) => d.ev(`document.querySelector(${j(sel)})?.getAttribute(${j(name)}) ?? null`);
const textsOf = (sel) => d.ev(`Array.from(document.querySelectorAll(${j(sel)})).map((e) => (e.innerText ?? e.textContent ?? '').replace(/\\s+/g, ' ').trim())`);
/** Unnormalised text: evidence (payload, matched, example) must compare verbatim. */
const rawText = (sel) => d.ev(`(() => { const e = document.querySelector(${j(sel)}); return e ? (e.textContent ?? null) : null; })()`);
const valueOf = (sel) => d.ev(`document.querySelector(${j(sel)})?.value ?? null`);

// --- real-input interactions -----------------------------------------------------------------
const goScan = () => d.click({ role: 'button', text: 'Scan', match: 'startsWith', within: SIDEBAR });
const clickTab = (label) => d.click({ role: 'tab', text: label, match: 'startsWith', within: TABLIST });

/** Clicks the field, selects its contents and types `text` with real key/insertText events. */
async function typeInto(sel, text) {
  await d.click({ sel });
  await d.selectAll();
  await d.type(text);
}

/** Picks an option in a real <select> the way a keyboard does: focus, then arrow until it matches. */
async function pickSelect(sel, wanted) {
  const ok = (v) => (wanted instanceof RegExp ? wanted.test(v ?? '') : v === wanted);
  const el = await d.locate({ sel });
  if (ok(await valueOf(sel))) return valueOf(sel);
  await d.mouse(el.x, el.y);
  for (const k of ['ArrowDown', 'ArrowUp']) {
    for (let i = 0; i < 24; i++) {
      await d.key(k);
      if (ok(await valueOf(sel))) return valueOf(sel);
    }
  }
  throw new Error(`could not pick ${wanted} in ${sel} (value stays ${j(await valueOf(sel))})`);
}

/** The probes numerator the UI renders for `job` (`418/2000` -> 418), or null. */
async function renderedProbes(sel) {
  const t = await d.q('text', sel);
  const m = typeof t === 'string' ? t.match(/(\d[\d,]*)\s*\/\s*(\d[\d,]*)/) : null;
  return m ? Number(m[1].replace(/,/g, '')) : null;
}

/** `running · auditing` -> `auditing`; a terminal state prints alone, so that yields the state. */
const phaseWord = (words) => (typeof words === 'string' && words.includes('·') ? words.split('·').pop().trim() : null);

const sameCounts = (bySeverity, rendered) => {
  const nonZero = Object.entries(bySeverity ?? {}).filter(([, n]) => Number(n) > 0);
  if (nonZero.length !== Object.keys(rendered).length) return false;
  return nonZero.every(([s, n]) => rendered[s] === Number(n));
};

async function renderedGroups() {
  const pairs = await d.ev(
    `Array.from(document.querySelectorAll(${j(`${SCANNER} [data-severity][data-count]`)})).map((e) => [e.getAttribute('data-severity'), Number(e.getAttribute('data-count'))])`,
  );
  return Object.fromEntries(pairs ?? []);
}

/** Finds an L4 target field by the candidate labels above; null when the UI pins other names. */
async function l4Field(labels, tag) {
  for (const label of labels) {
    const sel = `${tag}[aria-label="${label}"]`;
    if (await d.q('exists', sel)) return sel;
  }
  return null;
}

// ------------------------------------------------------------------------------------------
// Steps
// ------------------------------------------------------------------------------------------
async function run() {
  // 1 ----------------------------------------------------------------------------------------
  await step('01 the core offers the engine and the Scan panel opens', async () => {
    await d.open(env.operatorUiUrl ?? env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 20000, what: 'status bar "bus open"' });
    const tools = (await bus.tools()).map((t) => t.name);
    if (!tools.includes('scan.start')) {
      fail('01 the core offers the engine and the Scan panel opens', 'engine not available: scan.start not in tools/list');
      note('01 tools seen', tools.filter((t) => t.startsWith('scan.')).join(' ') || 'no scan.* verb at all');
      return;
    }
    engineOk = true;
    const item = await d.q('find', { role: 'button', text: 'Scan', match: 'startsWith', within: SIDEBAR });
    expect(!!item, '01a the sidebar shows Scan', 'no Scan item in the sidebar');
    await goScan();
    const std = await soft(() => d.q('exists', `${PROFILES} [data-profile="standard"]`), 10000);
    expect(!!std, '01b the v2 surface lists the standard profile', `${PROFILES} [data-profile="standard"] never appeared`);
  });
  if (!engineOk) {
    note('02-08 skipped', 'the scan engine is not on this core; nothing downstream can be proven');
    return;
  }

  // 2 ----------------------------------------------------------------------------------------
  await step('02 start a standard scan against the test target', async () => {
    await d.click({ sel: `${PROFILES} [data-profile="standard"]` });
    await pickSelect('select[aria-label="Origin scheme"]', 'http');
    await pickSelect('select[aria-label="Origin host"]', /127\.0\.0\.1/);
    await typeInto('input[aria-label="Origin port"]', String(target.port));
    await d.click({ role: 'button', text: 'Add origin', match: 'startsWith' });
    const origins = await d.q('text', '[aria-label="Origins"]');
    const want = `http://127.0.0.1:${target.port}`;
    expect((origins ?? '').includes(want), '02a the origin picker composed the target origin', `Origins reads ${j(origins)}, wanted ${want}`);
    const startBtn = await d.q('find', { role: 'button', text: 'Start', match: 'exact', within: SCANNER });
    if (startBtn?.disabled) note('02 Start disabled', `reason ${j(await d.q('text', `${SCANNER} [data-reason]`))}`);
    await d.click({ role: 'button', text: 'Start', match: 'exact', within: SCANNER });
    const jobsRow = async () => (await countOf(`${JOBS} [data-job]`)) > 0;
    if (!(await soft(jobsRow, 3000))) {
      await clickTab('Jobs');
      note('02 jobs tab', 'clicked the Jobs tab after Start (the shell does not switch tabs on launch)');
    }
    const seen = await soft(jobsRow, 20000);
    if (!seen) {
      const result = await d.q('text', `${SCANNER} [role=status]`);
      fail('02b a Jobs row appears for the launch', `no ${JOBS} [data-job] within 20 s; launch result reads ${j(result)}`);
      return;
    }
    jobId = await attr(`${JOBS} [data-job]`, 'data-job');
    const list = await bus.call('scan.list', {});
    const witnessJob = list.jobs?.[0]?.job ?? null;
    expect(jobId != null && jobId === witnessJob, '02b the Jobs row id equals the witness scan.list[0].job', `rendered ${j(jobId)}, witness ${j(list.jobs?.map((x) => x.job) ?? null)}`);
  });
  if (!jobId) {
    note('03-07 skipped', 'no job was started, so nothing downstream can be cross-checked');
    return;
  }

  // 3 ----------------------------------------------------------------------------------------
  await step('03 probes and phase track the witness', async () => {
    const probesSel = `${JOBS} [data-job="${jobId}"] [data-field=probes]`;
    const stateSel = `${JOBS} [data-job="${jobId}"] [data-field=state]`;
    // Each bracket: a witness read taken BRACKET_LEAD_MS before the DOM read (so it precedes the
    // poll the UI rendered) and one immediately after; `sent` is monotonic, so the rendered value
    // must lie between them.
    const bracket = async (label) => {
      const before = await bus.call('scan.status', { job: jobId });
      await sleep(BRACKET_LEAD_MS);
      const rendered = await renderedProbes(probesSel);
      const after = await bus.call('scan.status', { job: jobId });
      return { label, before: before.probes?.sent ?? null, rendered, after: after.probes?.sent ?? null };
    };
    const a = await bracket('a');
    await sleep(2000);
    const b = await bracket('b');
    for (const s of [a, b]) {
      expect(
        s.rendered != null && s.before != null && s.after != null && s.rendered >= s.before && s.rendered <= s.after,
        `03a rendered probes bracketed by witness scan.status (${s.label})`,
        `witness ${s.before} <= rendered ${s.rendered} <= witness ${s.after}`,
      );
    }
    expect(a.rendered != null && b.rendered != null && b.rendered > a.rendered, '03b rendered probes strictly increase over 2 s', `${a.rendered} -> ${b.rendered}`);

    // Phase: sample the rendered words and the witness phase together every 500 ms for up to 20 s.
    const witnessPhases = new Set();
    const matched = new Set();
    const renderedWords = new Set();
    const timeline = [];
    const t0 = Date.now();
    let last = null;
    while (Date.now() - t0 < 20000) {
      const words = await d.q('text', stateSel);
      const st = await bus.call('scan.status', { job: jobId });
      last = st;
      const rp = phaseWord(words);
      if (words) renderedWords.add(words);
      // A terminal job prints its state alone by design, so its phase is not expected on screen.
      if (st.phase && !TERMINAL.has(st.state)) witnessPhases.add(st.phase);
      if (rp && rp === st.phase) matched.add(st.phase);
      timeline.push({ at: Date.now() - t0, rendered: words, phase: st.phase ?? null, state: st.state });
      if (TERMINAL.has(st.state)) break;
      await sleep(500);
    }
    tx({ dir: 'note', what: 'phase timeline', job: jobId, timeline });
    const missed = [...witnessPhases].filter((p) => !matched.has(p));
    expect(
      witnessPhases.size > 0 && missed.length === 0,
      '03c every phase the witness saw was rendered at least once',
      `witness phases [${[...witnessPhases].join(', ')}], never rendered [${missed.join(', ')}], rendered words ${j([...renderedWords])}`,
    );
    note('03 job state after the phase track', `${last?.state ?? '?'} · ${last?.phase ?? '—'} (${last?.probes?.sent ?? '?'} probes)`);
  });

  // 4 ----------------------------------------------------------------------------------------
  await step('04 issues, evidence, flow, PoC and the false_positive round trip', async () => {
    await clickTab('Issues');
    const headers = await soft(async () => ((await countOf(`${SCANNER} [data-severity][data-count]`)) > 0 ? true : null), 30000);
    if (!headers) {
      const witnessIssues = await bus.call('scan.issues', { job: jobId, limit: 1024 });
      gap('04 issues', `no severity group rendered within 30 s; witness by_severity ${j(witnessIssues.by_severity ?? null)}`);
      return;
    }
    let rendered = {};
    let wanted = {};
    let agreed = false;
    const until = Date.now() + 5000; // "within one refresh"
    do {
      wanted = (await bus.call('scan.issues', { job: jobId, limit: 1024 })).by_severity ?? {};
      rendered = await renderedGroups();
      agreed = sameCounts(wanted, rendered);
      if (!agreed) await sleep(500);
    } while (!agreed && Date.now() < until);
    expect(agreed, '04a issue group counts equal the witness by_severity (zero groups absent)', `rendered ${j(rendered)} vs witness ${j(wanted)}`);

    const issueId = await attr(`${SCANNER} [data-issue]`, 'data-issue');
    if (!issueId) {
      gap('04 issue detail', 'the groups rendered but no [data-issue] row is present');
      return;
    }
    await d.click({ sel: `${SCANNER} [data-issue="${issueId}"]` });
    const issue = await bus.call('scan.issue', { id: issueId });
    const payload = await soft(async () => (await rawText('[data-field=payload]')) ?? null, 5000);
    expect(payload === (issue.evidence?.payload ?? null), '04b the detail payload is the witness payload verbatim', `rendered ${j(payload)} vs witness ${j(issue.evidence?.payload ?? null)}`);

    const probeFlow = issue.evidence?.probe_flows?.[0] ?? issue.evidence?.baseline_flow ?? null;
    if (!probeFlow) {
      gap('04c probe flow', 'the issue carries neither a probe flow nor a baseline flow');
    } else {
      await d.click({ role: 'button', text: `Open flow ${probeFlow}`, match: 'startsWith' });
      const selected = await soft(async () => (await attr(`${GRID} [role=row][aria-selected="true"]`, 'data-id')) ?? null, 5000);
      expect(selected === probeFlow, '04c the probe flow opens selected in the inspector', `grid selection ${j(selected)}, issue probe flow ${j(probeFlow)}`);
      await goScan();
      await clickTab('Issues');
    }

    if (!issue.poc_ref) {
      gap('04d PoC ref', 'no issue carries poc_ref on this engine');
    } else {
      await d.click({ role: 'button', text: `Open PoC ${issue.poc_ref}`, match: 'startsWith' });
      const row = await soft(() => d.q('find', { sel: `${FINDINGS_ROWS} [role=option][aria-selected="true"]` }), 5000);
      let title = null;
      try {
        const listed = await bus.call('poc.list', {});
        const entries = Array.isArray(listed) ? listed : (listed.findings ?? listed.pocs ?? []);
        const hit = entries.find((e) => e?.id === issue.poc_ref || e?.poc_path === issue.poc_ref);
        title = hit?.title ?? null;
      } catch (e) {
        note('04d poc.list', e.message.split('\n')[0]);
      }
      const ok = !!row && (title ? row.text.includes(title) : row.id === issue.poc_ref);
      expect(ok, '04d the PoC ref opens Findings with that PoC selected', `selected row ${j(row?.text ?? null)} (data-id ${j(row?.id ?? null)}), witness title ${j(title)}, poc_ref ${j(issue.poc_ref)}`);
      await goScan();
      await clickTab('Issues');
    }

    const statusGroup = '[role=radiogroup][aria-label="Issue status"]';
    const radio = (await d.q('find', { role: 'radio', text: 'false_positive', within: statusGroup })) ?? (await d.q('find', { role: 'radio', text: 'False positive', within: statusGroup }));
    if (!radio) {
      gap('04e false_positive round trip', `no false_positive radio under ${statusGroup}`);
      return;
    }
    await d.mouse(radio.x, radio.y);
    await typeInto('textarea[aria-label="Note"]', 'intended behaviour');
    await d.click({ role: 'button', text: 'Update status', match: 'startsWith' });
    const updated = await soft(async () => {
      const i = await bus.call('scan.issue', { id: issueId });
      return i.status === 'false_positive' ? i : null;
    }, 5000);
    const finalStatus = updated?.status ?? (await bus.call('scan.issue', { id: issueId }).then((i) => i.status).catch((e) => e.message));
    expect(!!updated, '04e false_positive round-trips through scan.issue.update', `witness status stays ${j(finalStatus)}`);
    expect(updated?.note === 'intended behaviour', '04f the note reached the core verbatim', `witness note ${j(updated?.note ?? null)}`);
  });

  // 5 ----------------------------------------------------------------------------------------
  await step('05 cancel', async () => {
    await clickTab('Jobs');
    const pre = await bus.call('scan.status', { job: jobId });
    if (TERMINAL.has(pre.state)) {
      gap('05 cancel', `the job reached ${pre.state} before the cancel step; there was nothing to cancel`);
      return;
    }
    const stateSel = `${JOBS} [data-job="${jobId}"] [data-field=state]`;
    await d.click({ role: 'button', text: `Cancel scan ${jobId}`, match: 'startsWith', within: STRIP });
    const immediate = await soft(async () => {
      const t = await d.q('text', stateSel);
      return typeof t === 'string' && /cancelling|cancelled/.test(t) ? t : null;
    }, 1500);
    expect(!!immediate, '05a the row reads cancelling or cancelled immediately', `rendered ${j(await d.q('text', stateSel))}`);
    const settled = await soft(async () => {
      const t = await d.q('text', stateSel);
      return typeof t === 'string' && /cancelled/.test(t) ? t : null;
    }, 5000);
    expect(!!settled, '05b the row reads cancelled within 5 s', `rendered ${j(await d.q('text', stateSel))}`);
    const st = await bus.call('scan.status', { job: jobId });
    expect(st.state === 'cancelled', '05c the witness scan.status.state is cancelled', `witness state ${j(st.state)}`);
  });

  // 6 ----------------------------------------------------------------------------------------
  await step('06 the site map renders the witness nodes and insertion points', async () => {
    await clickTab('Site map');
    const sm = await bus.call('scan.sitemap', { job: jobId, limit: 1024 });
    const nodes = sm.nodes ?? [];
    const points = sm.points ?? [];
    if (!nodes.length) {
      gap('06 site map', 'the witness scan.sitemap returned no nodes for this job');
      return;
    }
    const got = await soft(async () => ((await countOf(`${SITEMAP} [data-node]`)) > 0 ? true : null), 10000);
    if (!got) {
      fail('06a the site map renders the witness nodes', `${SITEMAP} [data-node] never appeared though the witness has ${nodes.length} node(s)`);
      return;
    }
    const rows = await textsOf(`${SITEMAP} [data-node]`);
    const missing = nodes.map((n) => n.path_template).filter((t) => !rows.some((r) => r.includes(t)));
    expect(missing.length === 0, '06a every witness path_template is rendered', `missing ${j(missing)} among ${j(rows)}`);
    const renderedKN = (await textsOf(`${SCANNER} [data-field=kind-name]`)).slice().sort();
    const witnessKN = points.map((p) => `${p.kind}:${p.name}`).sort();
    expect(j(renderedKN) === j(witnessKN), '06b the insertion-point kind:name set equals the witness', `rendered ${j(renderedKN)} vs witness ${j(witnessKN)}`);
    nodeId = await attr(`${SITEMAP} [data-node]`, 'data-node');
    await d.click({ sel: `${SITEMAP} [data-node="${nodeId}"]` });
    const sel = await soft(async () => (await attr(`${SITEMAP} [data-node][aria-selected="true"]`, 'data-node')) ?? null, 3000);
    expect(sel === nodeId, '06c selecting a node marks it aria-selected', `selected ${j(sel)}, clicked ${j(nodeId)}`);
  });

  // 7 ----------------------------------------------------------------------------------------
  await step('07 the scan surface survives leaving the panel', async () => {
    const row = await d.q('find', { sel: `${GRID} [role=row][data-id]` });
    if (!row) {
      gap('07 leave and return', 'the flow grid has no row to click');
      return;
    }
    await d.mouse(row.x, row.y);
    const unmounted = await soft(async () => ((await countOf(SCANNER)) === 0 ? true : null), 3000);
    note('07 panel left for the inspector', unmounted ? 'the Scan panel unmounted' : 'the Scan panel stayed mounted');
    await sleep(2000); // the store keeps polling while the panel is gone (W-6)
    await goScan();
    await waitFor(() => d.q('exists', SCANNER), { timeoutMs: 10000, what: 'the Scan panel to come back' });
    const tab = await attr(`${SCANNER} [role=tab][aria-selected="true"]`, 'data-tab');
    expect(tab === 'sitemap', '07a the Site map tab is still the selected tab', `selected tab ${j(tab)}`);
    const strip = await attr(STRIP, 'data-job');
    expect(strip === jobId, '07b the selected job is unchanged', `strip data-job ${j(strip)}, expected ${j(jobId)}`);
    if (nodeId) {
      const sel = await attr(`${SITEMAP} [data-node][aria-selected="true"]`, 'data-node');
      expect(sel === nodeId, '07c the same site-map node is still selected', `selected ${j(sel)}, expected ${j(nodeId)}`);
    }
  });

  // 8a ---------------------------------------------------------------------------------------
  await step('08a an L4 profile is blocked without an L4 scope entry', async () => {
    await clickTab('Profiles');
    const row = await soft(() => d.q('exists', `${PROFILES} [data-profile="l4-stream-safe"]`), 5000);
    if (!row) {
      gap('08a l4-stream-safe', 'this core does not offer the l4-stream-safe profile');
      return;
    }
    await d.click({ sel: `${PROFILES} [data-profile="l4-stream-safe"]` });
    const start = await soft(() => d.q('find', { role: 'button', text: 'Start', match: 'exact', within: SCANNER }), 5000);
    const reason = await d.q('text', `${SCANNER} [data-reason]`);
    expect(start?.disabled === true, '08a Start is disabled for an L4 profile with no L4 scope', `Start disabled=${j(start?.disabled ?? null)}`);
    expect((reason ?? '').includes('interface: "*"'), '08a the refusal reason carries the D11 hint', `reason ${j(reason)}`);
  });

  // 8b ---------------------------------------------------------------------------------------
  await step('08b with an L4 scope entry the confirm dialog shows the core prompt verbatim', async () => {
    bus.close();
    await env.stop();
    env = await startAitm({
      scope: [target.host],
      findingsDir: FINDINGS_DIR,
      l4: {
        enabled: true,
        scope: [{ addr: '127.0.0.1', prefix: 32, portLo: 0, portHi: 65535, interface: '*', direction: 'outbound', capability: 'inject' }],
      },
      log: (l) => (/error|panic/i.test(l) ? out('[aitm] ' + l) : null),
    });
    bus = await witness(env.busUrl, env.operatorToken ?? env.token, 'witness-l4');
    await d.open(env.operatorUiUrl ?? env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 20000, what: 'status bar "bus open" after the restart' });
    await goScan();
    await clickTab('Profiles');
    await d.click({ sel: `${PROFILES} [data-profile="l4-stream-safe"]` });

    const ipSel = await l4Field(L4_LABELS.ip, 'input');
    const portSel = await l4Field(L4_LABELS.port, 'input');
    const protoSel = await l4Field(L4_LABELS.proto, 'select');
    const addBtn = await d.q('find', { role: 'button', text: 'Add L4 target', match: 'startsWith' });
    if (!ipSel || !portSel || !addBtn) {
      gap('08b add an L4 target', `the L4 target fields are not reachable by the labels the plan pins (it names only the button "Add L4 target"); ip=${j(ipSel)} port=${j(portSel)} button=${!!addBtn}`);
      return;
    }
    await typeInto(ipSel, '127.0.0.1');
    await typeInto(portSel, String(target.port));
    if (protoSel) await pickSelect(protoSel, 'tcp').catch((e) => note('08b proto select', e.message.split('\n')[0]));
    await d.mouse(addBtn.x, addBtn.y);

    const start = await soft(() => d.q('find', { role: 'button', text: 'Start', match: 'exact', within: SCANNER }), 5000);
    if (!start || start.disabled) {
      gap('08b Start with an L4 scope entry', `Start is still disabled; reason ${j(await d.q('text', `${SCANNER} [data-reason]`))}, note ${j(await d.q('text', `${SCANNER} [data-note]`))}`);
      return;
    }
    const before = (await bus.call('scan.list', {})).jobs?.length ?? 0;
    await d.mouse(start.x, start.y);
    const dialog = await soft(() => d.q('find', { sel: '[role=alertdialog]' }), 8000);
    if (!dialog) {
      fail('08b the confirm dialog opens', `no [role=alertdialog] within 8 s; launch result ${j(await d.q('text', `${SCANNER} [role=status][aria-label="Launch result"]`))}`);
      return;
    }
    // The witness makes the same call AFTER the UI's and the two prompts are compared verbatim.
    let witnessPrompt = null;
    try {
      const profile = await bus.call('scan.profile.get', { name: 'l4-stream-safe' });
      const mirrored = {
        ...profile,
        target: { ...(profile.target ?? {}), origins: profile.target?.origins ?? [], l4: [{ ip: '127.0.0.1', port: target.port, proto: 'tcp', grammar: null }] },
      };
      const r = await bus.call('scan.start', { profile: mirrored });
      witnessPrompt = r?.prompt ?? null;
      note('08b witness scan.start', `status ${j(r?.status ?? null)}`);
    } catch (e) {
      note('08b witness scan.start', e.message.split('\n')[0]);
    }
    if (witnessPrompt) {
      expect(dialog.text.includes(witnessPrompt), '08b the dialog shows the core prompt verbatim', `dialog ${j(dialog.text)} does not contain witness prompt ${j(witnessPrompt)}`);
    } else {
      gap('08b prompt comparison', `the witness got no needs_confirmation prompt for l4-stream-safe; the dialog read ${j(dialog.text)}`);
    }
    await d.click({ role: 'button', text: 'Start scan', match: 'startsWith' });
    const grew = await soft(async () => {
      const l = await bus.call('scan.list', {});
      return (l.jobs?.length ?? 0) > before ? l : null;
    }, 8000);
    const resultText = await d.q('text', `${SCANNER} [role=status][aria-label="Launch result"]`);
    if (grew) pass('08b the confirmed L4 scan starts', `scan.list grew from ${before} to ${grew.jobs.length}`);
    else if ((resultText ?? '').includes('No requested lane is available on this build')) gap('08b lane_unavailable', `the dialog showed and the UI rendered: ${j(resultText)} (no L4 lane on this core)`);
    else fail('08b the confirmed L4 scan starts', `scan.list stayed at ${before}; launch result ${j(resultText)}`);
  });
}

// ------------------------------------------------------------------------------------------
// Harness
// ------------------------------------------------------------------------------------------
const RUN_DIR = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'aitm-scan-live-'));
const FINDINGS_DIR = join(RUN_DIR, 'findings');
mkdirSync(FINDINGS_DIR, { recursive: true });

try {
  target = await startTestTarget({ mode: 'vulnerable' });
  env = await startAitm({
    scope: [target.host],
    findingsDir: FINDINGS_DIR,
    log: (l) => (/error|panic/i.test(l) ? out('[aitm] ' + l) : null),
  });
  bus = await witness(env.busUrl, env.operatorToken ?? env.token, 'witness');
  out(`aitm up: proxy ${env.proxyPort}, ui ${env.operatorUiUrl ?? env.uiUrl}, target ${target.base} (${target.mode}), findings ${FINDINGS_DIR}`);
  cdp = await launchChrome({ width: W, height: H });
  d = makeDriver(cdp, { log, shotsDir: SHOTS });
  await run();
  if (cdp.consoleErrors.length) note('console errors', JSON.stringify(cdp.consoleErrors.slice(0, 10)));
} catch (e) {
  fail('harness', e.stack ?? e.message);
} finally {
  const summary = {
    pass: results.filter((r) => r.status === 'PASS').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    gap: results.filter((r) => r.status === 'GAP').length,
    shots: SHOTS,
    results,
  };
  out(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.gap} GAP · screenshots in ${SHOTS} · transcript ${TRANSCRIPT}`);
  if (KEEP && env) {
    out(`--keep: aitm and Chrome left running. UI: ${env.operatorUiUrl ?? env.uiUrl}  proxy: 127.0.0.1:${env.proxyPort}  target: ${target?.base}`);
    console.log(JSON.stringify(summary));
    await new Promise(() => {});
  }
  try {
    bus?.close();
  } catch {}
  cdp?.close();
  await env?.stop();
  await target?.stop();
  // The LAST stdout line is the result JSON, always.
  console.log(JSON.stringify(summary));
  process.exit(summary.fail ? 1 : 0);
}
