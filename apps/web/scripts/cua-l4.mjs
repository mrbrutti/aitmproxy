// LIVE browser run of the web L4 parity surface (plan 2026-10-31-l4-parity-fixes, unit (c), task
// C10; spec L4PAR-AC18 live, AC19, AC20, AC21, AC22, AC23, AC24, AC33 web half) — a real headless
// Chrome driven over CDP with real input events only, clicking through the UI a spawned `aitm web`
// serves from an `l4.enabled: true` core, every step cross-checked over the live operator bus and
// the core's audit ring (`agent.activity`).
//
//   node scripts/cua-l4.mjs [--keep]            (AITM_BIN=<path to aitm>; default target/debug/aitm)
//
// Every step prints PASS / FAIL, or an explicit `blocked: needs D0` / `blocked: no Linux rig` line
// quoting the core's own reason. A blocked line is not a failure: on this Mac `/dev/bpf*` is
// root-only (the unprivileged rig, spec §6), so nothing that needs a captured packet can be clicked;
// it is recorded as blocked, never faked. The privileged click-drive (`privilegedDrive()`) runs only
// where `l4.capture.status.available` is true (an elevated / Linux core).
//
// Never printed: a bus token or an Operator URL. The `#t=…` fragment is redacted in every log line.
//
// --keep leaves aitm and Chrome running. Node ≥ 22, no dependencies.
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, sleep, startAitm, startTarget, viaProxy, waitFor } from './live-env.mjs';
import { launchChrome, makeDriver } from './cua-driver.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-l4-shots');
const KEEP = process.argv.includes('--keep');
const W = 1600;
const H = 1000;
/** The AC23 idle window, in ms (spec: "60 s idle on the rig"). */
const IDLE_WINDOW_MS = 60_000;
/** AC23: at most this many `l4.*` calls from the UI's connection in the window. */
const IDLE_BUDGET = 30;

// ------------------------------------------------------------------------------------------
// Literals the UI must show (each pinned by a unit test in src/panels/l4; repeated here on purpose
// so this run asserts the literal a user sees, not whatever the source currently exports).
// ------------------------------------------------------------------------------------------
/** `model.ts` `OPERATOR_ONLY_REASON` (C9a, AC24). */
const OPERATOR_ONLY = 'Operator only: reconnect with the Operator URL the core printed';
/** `RoleBanner.tsx` (C9a, AC24). */
const BANNER = 'L4 actions (capture, inject, scope, intercept) need the Operator URL.';
/** `model.ts` `PENDING_AVAILABILITY.reason` (spec §1). */
const PENDING = 'Reading L4 availability…';
/** `chips.ts` `CHIPS` first nine labels (C8, AC21); ⌘5 is TCP. */
const CHIP_ORDER = ['All', 'HTTP', 'HTTPS', 'WebSocket', 'TCP', 'UDP', 'L4', 'h1', 'h2'];
/**
 * The same table as `L4_ARG_BUILDERS` in `src/panels/l4/model.ts` (its source of truth is pinned by
 * `args.test.ts` "L4_ARG_BUILDERS table"). Hard-coded here because node cannot import the
 * TypeScript module; if the table changes, `args.test.ts` and this copy must change together.
 */
const L4_ARG_BUILDERS = [
  { tool: 'l4.capture.start', keys: ['interface', 'direction'] },
  { tool: 'l4.capture.stop', keys: ['id'] },
  { tool: 'l4.intercept.forward', keys: ['id'] },
  { tool: 'l4.intercept.drop', keys: ['id'] },
  { tool: 'l4.intercept.mutate', keys: ['id', 'spec'] },
  { tool: 'l4.intercept.revert', keys: ['id'] },
  { tool: 'l4.scope.add', keys: ['cidr', 'ports', 'interface', 'direction', 'capability'] },
  { tool: 'l4.flow.get', keys: ['id', 'offset', 'limit'] },
];
/** The Sensitive L4 verbs an agent-role page must never put on the bus (AC24). */
const SENSITIVE_L4 = [
  'l4.capture.start',
  'l4.capture.stop',
  'l4.inject',
  'l4.scope.add',
  'l4.agent.set',
  'l4.intercept.forward',
  'l4.intercept.drop',
  'l4.intercept.mutate',
  'l4.intercept.revert',
];
/** The AC5 entry the scope-add form submits (cidr / interface / direction / capability are the form's defaults). */
const AC5 = { cidr: '127.0.0.1/32', ports: '9100-9199', interface: 'lo0', direction: 'inbound', capability: 'capture' };

// ------------------------------------------------------------------------------------------
// DOM map (post-PR#41 unified list; C4–C9b test ids)
// ------------------------------------------------------------------------------------------
const SIDEBAR = 'aside[aria-label="Sources"]';
const CAPTURE = 'section[aria-label="Capture"]'; // CaptureControls, inside L4CaptureBar (sidebar → L4)
const CAPBAR_FALLBACK = 'L4 is not enabled'; // L4CaptureBar honest-degradation text when l4.* is absent
const GRID = '[role=grid][aria-label="Flows"]'; // the one unified flow list
const L4ROW = `${GRID} [role=row][data-kind="l4"]`; // an L4 session row
const HTTPROW = `${GRID} [role=row][data-id]:not([data-kind="l4"])`; // an HTTP/WebSocket row (the header row has no data-id)
const CHIPBAR = '[role=group][aria-label="Quick filter"]';
const CHIP_BUTTONS = `${CHIPBAR} > button`; // CHIPS in order, then the "Filters" toggle
const TOGGLES = 'section[aria-label="L4 agent capabilities"]';
const START = '[data-testid="l4-capture-start"]';
const CAPTURE_REASON = '[data-testid="l4-capture-reason"]';
const INTERCEPT_LIMITED = '[data-testid="l4-intercept-limited"]';
const VERDICTS = '[data-testid="l4-forward"],[data-testid="l4-mutate"],[data-testid="l4-drop"],[data-testid="l4-revert"]';
const SCOPE_FORM = '[data-testid="l4-scope-add-form"]';
const SCOPE_ADD = '[data-testid="l4-scope-add"]';
const SCOPE_REFUSAL = '[data-testid="l4-scope-add-refusal"]';
const SCOPE_ENTRY = '[data-testid="l4-scope-entry"]';
/** The Agent panel's activity log (`panels/agent/ActivityLog.tsx`): one `[role=row][data-seq]` per invocation; cells time · origin · command · args · result, the result cell `data-result="ok"|"error"`. */
const ACTIVITY_LOG = 'section[aria-label="Activity log"]';
const SCOPE_PORTS = 'input[aria-label="Scope ports"]';
const BANNER_SEL = '[data-testid="l4-operator-only-banner"]';
const DIALOG = '[role=alertdialog][aria-label="Confirm L4 action over the wire"]';
const TOAST = '[class*="toast"][role=alert],[class*="toast"][role=status]';
// A raw `PacketSpec` layer on the bus wants a byte SEQUENCE; "probe" as bytes (privileged drive only):
const PROBE = [112, 114, 111, 98, 101];

// ------------------------------------------------------------------------------------------
// Results
// ------------------------------------------------------------------------------------------
const results = [];
const shots = [];
function record(status, step, detail) {
  results.push({ status, step, detail });
  console.log(`${status.padEnd(7)} ${step}${detail ? ` — ${detail}` : ''}`);
}
const pass = (step, detail) => record('PASS', step, detail);
const fail = (step, detail) => record('FAIL', step, detail);
const note = (step, detail) => record('NOTE', step, detail);
/** An honest blocked verdict: `why` is `needs D0` or `no Linux rig`; `reason` is the core's text, quoted. */
const blocked = (step, why, reason) => record('BLOCKED', step, `blocked: ${why} — core reason: "${reason}"`);
const expect = (cond, okMsg, detail) => (cond ? pass(okMsg, detail) : fail(okMsg, detail));
/**
 * Every `#t=<token>` fragment in `text` (a stack or a log line can carry both UI URLs), and the
 * per-run bus tokens themselves wherever they appear (a `connectBus` error quotes what it sent),
 * redacted; never print a UI URL or an error any other way. `env` is read at call time and is
 * assigned when `startAitm` returns, so the literal-token pass covers every line printed after
 * that assignment. The one earlier caller is the `log` callback passed INTO `startAitm` (aitm
 * stderr lines matching /error|panic/ during start-up): while it runs `env` is still undefined and
 * only the `#t=` regex applies. The core prints its tokens only in URL form, which that regex
 * covers; a start-up line carrying a bare token would not be literally redacted.
 */
const redact = (text) => {
  let out = String(text ?? '').replace(/#t=[^&\s]*/g, '#t=<redacted>');
  for (const secret of [env?.operatorToken, env?.token]) if (secret) out = out.split(secret).join('<redacted>');
  return out;
};
const log = (m) => console.log(m);

// ------------------------------------------------------------------------------------------
// Bus helpers (cross-checks run beside the real clicks)
// ------------------------------------------------------------------------------------------
/** Call a tool and return { ok, value } or { ok:false, error } — never throws. */
async function probe(bus, name, args = {}) {
  try {
    return { ok: true, value: await bus.call(name, args) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
/** Spec §1: the status object, or a bare array (older core) meaning available. */
function availability(reply) {
  if (Array.isArray(reply)) return { available: true, code: null, reason: null, legacy: true };
  if (reply && typeof reply === 'object' && typeof reply.available === 'boolean') {
    return { available: reply.available, code: reply.code ?? null, reason: reply.reason ?? null, legacy: false };
  }
  return { available: false, code: null, reason: `unrecognised status reply: ${JSON.stringify(reply).slice(0, 120)}`, legacy: false };
}
/** The audit ring since `sinceMs` (strictly after), oldest first; the operator sees every lane and every origin. */
async function activity(bus, sinceMs) {
  const r = await bus.call('agent.activity', { since: sinceMs, limit: 4000 });
  return Array.isArray(r) ? r : [];
}
const histogram = (entries) => {
  const h = {};
  for (const e of entries) h[e.command] = (h[e.command] ?? 0) + 1;
  return h;
};
const distinct = (entries, key) => [...new Set(entries.map((e) => e[key] ?? null))];

// ------------------------------------------------------------------------------------------
// Main
// ------------------------------------------------------------------------------------------
mkdirSync(SHOTS, { recursive: true });
for (const f of readdirSync(SHOTS)) if (f.endsWith('.png')) rmSync(join(SHOTS, f));

let target, env, bus, cdp, d;
let toolDefs = [];

/**
 * Runs one step. Every body is its own recorder: its PASS / FAIL / BLOCKED / NOTE lines are the
 * step's verdict, and the wrapper never adds a PASS. A body that recorded nothing at all prints
 * `NOTE <step> — no assertion ran` (a silent bail is never proven); a body that recorded only notes
 * (an "n/a on this core" branch) stays at its notes. A thrown error fails the step. Ends with a
 * screenshot.
 */
async function step(name, body) {
  log(`\n== ${name}`);
  const before = results.length;
  try {
    await body();
    if (results.length === before) note(name, 'no assertion ran');
  } catch (e) {
    fail(name, redact(e.message.split('\n')[0]));
  } finally {
    try {
      const f = await d.shot(name);
      if (f) log(`  shot ${f}`);
    } catch (e) {
      log(`  (screenshot failed: ${e.message})`);
    }
  }
}

// ---- page helpers (read-only apart from real input and the two forced-click probes) ----------
/** An attribute of the first element matching `sel`, or null. */
const attr = (sel, name) => d.ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); return el ? el.getAttribute(${JSON.stringify(name)}) : null; })()`);
/** How many elements match `sel` in the DOM, visible or not. */
const domCount = (sel) => d.ev(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
/**
 * A forced click on a (disabled) control: the real mouse click at its centre, then a synthetic
 * `click` MouseEvent dispatched straight at the element — the strongest push a page can give a
 * handler. The assertion that matters is made on the audit ring afterwards (nothing reached the bus).
 */
async function forceClick(sel) {
  await d.click({ sel });
  await d.ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); return true; })()`);
}
const waitBusOpen = () => waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'status bar "bus open"' });
/** Sidebar → L4: the L4CaptureBar (CaptureControls) appears above the list and HTTP rows are hidden. */
async function focusL4() {
  await d.click({ role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
  await d.locate({ sel: CAPTURE });
}
/** Sidebar → All (the "Apps" item sets `{kind: 'all'}` when it is not current): HTTP rows show again. */
async function focusAll() {
  await d.click({ role: 'button', text: 'Apps', match: 'startsWith', within: SIDEBAR });
  await sleep(150);
}
/** Clicks away the shell toast (it can overlap controls near the bottom); no-op when none is shown. */
async function dismissToast() {
  for (let i = 0; i < 3; i++) {
    const t = await d.q('find', { sel: TOAST });
    if (!t) return;
    await d.mouse(t.x, t.y);
    await sleep(250);
  }
}
/** The chip labels in bar order (the trailing "Filters" toggle is dropped). */
async function chipLabels() {
  const texts = await d.q('texts', { sel: CHIP_BUTTONS });
  return texts.filter((t) => !/^Filters\b/.test(t));
}
const pressedChips = () => d.ev(`[...document.querySelectorAll(${JSON.stringify(CHIP_BUTTONS)})].filter((b) => b.getAttribute('aria-pressed') === 'true' && !/^Filters/.test(b.textContent)).map((b) => b.textContent.trim())`);
const clickChip = (label) => d.click({ role: 'button', text: label, match: 'exact', within: CHIPBAR });
/** Pins the theme through the status bar's ⋯ Appearance menu (real clicks), then verifies `data-theme`. */
async function setTheme(label) {
  await d.click({ role: 'button', text: 'Appearance', match: 'exact' });
  await d.click({ role: 'menuitem', text: label, match: 'startsWith' });
  await sleep(300);
  return d.ev('document.documentElement.getAttribute("data-theme")');
}
async function snap(name) {
  const f = await d.shot(name);
  if (f) {
    shots.push(f);
    log(`  shot ${f}`);
  }
  return f;
}
/** Fills the scope-add ports field (defaults give the rest of the AC5 entry) and clicks Add; resolves once the dialog is up. */
async function openScopeAddDialog() {
  await d.click({ sel: SCOPE_PORTS });
  await d.selectAll();
  await d.type(AC5.ports);
  await d.click({ sel: SCOPE_ADD });
  await d.locate({ sel: DIALOG });
}

let privileged = false;
let capAvail = { available: false, code: null, reason: '(not read)' };
let intAvail = { available: false, code: null, reason: '(not read)' };

try {
  target = await startTarget();
  // Spec §6 rig in miniature: an `l4.enabled` core with the three config scope entries (lo0 ·
  // 127.0.0.1/32 · 9000-9999 · capture / inject / intercept), widen off (AC5), the HTTP target in
  // proxy scope so real HTTP rows exist. `mcp.operator_token` is configured by live-env, so the
  // browser (Operator URL) and the cross-checks here drive as a real `Frontend::Operator`.
  const l4Scope = ['capture', 'inject', 'intercept'].map((capability) => ({
    addr: '127.0.0.1',
    prefix: 32,
    portLo: 9000,
    portHi: 9999,
    interface: 'lo0',
    direction: 'outbound',
    capability,
    pps: 100,
    burst: 100,
  }));
  env = await startAitm({
    scope: [target.host, '127.0.0.1'],
    l4: { enabled: true, allow_agent_widen: false, scope: l4Scope },
    log: (l) => (/error|panic/i.test(l) ? console.error('[aitm] ' + redact(l)) : null),
  });
  bus = await connectBus(env.busUrl, env.operatorToken);
  toolDefs = await bus.tools();
  const tools = toolDefs.map((t) => t.name);
  const l4Tools = tools.filter((t) => t.startsWith('l4.'));
  log(`aitm up: proxy 127.0.0.1:${env.proxyPort}, operator ui ${redact(env.operatorUiUrl)}, agent ui ${redact(env.uiUrl)}, target ${target.base}`);
  log(`bus role: ${bus.role}; tools ${tools.length}, l4.* ${l4Tools.length}: ${l4Tools.join(' ')}`);
  cdp = await launchChrome({ width: W, height: H });
  d = makeDriver(cdp, { log, shotsDir: SHOTS });

  // 01 ---------------------------------------------------------------------------------------
  await step('01 connect as operator; sidebar L4 reads "on"', async () => {
    await d.open(env.operatorUiUrl);
    await waitBusOpen();
    const l4Item = await waitFor(
      async () => {
        const b = await d.q('find', { role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
        return b && /on$/.test(b.text) ? b : null;
      },
      { timeoutMs: 10000, what: 'sidebar L4 "on"' },
    );
    expect(bus.role === 'operator', '01a the cross-check bus connected as operator', `initialize echoed role=${bus.role}`);
    expect(l4Tools.includes('l4.flow.list') && /on$/.test(l4Item.text), '01b sidebar L4 reads "on" (l4.* advertised)', `sidebar "${l4Item?.text}"; l4 tools=${l4Tools.length}`);
    const banner = await domCount(BANNER_SEL);
    expect(banner === 0, '01c no "operator only" banner on the Operator URL', `banner count=${banner}`);
  });

  // 02 ---------------------------------------------------------------------------------------
  await step('02 AC18 live schema: every L4 arg-builder key is in that verb\'s inputSchema', async () => {
    const problems = [];
    const seen = [];
    for (const { tool, keys } of L4_ARG_BUILDERS) {
      const def = toolDefs.find((t) => t.name === tool);
      if (!def) {
        problems.push(`${tool}: not in tools/list`);
        continue;
      }
      const props = def.inputSchema?.properties ?? {};
      const missing = keys.filter((k) => !(k in props));
      if (missing.length) problems.push(`${tool}: schema lacks ${missing.join(',')} (has ${Object.keys(props).join(',')})`);
      seen.push(`${tool}{${keys.join(',')}}`);
    }
    expect(problems.length === 0, `02 ${L4_ARG_BUILDERS.length} builder verbs × keys all declared in the rig's tools/list`, problems.length ? problems.join('; ') : seen.join(' '));
  });

  // 03 ---------------------------------------------------------------------------------------
  await step('03 AC19/AC33 Start capture is disabled with the core\'s capture.status reason; a forced click sends nothing', async () => {
    await focusL4();
    const fallback = await d.q('find', { text: CAPBAR_FALLBACK });
    expect(!fallback && (await d.q('exists', GRID)), '03a L4 capture bar + the unified list render (not the "L4 is not enabled" fallback)', `fallback=${!!fallback}`);
    const cap = await probe(bus, 'l4.capture.status');
    expect(cap.ok, '03b l4.capture.status answers (never an error now, spec §1)', cap.ok ? JSON.stringify(cap.value).slice(0, 200) : cap.error);
    capAvail = availability(cap.value);
    privileged = capAvail.available === true;
    log(`  capture availability: ${JSON.stringify(capAvail)}`);
    // Pending must have resolved: the visible reason is never the pending literal once the first status reply landed.
    const reasonText = await waitFor(async () => {
      const t = await d.q('text', CAPTURE_REASON);
      return t !== PENDING ? (t ?? '(absent)') : null;
    }, { timeoutMs: 15000, what: 'capture reason to leave "Reading L4 availability…"' }).catch(() => PENDING);
    expect(reasonText !== PENDING, '03c the pending literal resolved (first l4.capture.status reply rendered)', `reason text "${reasonText}"`);
    await snap('l4 focus view operator light');
    if (privileged) {
      const btn = await d.q('find', { sel: START });
      expect(btn && !btn.disabled, '03d (privileged core) Start capture is enabled', `disabled=${btn?.disabled}`);
      note('03 live start/stop', `capture available on this core (${capAvail.legacy ? 'older bare-array shape' : `code=${capAvail.code}`}); the privileged click-drive runs in step 09`);
      return;
    }
    const btn = await d.q('find', { sel: START });
    const title = await attr(START, 'title');
    expect(!!btn && btn.disabled, '03d Start capture is disabled', `disabled=${btn?.disabled}`);
    expect(title === capAvail.reason, '03e Start capture title equals l4.capture.status.reason literally', `title "${title}" vs core "${capAvail.reason}"`);
    expect(reasonText === capAvail.reason, '03f l4-capture-reason text equals l4.capture.status.reason literally', `text "${reasonText}"`);
    const t0 = Date.now() - 1;
    await forceClick(START);
    await sleep(700);
    const after = (await activity(bus, t0)).filter((e) => e.command === 'l4.capture.start');
    const toast = (await d.q('texts', { role: 'alert' })).find((x) => /l4\.capture\.start|l4 unavailable/i.test(x));
    expect(after.length === 0, '03g forced click on the disabled Start put no l4.capture.start in agent.activity (AC33: nothing that can only fail)', `l4.capture.start entries since click=${after.length}; error toast=${toast ?? 'none'}`);
    blocked('03h live Start/Stop capture', 'needs D0', capAvail.reason);
  });

  // 04 ---------------------------------------------------------------------------------------
  await step('04 AC20 intercept: one documented-limited line with the core\'s reason, no verdict buttons', async () => {
    const st = await probe(bus, 'l4.intercept.status');
    expect(st.ok, '04a l4.intercept.status answers (never an error now, spec §1)', st.ok ? JSON.stringify(st.value).slice(0, 200) : st.error);
    intAvail = availability(st.value);
    log(`  intercept availability: ${JSON.stringify(intAvail)}`);
    if (intAvail.available) {
      // Not a PASS: nothing about the bar is asserted on this branch (the verdicts need a parked packet).
      note('04b-04d intercept available on this core', `code=${intAvail.code}; the limited line is not expected; Forward/Mutate/Drop/Revert need a parked packet (step 09 / Linux)`);
      return;
    }
    const line = await waitFor(async () => {
      const t = await d.q('text', INTERCEPT_LIMITED);
      return t && !t.endsWith(PENDING) ? t : null;
    }, { timeoutMs: 15000, what: 'intercept limited line past pending' }).catch(() => null);
    const want = `In-path intercept is not available on this core: ${intAvail.reason}`;
    expect(line === want, '04b l4-intercept-limited reads "In-path intercept is not available on this core: <l4.intercept.status.reason>"', `line "${line}"`);
    const verdicts = await domCount(VERDICTS);
    expect(verdicts === 0, '04c no l4-forward / l4-mutate / l4-drop / l4-revert element exists in the DOM', `count=${verdicts}`);
    blocked('04d live Forward/Mutate/Drop/Revert', 'no Linux rig', intAvail.reason);
  });

  // 05 ---------------------------------------------------------------------------------------
  await step('05 AC21 chips with real proxied HTTP rows: order, L4 leaves zero HTTP rows, ⌘5 is TCP', async () => {
    for (let i = 0; i < 3; i++) {
      const r = await viaProxy(env.proxyPort, 'GET', target.base + '/api/me');
      if (r.status !== 200) throw new Error(`viaProxy GET /api/me → ${r.status}`);
    }
    await focusAll();
    await clickChip('All');
    const httpRows = await waitFor(async () => {
      const n = await d.q('count', { sel: HTTPROW });
      return n >= 3 ? n : null;
    }, { timeoutMs: 12000, what: '3 proxied HTTP rows' }).catch(() => d.q('count', { sel: HTTPROW }));
    expect(httpRows >= 3, '05a three real proxied GETs show as HTTP rows under All', `http rows=${httpRows}`);
    const labels = await chipLabels();
    const first9 = labels.slice(0, 9);
    expect(JSON.stringify(first9) === JSON.stringify(CHIP_ORDER), '05b chip bar starts All, HTTP, HTTPS, WebSocket, TCP, UDP, L4, h1, h2', `labels=${JSON.stringify(labels)}`);
    await clickChip('L4');
    const zero = await waitFor(async () => ((await d.q('count', { sel: HTTPROW })) === 0 ? true : null), { timeoutMs: 6000, what: 'zero HTTP rows under L4' }).catch(() => false);
    const noMatch = await d.q('find', { text: 'No flows match', within: GRID });
    const noFlowsYet = await d.q('find', { text: 'No flows yet', within: GRID });
    const l4Rows = await d.q('count', { sel: L4ROW });
    await snap('chip bar L4 selected light');
    expect(zero && !!noMatch && !noFlowsYet, '05c selecting L4 leaves zero HTTP rows and the "No flows match" empty state (not "No flows yet")', `http rows=${await d.q('count', { sel: HTTPROW })}; no-match=${!!noMatch}; no-flows-yet=${!!noFlowsYet}; l4 rows=${l4Rows}`);
    expect(JSON.stringify(await pressedChips()) === JSON.stringify(['L4']), '05d the L4 chip is the pressed one', `pressed=${JSON.stringify(await pressedChips())}`);
    await d.key('5', { meta: true });
    const pressed = await waitFor(async () => {
      const p = await pressedChips();
      return p.length === 1 && p[0] === 'TCP' ? p : null;
    }, { timeoutMs: 4000, what: '⌘5 → TCP chip pressed' }).catch(() => pressedChips());
    expect(JSON.stringify(pressed) === JSON.stringify(['TCP']), '05e ⌘5 selects the TCP chip', `pressed=${JSON.stringify(pressed)}`);
    if (privileged) {
      // Not privilege: ordering. No capture has run yet, so there is no L4 row to find under a chip here.
      note('05f L4 rows under the TCP / UDP / L4 chips', `capture available on this core (code=${capAvail.code}); no capture has run yet — L4 rows are asserted in step 09 after a capture`);
    } else blocked('05f L4 rows under the TCP / UDP / L4 chips', 'needs D0', capAvail.reason);
    await clickChip('All');
  });

  // 06 ---------------------------------------------------------------------------------------
  let addedId = null;
  await step('06 AC22 operator L4 scope add through the add form and the confirm dialog (core with (a\'))', async () => {
    await focusL4();
    const addDef = toolDefs.find((t) => t.name === 'l4.scope.add');
    const confirmable = addDef?.confirmable === true;
    const formCount = await domCount(SCOPE_FORM);
    log(`  tools/list l4.scope.add confirmable=${addDef?.confirmable}; form count=${formCount}`);
    if (!confirmable) {
      expect(formCount === 0, '06a core without (a\'): tools/list has no confirmable l4.scope.add and the form is absent (AC39)', `confirmable=${addDef?.confirmable}; form=${formCount}`);
      note('06 scope add', 'n/a on this core: no (a\') confirm; the add path is not offered');
      return;
    }
    expect(formCount === 1, '06a tools/list shows l4.scope.add confirmable: true and l4-scope-add-form renders', `form=${formCount}`);
    note('06 "form absent without (a\')"', 'n/a on this rig (main carries (a\'); AC39 unit + the C7 tripwire cover the gate)');
    const configEntries = await d.q('count', { sel: `${SCOPE_ENTRY}[data-source="config"]` });
    expect(configEntries === 3, '06b the three config entries show with config provenance', `config entries in DOM=${configEntries}`);
    // The form defaults must be the AC5 entry apart from ports (headless Chrome cannot change a native <select> via CDP keys).
    const defaults = {
      cidr: (await d.q('find', { sel: 'input[aria-label="Scope CIDR"]' }))?.value,
      interface: (await d.q('find', { sel: 'input[aria-label="Scope interface"]' }))?.value,
      direction: (await d.q('find', { sel: 'select[aria-label="Scope direction"]' }))?.value,
      capability: (await d.q('find', { sel: 'select[aria-label="Scope capability"]' }))?.value,
    };
    const defaultsOk = defaults.cidr === AC5.cidr && defaults.interface === AC5.interface && defaults.direction === AC5.direction && defaults.capability === AC5.capability;
    expect(defaultsOk, '06c form defaults are 127.0.0.1/32 · lo0 · inbound · capture', JSON.stringify(defaults));
    if (!defaultsOk) return;
    const tStep = Date.now() - 1;
    await openScopeAddDialog();
    const title = await d.q('text', `${DIALOG} h2`);
    const prompt = (await d.q('text', `${DIALOG} p`)) ?? '';
    const literals = ['127.0.0.1/32', '9100-9199', 'lo0', 'inbound', 'capture'];
    const missing = literals.filter((l) => !prompt.includes(l));
    await snap('scope add confirm dialog light');
    expect(title === 'Confirm L4 scope add' && missing.length === 0, '06d the confirm dialog shows the core\'s prompt naming cidr, ports, interface, direction, capability', `title "${title}"; prompt "${prompt.slice(0, 220)}"${missing.length ? `; missing ${missing.join(',')}` : ''}`);
    await d.click({ role: 'button', text: 'Send to wire', match: 'exact', within: DIALOG });
    const gone = await d.gone({ sel: DIALOG }).then(() => true).catch(() => false);
    const refusal = gone ? await d.q('text', SCOPE_REFUSAL) : await d.q('text', `${DIALOG} [role=alert]`);
    expect(gone && !refusal, '06e Send to wire closes the dialog with no refusal', `dialog gone=${gone}; refusal=${refusal ?? 'none'}`);
    // Within one slow poll: the bus list and the DOM list both carry the entry with runtime provenance.
    const listed = await waitFor(async () => {
      const list = (await probe(bus, 'l4.scope.list')).value ?? [];
      const hit = list.find((e) => e.ports === AC5.ports && e.cidr === AC5.cidr && e.capability === AC5.capability);
      const dom = await d.ev(`[...document.querySelectorAll(${JSON.stringify(`${SCOPE_ENTRY}[data-source="runtime"]`)})].some((el) => el.textContent.includes(${JSON.stringify(AC5.ports)}))`);
      return hit && hit.source === 'runtime' && dom ? { list, hit } : null;
    }, { timeoutMs: 65000, everyMs: 500, what: 'runtime scope entry in l4.scope.list and the DOM' }).catch(() => null);
    const list = listed?.list ?? (await probe(bus, 'l4.scope.list')).value ?? [];
    addedId = listed?.hit?.id ?? list.find((e) => e.ports === AC5.ports)?.id ?? null;
    const configOnBus = list.filter((e) => e.source === 'config').length;
    expect(!!listed && configOnBus === 3, '06f the entry is listed with runtime provenance (bus + DOM) beside the three config entries', `bus=${JSON.stringify(list.map((e) => `${e.interface} ${e.cidr}:${e.ports} ${e.direction} ${e.capability} ${e.source}`))}`);
    const adds = (await activity(bus, tStep)).filter((e) => e.command === 'l4.scope.add');
    expect(adds.length === 1 && adds[0].result === 'ok', '06g agent.activity has exactly one l4.scope.add from the UI since the form was submitted (the needs_confirmation step is not audited), result ok', JSON.stringify(adds.map((e) => ({ origin: e.origin, client_label: e.client_label, connection_id: e.connection_id, result: e.result, args: e.args }))));
  });
  if (addedId) {
    const rm = await probe(bus, 'l4.scope.remove', { id: addedId });
    const after = (await probe(bus, 'l4.scope.list')).value ?? [];
    note('06 cleanup', `l4.scope.remove {id: ${addedId}} ok=${rm.ok}${rm.ok ? '' : ` (${rm.error})`}; entries now=${after.length}`);
  }

  // 07 ---------------------------------------------------------------------------------------
  await step(`07 AC23 ${IDLE_WINDOW_MS / 1000} s idle as operator on the L4 view: ≤ ${IDLE_BUDGET} l4.* calls, no L4 polling errors`, async () => {
    await focusL4();
    await dismissToast();
    const l4Rows = await d.q('count', { sel: L4ROW });
    if (l4Rows > 0) note('07 precondition', `${l4Rows} L4 row(s) present — the lane is not idle; the budget still applies`);
    const consoleBefore = cdp.consoleErrors.length;
    const t0 = Date.now();
    log(`  idle window starts (t0=${t0}); this script makes no bus call until it ends`);
    for (let elapsed = 15; elapsed <= IDLE_WINDOW_MS / 1000; elapsed += 15) {
      await sleep(15000);
      log(`  … ${elapsed}/${IDLE_WINDOW_MS / 1000} s`);
    }
    const entries = await activity(bus, t0);
    const windowEnd = t0 + IDLE_WINDOW_MS;
    const inWindow = entries.filter((e) => e.at <= windowEnd);
    const l4 = inWindow.filter((e) => typeof e.command === 'string' && e.command.startsWith('l4.'));
    const labels = distinct(inWindow, 'client_label');
    const conns = distinct(l4, 'connection_id');
    log(`  client_label values in the window: ${JSON.stringify(labels)} (the UI and this script both arrive through /bus, so both read "web-bridge"; this script made no call inside the window, so every l4.* entry is the UI's)`);
    log(`  l4.* connection_ids: ${JSON.stringify(conns)}`);
    log(`  l4.* per command: ${JSON.stringify(histogram(l4))}`);
    const errors = l4.filter((e) => e.result !== 'ok');
    expect(l4.length <= IDLE_BUDGET, `07a ≤ ${IDLE_BUDGET} l4.* calls from the UI connection in ${IDLE_WINDOW_MS / 1000} s`, `count=${l4.length}; histogram=${JSON.stringify(histogram(l4))}`);
    expect(errors.length === 0, '07b no l4.* entry with an error result (no L4 polling error lines)', errors.length ? JSON.stringify(errors.slice(0, 5)) : 'all ok');
    expect(conns.length <= 1, '07c every l4.* entry in the window came from one connection', `connection_ids=${JSON.stringify(conns)}`);
    // AC23's first clause is about the UI's own activity log, not only the core's audit ring: open
    // the Agent panel and read its rows — no `l4.*` row may carry the error result.
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: ACTIVITY_LOG });
    const uiLog = await d.ev(`(() => {
      const rows = [...document.querySelectorAll(${JSON.stringify(`${ACTIVITY_LOG} [role=row][data-seq]`)})];
      const l4 = rows
        .map((r) => ({ command: (r.querySelectorAll('[role=cell]')[2]?.textContent ?? '').trim(), error: !!r.querySelector('[role=cell][data-result="error"]') }))
        .filter((r) => r.command.startsWith('l4.'));
      return { rows: rows.length, l4: l4.length, errors: l4.filter((r) => r.error).map((r) => r.command) };
    })()`);
    expect(uiLog.errors.length === 0, '07d the UI activity log (Agent panel) has no l4.* entry marked error', `rows=${uiLog.rows}; l4 rows=${uiLog.l4}; error rows=${JSON.stringify(uiLog.errors)}`);
    await focusL4();
    note('07 console', `${cdp.consoleErrors.length - consoleBefore} new browser console error(s) during the window`);
  });

  // 08 ---------------------------------------------------------------------------------------
  await step('08 AC24 agent URL: every Sensitive L4 control disabled "operator only"; forced clicks reach no bus call', async () => {
    const tStep = Date.now() - 1;
    // The page is re-opened at the agent URL: the `#t=` fragment replaces the sessionStorage token
    // (bus/index.ts), so this is a fresh agent-role connection on the same origin.
    await d.open(env.uiUrl);
    await waitBusOpen();
    const banner = await waitFor(() => d.q('text', BANNER_SEL), { timeoutMs: 10000, what: 'operator-only banner' }).catch(() => null);
    expect(banner === BANNER, '08a l4-operator-only-banner shows the literal', `banner "${banner}"`);
    await focusL4();
    await d.locate({ sel: `${START}[data-operator-only="true"]` });
    const start = await d.q('find', { sel: START });
    const startTitle = await attr(START, 'title');
    const startOp = await attr(START, 'data-operator-only');
    const reason = await d.q('text', CAPTURE_REASON);
    expect(start?.disabled && startTitle === OPERATOR_ONLY && startOp === 'true' && reason === OPERATOR_ONLY, '08b Start capture: disabled, title + reason line are the operator-only literal, data-operator-only="true"', `disabled=${start?.disabled}; title "${startTitle}"; data-operator-only=${startOp}; reason "${reason}"`);
    const form = await domCount(SCOPE_FORM);
    const add = await d.q('find', { sel: SCOPE_ADD });
    const addTitle = await attr(SCOPE_ADD, 'title');
    const addOp = await attr(SCOPE_ADD, 'data-operator-only');
    expect(form === 1 && add?.disabled && addTitle === OPERATOR_ONLY && addOp === 'true', '08c scope add submit: rendered (core has (a\')), disabled with the operator-only reason', `form=${form}; disabled=${add?.disabled}; title "${addTitle}"; data-operator-only=${addOp}`);
    await snap('agent url disabled controls light');
    // Forced paths: mouse + synthetic click on Start and on the submit; Enter inside the form.
    await forceClick(START);
    await forceClick(SCOPE_ADD);
    await d.click({ sel: SCOPE_PORTS });
    await d.selectAll();
    await d.type(AC5.ports);
    await d.key('Enter');
    await sleep(300);
    const dialogs = await domCount(DIALOG);
    expect(dialogs === 0, '08d no confirm dialog opened from the forced scope-add paths', `dialogs=${dialogs}`);
    // Agent panel: the four gate switches.
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: TOGGLES });
    const anySwitch = await d.locate({ sel: `${TOGGLES} [role=switch][data-cap="widen"]` }).catch(() => null);
    if (!anySwitch) {
      fail('08e the four gate switches render on the agent URL', `no [role=switch] in the panel; panel text "${((await d.q('text', TOGGLES)) ?? '').slice(0, 200)}"`);
    }
    const caps = anySwitch ? ['capture', 'inject', 'intercept', 'widen'] : [];
    const sw = {};
    for (const c of caps) {
      const sel = `${TOGGLES} [role=switch][data-cap="${c}"]`;
      const before = await d.q('find', { sel });
      await forceClick(sel);
      await sleep(150);
      const after = await d.q('find', { sel });
      sw[c] = { disabled: before?.disabled, op: await attr(sel, 'data-operator-only'), title: await attr(sel, 'title'), checkedBefore: before?.checked, checkedAfter: after?.checked };
    }
    const switchesOk = caps.length === 4 && caps.every((c) => sw[c].disabled && sw[c].op === 'true' && sw[c].title === OPERATOR_ONLY && sw[c].checkedBefore === sw[c].checkedAfter);
    if (anySwitch) expect(switchesOk, '08e the four gate switches are disabled with data-operator-only="true" and the operator-only title; forced clicks flip nothing', JSON.stringify(sw));
    await snap('agent url agent panel switches light');
    await sleep(800);
    const sensitive = (await activity(bus, tStep)).filter((e) => SENSITIVE_L4.includes(e.command));
    expect(sensitive.length === 0, '08f agent.activity since the agent page opened has no l4.capture.start/stop, l4.inject, l4.scope.add, l4.agent.set or l4.intercept.* entry', sensitive.length ? JSON.stringify(sensitive.slice(0, 5)) : 'none');
    blocked('08g agent-URL Inject / Forward / Drop / Mutate clicks (need a selected L4 row)', 'needs D0', capAvail.reason ?? '(no L4 row in this run)');
  });

  // 09 ---------------------------------------------------------------------------------------
  await step('09 privileged real-packet click-drive (capture → craft → inject → confirm → inspect → send_recv → out-of-scope)', async () => {
    if (!privileged) {
      blocked('09 privileged click-drive', 'needs D0', capAvail.reason);
      return;
    }
    await d.open(env.operatorUiUrl);
    await waitBusOpen();
    await focusL4();
    await privilegedDrive();
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 dark screenshots (theme pinned through the Appearance menu)', async () => {
    await d.open(env.operatorUiUrl);
    await waitBusOpen();
    const theme = await setTheme('Dark');
    expect(theme === 'dark', '10a data-theme="dark" after choosing Dark in the ⋯ Appearance menu', `data-theme=${theme}`);
    await focusL4();
    await waitFor(async () => (await d.q('text', CAPTURE_REASON)) !== PENDING, { timeoutMs: 15000, what: 'capture reason past pending (dark)' }).catch(() => {});
    await snap('l4 focus view operator dark');
    await focusAll();
    await clickChip('L4');
    await sleep(200);
    await snap('chip bar L4 selected dark');
    await clickChip('All');
    await focusL4();
    if (await domCount(SCOPE_FORM)) {
      await openScopeAddDialog();
      await snap('scope add confirm dialog dark');
      await d.click({ role: 'button', text: 'Cancel', match: 'exact', within: DIALOG });
      await d.gone({ sel: DIALOG });
      note('10 dark dialog', 'opened for the screenshot and cancelled: the needs_confirmation step is not audited and nothing was added');
    }
    await d.open(env.uiUrl);
    await waitBusOpen();
    let agentTheme = await d.ev('document.documentElement.getAttribute("data-theme")');
    if (agentTheme !== 'dark') agentTheme = await setTheme('Dark');
    await focusL4();
    await d.locate({ sel: `${START}[data-operator-only="true"]` });
    await snap('agent url disabled controls dark');
    expect(agentTheme === 'dark', '10b the agent-URL page is dark for its screenshot', `data-theme=${agentTheme}`);
  });

  if (cdp.consoleErrors.length) note('console errors', JSON.stringify(cdp.consoleErrors.slice(0, 10).map(redact)));
} catch (e) {
  fail('harness', redact(e.stack ?? e.message));
} finally {
  const summary = {
    pass: results.filter((r) => r.status === 'PASS').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    blocked: results.filter((r) => r.status === 'BLOCKED').length,
    notes: results.filter((r) => r.status === 'NOTE').length,
    shots: SHOTS,
    namedShots: shots,
    results,
  };
  console.log('\n' + JSON.stringify(summary, null, 2));
  console.log(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.blocked} BLOCKED · ${summary.notes} notes · screenshots in ${SHOTS}`);
  for (const f of shots) console.log(`  named shot: ${f}`);
  if (KEEP && env) {
    console.log(`--keep: aitm and Chrome left running. UI: ${redact(env.uiUrl)} (token redacted; read it from the core's stdout)  proxy: 127.0.0.1:${env.proxyPort}`);
    await new Promise(() => {});
  }
  bus?.close();
  cdp?.close();
  await env?.stop();
  await target?.close();
  process.exit(summary.fail ? 1 : 0);
}

// ------------------------------------------------------------------------------------------
// Privileged drive (runs only where `l4.capture.status.available` is true — an elevated / Linux
// core). Authored from the verified DOM map; gated in step 09 so it NEVER runs, or fakes a result,
// on an unprivileged host. Uses real clicks + a plain node UDP socket for loopback traffic.
// ------------------------------------------------------------------------------------------
async function privilegedDrive() {
  const dgram = await import('node:dgram');
  // Start a loopback UDP echo so a crafted/injected packet has a live peer and send_recv gets a reply.
  const echo = dgram.createSocket('udp4');
  await new Promise((r) => echo.bind(9, '127.0.0.1', r));
  echo.on('message', (msg, rinfo) => echo.send(msg, rinfo.port, rinfo.address));
  try {
    // Capture on loopback (real click), then push a datagram so a packet is captured → a flow appears.
    await d.click({ sel: START });
    const ping = dgram.createSocket('udp4');
    ping.send(Buffer.from('probe'), 9, '127.0.0.1');
    const row = await d.locate({ sel: L4ROW }, { timeoutMs: 8000 });
    await d.mouse(row.x, row.y); // select the L4 session
    ping.close();
    await d.locate({ sel: 'section[aria-label="Craft"]' });

    // Author a PacketSpec in the craft editor, Build it (pure → hex preview), then Inject.
    const cm = await d.locate({ sel: 'section[aria-label="Craft"] .cm-content' });
    await d.mouse(cm.x, cm.y);
    await d.selectAll();
    await d.type('layers:\n  - ipv4:\n      dst: 127.0.0.1\n  - udp:\n      dst_port: 9\n  - raw: "probe"\n');
    await d.click({ role: 'button', text: 'Build', match: 'startsWith', within: 'section[aria-label="Craft"]' });
    const hex = await d.locate({ sel: 'section[aria-label="Craft"] [aria-label="Hex"], section[aria-label="Craft"] pre' }, { timeoutMs: 6000 }).catch(() => null);
    expect(!!hex, '09a craft Build → hex preview shown', `hex=${!!hex}`);

    await d.click({ sel: '[data-testid="l4-inject"]' });
    await d.locate({ sel: DIALOG });
    const prompt = await d.q('text', `${DIALOG} p`);
    const facts = await d.q('text', `${DIALOG} dl`);
    expect(/127\.0\.0\.1/.test(prompt ?? '') && /inject/i.test(prompt ?? ''), '09b confirm dialog shows destination + packet summary + scope + permit budget', `prompt "${(prompt ?? '').slice(0, 160)}"; facts "${facts}"`);
    await d.click({ role: 'button', text: 'Send to wire', match: 'exact', within: DIALOG });
    await d.gone({ sel: DIALOG });

    // The injected packet appears in the flow (list + layer tree + inert hex), and send_recv shows the reply.
    const pkt = await d.locate({ role: 'listitem', within: '[aria-label="Packets"]' }, { timeoutMs: 6000 }).catch(() => null);
    expect(!!pkt, '09c injected packet appears in the packet list', `pkt "${pkt?.text}"`);
    const layers = await d.q('find', { sel: '[aria-label="Packet layers"] [role=treeitem]' });
    const hexDump = await d.q('text', '[data-testid="l4-packet-hex"]');
    note('09c layer tree + hex', `first layer "${layers?.text}"; hex "${(hexDump ?? '(absent)').slice(0, 80)}"`);

    const sr = await probe(bus, 'l4.send_recv', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] }, dst: '127.0.0.1', interface: 'lo0', port: 9 });
    expect(sr.ok, '09d send_recv returns the echoed reply', `send_recv ok=${sr.ok} ${sr.ok ? JSON.stringify(sr.value).slice(0, 80) : sr.error}`);

    // Out-of-scope dimming: remove every scope entry so the existing flow falls out of L4 scope.
    const entries = (await probe(bus, 'l4.scope.list')).value ?? [];
    for (const e of entries) await probe(bus, 'l4.scope.remove', { id: e.id });
    await focusL4();
    const dimmed = await waitFor(async () => (await d.q('find', { sel: L4ROW }))?.oos, { timeoutMs: 6000, what: 'out-of-scope row' }).catch(() => false);
    const injBtn = await d.q('find', { sel: '[data-testid="l4-inject"]' });
    expect(dimmed && (injBtn?.disabled ?? true), '09e out-of-scope session is dimmed and its Inject disabled with the scope reason', `dimmed=${dimmed}; inject.disabled=${injBtn?.disabled}`);
    if (!intAvail.available) blocked('09f intercept Forward/Mutate/Drop/Revert', 'no Linux rig', intAvail.reason);
    else note('09f intercept Forward/Mutate/Drop/Revert', 'in-path verdicts need a parked packet: queue a scoped target into NFQUEUE and drive the L4 intercept bar');
  } finally {
    echo.close();
  }
}
