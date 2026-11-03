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
//
// Jobs view (spec D18 W2, AC58/AC59; plan Task 3.11): steps 09–11 drive the Jobs tab's card and
// table through auditing, cancelled and dead-target done, each after a poll of the witness's
// `scan.status` *state* (never the rendered word), keep that JSON as `status-<step>.json` beside a
// 1440 × 900 still (`09-jobs-auditing.png`, `10-jobs-cancelled.png`, `11-jobs-dead.png`), and
// judge the words against the witness. Guard (gap 57): the written config must point `mcp.audit_log`
// and `ca.audit_log` into the run directory or the run exits 2 before any step
// (`config-audit-lines.txt`), and Matt's real `audit.jsonl` / `ca-audit.jsonl` are hashed before the
// first step and after the last (`audit-before-after.txt`). The pure matchers (gap 56: the W2 words
// `Auditing`, `287 of 2,000`) live in `scan-live-matchers.mjs`, pinned under vitest by
// `src/panels/scanner/tester.scan-live-matchers.test.ts` (Task 3.12 C). The operator URL is printed
// with its token redacted; the dead port of step 11 is checked distinct from every port of the run and
// refused on connect after each `startAitm`, or the run FAILs and stops.
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { connect as tcpConnect } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, freePort, REPO, sleep, startAitm, startTestTarget, waitFor } from './live-env.mjs';
import { launchChrome, makeDriver } from './cua-driver.mjs';
import {
  ATTENTION_ERRORS,
  CANCEL_WORDS,
  CANCELLED_SENTENCE,
  CANCELLED_WORD,
  PERCENT_TEXT,
  RAW_ERRORS_LINE,
  ROW_PROGRESS_AUDITING,
  STOPPED_ERRORS_SENTENCE,
  TERMINAL,
  auditLogLines,
  auditLogPath,
  cancelLinesFor,
  elapsedSeconds,
  fmtElapsed,
  grouped,
  insideDir,
  listenPortsIn,
  parseProbesText,
  phaseWord,
  portClashes,
  redactOperatorUrl,
  sameDigests,
  shellQuote,
  strayErrorsTokens,
  terminalWord,
  ungroup,
} from './scan-live-matchers.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-shots/scan');
const TRANSCRIPT = join(SHOTS, 'bus-transcript.jsonl');
const KEEP = process.argv.includes('--keep');
const JSON_MODE = process.argv.includes('--json');
const W = 1600;
const H = 1000;
/** The AC59 stills of steps 09–11 are taken at the comp's size (`committed-1440.jpg`). */
const JOBS_VIEWPORT = { width: 1440, height: 900 };
/** AC58's target: `aitm-testtarget-serve --latency-ms 400`; `SCAN_LIVE_TARGET_LATENCY_MS=0` runs it unslowed. */
const TARGET_LATENCY_MS = Number(process.env.SCAN_LIVE_TARGET_LATENCY_MS ?? 400);
/**
 * The profile step 11 runs against the dead port: the plan's `standard` (Task 3.12 C). Against a refused
 * port it ends `done` with `stopped_reason: errors` in about 30 s; run 1's `light-http` ended at four
 * errors without a `stopped_reason`, which step 11 reports as a GAP.
 */
const DEAD_PROFILE = process.env.SCAN_LIVE_DEAD_PROFILE ?? 'standard';
/** Matt's real store: the two files AC59 requires unchanged. `audit.reads.jsonl` is never read. */
const OPERATOR_STORE = join(homedir(), 'Library', 'Application Support', 'aitmproxy');
const OPERATOR_AUDIT_FILES = ['audit.jsonl', 'ca-audit.jsonl'];
const j = JSON.stringify;

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

// The L4 target fields' labels are pinned by ProfileEditor.tsx (`TextField`/`Picker` put the label
// on the control's aria-label): `L4 target IP`, `L4 target port`, `L4 target proto`, `L4 target grammar`.
const L4_IP = 'input[aria-label="L4 target IP"]';
const L4_PORT = 'input[aria-label="L4 target port"]';
const L4_PROTO = 'select[aria-label="L4 target proto"]';
// The shell's toast (shell/Toast.tsx): `role=alert` for an error notice (the PoC fallback is one),
// `role=status` for an info notice.
const TOAST = '[role=alert]';
// The D-T8.9 fallback the store shows when `poc_ref` is not in the Findings list (scanner/store.ts openPoc).
const POC_FALLBACK = 'is not in the Findings list';

// The store polls scan.status every 1000 ms (D10), so a witness read taken this long before the DOM
// read is guaranteed to precede the poll the rendered number came from: that is what makes the
// bracket `status_before.sent <= rendered <= status_after.sent` a sound assertion and not a race.
const BRACKET_LEAD_MS = 1300;
// Step 09's now tag alone takes one more witness read this long before the DOM read (Task 3.12 C):
// the running check ids rotate faster than BRACKET_LEAD_MS (run 1 saw `xxe` between `xss-reflected`
// and `crlf`), so the tag is judged against the union of three reads.
const NOW_TAG_LEAD_MS = 2000;

/** Size and sha256 of a file; `absent` for a file that does not exist. */
function fileDigest(path) {
  if (!existsSync(path)) return { size: 'absent', sha256: 'absent' };
  const buf = readFileSync(path);
  return { size: buf.length, sha256: createHash('sha256').update(buf).digest('hex') };
}

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

/**
 * The run drives the web surface as a real `Frontend::Operator`, never as the agent: a core that
 * printed no `Operator` line (so `startAitm` has no operator URL) ends the run with a FAIL instead
 * of silently falling back to the agent token's URL (run 2 of the T8 proof was such a session).
 * `where` names the moment (`at startup`, `after the 08b restart`) in the FAIL line.
 */
function requireOperator(where) {
  if (env?.operatorUiUrl && env.operatorToken) return true;
  fail('00 operator URL', `the core printed no Operator line (${where}); this run would be an agent session`);
  return false;
}

/** Whether a TCP connect to 127.0.0.1:`port` is refused within `timeoutMs`: null when it is, else the reason it was not. */
const connectNotRefused = (port, timeoutMs = 1000) =>
  new Promise((res) => {
    const s = tcpConnect({ host: '127.0.0.1', port });
    const t = setTimeout(() => {
      s.destroy();
      res(`no answer within ${timeoutMs} ms`);
    }, timeoutMs);
    s.once('connect', () => {
      clearTimeout(t);
      s.destroy();
      res('something accepted the connection');
    });
    s.once('error', (e) => {
      clearTimeout(t);
      res(e.code === 'ECONNREFUSED' ? null : (e.code ?? e.message));
    });
  });

/**
 * Task 3.12 C: step 11's dead port must be no port of this run (the proxy, the web UI, the target, and
 * the `listen` / `browser.proxy_addr` ports of the written config, since `startAitm` does not return
 * the browser proxy port) and a TCP connect to it must be refused within 1 s. `freePort` picks by
 * bind-and-close, so the OS may hand the same number to `startAitm`'s own picks a moment later; a
 * clash would aim the dead-target job at a live service. A miss FAILs under `00 dead port` and the
 * caller stops the run. Run after each `startAitm` (startup and the 08b restart).
 */
async function requireDeadPortIsolated(where) {
  const named = { proxy: env.proxyPort, web: env.webPort, target: target.port };
  const configPorts = listenPortsIn(readFileSync(env.cfg, 'utf8'));
  const problems = [];
  if (!Number.isInteger(DEAD_PORT) || DEAD_PORT <= 0) problems.push(`is not a port (${j(DEAD_PORT)})`);
  for (const name of portClashes(DEAD_PORT, named)) problems.push(`equals the ${name} port`);
  if (configPorts.includes(DEAD_PORT)) problems.push(`is a listen or proxy_addr port of the written config ${j(configPorts)}`);
  const notRefused = problems.length ? null : await connectNotRefused(DEAD_PORT);
  if (notRefused) problems.push(`connect to 127.0.0.1:${DEAD_PORT} was not refused: ${notRefused}`);
  if (problems.length === 0) {
    note(`00 dead port ${where}`, `${DEAD_PORT} is none of ${j(named)} nor of the config's ${j(configPorts)}, and a connect is refused`);
    return true;
  }
  fail(`00 dead port ${where}`, `dead port ${DEAD_PORT} ${problems.join('; ')}; the run stops here`);
  return false;
}

// Phase tracking (03c): every `scan.status` read the script makes from step 2 onward feeds one set
// of witness phases, and every `[data-field=state]` read feeds one set of rendered words, so a job
// that finishes before step 3's loop starts is still judged on what the witness and the UI showed.
const witnessPhases = new Set();
const witnessStates = new Set();
const renderedStateWords = new Set();
/** The witness's `scan.status { job }`, recorded into the phase/state sets. */
async function status(job) {
  const st = await bus.call('scan.status', { job });
  if (typeof st.phase === 'string' && st.phase !== '') witnessPhases.add(st.phase);
  if (typeof st.state === 'string') witnessStates.add(st.state);
  return st;
}
/** The rendered state words of `job` (Jobs row, then the strip), recorded into the rendered set. */
async function renderedState(job) {
  const sels = [`${JOBS} [data-job="${job}"] [data-field=state]`, `${STRIP}[data-job="${job}"] [data-field=state]`];
  let first = null;
  for (const sel of sels) {
    const words = await d.q('text', sel);
    if (typeof words === 'string' && words !== '') {
      renderedStateWords.add(words);
      first ??= words;
    }
  }
  return first;
}

/** Runs one step: PASS unless the body throws or records a non-NOTE result; always screenshots. */
async function step(name, body) {
  out(`\n== ${name}`);
  const before = results.length;
  try {
    await body();
    if (!results.slice(before).some((r) => r.status !== 'NOTE')) pass(name);
  } catch (e) {
    fail(name, e.message.split('\n')[0]);
  } finally {
    try {
      const f = await d.shot(name);
      if (f) out(`  shot ${f}`);
    } catch (e) {
      out(`  (screenshot failed: ${e.message})`);
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
// Laid-out text (innerText): block siblings separated by whitespace, so a token at the end of one line
// never runs into the next (`textContent` joins `stopped_reason: errors` + `crawl.last_error: …` as
// `errorscrawl.last_error`, which no word-boundary match sees).
const layoutText = (sel) => d.ev(`(() => { const e = document.querySelector(${j(sel)}); return e ? ((e.innerText ?? e.textContent ?? '').replace(/\\s+/g, ' ').trim()) : null; })()`);
const valueOf = (sel) => d.ev(`document.querySelector(${j(sel)})?.value ?? null`);

// --- real-input interactions -----------------------------------------------------------------
const goScan = () => d.click({ role: 'button', text: 'Scan', match: 'startsWith', within: SIDEBAR });
const clickTab = (label) => d.click({ role: 'tab', text: label, match: 'startsWith', within: TABLIST });
const JOBS_TAB = `${TABLIST} [role=tab][data-tab="jobs"]`;
const SELECTED_PROFILE = `${PROFILES} [data-profile][aria-selected="true"]`;

/**
 * Waits for the panel's layout to settle after a mount: the Jobs tab count has loaded (its text no
 * longer ends in `0`), or 2 s have passed (a core with no jobs reads `0` for good). A freshly
 * (re)started core loads its persisted jobs a moment after the panel mounts, and the job strip
 * that then appears pushes everything below it down — a click located before that lands on the
 * wrong row (live run 6, step 08b: `l4-stream-safe` was located, `thorough` was clicked).
 */
const waitForJobsSettled = () =>
  soft(async () => {
    const t = await d.q('text', JOBS_TAB);
    return typeof t === 'string' && t.trim() !== '' && !/0$/.test(t.trim()) ? true : null;
  }, 2000);

/**
 * Selects a profile row the way an operator does and proves the selection landed: settle first,
 * click the row, and expect `[data-profile=name][aria-selected=true]` within 1 s. A miss re-locates
 * and clicks once more; a second miss FAILs the step naming the row that IS selected. Returns
 * whether `name` is selected, so the caller can stop instead of editing another profile's draft.
 */
async function selectProfile(name, label) {
  await waitForJobsSettled();
  const sel = `${PROFILES} [data-profile="${name}"]`;
  for (let attempt = 1; attempt <= 2; attempt++) {
    await d.click({ sel });
    const picked = await soft(async () => ((await countOf(`${sel}[aria-selected="true"]`)) > 0 ? true : null), 1000);
    if (picked) return true;
    if (attempt === 1) out(`  ${name} is not selected after the click (selected: ${j(await attr(SELECTED_PROFILE, 'data-profile'))}); re-locating and clicking once more`);
  }
  fail(`${label} select ${name}`, `clicked ${sel} twice; the selected row is ${j(await attr(SELECTED_PROFILE, 'data-profile'))}`);
  return false;
}

/** `true` when the page's focused element is the one `sel` selects. */
const isFocused = (sel) => d.ev(`(() => { const e = document.querySelector(${j(sel)}); return !!e && document.activeElement === e; })()`);

/**
 * Clicks the field, selects its contents and types `text` with real key/insertText events.
 * The click must land focus on the field itself: when it does not (something overlays it, or it sits
 * off-screen) the element is scrolled to the viewport's centre and clicked once more; if focus still
 * rests elsewhere the caller's step FAILs with the active element's description. The value is never
 * written from JS — a note the user did not type would prove nothing.
 */
async function typeInto(sel, text) {
  await d.click({ sel });
  if (!(await isFocused(sel))) {
    const active = await d.q('active');
    out(`  focus after click: ${active ?? 'none'}, wanted ${sel}; scrolling it to centre and clicking again`);
    await d.ev(`document.querySelector(${j(sel)})?.scrollIntoView({ block: 'center', inline: 'nearest' })`);
    await sleep(150);
    await d.click({ sel });
    if (!(await isFocused(sel))) {
      const disabled = await d.ev(`document.querySelector(${j(sel)})?.disabled ?? null`);
      throw new Error(`focus did not land on ${sel} after two clicks; active element is ${j(await d.q('active'))}${disabled ? ' (the field is disabled)' : ''}`);
    }
  }
  await d.selectAll();
  await d.type(text);
}

/**
 * Picks an option in a real <select> the way a keyboard does: focus, then arrow until it matches.
 * Headless Chrome does not change a native <select> from key events (its popup is a native widget),
 * so a miss is recorded as a GAP of the harness, not as a FAIL of the UI, and `null` is returned.
 */
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
  gap(`select ${sel}`, `could not pick ${j(String(wanted))} (value stays ${j(await valueOf(sel))}): headless Chrome does not change a native <select> from key events`);
  return null;
}

/** The visible error-toast texts (shell/Toast.tsx renders one at a time). */
const toastTexts = () => textsOf(TOAST);

/** Dismisses a visible toast with a real click (Toast.tsx clears on click) so it cannot overlay a later target. */
async function dismissToast() {
  const t = await d.q('find', { sel: TOAST });
  if (t) {
    await d.mouse(t.x, t.y);
    await sleep(250);
  }
}

/**
 * Picks in a real <select> only when its current value does not already match `wanted`; when it
 * does (the proof's scope has exactly one concrete host, already selected) no key event is sent.
 * Headless Chrome on macOS does not change a native <select> from ArrowDown (the popup is a native
 * widget), so driving one is a last resort, kept only as the fallback.
 */
async function pickSelectUnless(sel, wanted) {
  const ok = (v) => (wanted instanceof RegExp ? wanted.test(v ?? '') : v === wanted);
  const current = await valueOf(sel);
  if (ok(current)) return current;
  return pickSelect(sel, wanted);
}

const SCHEME_GROUP = '[role=radiogroup][aria-label="Origin scheme"]';
/** Clicks the `https` | `http` radio of the Origin scheme segmented control and asserts it took. */
async function pickScheme(scheme) {
  await d.click({ role: 'radio', text: scheme, match: 'exact', within: SCHEME_GROUP });
  const checked = await d.ev(
    `Array.from(document.querySelectorAll(${j(`${SCHEME_GROUP} [role=radio]`)})).find((b) => (b.textContent ?? '').trim() === ${j(scheme)})?.getAttribute('aria-checked') ?? null`,
  );
  if (checked !== 'true') throw new Error(`Origin scheme radio ${j(scheme)} is not checked after the click (aria-checked ${j(checked)})`);
  return scheme;
}

/** The probes numerator the UI renders for `job` (`287 of 2,000` -> 287; the older `418/2000` too), or null. */
async function renderedProbes(sel) {
  return parseProbesText(await d.q('text', sel))?.sent ?? null;
}

const sameCounts = (bySeverity, rendered) => {
  const nonZero = Object.entries(bySeverity ?? {}).filter(([, n]) => Number(n) > 0);
  if (nonZero.length !== Object.keys(rendered).length) return false;
  return nonZero.every(([s, n]) => rendered[s] === Number(n));
};

/**
 * The Issues tab's severity groups: `[data-severity][data-count]`. The Jobs tab's ledger marks and
 * severity words carry `data-severity` alone (plan gap 55), so this count never reads them even
 * when the Jobs view is the mounted tab.
 */
async function renderedGroups() {
  const pairs = await d.ev(
    `Array.from(document.querySelectorAll(${j(`${SCANNER} [data-severity][data-count]`)})).map((e) => [e.getAttribute('data-severity'), Number(e.getAttribute('data-count'))])`,
  );
  return Object.fromEntries(pairs ?? []);
}

/**
 * Adds the L4 target `127.0.0.1:<target port> tcp` through the editor's row with real input.
 * `l4-stream-safe` ships with no origin and no L4 target, so `preflight` (launch.ts) says
 * `add an origin or an L4 target` first; only with a target does the L4 coverage rule speak.
 */
async function addL4Target() {
  await typeInto(L4_IP, '127.0.0.1');
  await typeInto(L4_PORT, String(target.port));
  await pickSelectUnless(L4_PROTO, 'tcp');
  await d.click({ role: 'button', text: 'Add L4 target', match: 'startsWith' });
  const listed = await soft(() => d.q('exists', `[role=list][aria-label="L4 targets"] [data-l4="127.0.0.1:${target.port}"]`), 3000);
  if (!listed) throw new Error(`the L4 targets list shows no 127.0.0.1:${target.port} row after Add L4 target`);
}

/**
 * Composes `http://127.0.0.1:<target port>` in the origin picker and clicks `Add origin`.
 * When the chosen `Origin host` option already carries a port (the proof's scope host is
 * `127.0.0.1:<target port>`) the editor disables `Origin port` by design (D-T8.5 amendment A2);
 * typing into a disabled input cannot take focus, so the port is typed only when the input is enabled.
 */
async function addTargetOrigin() {
  await pickScheme('http');
  // The exact host: the scope carries a second 127.0.0.1 entry (the dead port of step 11), and the
  // picker defaults to the first scope host, which `scopeHosts()` keeps as the target.
  await pickSelectUnless('select[aria-label="Origin host"]', target.host);
  const portDisabled = await d.ev(`document.querySelector('input[aria-label="Origin port"]')?.disabled ?? null`);
  if (portDisabled === true) out('  Origin port is disabled (host carries the port); not typed');
  else await typeInto('input[aria-label="Origin port"]', String(target.port));
  await d.click({ role: 'button', text: 'Add origin', match: 'startsWith' });
  return d.q('text', '[aria-label="Origins"]');
}

/** The ids of the rendered Jobs rows. */
const renderedJobIds = async () => (await d.ev(`Array.from(document.querySelectorAll(${j(`${JOBS} [data-job]`)})).map((e) => e.getAttribute('data-job'))`)) ?? [];

/** Clicks Start and waits for a Jobs row whose id is not in `known`; returns its id or null. */
async function startAndWaitForJob(known, { label, timeoutMs = 20000, tabWaitMs = 3000 } = {}) {
  await d.click({ role: 'button', text: 'Start', match: 'exact', within: SCANNER });
  const newJob = async () => (await renderedJobIds()).find((id) => !known.includes(id)) ?? null;
  // The store switches to the Jobs tab itself on a start (store.ts afterStart); the click below is
  // only a timing fallback.
  if (!(await soft(newJob, tabWaitMs))) {
    await clickTab('Jobs');
    note(`${label} jobs tab`, `Jobs row not visible within ${tabWaitMs / 1000} s; clicked the tab`);
  }
  return soft(newJob, timeoutMs);
}

/**
 * Starts a `standard` job against the test target the way an operator does (Profiles tab, the
 * `standard` row, the origin re-added when the draft lost it, Start) and returns the new Jobs row's
 * id, or null after recording the FAIL under `failTitle`. `extraKnown` are ids a new row must not be.
 */
async function launchStandard(label, extraKnown, { failTitle, tabWaitMs = 1500, timeoutMs = 10000 } = {}) {
  await clickTab('Profiles');
  if (!(await selectProfile('standard', label))) return null;
  const want = `http://127.0.0.1:${target.port}`;
  let origins = await d.q('text', '[aria-label="Origins"]');
  if (!(origins ?? '').includes(want)) {
    note(`${label} origins`, `the standard draft lost its origin (Origins reads ${j(origins)}); re-adding it`);
    origins = await addTargetOrigin();
    if (!(origins ?? '').includes(want)) throw new Error(`Origins reads ${j(origins)} after re-adding ${want}`);
  }
  const known = [...(await renderedJobIds()), ...extraKnown];
  const job = await startAndWaitForJob(known, { label, tabWaitMs, timeoutMs });
  if (!job) fail(failTitle ?? `${label} a standard job starts`, `no new ${JOBS} [data-job] within ${timeoutMs / 1000} s; launch result ${j(await d.q('text', `${SCANNER} [role=status][aria-label="Launch result"]`))}`);
  return job;
}

// --- Jobs view (steps 09–11) ------------------------------------------------------------------
const cardSel = (job) => `${STRIP}[data-job="${job}"]`;
const rowSel = (job) => `${JOBS} [data-job="${job}"]`;
/** The numeral of a KPI cell (`.kpi > .kpiLabel, .kpiValue > (Tick span, unit)`; JobCard.tsx). */
const kpiNumeral = (label) => rawText(`${STRIP} [data-kpi="${label}"] > span:nth-child(2) > span:first-child`);
/** The selected tab's `data-tab`. */
const selectedTab = () => attr(`${SCANNER} [role=tab][aria-selected="true"]`, 'data-tab');
/** Shows the Jobs tab (the store switches to it on a start; this is the fallback). */
async function ensureJobsTab() {
  if ((await selectedTab()) !== 'jobs') await clickTab('Jobs');
}
/** Selects a job's row with a real click and waits for its card. */
async function selectJobRow(job) {
  await d.click({ sel: rowSel(job) });
  return soft(async () => ((await attr(STRIP, 'data-job')) === job ? true : null), 3000);
}
/** The witness's `scan.status` once `pred` holds, else null after `timeoutMs`. */
const witnessUntil = (job, pred, timeoutMs) =>
  soft(async () => {
    const st = await status(job);
    return pred(st) ? st : null;
  }, timeoutMs);
/** Waits (bounded) for every listed job to be terminal: the engine runs one job per origin and two at once. */
async function waitForQuietEngine(label, timeoutMs) {
  const quiet = await soft(async () => {
    const l = await bus.call('scan.list', {});
    return (l.jobs ?? []).every((x) => TERMINAL.has(x.state)) ? true : null;
  }, timeoutMs);
  if (!quiet) {
    const l = await bus.call('scan.list', {});
    note(`${label} earlier jobs`, `still live after ${timeoutMs / 1000} s: ${j((l.jobs ?? []).filter((x) => !TERMINAL.has(x.state)).map((x) => `${x.job} ${x.state}`))}; going on`);
  }
  return quiet;
}
/** Sets the page's viewport (CDP emulation on the driver's session; Chrome's window stays 1600 × 1000). */
async function setViewport({ width, height }) {
  await cdp.s('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await sleep(300);
}
/** A still of the current viewport under an explicit file name (the AC59 stills), apart from `d.shot`'s counter. */
async function still(file) {
  const r = await cdp.s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  const path = join(SHOTS, file);
  writeFileSync(path, Buffer.from(r.data, 'base64'));
  out(`  still ${path}`);
  return path;
}
/** The witness JSON kept beside a still. */
const keepStatus = (name, payload) => writeFileSync(join(SHOTS, `status-${name}.json`), JSON.stringify(payload, null, 2) + '\n');
const doneOver = (st) => (st?.checks?.scheduled > 0 ? st.checks.done / st.checks.scheduled : null);

// ------------------------------------------------------------------------------------------
// Steps
// ------------------------------------------------------------------------------------------
async function run() {
  // 1 ----------------------------------------------------------------------------------------
  await step('01 the core offers the engine and the Scan panel opens', async () => {
    await d.open(env.operatorUiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 20000, what: 'status bar "bus open"' });
    const tools = (await bus.tools()).map((t) => t.name);
    if (!tools.includes('scan.start')) {
      fail('01 the core offers the engine and the Scan panel opens', 'engine not available: scan.start not in tools/list');
      note('01 tools seen', tools.filter((t) => t.startsWith('scan.')).join(' ') || 'no scan.* verb at all');
      return;
    }
    engineOk = true;
    // The sidebar paints after the bus opens; a one-shot find here raced it once (first paint).
    const item = await soft(() => d.q('find', { role: 'button', text: 'Scan', match: 'startsWith', within: SIDEBAR }), 5000);
    expect(!!item, '01a the sidebar shows Scan', 'no Scan item in the sidebar within 5 s');
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
    if (!(await selectProfile('standard', '02'))) return;
    const origins = await addTargetOrigin();
    const want = `http://127.0.0.1:${target.port}`;
    expect((origins ?? '').includes(want), '02a the origin picker composed the target origin', `Origins reads ${j(origins)}, wanted ${want}`);
    const startBtn = await d.q('find', { role: 'button', text: 'Start', match: 'exact', within: SCANNER });
    if (startBtn?.disabled) note('02 Start disabled', `reason ${j(await d.q('text', `${SCANNER} [data-reason]`))}`);
    const seen = await startAndWaitForJob([], { label: '02' });
    if (!seen) {
      const result = await d.q('text', `${SCANNER} [role=status]`);
      fail('02b a Jobs row appears for the launch', `no ${JOBS} [data-job] within 20 s; launch result reads ${j(result)}`);
      return;
    }
    jobId = seen;
    // The first state words and the first witness read, taken as early as possible: a short job
    // may be past `crawling` before step 3 starts (03c judges the union of every read).
    await renderedState(jobId);
    await status(jobId);
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
    // Each bracket: a witness read taken BRACKET_LEAD_MS before the DOM read (so it precedes the
    // poll the UI rendered) and one immediately after; `sent` is monotonic, so the rendered value
    // must lie between them. Every read here also feeds the 03c phase sets.
    const bracket = async (label) => {
      const before = await status(jobId);
      await renderedState(jobId);
      await sleep(BRACKET_LEAD_MS);
      const rendered = await renderedProbes(probesSel);
      await renderedState(jobId);
      const after = await status(jobId);
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

    // Phase: sample the rendered words and the witness phase together every 500 ms for up to 20 s
    // (or until the job is terminal). The judgement below is over the UNION of every read made
    // since step 2, not only this loop's: a job that is `done` within a few seconds has no phase
    // left to show here, and that is not a UI defect.
    const timeline = [];
    const t0 = Date.now();
    let last = null;
    while (Date.now() - t0 < 20000) {
      const words = await renderedState(jobId);
      const st = await status(jobId);
      last = st;
      timeline.push({ at: Date.now() - t0, rendered: words, phase: st.phase ?? null, state: st.state });
      if (TERMINAL.has(st.state)) break;
      await sleep(500);
    }
    tx({ dir: 'note', what: 'phase timeline', job: jobId, timeline });
    // The rendered words are the glossary's: the capitalised phase for a live job (`Auditing`) and
    // the capitalised state for a terminal one (`Done`; helpers.ts stateWords, gap 56), so both are
    // lowercased before they meet the witness's tokens; a phase is "rendered" when some words
    // lowercase to it, and the terminal word is rendered when some words are a terminal state.
    const renderedPhaseWords = new Set([...renderedStateWords].map(phaseWord).filter(Boolean));
    const terminalRendered = [...renderedStateWords].map(terminalWord).find(Boolean) ?? null;
    // `queued` is the pre-start phase: a job can leave it before the UI's first poll.
    const judged = [...witnessPhases].filter((p) => p !== 'queued');
    const missed = judged.filter((p) => !renderedPhaseWords.has(p));
    const detail = `witness phases [${[...witnessPhases].join(', ')}], witness states [${[...witnessStates].join(', ')}], rendered words ${j([...renderedStateWords])}, terminal word rendered ${j(terminalRendered)}`;
    if (witnessPhases.size === 0) {
      note('03c every phase the witness saw was rendered or the terminal word was', `no scan.status read since step 2 carried a phase (${[...witnessStates].join(', ') || 'no state either'}); nothing to judge — ${detail}`);
    } else {
      expect(
        missed.length === 0 || terminalRendered !== null,
        '03c every phase the witness saw was rendered or the terminal word was',
        `never rendered [${missed.join(', ')}] and no terminal word rendered — ${detail}`,
      );
    }
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

    // D6: `poc_ref` is linked only for a hinted class (T3's natives: xss-reflected, open-redirect,
    // ...), so 04d judges the engine on one of those rows, not on whichever row renders first.
    const HINTED = ['xss-reflected', 'open-redirect'];
    const listed = (await bus.call('scan.issues', { job: jobId, limit: 1024 })).issues ?? [];
    const hinted = listed.find((i) => HINTED.includes(i.check_id)) ?? null;
    const hintedRendered = hinted ? await d.q('exists', `${SCANNER} [data-issue="${hinted.id}"]`) : false;
    if (hinted && hintedRendered) note('04 issue pick', `hinted class ${hinted.check_id} (${hinted.id})`);
    else note('04 issue pick', `no hinted-class row (listed: ${[...new Set(listed.map((i) => i.check_id))].join(', ') || 'none'}); first row`);
    const issueId = hintedRendered ? hinted.id : await attr(`${SCANNER} [data-issue]`, 'data-issue');
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
      gap('04d PoC ref', `${issue.check_id} (${issue.class}, ${issue.confidence}) carries no poc_ref${HINTED.includes(issue.check_id) ? ' though its class is hinted: the PoC run did not pass or the engine did not link it (D6)' : ' and no hinted-class issue was listed'}`);
    } else {
      await d.click({ role: 'button', text: `Open PoC ${issue.poc_ref}`, match: 'startsWith' });
      // Two honest outcomes (D-T8.9): the Findings panel selects the PoC's row, or the store's
      // fallback toast says the ref is not in the Findings list. The core's `poc.list`
      // (crates/aitm-poc/src/library.rs) lists `*.yaml` files directly in `poc.dir` only, while the
      // scanner writes `poc_ref` under `<findings.dir>/scan/pocs/<subdir>/`, so on this core the
      // list can never hold it and the fallback is the designed path. The toast is watched in the
      // same poll as the row because it clears itself after 6 s.
      let toast = null;
      const row = await soft(async () => {
        const sel = await d.q('find', { sel: `${FINDINGS_ROWS} [role=option][aria-selected="true"]` });
        if (sel) return sel;
        toast ??= (await toastTexts()).find((t) => t.includes(POC_FALLBACK)) ?? null;
        return toast ? { fallback: true } : null;
      }, 5000);
      let title = null;
      try {
        const listed = await bus.call('poc.list', {});
        const entries = Array.isArray(listed) ? listed : (listed.findings ?? listed.pocs ?? []);
        const hit = entries.find((e) => e?.id === issue.poc_ref || e?.poc_path === issue.poc_ref);
        title = hit?.title ?? null;
      } catch (e) {
        note('04d poc.list', e.message.split('\n')[0]);
      }
      const selectedRow = row && !row.fallback ? row : null;
      const where = `poc_ref ${j(issue.poc_ref)}, witness poc.list title ${j(title)}`;
      if (selectedRow) {
        const ok = title ? selectedRow.text.includes(title) : selectedRow.id === issue.poc_ref;
        expect(ok, '04d the PoC ref opens Findings with that PoC selected', `selected row ${j(selectedRow.text)} (data-id ${j(selectedRow.id)}), ${where}`);
      } else if (toast) {
        pass('04d the PoC ref opens Findings with that PoC selected', `fallback: the toast read ${j(toast)}`);
        note('04d PoC fallback', `poc.dir does not list ${FINDINGS_DIR}/scan/pocs on this core (poc.list is non-recursive); the UI showed the spec's fallback`);
        await dismissToast();
      } else {
        fail('04d the PoC ref opens Findings with that PoC selected', `neither a selected Findings row nor a "${POC_FALLBACK}" toast within 5 s; toasts ${j(await toastTexts())}, ${where}`);
      }
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
    // A toast still on screen (04d's fallback) sits bottom-centre, where the Note field can be;
    // `typeInto` re-clicks once after scrolling and FAILs 04f if focus still is not the textarea.
    let noteTyped = false;
    try {
      await typeInto('textarea[aria-label="Note"]', 'intended behaviour');
      noteTyped = true;
    } catch (e) {
      fail('04f the note reached the core verbatim', e.message.split('\n')[0]);
    }
    await d.click({ role: 'button', text: 'Update status', match: 'startsWith' });
    const updated = await soft(async () => {
      const i = await bus.call('scan.issue', { id: issueId });
      return i.status === 'false_positive' ? i : null;
    }, 5000);
    const finalStatus = updated?.status ?? (await bus.call('scan.issue', { id: issueId }).then((i) => i.status).catch((e) => e.message));
    expect(!!updated, '04e false_positive round-trips through scan.issue.update', `witness status stays ${j(finalStatus)}`);
    if (noteTyped) expect(updated?.note === 'intended behaviour', '04f the note reached the core verbatim', `witness note ${j(updated?.note ?? null)}`);
  });

  // 5 ----------------------------------------------------------------------------------------
  await step('05 cancel', async () => {
    // The cancel is proven on a SECOND standard job against the same origin, so the first must be
    // over: the engine admits one job per origin (`scan: busy`), and a debug-build core takes
    // ~30 s for a standard scan of the test target.
    // With `--latency-ms 400` on the target a standard job runs ~2 min (the mac driver's measure).
    const settledAt = Date.now();
    const first = await soft(async () => (TERMINAL.has((await status(jobId)).state) ? true : null), FIRST_JOB_WAIT_MS);
    if (!first) {
      fail('05 the first job ends before the cancel job starts', `job ${jobId} not terminal after ${FIRST_JOB_WAIT_MS / 1000} s (witness scan.status)`);
      return;
    }
    note('05 first job', `terminal ${Date.now() - settledAt} ms after step 4 ended`);
    const started = Date.now();
    const job2 = await launchStandard('05', [jobId], { failTitle: '05 a second job starts for the cancel' });
    if (!job2) return;
    const cancelSpec = { role: 'button', text: `Cancel scan ${job2}`, match: 'startsWith', within: STRIP };
    const cancel = await soft(() => d.q('find', cancelSpec), 1000);
    const toCancel = Date.now() - started;
    const preState = await renderedState(job2);
    if (!cancel || cancel.disabled) {
      const pre = await status(job2);
      if (TERMINAL.has(pre.state)) {
        gap('05 cancel', `the second job was already ${pre.state} ${toCancel} ms after the launch began, before Cancel was clickable (rendered ${j(preState)})`);
        return;
      }
      fail('05 cancel', `Cancel scan ${job2} is ${cancel ? 'disabled' : 'absent'} in the strip ${toCancel} ms after the launch began though the witness says ${pre.state}`);
      return;
    }
    await d.mouse(cancel.x, cancel.y);
    out(`  click Cancel scan ${job2} ${Date.now() - started} ms after the launch began`);
    const stateSel = `${JOBS} [data-job="${job2}"] [data-field=state]`;
    const stripSel = `${STRIP}[data-job="${job2}"] [data-field=state]`;
    const readBoth = async () => [await d.q('text', stateSel), await d.q('text', stripSel)].filter((t) => typeof t === 'string');
    const immediate = await soft(async () => (await readBoth()).find((t) => CANCEL_WORDS.test(t)) ?? null, 1000);
    expect(!!immediate, '05a the row or strip reads cancelling or cancelled immediately', `rendered ${j(await readBoth())}`);
    const settled = await soft(async () => (await readBoth()).find((t) => CANCELLED_WORD.test(t)) ?? null, 5000);
    expect(!!settled, '05b the row reads cancelled within 5 s', `rendered ${j(await readBoth())}`);
    // The witness's own reply is what is judged: the one that read `cancelled`, else the last one.
    const st =
      (await soft(async () => {
        const s = await status(job2);
        return s.state === 'cancelled' ? s : null;
      }, 5000)) ?? (await status(job2));
    expect(st.state === 'cancelled', '05c the witness scan.status.state is cancelled', `witness state ${j(st.state)}`);
    // Steps 6 and 7 are about the FIRST job (its site map, its strip): re-select it in the Jobs list.
    await d.click({ sel: `${JOBS} [data-job="${jobId}"]` });
    const back = await soft(async () => ((await attr(STRIP, 'data-job')) === jobId ? true : null), 3000);
    if (!back) note('05 re-select', `the strip shows ${j(await attr(STRIP, 'data-job'))} after clicking the first job's row ${jobId}`);
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
    if (!(await selectProfile('l4-stream-safe', '08a'))) return;
    // With neither an origin nor an L4 target the (correct) first reason is `add an origin or an L4
    // target`; the D11 coverage hint is the reason for a TARGET no L4 scope entry covers.
    await addL4Target();
    const start = await soft(() => d.q('find', { role: 'button', text: 'Start', match: 'exact', within: SCANNER }), 5000);
    const reason = await d.q('text', `${SCANNER} [data-reason]`);
    expect(start?.disabled === true, '08a Start is disabled for an L4 profile with no L4 scope', `Start disabled=${j(start?.disabled ?? null)}`);
    const tools = (await bus.tools()).map((t) => t.name);
    if (!tools.includes('l4.scope.list')) {
      // preflight (launch.ts) says `the L4 layer is not enabled on this core` before it can judge
      // coverage; the hint is unreachable on a core without the L4 layer, which is not a UI defect.
      gap('08a the refusal reason carries the D11 hint', `this core offers no l4.scope.list (L4 layer off), so the UI cannot reach the coverage rule; reason ${j(reason)}`);
      return;
    }
    expect((reason ?? '').includes('interface: "*"'), '08a the refusal reason carries the D11 hint', `reason ${j(reason)}`);
  });

  // 8b ---------------------------------------------------------------------------------------
  // Steps 09–11 need the restarted core and its witness: 08b closes the first witness before the
  // restart, so a restart that did not come up leaves nothing for them to talk to.
  let coreReady = false;
  await step('08b with an L4 scope entry the confirm dialog shows the core prompt verbatim', async () => {
    bus.close();
    await env.stop();
    env = await startAitm({
      scope: scopeHosts(),
      findingsDir: FINDINGS_DIR,
      l4: {
        enabled: true,
        scope: [{ addr: '127.0.0.1', prefix: 32, portLo: 0, portHi: 65535, interface: '*', direction: 'outbound', capability: 'inject' }],
      },
      log: (l) => (/error|panic/i.test(l) ? out('[aitm] ' + l) : null),
    });
    // The restarted core has a fresh config: the same guard as at startup (gap 57).
    await auditPreflightOrExit('after the 08b restart');
    if (!requireOperator('after the 08b restart')) return;
    if (!(await requireDeadPortIsolated('after the 08b restart'))) return;
    bus = await witness(env.busUrl, env.operatorToken, 'witness-l4');
    coreReady = true;
    await d.open(env.operatorUiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 20000, what: 'status bar "bus open" after the restart' });
    await goScan();
    // The restarted core loads its persisted jobs a beat after the panel mounts: let the strip
    // appear (or not) before the first click in the panel, so nothing moves under the pointer.
    await waitForJobsSettled();
    await clickTab('Profiles');
    if (!(await selectProfile('l4-stream-safe', '08b'))) return;
    // The fresh page has a fresh draft: the L4 target is added again.
    await addL4Target();

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

  // 9 ----------------------------------------------------------------------------------------
  // The Jobs view (AC58). Each step polls the witness's scan.status STATE before its capture, keeps
  // that JSON beside the still, and judges the rendered words against the witness. The viewport is
  // the comp's 1440 × 900 for the three steps (AC59).
  let job3 = null;
  if (!coreReady) {
    note('09-11 skipped', 'the 08b restart gave no usable core (no Operator line, a dead-port clash, or no witness); the Jobs view cannot be driven');
    return;
  }
  await step('09 Jobs view: auditing with the now mark', async () => {
    await setViewport(JOBS_VIEWPORT);
    await waitForQuietEngine('09', 90000);
    job3 = await launchStandard('09', [], { failTitle: '09 a standard job starts for the Jobs view' });
    if (!job3) return;
    const job = job3;
    // The witness's state, never the rendered word: running · auditing with a check in flight.
    const auditing = await witnessUntil(job, (st) => st.state === 'running' && st.phase === 'auditing' && (st.checks?.running?.length ?? 0) > 0, 180000);
    if (!auditing) {
      const last = await status(job);
      keepStatus('09', { last });
      fail('09 the witness reads running · auditing with checks.running', `not within 180 s; last ${last.state} · ${last.phase ?? '—'} (checks ${j(last.checks ?? null)})`);
      return;
    }
    await ensureJobsTab();
    const card = cardSel(job);
    if ((await attr(STRIP, 'data-job')) !== job && !(await selectJobRow(job))) {
      fail('09 the card shows the job', `the Selected job region reads data-job ${j(await attr(STRIP, 'data-job'))}, wanted ${job}`);
      return;
    }
    // The audit fill and its now tag need the store's status poll (1 s) to have landed.
    await soft(() => d.q('exists', `${card} [data-field=now] [data-role=checkId]`), 5000);
    // Bracket (03's rule): a witness read BRACKET_LEAD_MS before the DOM reads, one right after; and
    // for the now tag alone one more read NOW_TAG_LEAD_MS before them (the ids rotate faster than
    // the lead), so the tag is judged against the union of the three reads' `checks.running`.
    const early = await status(job);
    await sleep(NOW_TAG_LEAD_MS - BRACKET_LEAD_MS);
    const before = await status(job);
    await sleep(BRACKET_LEAD_MS);
    const rendered = {
      chip: await d.q('text', `${card} [data-field=state]`),
      rowState: await d.q('text', `${rowSel(job)} [data-field=state]`),
      nowId: await rawText(`${card} [data-field=now] [data-role=checkId]`),
      nowTag: await d.q('text', `${card} [data-field=now]`),
      laneFraction: await attr(`${card} [data-field=lane][role=progressbar]`, 'data-fraction'),
      kpiProgress: await kpiNumeral('Progress'),
      kpiChecks: await kpiNumeral('Checks'),
      rowProgress: await rawText(`${rowSel(job)} [data-field=progress]`),
      rowProbes: await d.q('text', `${rowSel(job)} [data-field=probes]`),
    };
    const after = await status(job);
    keepStatus('09', { job, early, before, after, rendered });
    await still('09-jobs-auditing.png');
    const liveBoth = [before, after].every((st) => st.state === 'running' && st.phase === 'auditing');
    if (!liveBoth) {
      gap('09 bracket', `the job left auditing during the capture (${before.state} · ${before.phase} -> ${after.state} · ${after.phase}); the still and status-09.json stand, the numbers are not judged`);
      return;
    }
    expect(rendered.chip === 'Auditing', '09a the card chip reads Auditing while the witness reads running · auditing', `chip ${j(rendered.chip)}`);
    expect(rendered.rowState === 'Auditing', '09a the row state word reads Auditing', `row ${j(rendered.rowState)}`);
    // The now tag: the ids rotate between polls faster than the bracket's lead, so the sound claim is
    // membership in the union of the three witness reads' `checks.running` (2 s before, 1.3 s before,
    // right after the DOM read; Task 3.12 C); whether it equals a read's running[0] stays a NOTE.
    const reads = { early, before, after };
    const runningOf = (st) => st.checks?.running ?? [];
    const running = new Set(Object.values(reads).flatMap(runningOf));
    const firsts = Object.values(reads).map((st) => runningOf(st)[0] ?? null);
    const witnessRunning = Object.entries(reads)
      .map(([k, st]) => `${k} ${j(runningOf(st))}`)
      .join(', ');
    expect(rendered.nowId !== null && running.has(rendered.nowId), '09b the now tag names a check the witness had running (the union of three reads)', `now tag ${j(rendered.nowTag)}; witness running ${witnessRunning}`);
    expect(typeof rendered.nowTag === 'string' && rendered.nowTag.startsWith(`now · ${rendered.nowId}`), '09b the now tag reads `now · <id>`', `now tag ${j(rendered.nowTag)}`);
    note('09b now tag vs running[0]', `${j(rendered.nowId)} ${firsts.includes(rendered.nowId) ? 'equals' : 'differs from'} a witness running[0] of the three reads (${j(firsts)})`);
    const fractions = [doneOver(before), doneOver(after)];
    const lo = Math.min(...fractions) - 0.02;
    const hi = Math.max(...fractions) + 0.02;
    const fr = rendered.laneFraction === null ? NaN : Number(rendered.laneFraction);
    expect(fr >= lo && fr <= hi, '09c the lane data-fraction is within 0.02 of the witness done / scheduled', `data-fraction ${j(rendered.laneFraction)}, witness ${fractions.map((f) => f?.toFixed(4)).join(' .. ')}`);
    const pcts = fractions.map((f) => Math.floor(100 * f));
    const kpiPct = PERCENT_TEXT.exec(rendered.kpiProgress ?? '')?.[1] ?? null;
    const kp = kpiPct === null ? NaN : Number(kpiPct);
    expect(kp >= Math.min(...pcts) - 1 && kp <= Math.max(...pcts) + 1, '09d the KPI Progress numeral is within 1 of floor(100 · done / scheduled)', `KPI ${j(rendered.kpiProgress)} (U+00A0 before % required), witness ${pcts.join(' .. ')}`);
    const rp = ROW_PROGRESS_AUDITING.exec(rendered.rowProgress ?? '');
    expect(!!rp, '09e the row progress reads `<n> % · <done> of <scheduled>` with U+00A0 before %', `row progress ${j(rendered.rowProgress)}`);
    if (rp) {
      expect(rp[1] === kpiPct, '09e the row percent equals the KPI percent', `row ${rp[1]} vs KPI ${j(kpiPct)}`);
      expect(ungroup(rp[3]) === before.checks.scheduled && ungroup(rp[2]) >= before.checks.done && ungroup(rp[2]) <= after.checks.done, '09e the row done / scheduled are the witness counts (bracket)', `row ${rp[2]} of ${rp[3]}, witness done ${before.checks.done}..${after.checks.done} of ${before.checks.scheduled}`);
    }
    const kc = rendered.kpiChecks === null ? NaN : ungroup(rendered.kpiChecks);
    expect(kc >= before.checks.done && kc <= after.checks.done && rendered.kpiChecks === grouped(kc), '09f the KPI Checks numeral is the witness checks.done, grouped (bracket)', `KPI ${j(rendered.kpiChecks)}, witness ${before.checks.done}..${after.checks.done}`);
    const probes = parseProbesText(rendered.rowProbes);
    expect(probes !== null && probes.sent >= (before.probes?.sent ?? Infinity) && probes.sent <= (after.probes?.sent ?? -1), '09g the row probes cell reads `<sent> of <budget>` inside the witness bracket', `row ${j(rendered.rowProbes)}, witness sent ${before.probes?.sent}..${after.probes?.sent}`);
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 Jobs view: cancelled', async () => {
    if (!job3) {
      note('10 skipped', 'step 09 started no job');
      return;
    }
    const job = job3;
    const card = cardSel(job);
    const pre = await status(job);
    if (TERMINAL.has(pre.state)) {
      gap('10 cancel', `job ${job} is already ${pre.state} before Cancel could be pressed`);
      return;
    }
    const cancel = await soft(() => d.q('find', { sel: `${card} button[aria-label="Cancel scan ${job}"]` }), 3000);
    if (!cancel || cancel.disabled) {
      fail('10 the card offers Cancel scan', `Cancel scan ${job} is ${cancel ? 'disabled' : 'absent'} in the card though the witness reads ${pre.state}`);
      return;
    }
    await d.mouse(cancel.x, cancel.y); // one real click, the only Cancel press of this job
    const pressedAt = Date.now();
    out(`  click Cancel scan ${job}`);
    const cancelled = await witnessUntil(job, (st) => st.state === 'cancelled', 20000);
    if (!cancelled) {
      const last = await status(job);
      keepStatus('10', { job, last });
      fail('10 the witness reads cancelled after one Cancel press', `not within 20 s; last ${last.state} · ${last.phase ?? '—'}`);
      return;
    }
    note('10 witness', `cancelled ${Date.now() - pressedAt} ms after the press`);
    // The end sentence waits for the store's terminal status read (D9): give it the poll.
    const end = await soft(async () => (await rawText(`${card} [data-field=end]`)) || null, 8000);
    const rendered = {
      chip: await d.q('text', `${card} [data-field=state]`),
      rowState: await d.q('text', `${rowSel(job)} [data-field=state]`),
      end,
      stopped: await rawText(`${card} [data-field=stopped]`),
      rowProgress: await rawText(`${rowSel(job)} [data-field=progress]`),
    };
    const final = await status(job);
    keepStatus('10', { job, cancelled, final, rendered });
    await still('10-jobs-cancelled.png');
    expect(rendered.chip === 'Cancelled', '10a the card chip reads Cancelled after the witness read cancelled', `chip ${j(rendered.chip)}`);
    expect(rendered.rowState === 'Cancelled', '10a the row state word reads Cancelled', `row ${j(rendered.rowState)}`);
    const m = CANCELLED_SENTENCE.exec(end ?? '');
    const want = { done: grouped(final.checks.done), scheduled: grouped(final.checks.scheduled), elapsed: Math.floor(final.elapsed_ms / 1000) };
    expect(!!m && m[2] === want.done && m[3] === want.scheduled, '10b the end sentence is `Cancelled after m:ss; N of M checks had run. What it found stays.` with the witness numbers', `end ${j(end)}; witness ${want.done} of ${want.scheduled}`);
    if (m) expect(Math.abs(elapsedSeconds(m[1]) - want.elapsed) <= 1, '10b the end sentence elapsed is the witness elapsed_ms (±1 s)', `sentence ${m[1]}, witness ${fmtElapsed(final.elapsed_ms)} (${final.elapsed_ms} ms)`);
    // D4: the `cancelled` reason is said by the state sentence, so no Stopped line; any other
    // reason reads as its D4 sentence, never the raw token.
    if (final.stopped_reason === 'cancelled' || final.stopped_reason == null) expect(rendered.stopped === null, '10c no [data-field=stopped] line for a cancelled job (D4)', `stopped ${j(rendered.stopped)}, witness stopped_reason ${j(final.stopped_reason ?? null)}`);
    else expect(typeof rendered.stopped === 'string' && rendered.stopped.startsWith('Stopped early'), '10c [data-field=stopped] is the D4 sentence for the witness stopped_reason', `stopped ${j(rendered.stopped)}, witness stopped_reason ${j(final.stopped_reason)}`);
    // The run directory's audit log (gap 57): exactly one scan.cancel for the job.
    const auditPath = join(env.dir, 'audit.jsonl');
    const lines = (await soft(async () => {
      const hits = cancelLinesFor(existsSync(auditPath) ? readFileSync(auditPath, 'utf8') : '', job);
      return hits.length > 0 ? hits : null;
    }, 5000)) ?? [];
    expect(lines.length === 1, '10d the run directory audit log holds exactly one scan.cancel for the job', `${lines.length} line(s) in ${auditPath}`);
  });

  // 11 ---------------------------------------------------------------------------------------
  await step('11 Jobs view: dead target done', async () => {
    await setViewport(JOBS_VIEWPORT);
    await waitForQuietEngine('11', 60000);
    // The dead origin is the scope's second host; the editor's `Origin host` is a native <select>
    // headless Chrome cannot drive with key events (see pickSelect), so the launch goes over the
    // witness bus (the same real core; the UI renders what the engine did). The capture and every
    // assertion are on the UI.
    const listed = (await bus.call('scan.list', {})).jobs?.map((x) => x.job) ?? [];
    let started;
    try {
      started = await bus.call('scan.start', { profile_name: DEAD_PROFILE, overrides: { target: { origins: [DEAD_ORIGIN] } } });
    } catch (e) {
      fail('11 the dead-target job starts', e.message.split('\n')[0]);
      return;
    }
    const job = started?.job ?? null;
    if (!job || listed.includes(job)) {
      fail('11 the dead-target job starts', `scan.start answered ${j(started)}`);
      return;
    }
    note('11 start', `${DEAD_PROFILE} against ${DEAD_ORIGIN} (port ${DEAD_PORT}, never listened on) over the witness: ${job}`);
    const terminal = await witnessUntil(job, (st) => TERMINAL.has(st.state), 180000);
    if (!terminal) {
      const last = await status(job);
      keepStatus('11', { job, last });
      fail('11 the witness reads a terminal state', `not within 180 s; last ${last.state} · ${last.phase ?? '—'}`);
      return;
    }
    if (!(terminal.state === 'done' && terminal.stopped_reason === 'errors')) {
      keepStatus('11', { job, terminal });
      gap('11 dead target', `the engine ended ${job} ${terminal.state} with stopped_reason ${j(terminal.stopped_reason ?? null)} (checks.errors ${terminal.checks?.errors ?? '?'}); AC58 (c) needs done + errors`);
      return;
    }
    await ensureJobsTab();
    const row = await soft(() => d.q('exists', rowSel(job)), 10000);
    if (!row) {
      fail('11 the Jobs table lists the dead-target job', `${rowSel(job)} never appeared within 10 s`);
      return;
    }
    if (!(await selectJobRow(job))) {
      fail('11 the card shows the dead-target job', `the Selected job region reads data-job ${j(await attr(STRIP, 'data-job'))}, wanted ${job}`);
      return;
    }
    const card = cardSel(job);
    // The Stopped line needs the card's own status read (W1): wait for it, then read everything.
    const stopped = await soft(async () => (await rawText(`${card} [data-field=stopped]`)) || null, 8000);
    const summaries = await textsOf(`${card} [data-field=attention] details > summary`);
    const plain = await textsOf(`${card} [data-field=attention] > p`);
    const attentionLine = [...summaries, ...plain].find((t) => ATTENTION_ERRORS.test(t)) ?? null;
    let opened = null;
    if (attentionLine !== null && summaries.includes(attentionLine)) {
      await d.click({ sel: `${card} [data-field=attention] details > summary`, text: attentionLine, match: 'exact' });
      opened = await soft(async () => ((await countOf(`${card} [data-field=attention] details[open]`)) > 0 ? true : null), 2000);
    }
    const rendered = {
      chip: await d.q('text', `${card} [data-field=state]`),
      rowState: await d.q('text', `${rowSel(job)} [data-field=state]`),
      stopped,
      stoppedRaw: await rawText(`${card} [data-field="stopped-raw"]`),
      attentionLine,
      opened,
      sub: await rawText(`${rowSel(job)} [data-field=sub]`),
      subTitle: await attr(`${rowSel(job)} [data-field=sub]`, 'title'),
      cardText: await layoutText(card),
    };
    const final = await status(job);
    keepStatus('11', { job, terminal, final, rendered });
    await still('11-jobs-dead.png');
    expect(rendered.stopped === STOPPED_ERRORS_SENTENCE, '11a [data-field=stopped] reads the D4 sentence for stopped_reason errors', `stopped ${j(rendered.stopped)}`);
    expect(rendered.stoppedRaw === RAW_ERRORS_LINE, '11b [data-field="stopped-raw"] reads the raw token line', `stopped-raw ${j(rendered.stoppedRaw)}`);
    const n = attentionLine === null ? null : ungroup(ATTENTION_ERRORS.exec(attentionLine)[1]);
    expect(n !== null && n === final.checks.errors, '11c the attention line reads `<n> checks could not run` with n = the witness checks.errors', `line ${j(attentionLine)}, witness checks.errors ${final.checks.errors}; summaries ${j(summaries)}, plain ${j(plain)}`);
    if (opened !== null) expect(opened === true, '11c the attention details opens on a real click', 'details[open] absent 2 s after the click');
    else note('11c attention disclosure', attentionLine === null ? 'no count line to open' : 'the count line is a plain <p> (no samples), nothing to open');
    const rawCount = (rendered.cardText?.match(/stopped_reason:/g) ?? []).length;
    const stray = strayErrorsTokens(rendered.cardText ?? '');
    expect(rawCount === 1 && stray === 1, '11d `stopped_reason: errors` is the only raw errors token inside the card', `stopped_reason: ×${rawCount}, errors tokens outside the D4 and crawl sentences ${stray}`);
    expect(rendered.subTitle === STOPPED_ERRORS_SENTENCE && rendered.sub === STOPPED_ERRORS_SENTENCE, '11e the row sub-line carries the D4 sentence (title = the full sentence)', `sub ${j(rendered.sub)}, title ${j(rendered.subTitle)}`);
    expect(rendered.rowState === 'Done' && rendered.chip === 'Done', '11f the row and the chip read Done', `row ${j(rendered.rowState)}, chip ${j(rendered.chip)}`);
  });
  await setViewport({ width: W, height: H });
}

// ------------------------------------------------------------------------------------------
// Harness
// ------------------------------------------------------------------------------------------
const RUN_DIR = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'aitm-scan-live-'));
const FINDINGS_DIR = join(RUN_DIR, 'findings');
mkdirSync(FINDINGS_DIR, { recursive: true });
/** Step 05's wait for the first standard job: ~2 min with the 400 ms target latency. */
const FIRST_JOB_WAIT_MS = TARGET_LATENCY_MS > 0 ? 300000 : 120000;
/** The dead port of step 11: picked free (in the try below), never listened on, in scope from the start (AC58 (c)). */
let DEAD_PORT = null;
let DEAD_HOST = null;
let DEAD_ORIGIN = null;
/** The run's scope: the target first (the origin picker defaults to the first scope host), then the dead host. */
const scopeHosts = () => [target.host, DEAD_HOST];

/**
 * The test target binary with AC58's `--latency-ms`: `startTestTarget` (live-env.mjs) takes a
 * `bin` and no extra arguments, so a one-line `exec` shim in the run dir appends the flag; `exec`
 * keeps the pid the binary's, so `stop()`'s SIGINT reaches it. Without latency the real binary.
 */
function testTargetBin() {
  const real = process.env.AITM_TESTTARGET_BIN ?? join(REPO, 'target/debug/aitm-testtarget-serve');
  if (!(TARGET_LATENCY_MS > 0) || !existsSync(real)) return real;
  const shim = join(RUN_DIR, 'aitm-testtarget-serve-latent.sh');
  writeFileSync(shim, `#!/bin/sh\nexec ${shellQuote(real)} "$@" --latency-ms ${Math.floor(TARGET_LATENCY_MS)}\n`, { mode: 0o755 });
  return shim;
}

/**
 * Gap 57 / AC59: the written config must carry `audit_log` under `mcp:` and under `ca:` with both
 * paths inside the run dir; the lines are quoted into `config-audit-lines.txt`. Otherwise both lines
 * are printed and the process exits 2 before any step: the proof never runs against the operator's
 * logs. (`startAitm` already refuses such a config; this is the proof's own record of the fact.)
 */
async function auditPreflightOrExit(where) {
  const text = readFileSync(env.cfg, 'utf8');
  const lines = auditLogLines(text);
  const ok = insideDir(auditLogPath(lines.mcp), env.dir) && insideDir(auditLogPath(lines.ca), env.dir);
  const report = [`# ${where}: ${env.cfg}`, `run dir: ${env.dir}`, `mcp: ${lines.mcp ?? '(no audit_log line under mcp:)'}`, `ca: ${lines.ca ?? '(no audit_log line under ca:)'}`, `verdict: ${ok ? 'both inside the run dir' : 'REFUSED'}`, ''].join('\n');
  appendFileSync(join(SHOTS, 'config-audit-lines.txt'), report + '\n');
  if (ok) {
    note(`00 audit-log preflight ${where}`, `mcp ${j(auditLogPath(lines.mcp))} · ca ${j(auditLogPath(lines.ca))} (inside ${env.dir})`);
    return;
  }
  out(`REFUSED: the written config does not keep both audit logs in the run dir (${where})\n${report}`);
  try {
    bus?.close();
  } catch {}
  cdp?.close();
  await env?.stop();
  await target?.stop();
  process.exit(2);
}

/** `{ 'audit.jsonl': { size, sha256 }, 'ca-audit.jsonl': … }` of Matt's real store. */
const operatorAuditDigests = () => Object.fromEntries(OPERATOR_AUDIT_FILES.map((f) => [f, fileDigest(join(OPERATOR_STORE, f))]));
const digestLines = (digests) => Object.entries(digests).map(([f, dg]) => `  ${f} size=${dg.size} sha256=${dg.sha256}`);
let auditBefore = null;

try {
  DEAD_PORT = await freePort();
  DEAD_HOST = `127.0.0.1:${DEAD_PORT}`;
  DEAD_ORIGIN = `http://${DEAD_HOST}`;
  target = await startTestTarget({ mode: 'vulnerable', bin: testTargetBin() });
  env = await startAitm({
    scope: scopeHosts(),
    findingsDir: FINDINGS_DIR,
    // The L4 layer is ON with NO scope entry: that is the "no L4 scope" of step 8a. With the layer
    // off the core offers no `l4.scope.list`, and preflight (launch.ts) then stops at `the L4 layer
    // is not enabled on this core` before the D11 coverage hint can be reached. Enabling it builds
    // the guard and the flow store only (crates/aitm/src/main.rs); no capture is opened.
    l4: { enabled: true },
    log: (l) => (/error|panic/i.test(l) ? out('[aitm] ' + l) : null),
  });
  writeFileSync(join(SHOTS, 'config-audit-lines.txt'), '');
  await auditPreflightOrExit('at startup');
  // AC59: Matt's real logs, hashed before the first step; compared after the last (the finally block).
  auditBefore = operatorAuditDigests();
  writeFileSync(join(SHOTS, 'audit-before-after.txt'), [`operator store: ${OPERATOR_STORE}`, `before ${new Date().toISOString()}`, ...digestLines(auditBefore), ''].join('\n'));
  if (requireOperator('at startup') && (await requireDeadPortIsolated('at startup'))) {
    bus = await witness(env.busUrl, env.operatorToken, 'witness');
    // The operator URL carries the bridge token: printed redacted, here and under --keep.
    out(`aitm up: proxy ${env.proxyPort}, ui ${redactOperatorUrl(env.operatorUiUrl)}, target ${target.base} (${target.mode}, latency ${TARGET_LATENCY_MS} ms), dead port ${DEAD_PORT}, findings ${FINDINGS_DIR}`);
    cdp = await launchChrome({ width: W, height: H });
    d = makeDriver(cdp, { log: out, shotsDir: SHOTS });
    await run();
    if (cdp.consoleErrors.length) note('console errors', JSON.stringify(cdp.consoleErrors.slice(0, 10)));
  }
} catch (e) {
  fail('harness', e.stack ?? e.message);
} finally {
  if (auditBefore !== null) {
    const auditAfter = operatorAuditDigests();
    const unchanged = sameDigests(auditBefore, auditAfter);
    appendFileSync(join(SHOTS, 'audit-before-after.txt'), [`after ${new Date().toISOString()}`, ...digestLines(auditAfter), `verdict: ${unchanged ? 'UNCHANGED' : 'CHANGED'}`, ''].join('\n'));
    expect(unchanged, "12 Matt's real audit.jsonl and ca-audit.jsonl are unchanged by the run (size and sha256)", `before ${j(auditBefore)} after ${j(auditAfter)}`);
  }
  const summary = {
    pass: results.filter((r) => r.status === 'PASS').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    gap: results.filter((r) => r.status === 'GAP').length,
    shots: SHOTS,
    results,
  };
  out(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.gap} GAP · screenshots in ${SHOTS} · transcript ${TRANSCRIPT}`);
  if (KEEP && env) {
    out(`--keep: aitm and Chrome left running. UI: ${redactOperatorUrl(env.operatorUiUrl)} (token redacted)  proxy: 127.0.0.1:${env.proxyPort}  target: ${target?.base}`);
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
