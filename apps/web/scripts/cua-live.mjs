// HUMAN-PATH live check of the web operator UI: a real headless Chrome, driven over CDP with real
// input events only (Input.dispatchMouseEvent / dispatchKeyEvent / insertText — never synthetic
// DOM events, never app functions), clicking and typing through the UI served by a spawned
// `aitm web`, with real traffic through the real proxy. Every step takes a screenshot into
// .cua-shots/ and is cross-checked over the bus. Exit 1 on any FAIL.
//
//   node scripts/cua-live.mjs [--keep]
//
// --keep leaves aitm and Chrome running and prints the UI URL. Node ≥ 22, no dependencies.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, sleep, startAitm, startTarget, viaProxy, waitFor } from './live-env.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-shots');
const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const KEEP = process.argv.includes('--keep');
const W = 1600;
const H = 1000;

// ------------------------------------------------------------------------------------------
// Results
// ------------------------------------------------------------------------------------------
const results = [];
let shotN = 0;
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
function record(status, step, detail) {
  results.push({ status, step, detail });
  console.log(`${status.padEnd(4)} ${step}${detail ? ` — ${detail}` : ''}`);
}
const pass = (step, detail) => record('PASS', step, detail);
const fail = (step, detail) => record('FAIL', step, detail);
const gap = (step, detail) => record('GAP', step, detail);
const note = (step, detail) => record('NOTE', step, detail);

// ------------------------------------------------------------------------------------------
// Chrome over CDP
// ------------------------------------------------------------------------------------------
async function launchChrome() {
  const profile = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'aitm-cua-profile-'));
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--hide-scrollbars',
      '--force-device-scale-factor=1',
      `--window-size=${W},${H}`,
      '--user-data-dir=' + profile,
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
  const wsUrl = await new Promise((res, rej) => {
    let buf = '';
    chrome.stderr.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) res(m[1]);
    });
    chrome.on('exit', (code) => rej(new Error(`chrome exited ${code}\n${buf}`)));
    setTimeout(() => rej(new Error('chrome did not start\n' + buf)), 15000);
  });
  const ws = new WebSocket(wsUrl);
  await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = () => j(new Error('cdp connect failed')))));
  let nextId = 1;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`${msg.error.message}${msg.error.data ? ` ${msg.error.data}` : ''}`)) : resolve(msg.result);
    } else if (msg.method && listeners.has(msg.method)) for (const fn of listeners.get(msg.method)) fn(msg.params);
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const s = (m, p) => send(m, p, sessionId);
  const on = (method, fn) => {
    if (!listeners.has(method)) listeners.set(method, new Set());
    listeners.get(method).add(fn);
    return () => listeners.get(method).delete(fn);
  };
  await s('Page.enable');
  await s('Runtime.enable');
  await s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  await s('Emulation.setFocusEmulationEnabled', { enabled: true });
  const consoleErrors = [];
  on('Runtime.exceptionThrown', (p) => consoleErrors.push(p.exceptionDetails?.exception?.description ?? p.exceptionDetails?.text ?? 'exception'));
  on('Runtime.consoleAPICalled', (p) => {
    if (p.type === 'error') consoleErrors.push(p.args.map((a) => a.value ?? a.description ?? '').join(' '));
  });
  return {
    s,
    on,
    consoleErrors,
    close: () => {
      try {
        ws.close();
      } catch {}
      chrome.kill('SIGTERM');
      setTimeout(() => rmSync(profile, { recursive: true, force: true }), 500);
    },
  };
}

// ------------------------------------------------------------------------------------------
// Page-side locator (installed with Runtime.evaluate; read-only on the DOM apart from scrollIntoView)
// ------------------------------------------------------------------------------------------
function pageHelper() {
  const norm = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const visible = (el) => {
    if (!el.isConnected || el.closest('[aria-hidden="true"]')) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
  };
  const ROLE_SEL = {
    any: '*',
    button: 'button,[role=button]',
    tab: '[role=tab]',
    row: '[role=row]',
    menuitem: '[role=menuitem],[role=menuitemradio]',
    input: 'input,textarea,select',
    option: '[role=option]',
    radio: '[role=radio]',
    status: '[role=status]',
    dialog: '[role=dialog]',
    alert: '[role=alert]',
    cell: '[role=cell],[role=gridcell]',
    menu: '[role=menu]',
    region: '[role=region]',
  };
  const parts = (el) => {
    const p = [];
    if (el.matches('input,textarea,select')) p.push(el.getAttribute('aria-label'), el.placeholder, el.value);
    else p.push(norm(el.innerText ?? el.textContent), el.getAttribute('aria-label'), el.getAttribute('title'));
    return p.filter((x) => x != null && x !== '').map(norm);
  };
  const matches = (el, text, mode) => {
    const ps = parts(el);
    if (mode === 'exact') return ps.some((p) => p === text);
    if (mode === 'startsWith') return ps.some((p) => p.startsWith(text));
    return ps.some((p) => p.includes(text));
  };
  function all(spec) {
    const { role = 'any', text, match = 'includes', within, sel } = spec;
    const roots = within ? Array.from(document.querySelectorAll(within)) : [document];
    const selector = sel ?? ROLE_SEL[role] ?? `[role=${role}]`;
    let out = [];
    for (const root of roots) for (const el of root.querySelectorAll(selector)) if (visible(el) && (text == null || matches(el, text, match))) out.push(el);
    if (role === 'any' && !sel && text != null) out = out.filter((el) => !out.some((o) => o !== el && el.contains(o)));
    return out;
  }
  function describe(el) {
    const r = el.getBoundingClientRect();
    return {
      x: r.left + r.width / 2,
      y: r.top + r.height / 2,
      w: r.width,
      h: r.height,
      tag: el.tagName,
      text: norm(el.innerText ?? el.textContent).slice(0, 240),
      value: 'value' in el ? el.value : null,
      id: el.dataset?.id ?? null,
      disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
    };
  }
  function find(spec) {
    const els = all(spec);
    const n = spec.nth ?? 0;
    const el = els[n < 0 ? els.length + n : n];
    if (!el) return null;
    el.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    return { ...describe(el), count: els.length };
  }
  const count = (spec) => all(spec).length;
  const texts = (spec) => all(spec).map((el) => norm(el.innerText ?? el.textContent).slice(0, 240));
  function text(selector) {
    const el = document.querySelector(selector);
    return el ? norm(el.innerText ?? el.textContent) : null;
  }
  const exists = (selector) => !!document.querySelector(selector);
  function rowInfo(id) {
    const el = document.querySelector(`[role=row][data-id="${CSS.escape(id)}"]`);
    if (!el) return null;
    return {
      text: norm(el.innerText),
      edited: !!el.querySelector('[title="Edited while paused"]'),
      mark: el.querySelector('[title^="Marked "]')?.getAttribute('title') ?? null,
      selected: el.getAttribute('aria-selected') === 'true',
      ...describe(el),
    };
  }
  /** The value input of the editable request-header row whose name input reads `name`. */
  function headerValueInput(name) {
    for (const row of document.querySelectorAll('section[aria-label="Request"] [role=table] [role=row]')) {
      const ins = row.querySelectorAll('input');
      if (ins.length >= 2 && ins[0].value.toLowerCase() === name.toLowerCase()) return describe(ins[1]);
    }
    return null;
  }
  /** A blank spot in the flow grid (below the last row) to click so focus rests on the list, not an input. */
  function gridBlank() {
    const grid = document.querySelector('[role=grid][aria-label="Flows"]');
    if (!grid) return null;
    const g = grid.getBoundingClientRect();
    let maxBottom = g.top + 28;
    for (const r of grid.querySelectorAll('[role=row]')) maxBottom = Math.max(maxBottom, r.getBoundingClientRect().bottom);
    const y = Math.min(g.bottom - 6, maxBottom + 12);
    return { x: g.left + g.width / 2, y, roomBelowRows: g.bottom - maxBottom };
  }
  function active() {
    const a = document.activeElement;
    if (!a) return null;
    return `${a.tagName.toLowerCase()}${a.getAttribute('role') ? `[role=${a.getAttribute('role')}]` : ''}${a.getAttribute('aria-label') ? `[aria-label=${a.getAttribute('aria-label')}]` : ''}`;
  }
  const cm = (within) => {
    const el = document.querySelector(`${within} .cm-content`);
    return el ? (el.innerText ?? el.textContent) : null;
  };
  window.__cua = { find, count, texts, text, exists, rowInfo, headerValueInput, gridBlank, active, cm };
  return true;
}

// ------------------------------------------------------------------------------------------
// Driver
// ------------------------------------------------------------------------------------------
const VK = { Enter: 13, Escape: 27, Tab: 9, Backspace: 8, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Home: 36, End: 35, ' ': 32 };

function makeDriver(cdp, log) {
  const { s } = cdp;
  const ev = async (expression) => {
    const r = await s('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(`page eval failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  };
  const q = (fn, ...args) => ev(`window.__cua.${fn}(${args.map((a) => JSON.stringify(a)).join(',')})`);
  const install = () => ev(`(${pageHelper.toString()})()`);
  const describeSpec = (spec) => (spec.sel ? spec.sel : `${spec.role ?? 'element'}${spec.text != null ? ` "${spec.text}"` : ''}${spec.within ? ` within ${spec.within}` : ''}`);

  const locate = (spec, { timeoutMs = 8000 } = {}) => waitFor(() => q('find', spec), { timeoutMs, everyMs: 100, what: describeSpec(spec) });
  const gone = (spec, { timeoutMs = 8000 } = {}) => waitFor(async () => (await q('count', spec)) === 0, { timeoutMs, everyMs: 100, what: `${describeSpec(spec)} to go away` });

  async function mouse(x, y, { button = 'left', clickCount = 1 } = {}) {
    await s('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, button: 'none' });
    await s('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button, clickCount, buttons: button === 'left' ? 1 : 2 });
    await s('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button, clickCount, buttons: 0 });
  }
  async function click(spec, opts = {}) {
    const p = await locate(spec, opts);
    log(`  click ${describeSpec(spec)} @ ${Math.round(p.x)},${Math.round(p.y)}${opts.button === 'right' ? ' (right)' : ''}`);
    await mouse(p.x, p.y, opts);
    return p;
  }
  const rightClick = (spec, opts = {}) => click(spec, { ...opts, button: 'right' });
  const type = async (text) => {
    log(`  type ${JSON.stringify(text)} into ${await q('active')}`);
    await s('Input.insertText', { text });
  };
  async function key(name, { meta = false, shift = false, commands } = {}) {
    const vk = VK[name] ?? name.toUpperCase().charCodeAt(0);
    const code = name.length === 1 ? (name === ' ' ? 'Space' : `Key${name.toUpperCase()}`) : name;
    const modifiers = (meta ? 4 : 0) | (shift ? 8 : 0);
    const base = { key: name, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers };
    log(`  key ${meta ? '⌘' : ''}${shift ? '⇧' : ''}${name === ' ' ? 'Space' : name} (focus: ${await q('active')})`);
    // Enter needs a `text` of \r to produce the keypress that drives implicit form submission, as a real keyboard does.
    const text = name.length === 1 && !meta ? name : name === 'Enter' && !meta ? '\r' : null;
    await s('Input.dispatchKeyEvent', { type: 'keyDown', ...base, ...(text ? { text, unmodifiedText: text } : {}), ...(commands ? { commands } : {}) });
    await s('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
  }
  const selectAll = () => key('a', { meta: true, commands: ['selectAll'] });
  async function focusList() {
    const p = await waitFor(() => q('gridBlank'), { what: 'flow grid' });
    await mouse(p.x, p.y);
    await sleep(80);
    return q('active');
  }
  async function shot(name, { scale = 1 } = {}) {
    if (scale !== 1) await s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: scale, mobile: false });
    await sleep(scale !== 1 ? 250 : 60);
    const r = await s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    const file = join(SHOTS, `${String(++shotN).padStart(2, '0')}-${slug(name)}.png`);
    writeFileSync(file, Buffer.from(r.data, 'base64'));
    if (scale !== 1) await s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    return file;
  }
  async function open(url) {
    // Navigating to the URL already shown (same path, only a fragment) never fires a load event;
    // go through about:blank so a reload is a real reload.
    for (const u of ['about:blank', url]) {
      const loaded = new Promise((r) => cdp.on('Page.loadEventFired', r));
      await s('Page.navigate', { url: u });
      await Promise.race([loaded, sleep(5000)]);
    }
    await install();
  }
  return { ev, q, install, locate, gone, mouse, click, rightClick, type, key, selectAll, focusList, shot, open };
}

// ------------------------------------------------------------------------------------------
// Main
// ------------------------------------------------------------------------------------------
const REQ = 'section[aria-label="Request"]';
const RES = 'section[aria-label="Response"]';
const GRID = '[role=grid][aria-label="Flows"]';
const BAR = '[role=status]';
const EDITBAR = '[role=region][aria-label="Pending edits"]';
const SIDEBAR = 'aside[aria-label="Sources"]';

mkdirSync(SHOTS, { recursive: true });
for (const f of (await import('node:fs')).readdirSync(SHOTS)) if (f.endsWith('.png')) rmSync(join(SHOTS, f));

let target, env, bus, cdp, d;
const log = (m) => console.log(m);
const hdr = (h) => Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
const detailHeaders = (detail) => {
  const h = detail?.request?.headers;
  if (Array.isArray(h)) return hdr(Object.fromEntries(h.map((x) => (Array.isArray(x) ? x : [x.name, x.value]))));
  return hdr(h);
};

/** Runs one step: PASS unless the body throws or calls fail(); always ends with a screenshot. */
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
      log(`  shot ${f}`);
    } catch (e) {
      log(`  (screenshot failed: ${e.message})`);
    }
  }
}
const expect = (cond, okMsg, badMsg) => (cond ? pass(okMsg) : fail(okMsg, badMsg));

try {
  target = await startTarget();
  env = await startAitm({ scope: [target.host], log: (l) => (/error|panic/i.test(l) ? console.error('[aitm] ' + l) : null) });
  bus = await connectBus(env.busUrl, env.token);
  const tools = (await bus.tools()).map((t) => t.name);
  log(`aitm up: proxy ${env.proxyPort}, ui ${env.uiUrl}, target ${target.base}`);
  log(`bus tools: ${tools.join(' ')}`);
  cdp = await launchChrome();
  d = makeDriver(cdp, log);

  let meId = null;
  let meRowSpec = null;

  // 1 ----------------------------------------------------------------------------------------
  await step('01 connect', async () => {
    await d.open(env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'status bar "bus open"' });
    await d.locate({ sel: GRID });
    const empty = await d.q('find', { text: 'No flows yet', within: GRID });
    const busText = (await d.q('texts', { sel: 'span[title="bus open"]' }))[0];
    pass('01 connect', `status bar "${busText}"; empty state: ${empty ? `"${empty.text}"` : 'not shown'}`);
  });

  // 2 ----------------------------------------------------------------------------------------
  await step('02 capture and inspect', async () => {
    const r = await viaProxy(env.proxyPort, 'GET', `${target.base}/api/me`);
    if (r.status !== 200) throw new Error(`proxy GET /api/me → ${r.status}`);
    meRowSpec = { role: 'row', text: '/api/me', within: GRID };
    const row = await d.click(meRowSpec);
    meId = row.id;
    await d.locate({ sel: `${REQ} [role=table]` });
    // Request pane may still be on a non-Headers tab from a previous session; select Headers.
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    const host = await d.locate({ role: 'cell', text: 'host', match: 'exact', within: REQ });
    expect(!!host, '02a request Headers tab shows host', 'no host cell');
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: RES });
    const sc = await d.locate({ role: 'cell', text: 'set-cookie', match: 'exact', within: RES });
    expect(!!sc, '02b response Headers shows set-cookie row');
    await d.click({ role: 'tab', text: 'Set-Cookie', match: 'startsWith', within: RES });
    const cookie = await d.locate({ role: 'cell', text: 'session', match: 'exact', within: RES });
    expect(!!cookie, '02c response Set-Cookie shows cookie "session"');
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: RES });
    const body = await waitFor(async () => {
      const t = await d.q('cm', RES);
      return t && t.includes('ops@target.test') ? t : null;
    }, { what: 'response body in CodeMirror' });
    expect(body.includes('ops@target.test'), '02d response Body (.cm-content) contains ops@target.test');
    await d.click({ role: 'tab', text: 'Raw', match: 'startsWith', within: REQ });
    await sleep(400);
    const raw = (await d.q('cm', REQ)) ?? '';
    const rawPane = (await d.q('find', { text: 'No body', within: REQ }))?.text ?? raw.slice(0, 60);
    if (raw.trim().startsWith('GET /api/me')) pass('02e request Raw starts with "GET /api/me"', raw.slice(0, 60));
    else gap('02e request Raw does not show the request line/headers', `Request › Raw shows only the raw BODY ("${rawPane}") — the "GET /api/me HTTP/1.1 + headers" document exists only while editing a paused request; a human cannot see the raw request of a completed flow`);
    const summary = await d.q('text', '[role=region][aria-label="Flow summary"]');
    expect(/\b200\b/.test(summary ?? ''), '02f summary strip shows 200', `strip: "${summary}"`);
  });

  // 3 ----------------------------------------------------------------------------------------
  await step('03 arm by keyboard (i)', async () => {
    const focus = await d.focusList();
    await d.key('i');
    const bar = await d.locate({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(bar && st.intercept_armed === true, '03 "i" arms intercept', `focus was ${focus}; bar "${bar?.text}"; proxy.status.intercept_armed=${st.intercept_armed}`);
  });

  // 4 ----------------------------------------------------------------------------------------
  let pausedId = null;
  await step('04 intercept, edit headers by clicking, Apply & Resume', async () => {
    const pending = viaProxy(env.proxyPort, 'POST', `${target.base}/api/echo`, { headers: { 'x-orig': 'a', 'content-type': 'application/json' }, body: '{"n":1}', timeoutMs: 60000 });
    pending.catch(() => {});
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    pausedId = row.id;
    const bar = await d.locate({ role: 'status', text: '1 paused' });
    pass('04a paused row + bar', `row "${row.text}"; bar "${bar.text.slice(0, 80)}"`);
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    await d.click({ role: 'button', text: 'Add header', match: 'exact', within: REQ }, { timeoutMs: 10000 });
    // The new row is the last name input (empty, placeholder "name"). Type like a human: one key at a time.
    const nameSpec = { role: 'input', text: 'name', match: 'exact', within: `${REQ} [role=table]`, nth: -1 };
    await d.click(nameSpec);
    const focusBefore = await d.q('active');
    let lostFocusAt = null;
    for (const ch of 'x-cua') {
      await d.type(ch);
      const now = await d.q('active');
      if (now !== focusBefore) {
        lostFocusAt ??= { ch, now };
        await d.click(nameSpec); // a human has to click back into the field after every keystroke
        await d.key('End');
      }
    }
    const nameNow = await d.q('find', nameSpec);
    if (lostFocusAt) fail('04b-focus typing a header name keeps focus', `focus left the input after the first keystroke "${lostFocusAt.ch}" (went to ${lostFocusAt.now}); every keystroke re-renders the header rows (setHeaders → new objects → <For> rebuilds the inputs), so a human cannot type a header name without clicking back in after each character. Name input now reads "${nameNow?.value}"`);
    else pass('04b-focus typing a header name keeps focus');
    // Tab is unreliable once focus was lost; click the value cell as a human would.
    const valueSpec = { role: 'input', text: 'value', match: 'exact', within: `${REQ} [role=table]`, nth: -1 };
    await d.click(valueSpec);
    for (const ch of 'yes') {
      await d.type(ch);
      if ((await d.q('active')) === 'body') {
        await d.click(valueSpec);
        await d.key('End');
      }
    }
    const added = await waitFor(() => d.q('headerValueInput', 'x-cua'), { what: 'x-cua header row' });
    expect(added.value === 'yes', '04b Add header → x-cua: yes present in the draft', `name "${nameNow?.value}" value "${added.value}"`);
    const orig = await d.locate({ sel: 'input', text: 'a', match: 'exact', within: `${REQ} [role=table]` });
    const origInput = await d.q('headerValueInput', 'x-orig');
    if (!origInput) throw new Error('no editable x-orig row');
    await d.mouse(origInput.x, origInput.y);
    await d.selectAll();
    await d.type('b');
    const changed = await waitFor(async () => {
      const v = await d.q('headerValueInput', 'x-orig');
      return v && v.value === 'b' ? v : null;
    }, { what: 'x-orig value to read b', timeoutMs: 3000 }).catch(() => d.q('headerValueInput', 'x-orig'));
    expect(changed?.value === 'b', '04c existing header x-orig: a → b (⌘A + type)', `value input reads "${changed?.value}" (was "${orig?.value}")`);
    const hint = await d.q('text', EDITBAR);
    note('04 edit bar', `"${hint}"`);
    await d.click({ role: 'button', text: 'Apply & Resume', match: 'startsWith', within: EDITBAR });
    const res = await pending;
    let echo = null;
    try {
      echo = JSON.parse(res.body);
    } catch {}
    const eh = hdr(echo?.headers);
    expect(res.status === 200 && eh['x-cua'] === 'yes' && eh['x-orig'] === 'b', '04d upstream saw the operator edit (echo x-cua: yes, x-orig: b)', `status ${res.status}; echo headers x-cua=${eh['x-cua']} x-orig=${eh['x-orig']}`);
    const info = await waitFor(async () => {
      const i = await d.q('rowInfo', pausedId);
      return i && /\b200\b/.test(i.text) && i.edited ? i : null;
    }, { what: 'row to show 200 + Edited marker', timeoutMs: 6000 }).catch(() => d.q('rowInfo', pausedId));
    expect(/\b200\b/.test(info?.text ?? '') && info?.edited, '04e row shows 200 and the Edited marker', `row "${info?.text}" edited=${info?.edited}`);
    const det = await bus.call('flow.detail', { id: pausedId, body: 'none' });
    const dh = detailHeaders(det);
    expect(det.edited === true && dh['x-cua'] === 'yes' && dh['x-orig'] === 'b', '04f bus flow.detail edited:true with the edited headers', `edited=${det.edited} x-cua=${dh['x-cua']} x-orig=${dh['x-orig']}`);
  });

  await step('04g intercept, edit body in the Body tab, Apply & Resume', async () => {
    const pending = viaProxy(env.proxyPort, 'POST', `${target.base}/api/echo`, { headers: { 'content-type': 'application/json' }, body: '{"n":1}', timeoutMs: 60000 });
    pending.catch(() => {});
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: REQ });
    await d.locate({ sel: EDITBAR }, { timeoutMs: 10000 });
    const before = await waitFor(() => d.q('cm', REQ), { what: 'editable request body' });
    const cm = await d.locate({ sel: `${REQ} .cm-content` });
    await d.mouse(cm.x, cm.y);
    await d.selectAll();
    await d.type('{"n":2}');
    const after = await waitFor(async () => {
      const t = await d.q('cm', REQ);
      return t && t.trim() === '{"n":2}' ? t : null;
    }, { what: 'body editor to read {"n":2}', timeoutMs: 3000 }).catch(() => d.q('cm', REQ));
    note('04g body editor', `before "${(before ?? '').trim()}" → after "${(after ?? '').trim()}"; edit bar "${await d.q('text', EDITBAR)}"`);
    await d.click({ role: 'button', text: 'Apply & Resume', match: 'startsWith', within: EDITBAR });
    const res = await pending;
    let echo = null;
    try {
      echo = JSON.parse(res.body);
    } catch {}
    expect(res.status === 200 && echo?.body === '{"n":2}', '04g upstream received the edited body {"n":2}', `status ${res.status}; echo body=${JSON.stringify(echo?.body)} content-length=${hdr(echo?.headers)['content-length']}`);
    const det = await bus.call('flow.detail', { id: row.id, body: 'none' });
    expect(det.edited === true, '04h bus flow.detail edited:true after body edit', `edited=${det.edited}`);
  });

  // 5 ----------------------------------------------------------------------------------------
  await step('05 disarm by clicking', async () => {
    await d.click({ role: 'button', text: 'Disarm', match: 'startsWith', within: BAR });
    await d.gone({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(st.intercept_armed === false, '05 Disarm → bar gone, intercept_armed false', `intercept_armed=${st.intercept_armed}`);
  });

  // 6 ----------------------------------------------------------------------------------------
  await step('06 kill a paused request', async () => {
    await d.focusList();
    await d.key('i');
    await d.locate({ role: 'status', text: 'Intercept armed' });
    const pending = viaProxy(env.proxyPort, 'GET', `${target.base}/api/me`, { timeoutMs: 20000 });
    let clientOutcome = null;
    pending.then((r) => (clientOutcome = `response ${r.status}`), (e) => (clientOutcome = `error: ${e.message}`));
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    await d.click({ role: 'button', text: 'Kill', match: 'startsWith', within: BAR });
    await d.click({ role: 'menuitem', text: 'Reset connection', match: 'startsWith' });
    const info = await waitFor(async () => {
      const i = await d.q('rowInfo', row.id);
      return i && /killed/i.test(i.text) ? i : null;
    }, { what: 'row to show killed', timeoutMs: 6000 }).catch(() => d.q('rowInfo', row.id));
    await waitFor(() => clientOutcome, { what: 'client outcome', timeoutMs: 15000 }).catch(() => (clientOutcome = 'still pending after 15 s'));
    const det = await bus.call('flow.detail', { id: row.id, body: 'none' });
    const killedUpstream = /^error/.test(clientOutcome ?? '') && det.intercept === 'killed';
    expect(
      /killed/i.test(info?.text ?? '') && killedUpstream,
      '06 Kill → Reset connection: row killed, client connection dropped, bus intercept=killed',
      `row "${info?.text}"; client ${clientOutcome}; bus flow.detail.intercept=${det.intercept}${
        !killedUpstream && det.intercept === 'resumed' ? ' — CORE BUG: the UI shows "killed" only from its optimistic patch; the request was forwarded and answered. chain.rs dispatch() sets InterceptState::Resumed unconditionally when the parked handle fires, overwriting the Killed state flow.kill wrote (crates/aitm-core/src/chain.rs ~L80-86), so proto-http never sees Killed' : ''
      }`,
    );
    await d.focusList();
    await d.key('i');
    await d.gone({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(st.intercept_armed === false, '06b "i" again disarms', `intercept_armed=${st.intercept_armed}`);
  });

  // 7 ----------------------------------------------------------------------------------------
  await step('07 context menu: Replay, Mark, Comment', async () => {
    const hitsBefore = target.hits.filter((h) => h.url === '/api/me').length;
    const meRow = { sel: `[role=row][data-id="${meId}"]` };
    await d.rightClick(meRow);
    await d.locate({ role: 'menu', text: '', match: 'includes' });
    await d.click({ role: 'menuitem', text: 'Replay', match: 'startsWith' });
    const replayRow = await waitFor(() => d.q('find', { role: 'row', text: '↻', within: GRID }), { what: 'replay row with ↻', timeoutMs: 8000 });
    await waitFor(() => target.hits.filter((h) => h.url === '/api/me').length > hitsBefore, { what: 'target hit from replay' });
    pass('07a Replay → new ↻ row, target hits grew', `row "${replayRow.text}"; /api/me hits ${hitsBefore} → ${target.hits.filter((h) => h.url === '/api/me').length}`);

    await d.rightClick(meRow);
    await d.click({ role: 'menuitem', text: 'Mark', match: 'startsWith' });
    await d.click({ role: 'menuitem', text: 'Red', match: 'exact' });
    const marked = await waitFor(async () => {
      const i = await d.q('rowInfo', meId);
      return i?.mark ? i : null;
    }, { what: 'mark swatch on the row', timeoutMs: 5000 }).catch(() => d.q('rowInfo', meId));
    const menuStillOpen = (await d.q('count', { role: 'menu' })) > 0;
    if (menuStillOpen) {
      note('07b UX', 'picking a colour from the Mark ▸ submenu leaves the parent context menu open (closed with Esc)');
      await d.key('Escape');
      await d.gone({ role: 'menu' });
    }
    let det = await bus.call('flow.detail', { id: meId, body: 'none' });
    expect(marked?.mark === 'Marked red' && Array.isArray(det.meta?.marks) && det.meta.marks.length > 0, '07b Mark ▸ Red → swatch on the row, bus meta.marks non-empty', `row mark="${marked?.mark}" bus marks=${JSON.stringify(det.meta?.marks)}`);

    await d.rightClick(meRow);
    await d.click({ role: 'menuitem', text: 'Comment', match: 'startsWith' });
    await d.click({ role: 'input', text: 'Comment', match: 'exact', within: '[role=dialog][aria-label="Comment"]' });
    await d.type('cua note');
    await d.key('Enter');
    await d.gone({ sel: '[role=dialog][aria-label="Comment"]' });
    det = await waitFor(async () => {
      const x = await bus.call('flow.detail', { id: meId, body: 'none' });
      return x.meta?.comment === 'cua note' ? x : null;
    }, { what: 'bus comment', timeoutMs: 4000 }).catch(() => bus.call('flow.detail', { id: meId, body: 'none' }));
    expect(det.meta?.comment === 'cua note', '07c Comment… → type → Enter → bus meta.comment', `comment=${JSON.stringify(det.meta?.comment)}`);
  });

  // 8 ----------------------------------------------------------------------------------------
  await step('08 compose (n), send with ⌘⏎, out-of-scope host blocks Send', async () => {
    await d.focusList();
    await d.key('n');
    const dlg = '[role=dialog][aria-modal="true"]';
    await d.locate({ sel: dlg });
    await d.click({ role: 'input', text: 'URL', match: 'exact', within: dlg });
    await d.type(`${target.base}/api/echo?from=cua`);
    const foot = await waitFor(async () => {
      const t = await d.q('text', `${dlg} footer`);
      return t && /in scope/.test(t) ? t : null;
    }, { what: 'compose footer "in scope"', timeoutMs: 3000 }).catch(() => d.q('text', `${dlg} footer`));
    note('08 compose footer', `"${foot}"`);
    await d.key('Enter', { meta: true });
    await d.gone({ sel: dlg });
    const row = await d.locate({ role: 'row', text: 'from=cua', within: GRID }, { timeoutMs: 8000 });
    const hit = target.hits.find((h) => h.url === '/api/echo?from=cua');
    expect(!!row && !!hit, '08a compose GET …/api/echo?from=cua via ⌘⏎ → row + target hit', `row "${row?.text}"; hit ${hit ? `${hit.method} ${hit.url}` : 'none'}`);

    await d.focusList();
    await d.key('n');
    await d.locate({ sel: dlg });
    await d.click({ role: 'input', text: 'URL', match: 'exact', within: dlg });
    await d.type('http://not-in-scope.test/x');
    const foot2 = await waitFor(async () => {
      const t = await d.q('text', `${dlg} footer`);
      return t && /Out of scope/.test(t) ? t : null;
    }, { what: 'compose footer "Out of scope"', timeoutMs: 3000 }).catch(() => d.q('text', `${dlg} footer`));
    const send = await d.q('find', { role: 'button', text: 'Send', match: 'startsWith', within: `${dlg} footer` });
    const f = await d.shot('08b compose out of scope');
    log(`  shot ${f}`);
    expect(/Out of scope/.test(foot2 ?? '') && send?.disabled === true, '08b out-of-scope URL → footer says out of scope, Send disabled', `footer "${foot2}"; Send disabled=${send?.disabled}`);
    await d.key('Escape');
    await d.gone({ sel: dlg });
  });

  // 9 ----------------------------------------------------------------------------------------
  let pocYaml = null;
  await step('09 Build PoC from flow… → Findings', async () => {
    await viaProxy(env.proxyPort, 'GET', `${target.base}/search?q=probe`);
    const row = await d.locate({ role: 'row', text: '/search', within: GRID });
    await d.rightClick({ sel: `[role=row][data-id="${row.id}"]` });
    await d.click({ role: 'menuitem', text: 'Build PoC', match: 'startsWith' });
    const pop = '[role=dialog][aria-label="Build PoC from flow"]';
    await d.locate({ sel: pop });
    await d.click({ role: 'input', text: 'PoC name', match: 'exact', within: pop });
    await d.selectAll();
    await d.type('cua-reflected');
    await d.click({ role: 'input', text: 'Parameter', match: 'exact', within: pop });
    await d.type('q');
    await d.click({ role: 'button', text: 'Build', match: 'startsWith', within: pop });
    await d.gone({ sel: pop });
    await sleep(1200);
    const toast = (await d.q('texts', { role: 'status' })).concat(await d.q('texts', { role: 'alert' })).filter(Boolean);
    const listed = await d.q('find', { role: 'option', text: 'cua-reflected' });
    const pocList = await bus.call('poc.list').catch((e) => ({ error: e.message }));
    const lowerText = await d.q('text', '#aitm-lower');
    note('09 after Build', `toast ${JSON.stringify(toast)}; lower panel "${(lowerText ?? '').slice(0, 120)}"; bus poc.list=${JSON.stringify(pocList).slice(0, 200)}`);
    if (listed) {
      pass('09a finding listed after Build', listed.text);
    } else {
      gap('09a Build PoC from flow…', `poc.build returns YAML text only (never writes poc.dir); bus poc.list=${JSON.stringify(pocList)}. The UI switches to Findings, which shows "${(lowerText ?? '').slice(0, 80)}". Because poc.list exists the store treats the PoC as "listed" and does NOT copy the YAML to the clipboard either — the operator's PoC is discarded with no way to see or save it from the UI.`);
    }
    // Seed: a human who had the YAML (poc.build over the bus is the only way to get it) saves it into poc.dir and reloads.
    pocYaml = await bus.call('poc.build', { flow_id: row.id, name: 'cua-reflected', param: 'q' });
    if (typeof pocYaml !== 'string') pocYaml = pocYaml?.yaml ?? JSON.stringify(pocYaml);
    writeFileSync(join(env.pocDir, 'cua-reflected.yaml'), pocYaml);
    note('09 seeded', `wrote ${join(env.pocDir, 'cua-reflected.yaml')} (${pocYaml.length} bytes) by hand so the Findings path below can be exercised; reloading the UI`);
    await d.open(env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'bus open after reload' });
    // Wait until the store has fetched poc.list (the sidebar count leaves 0) before clicking.
    await waitFor(async () => {
      const b = await d.q('find', { role: 'button', text: 'Findings', match: 'startsWith', within: SIDEBAR });
      return b && !/Findings\s*0$/.test(b.text) ? b : null;
    }, { timeoutMs: 10000, what: 'sidebar Findings count > 0' });
    await sleep(300);
    for (let attempt = 0; attempt < 2; attempt++) {
      await d.click({ role: 'button', text: 'Findings', match: 'startsWith', within: SIDEBAR });
      const ok = await waitFor(() => d.q('exists', '[role=listbox][aria-label="Findings"]'), { timeoutMs: 3000, what: 'Findings list' }).catch(() => false);
      if (ok) break;
      note('09 sidebar', 'first click on Findings did not switch the panel; clicked again');
    }
    const opt = await d.locate({ role: 'option', text: 'cua-reflected' }, { timeoutMs: 8000 });
    await d.mouse(opt.x, opt.y);
    const detail = await waitFor(() => d.q('text', '#aitm-lower'), { what: 'finding detail' });
    const yamlShown = await d.q('find', { sel: '#aitm-lower pre[aria-label="PoC YAML"]' });
    if (yamlShown) pass('09b (seeded file) finding listed and YAML visible', yamlShown.text.slice(0, 80));
    else gap('09b (seeded file) finding listed but YAML not visible', `poc.list summaries carry only {id,title,severity,poc_path}; the detail shows "${/No YAML for this run\./.test(detail) ? 'No YAML for this run.' : detail.slice(0, 100)}" and the UI never calls poc.get`);
    await d.click({ role: 'button', text: 'Run again', match: 'startsWith', within: '#aitm-lower' });
    const runPop = '[role=dialog][aria-label="Run again"]';
    await d.locate({ sel: runPop });
    await d.click({ role: 'input', text: 'https://host', match: 'exact', within: runPop });
    await d.type(target.base);
    await d.click({ role: 'button', text: 'Run', match: 'startsWith', within: runPop }); // the popover has only Cancel and Run ⏎
    await d.gone({ sel: runPop });
    await waitFor(async () => (await d.q('count', { text: 'Running…', within: '#aitm-lower' })) === 0, { what: 'run to finish', timeoutMs: 20000 });
    await sleep(500);
    const after = await d.q('text', '#aitm-lower');
    const alerts = await d.q('texts', { role: 'alert' });
    const statuses = await d.q('texts', { role: 'status' });
    const list2 = await bus.call('poc.list').catch((e) => ({ error: e.message }));
    const hitSearch = target.hits.filter((h) => h.url.startsWith('/search')).length;
    const verdict = /Passed|Failed/.test(after ?? '');
    if (verdict) pass('09c Run again → Run → verdict shown', `${(after.match(/Passed|Failed/) ?? [])[0]}; target /search hits=${hitSearch}; poc.list=${JSON.stringify(list2).slice(0, 160)}`);
    else gap('09c Run again → Run shows no verdict', `after run: no "Passed"/"Failed" in the detail; toasts ${JSON.stringify([...alerts, ...statuses])}; target /search hits=${hitSearch}; the panel re-reads poc.list (which lists files, not runs) so the run result is dropped unless its id matches a listed PoC; poc.list=${JSON.stringify(list2).slice(0, 160)}`);
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 scope panel: add and remove a host', async () => {
    await d.click({ role: 'button', text: 'Scope', match: 'startsWith', within: SIDEBAR });
    const panel = 'section[aria-label="Scope"]';
    await d.locate({ sel: panel });
    await d.click({ role: 'input', text: 'Add host to scope', match: 'exact', within: panel });
    await d.type('example.test');
    await d.key('Enter');
    const cell = await d.locate({ role: 'cell', text: 'example.test', match: 'exact', within: '[role=table][aria-label="Hosts in scope"]' });
    let list = await bus.call('scope.list');
    const has = (l) => JSON.stringify(l).includes('example.test');
    expect(!!cell && has(list), '10a Add host example.test → row + scope.list', `scope.list=${JSON.stringify(list)}`);
    await d.click({ role: 'button', text: 'Remove example.test from scope', match: 'exact', within: panel });
    await d.gone({ role: 'cell', text: 'example.test', match: 'exact', within: '[role=table][aria-label="Hosts in scope"]' });
    list = await bus.call('scope.list');
    expect(!has(list), '10b remove × → row gone + scope.list', `scope.list=${JSON.stringify(list)}`);
  });

  // 11 ---------------------------------------------------------------------------------------
  await step('11a agent panel', async () => {
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    const group = await d.locate({ sel: '[role=radiogroup][aria-label="Agent policy"]' });
    const radios = await d.ev(`Array.from(document.querySelectorAll('[role=radiogroup][aria-label="Agent policy"] [role=radio]')).map(b => ({ label: b.innerText.trim(), disabled: b.disabled, checked: b.getAttribute('aria-checked') }))`);
    const title = await d.ev(`document.querySelector('[role=radiogroup][aria-label="Agent policy"]')?.getAttribute('title')`);
    const allDisabled = radios.length > 0 && radios.every((r) => r.disabled);
    expect(group.disabled && allDisabled, '11a Agent policy control present and disabled (no agent.set)', `radios=${JSON.stringify(radios)}; tooltip="${title}"; bus has agent.set=${tools.includes('agent.set')}`);
  });
  await step('11b browser panel', async () => {
    await d.click({ role: 'button', text: 'Browser', match: 'startsWith', within: SIDEBAR });
    await sleep(800);
    const empty = await d.q('find', { text: 'No embedded browser', within: '#aitm-lower' });
    const alerts = await d.q('texts', { role: 'alert' });
    const lower = await d.q('text', '#aitm-lower');
    gap('11b Browser panel (F14 / no engine)', `${empty ? `honest empty state: "${empty.text}"` : `no empty-state text; alerts ${JSON.stringify(alerts)}`}; bus browser.navigate present=${tools.includes('browser.navigate')}; panel text "${(lower ?? '').slice(0, 160)}"`);
  });

  // 12 ---------------------------------------------------------------------------------------
  await step('12 hero', async () => {
    await d.click({ sel: `[role=row][data-id="${meId}"]` });
    // Dismiss any lingering toast (the Browser panel's screenshot error) the way a human would: click it.
    const toast = await d.q('find', { role: 'alert' });
    if (toast) {
      await d.mouse(toast.x, toast.y);
      await d.gone({ role: 'alert' }, { timeoutMs: 3000 }).catch(() => {});
    }
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: RES });
    await waitFor(async () => (await d.q('cm', RES))?.includes('ops@target.test'), { what: 'hero response body' });
    await sleep(300);
    const r = await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 2, mobile: false });
    await sleep(300);
    const png = await cdp.s('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(SHOTS, '99-hero.png'), Buffer.from(png.data, 'base64'));
    await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    pass('12 hero', `${join(SHOTS, '99-hero.png')} (${W}x${H}@2x)`);
  });

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
  console.log('\n' + JSON.stringify(summary, null, 2));
  console.log(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.gap} GAP · screenshots in ${SHOTS}`);
  if (KEEP && env) {
    console.log(`--keep: aitm and Chrome left running. UI: ${env.uiUrl}  proxy: 127.0.0.1:${env.proxyPort}  target: ${target?.base}  poc.dir: ${env.pocDir}`);
    await new Promise(() => {});
  }
  bus?.close();
  cdp?.close();
  await env?.stop();
  await target?.close();
  process.exit(summary.fail ? 1 : 0);
}
