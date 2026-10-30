// The shared web-CUA driver: a real headless Chrome over CDP, driven with real input events only
// (Input.dispatchMouseEvent / dispatchKeyEvent / insertText — never synthetic DOM events, never app
// functions), plus a read-only page-side locator. Extracted from cua-live.mjs so the HTTP CUA
// (cua-live.mjs) and the L4 CUA (cua-l4.mjs) click through the same harness. Node ≥ 22, no deps.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sleep, waitFor } from './live-env.mjs';

export const DEFAULT_CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

export const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);

// ------------------------------------------------------------------------------------------
// Chrome over CDP
// ------------------------------------------------------------------------------------------
export async function launchChrome({ chromePath = process.env.CHROME ?? DEFAULT_CHROME, width = 1600, height = 1000 } = {}) {
  const profile = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'aitm-cua-profile-'));
  const chrome = spawn(
    chromePath,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--hide-scrollbars',
      '--force-device-scale-factor=1',
      `--window-size=${width},${height}`,
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
  await s('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
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
    width,
    height,
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
export function pageHelper() {
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
    switch: '[role=switch]',
    status: '[role=status]',
    dialog: '[role=dialog],[role=alertdialog]',
    alert: '[role=alert]',
    cell: '[role=cell],[role=gridcell]',
    menu: '[role=menu]',
    region: '[role=region]',
    listitem: '[role=listitem]',
    treeitem: '[role=treeitem]',
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
      checked: el.getAttribute('aria-checked'),
      disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
      oos: el.getAttribute('data-oos') === 'true',
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
export const VK = { Enter: 13, Escape: 27, Tab: 9, Backspace: 8, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Home: 36, End: 35, ' ': 32 };

export function makeDriver(cdp, { log = () => {}, shotsDir } = {}) {
  const { s } = cdp;
  const W = cdp.width ?? 1600;
  const H = cdp.height ?? 1000;
  let shotN = 0;
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
    if (!shotsDir) return null;
    if (scale !== 1) await s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: scale, mobile: false });
    await sleep(scale !== 1 ? 250 : 60);
    const r = await s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    const file = join(shotsDir, `${String(++shotN).padStart(2, '0')}-${slug(name)}.png`);
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
