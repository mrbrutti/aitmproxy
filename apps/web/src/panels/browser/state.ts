// Browser view state (foundation §2.7 "Browser view"). One instance per app store, created once
// and kept for the page's lifetime, so leaving and returning to the panel keeps the last frame,
// the local history and the eval log. The live screenshot poller is gated on the panel being
// the visible one (`app.ui.panel === 'browser'`) and on document visibility.
import { batch, createEffect, createMemo, createRoot, createSignal, on } from 'solid-js';
import type { AppStore } from '~/state/app';
import { createPoller } from './poller';
import { createHistory, hostOf, normalizeUrl } from './url';

export interface BrowserTab {
  id: string;
  url: string;
  title: string | null;
  active: boolean;
}

export interface EvalEntry {
  seq: number;
  script: string;
  result: string | null;
  error: string | null;
}

export type Availability = 'unknown' | 'yes' | 'no';

export const LIVE_INTERVAL_MS = 800;
const EVAL_LOG_MAX = 200;

/** The core registers `browser.*` even without an engine; every call then fails with one of these. */
export const NO_ENGINE = /no browser is configured|browser unavailable|no obscura/i;
export const NO_ENGINE_TEXT = 'No embedded browser on this server — start aitm with browser.engine: obscura.';

/** `browser.screenshot` is a base64 PNG string today; accept the obvious envelopes too. */
function asBase64(r: unknown): string | null {
  if (typeof r === 'string') return r || null;
  if (r && typeof r === 'object') {
    const o = r as Record<string, unknown>;
    for (const k of ['base64', 'png', 'data']) if (typeof o[k] === 'string' && o[k]) return o[k] as string;
  }
  return null;
}

function asText(r: unknown): string {
  if (typeof r === 'string') return r;
  if (r && typeof r === 'object') {
    const o = r as Record<string, unknown>;
    if ('result' in o) return asText(o.result);
    if (typeof o.html === 'string') return o.html;
  }
  if (r === undefined) return 'undefined';
  try {
    return JSON.stringify(r, null, 2);
  } catch {
    return String(r);
  }
}

/** Decode off-screen so the swap never shows a blank frame. */
async function predecode(dataUrl: string) {
  if (typeof Image === 'undefined') return;
  const im = new Image();
  im.src = dataUrl;
  if (typeof im.decode === 'function') await im.decode().catch(() => {});
}

function download(dataUrl: string, filename: string) {
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export function createBrowserState(app: AppStore) {
  const has = (n: string) => app.proxy.tools.some((t) => t.name === n);
  /** True once any browser.* call said there is no engine behind the registered tools. */
  const [engineMissing, setEngineMissing] = createSignal(false);
  const [probing, setProbing] = createSignal(false);
  const availability = createMemo<Availability>(() => (app.proxy.tools.length === 0 ? 'unknown' : has('browser.navigate') && !engineMissing() ? 'yes' : 'no'));
  const available = () => availability() === 'yes';
  const hasTabs = createMemo(() => has('browser.tabs'));

  const [remoteTabs, setRemoteTabs] = createSignal<BrowserTab[]>([]);
  const [url, setUrl] = createSignal('');
  const [title, setTitle] = createSignal<string | null>(null);
  const [draft, setDraft] = createSignal('');
  const [frame, setFrame] = createSignal<string | null>(null);
  const [navigating, setNavigating] = createSignal(false);
  const [live, setLive] = createSignal(true);
  const [dom, setDom] = createSignal<string | null>(null);
  const [domOpen, setDomOpen] = createSignal(false);
  const [domLoading, setDomLoading] = createSignal(false);
  const [evalOpen, setEvalOpen] = createSignal(false);
  const [evalLog, setEvalLog] = createSignal<EvalEntry[]>([]);
  const history = createHistory();

  /** Without `browser.tabs` (F14) the strip shows one tab built from what this view knows. */
  const tabs = createMemo<BrowserTab[]>(() => (hasTabs() && remoteTabs().length ? remoteTabs() : [{ id: 'local', url: url(), title: title(), active: true }]));

  /** A bus error. "No engine" flips the view to its unavailable state (one notice, poller off) instead of toasting per call. */
  let noEngineNoticed = false;
  const fail = (label: string, e: unknown) => {
    const msg = (e as Error)?.message ?? String(e);
    if (NO_ENGINE.test(msg)) {
      setEngineMissing(true);
      if (!noEngineNoticed) {
        noEngineNoticed = true;
        app.notice(NO_ENGINE_TEXT);
      }
      return;
    }
    app.notice(`${label}: ${msg}`, 'error');
  };

  /** Re-probe once (a cheap read) after the operator fixed the server; success brings the view back. */
  async function retry() {
    if (probing()) return;
    setProbing(true);
    try {
      await app.call<unknown>('browser.get_dom');
      frameFailures = 0;
      noEngineNoticed = false;
      setEngineMissing(false);
    } catch (e) {
      const msg = (e as Error)?.message ?? String(e);
      if (NO_ENGINE.test(msg)) app.notice('Still no embedded browser on this server');
      else fail('browser', e);
    } finally {
      setProbing(false);
    }
  }

  async function refreshTabs() {
    if (!hasTabs()) return;
    try {
      const t = await app.call<unknown>('browser.tabs');
      if (!Array.isArray(t)) return;
      const list = (t as Partial<BrowserTab>[]).map((x, i) => ({
        id: String(x.id ?? i),
        url: typeof x.url === 'string' ? x.url : '',
        title: typeof x.title === 'string' && x.title ? x.title : null,
        active: !!x.active,
      }));
      setRemoteTabs(list);
      const a = list.find((x) => x.active) ?? list[0];
      if (a && !url() && a.url) {
        batch(() => {
          setUrl(a.url);
          setTitle(a.title);
          setDraft(a.url);
          history.push(a.url);
        });
      }
    } catch (e) {
      fail('tabs', e);
    }
  }

  let frameFailures = 0;
  async function fetchFrame(): Promise<string | null> {
    const b64 = asBase64(await app.call<unknown>('browser.screenshot'));
    if (!b64) return null;
    const data = `data:image/png;base64,${b64}`;
    await predecode(data);
    setFrame(data);
    return data;
  }
  /** The live tick: tells the operator about the first failure of a streak, then stays quiet. */
  async function refreshFrame() {
    try {
      await fetchFrame();
      frameFailures = 0;
    } catch (e) {
      if (frameFailures++ === 0) fail('screenshot', e);
    }
  }

  async function refreshDom() {
    setDomLoading(true);
    try {
      setDom(asText(await app.call<unknown>('browser.get_dom')));
    } catch (e) {
      fail('DOM', e);
    } finally {
      setDomLoading(false);
    }
  }

  async function go(target: string, record: boolean) {
    if (!available()) return;
    setNavigating(true);
    try {
      const r = await app.call<unknown>('browser.navigate', { url: target });
      const o = r && typeof r === 'object' ? (r as Record<string, unknown>) : {};
      const final = typeof o.url === 'string' && o.url ? o.url : target;
      batch(() => {
        setUrl(final);
        setTitle(typeof o.title === 'string' && o.title ? o.title : null);
        setDraft(final);
        if (record) history.push(final);
      });
      await Promise.all([refreshFrame(), refreshTabs(), domOpen() ? refreshDom() : Promise.resolve()]);
    } catch (e) {
      fail('navigate', e);
    } finally {
      setNavigating(false);
    }
  }

  const navigate = (input: string): Promise<void> => {
    const u = normalizeUrl(input);
    return u ? go(u, true) : Promise.resolve();
  };
  const back = () => {
    const u = history.back();
    if (u) void go(u, false);
  };
  const forward = () => {
    const u = history.forward();
    if (u) void go(u, false);
  };
  const reload = () => {
    if (url()) void go(url(), false);
  };

  async function screenshot() {
    try {
      const data = await fetchFrame();
      if (!data) throw new Error('empty screenshot');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      download(data, `aitm-${hostOf(url()) || 'page'}-${stamp}.png`);
    } catch (e) {
      fail('screenshot', e);
    }
  }

  async function clickSelector(selector: string): Promise<boolean> {
    try {
      await app.call('browser.click', { selector });
      void refreshFrame();
      return true;
    } catch (e) {
      fail('click', e);
      return false;
    }
  }

  async function typeInto(selector: string, text: string): Promise<boolean> {
    try {
      // browser.type requires a selector; `:focus` addresses the focused element.
      await app.call('browser.type', { selector: selector.trim() || ':focus', text });
      void refreshFrame();
      return true;
    } catch (e) {
      fail('type', e);
      return false;
    }
  }

  let evalSeq = 0;
  async function evaluate(script: string) {
    const s = script.trim();
    if (!s) return;
    const seq = ++evalSeq;
    setEvalLog((l) => [...l, { seq, script: s, result: null, error: null }].slice(-EVAL_LOG_MAX));
    const settle = (p: Partial<EvalEntry>) => setEvalLog((l) => l.map((e) => (e.seq === seq ? { ...e, ...p } : e)));
    try {
      // The core's parameter is `expr` (verified against the running core; the foundation text says `script`).
      settle({ result: asText(await app.call<unknown>('browser.eval', { expr: s })) });
    } catch (e) {
      settle({ error: (e as Error).message });
      fail('eval', e);
    }
  }

  function toggleDom(open = !domOpen()) {
    setDomOpen(open);
    if (open && dom() == null && available()) void refreshDom();
  }

  const { polling } = createPoller({
    intervalMs: LIVE_INTERVAL_MS,
    enabled: () => live() && available() && app.ui.panel === 'browser',
    tick: refreshFrame,
  });

  // First contact once tools/list says the browser is there: tabs, then one frame if not live.
  createEffect(
    on(available, (ok) => {
      if (!ok) return;
      void refreshTabs().then(() => {
        if (!live()) void refreshFrame();
      });
    }),
  );

  return {
    availability,
    available,
    engineMissing,
    probing,
    retry,
    hasTabs,
    tabs,
    url,
    title,
    draft,
    setDraft,
    frame,
    navigating,
    live,
    setLive,
    polling,
    history,
    navigate,
    back,
    forward,
    reload,
    screenshot,
    clickSelector,
    typeInto,
    dom,
    domOpen,
    domLoading,
    toggleDom,
    refreshDom,
    evalOpen,
    setEvalOpen,
    evalLog,
    evaluate,
  };
}

export type BrowserState = ReturnType<typeof createBrowserState>;

const cache = new WeakMap<AppStore, BrowserState>();

/** The one browser state for this app store; lives as long as the page. */
export function browserState(app: AppStore): BrowserState {
  let s = cache.get(app);
  if (!s) {
    s = createRoot(() => createBrowserState(app));
    cache.set(app, s);
  }
  return s;
}
