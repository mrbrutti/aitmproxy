// Fixture bus: a BusClient that serves the command set (§4.3 plus the F1–F15 additions the UI
// expects) from in-memory fixtures and streams flows at a configurable rate. Used by `vite dev`
// (unless `?bus=live`), by tests, and by the perf measurements. Same wire shapes as the bridge.

import { createSignal } from 'solid-js';
import type { FlowDetail, FlowSummary } from '~/model/flow';
import {
  AGENT_CLIENT,
  SCOPE_HOSTS,
  asAgentReplay,
  generateBigJsonFlow,
  generateRequest,
  generateResponse,
  generateWebSocket,
  mulberry32,
  statusText,
} from './fixtures';
import {
  BusError,
  type AgentNotification,
  type BusClient,
  type BusState,
  type FlowNotification,
  type NotificationHandler,
  type StateNotification,
  type ToolDef,
} from './types';

export interface MockBusOptions {
  /** New flows per second while capturing. */
  rate?: number;
  seed?: number;
  /** Flows to pre-populate before the first paint. */
  initial?: number;
  /** Simulated agent activity (replays every few seconds). */
  agentActive?: boolean;
}

export interface PocRun {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  passed: boolean;
  at: number;
  origin: 'human' | 'agent';
  poc_path: string;
  yaml: string;
  finding_capture: string;
  screenshot_path: string | null;
  evaluated: { assertion: string; matched: boolean }[];
  /** Built in this session but not yet saved under poc.dir (the core returns YAML text only). */
  local?: boolean;
  /** True once the core has been asked for the source (poc.get) or none exists. */
  description?: string;
  /** Set when this entry has a run result in this session (poc.run keeps no history). */
  ran?: boolean;
}

export interface MockControls {
  setRate(perSecond: number): void;
  rate(): number;
  /** Direct access for tests. */
  flowsById(): Map<string, FlowDetail>;
}

const summaryOf = (f: FlowDetail): FlowSummary => {
  const { request: _r, response: _s, conn: _c, timing: _t, wsMessages: _w, original: _o, ...s } = f;
  return s;
};

const POC_YAML = (name: string, host: string, path: string) => `name: ${name}
severity: high
target: https://${host}
description: >
  Reflected input reaches the response body unencoded.
steps:
  - request:
      method: GET
      path: ${path}
      query:
        q: '"><img src=x onerror=alert(1)>'
    expect:
      status: 200
      body_contains: '<img src=x onerror=alert(1)>'
  - screenshot: true
`;

export function createMockBus(opts: MockBusOptions = {}): BusClient & MockControls {
  const rng = mulberry32(opts.seed ?? 42);
  let rate = opts.rate ?? 4;
  const [state, setState] = createSignal<BusState>('idle');
  const [lastError] = createSignal<string | null>(null);
  const handlers = new Set<NotificationHandler>();
  const flows = new Map<string, FlowDetail>();
  let seq = 0;
  let armed = false;
  let capturing = true;
  let agentPolicy: StateNotification['agent'] = 'all';
  const scope = new Set<string>(SCOPE_HOSTS);
  const pocs: PocRun[] = [];
  const activity: AgentNotification[] = [];
  const agentTimes: number[] = [];
  let browserUrl = 'https://shop-staging.test/';

  // ---- L4 session fixtures (M5) ----------------------------------------------------------------
  // A few `l4.*` sessions so the unified flow list shows L4 rows alongside HTTP, with packet
  // drill-down. Wire shapes mirror `panels/l4/model` (L4FlowWire / L4ScopeEntryWire). The en0
  // session is intentionally out of L4 scope so scope dimming is visible.
  interface L4PacketFx {
    dir: 'inbound' | 'outbound';
    length: number;
    injected: boolean;
    layers: string[];
  }
  interface L4FlowFx {
    id: string;
    kind: 'capture' | 'craft' | 'send_recv' | 'intercept';
    interface: string;
    filter: string | null;
    queue: number | null;
    injected_count: number;
    packets: L4PacketFx[];
  }
  const l4Flows: L4FlowFx[] = [
    {
      id: 'l4-cap-1',
      kind: 'capture',
      interface: 'lo0',
      filter: 'udp port 9',
      queue: null,
      injected_count: 0,
      packets: [
        { dir: 'outbound', length: 42, injected: false, layers: ['Ether', 'IPv4', 'UDP', 'Raw'] },
        { dir: 'inbound', length: 42, injected: false, layers: ['Ether', 'IPv4', 'ICMP'] },
        { dir: 'outbound', length: 50, injected: false, layers: ['Ether', 'IPv4', 'UDP', 'Raw'] },
        { dir: 'inbound', length: 66, injected: false, layers: ['Ether', 'IPv4', 'TCP'] },
      ],
    },
    {
      id: 'l4-craft-1',
      kind: 'craft',
      interface: 'lo0',
      filter: null,
      queue: null,
      injected_count: 1,
      packets: [{ dir: 'outbound', length: 33, injected: true, layers: ['IPv4', 'UDP', 'Raw'] }],
    },
    {
      id: 'l4-icept-1',
      kind: 'intercept',
      interface: 'en0',
      filter: 'tcp port 443',
      queue: 0,
      injected_count: 0,
      packets: [
        { dir: 'inbound', length: 74, injected: false, layers: ['Ether', 'IPv4', 'TCP'] },
        { dir: 'outbound', length: 74, injected: false, layers: ['Ether', 'IPv4', 'TCP'] },
      ],
    },
  ];
  const l4Scope = [
    { id: 's1', cidr: '127.0.0.1/32', ports: '0-65535', interface: 'lo0', direction: 'outbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } },
    { id: 's2', cidr: '127.0.0.1/32', ports: '0-65535', interface: 'lo0', direction: 'inbound', capability: 'capture', inject_rate: { pps: 0, burst: 0 } },
  ];
  let l4Gates = { capture: true, inject: false, intercept: false, widen: false };
  let l4CraftSeq = 0;
  const l4Wire = (f: L4FlowFx) => ({
    id: f.id,
    kind: f.kind,
    interface: f.interface,
    filter: f.filter,
    queue: f.queue,
    packet_count: f.packets.length,
    injected_count: f.injected_count,
    packets: f.packets,
  });

  const timers = new Set<ReturnType<typeof setTimeout>>();
  let loop: ReturnType<typeof setInterval> | null = null;
  let stateLoop: ReturnType<typeof setInterval> | null = null;
  let agentLoop: ReturnType<typeof setInterval> | null = null;
  let up = 0;
  let down = 0;

  const notify = (method: string, params: unknown) => {
    for (const h of handlers) h(method, params);
  };
  const flowEvent = (event: FlowNotification['event'], f: FlowDetail) =>
    notify('notifications/aitm/flow', { event, id: f.id, summary: summaryOf(f) } satisfies FlowNotification);

  const later = (ms: number, fn: () => void) => {
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    timers.add(t);
  };

  function complete(f: FlowDetail, delay = 20 + rng() * 400) {
    later(delay, () => {
      const cur = flows.get(f.id);
      if (!cur || cur.intercept === 'killed' || cur.intercept === 'paused') return;
      const done = generateResponse(cur, rng, Date.now());
      flows.set(done.id, done);
      up += done.reqSize ?? 0;
      down += done.resSize ?? 0;
      flowEvent('response', done);
    });
  }

  function addFlow(f: FlowDetail) {
    flows.set(f.id, f);
    flowEvent(f.intercept === 'paused' ? 'intercepted' : 'created', f);
    if (f.response == null && f.kind === 'http' && f.intercept !== 'paused') complete(f);
    else if (f.response) flowEvent('response', f);
  }

  function spawn(now = Date.now()) {
    seq++;
    const o = { rng, seq, now, armed, scope: [...scope] };
    const r = rng();
    if (r < 0.03) addFlow(generateWebSocket(o));
    else addFlow(generateRequest(o));
  }

  function recordActivity(command: string, args: unknown, origin: AgentNotification['origin'], result: 'ok' | 'error' = 'ok') {
    const entry: AgentNotification = { origin, command, args, result, at: new Date().toISOString() };
    activity.push(entry);
    if (activity.length > 500) activity.shift();
    if (origin === 'mcp') agentTimes.push(Date.now());
    notify('notifications/aitm/agent', entry);
  }

  function agentTick() {
    if (agentPolicy !== 'all' || !capturing) return;
    const done = [...flows.values()].filter((f) => f.response && f.inScope && f.kind === 'http');
    const src = done[Math.floor(rng() * done.length)];
    if (!src) return;
    seq++;
    const replay = asAgentReplay(src, seq, Date.now(), 'agent');
    recordActivity('flow.replay', { id: src.id }, 'mcp');
    addFlow(replay);
  }

  function pausedCount() {
    let n = 0;
    for (const f of flows.values()) if (f.intercept === 'paused') n++;
    return n;
  }

  function stateTick() {
    const cutoff = Date.now() - 60_000;
    while (agentTimes.length && agentTimes[0]! < cutoff) agentTimes.shift();
    const s: StateNotification = {
      listening: capturing,
      address: '127.0.0.1:8080',
      protocol: 'HTTP/2',
      intercept_armed: armed,
      paused: pausedCount(),
      agent: agentPolicy,
      agent_actions_last_minute: agentTimes.length,
      throughput: { up, down },
      memory_bytes: 96 * 1024 * 1024 + flows.size * 4096,
    };
    up = 0;
    down = 0;
    notify('notifications/aitm/state', s);
  }

  function startLoops() {
    stopLoops();
    const period = 50;
    let carry = 0;
    loop = setInterval(() => {
      if (!capturing) return;
      carry += (rate * period) / 1000;
      const n = Math.floor(carry);
      carry -= n;
      const now = Date.now();
      for (let i = 0; i < n; i++) spawn(now);
    }, period);
    stateLoop = setInterval(stateTick, 1000);
    if (opts.agentActive ?? true) agentLoop = setInterval(agentTick, 7000);
  }
  function stopLoops() {
    if (loop) clearInterval(loop);
    if (stateLoop) clearInterval(stateLoop);
    if (agentLoop) clearInterval(agentLoop);
    loop = stateLoop = agentLoop = null;
  }

  function seed() {
    const n = opts.initial ?? 40;
    const base = Date.now() - n * 900;
    for (let i = 0; i < n; i++) {
      seq++;
      const now = base + i * 900 + rng() * 300;
      const o = { rng, seq, now, armed: false, scope: [...scope] };
      let f: FlowDetail;
      if (i === Math.floor(n / 2)) f = generateBigJsonFlow(o);
      else if (i === 7 || i === n - 6) f = generateWebSocket(o);
      else if (i === n - 9) {
        seq++;
        f = asAgentReplay(generateResponse(generateRequest(o), rng, now + 100), seq, now, 'agent');
        f = generateResponse(f, rng, now + 300);
      } else f = generateResponse(generateRequest(o), rng, now + 50 + rng() * 300);
      if (i === n - 4) f = { ...f, intercept: 'killed', status: null, statusText: null, response: null, durationMs: null, resSize: null };
      if (i === 12) f = { ...f, mark: 'blue' };
      if (i === n - 3) f = { ...f, mark: 'red', comment: 'reflected q param' };
      flows.set(f.id, f);
    }
    // a finding from the seeded agent run
    const xss = [...flows.values()].find((f) => f.path === '/api/search' && f.query?.includes('onerror'));
    if (xss) {
      pocs.push({
        id: 'poc_1',
        title: 'Reflected XSS in search',
        severity: 'high',
        target: 'https://api.shop-staging.test',
        passed: true,
        at: xss.startedAt + 2000,
        origin: 'agent',
        poc_path: '/Users/matt/aitm/poc/reflected-xss-search.yaml',
        yaml: POC_YAML('reflected-xss-search', 'api.shop-staging.test', '/api/search'),
        finding_capture: xss.id,
        screenshot_path: '/Users/matt/aitm/poc/reflected-xss-search.png',
        evaluated: [
          { assertion: 'status == 200', matched: true },
          { assertion: "body contains '<img src=x onerror=alert(1)>'", matched: true },
          { assertion: 'content-type is text/html', matched: false },
        ],
      });
    }
    pocs.push({
      id: 'poc_2',
      title: 'Missing rate limit on login',
      severity: 'medium',
      target: 'https://auth.shop-staging.test',
      passed: false,
      at: Date.now() - 400_000,
      origin: 'human',
      poc_path: '/Users/matt/aitm/poc/login-rate-limit.yaml',
      yaml: POC_YAML('login-rate-limit', 'auth.shop-staging.test', '/api/auth/login').replace('severity: high', 'severity: medium'),
      finding_capture: [...flows.values()].find((f) => f.path === '/api/auth/login')?.id ?? '',
      screenshot_path: null,
      evaluated: [
        { assertion: '20 requests in 10s all return 200', matched: false },
        { assertion: 'no retry-after header', matched: true },
      ],
    });
  }

  function need(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v) throw new BusError(`missing required parameter '${key}'`, -32602);
    return v;
  }
  function flowArg(args: Record<string, unknown>, key = 'id'): FlowDetail {
    const id = need(args, key);
    const f = flows.get(id);
    if (!f) throw new BusError(`unknown flow ${id}`);
    return f;
  }

  async function screenshotPng(url: string): Promise<string> {
    if (typeof OffscreenCanvas === 'undefined') return '';
    const c = new OffscreenCanvas(1280, 800);
    const g = c.getContext('2d')!;
    g.fillStyle = '#ffffff';
    g.fillRect(0, 0, 1280, 800);
    g.fillStyle = '#2563eb';
    g.fillRect(0, 0, 1280, 56);
    g.fillStyle = '#ffffff';
    g.font = '600 20px system-ui';
    g.fillText('Shop (staging)', 24, 36);
    g.fillStyle = '#111827';
    g.font = '28px system-ui';
    g.fillText('Welcome back, ops@shop-staging.test', 24, 120);
    g.fillStyle = '#6b7280';
    g.font = '14px ui-monospace, monospace';
    g.fillText(url, 24, 150);
    for (let i = 0; i < 6; i++) {
      const x = 24 + (i % 3) * 410;
      const y = 200 + Math.floor(i / 3) * 260;
      g.fillStyle = '#f3f4f6';
      g.fillRect(x, y, 380, 220);
      g.fillStyle = '#e5e7eb';
      g.fillRect(x, y, 380, 140);
      g.fillStyle = '#111827';
      g.font = '500 16px system-ui';
      g.fillText(['Aurora Lamp', 'Kestrel Desk', 'Vela Chair', 'Orion Speaker', 'Tidal Mug', 'Fennel Rug'][i]!, x + 16, y + 170);
      g.fillStyle = '#2563eb';
      g.fillText(`€${(49 + i * 37).toFixed(2)}`, x + 16, y + 200);
    }
    const blob = await c.convertToBlob({ type: 'image/png' });
    const buf = new Uint8Array(await blob.arrayBuffer());
    let bin = '';
    for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  async function call(tool: string, args: Record<string, unknown>): Promise<unknown> {
    // Simulate a loopback round trip so the UI's loading states are real.
    await new Promise((r) => setTimeout(r, 4 + rng() * 12));
    switch (tool) {
      case 'flow.list':
        return [...flows.keys()];
      case 'flow.get':
        return summaryOf(flowArg(args));
      case 'flow.detail':
        return flowArg(args);
      case 'flow.intercept': {
        if (typeof args.enabled === 'boolean') armed = args.enabled;
        recordActivity(tool, args, 'web');
        stateTick();
        return armed;
      }
      case 'flow.resume': {
        const f = flowArg(args);
        if (f.intercept !== 'paused') throw new BusError(`flow ${f.id} is not paused`);
        const resumed = { ...f, intercept: 'resumed' as const };
        flows.set(f.id, resumed);
        flowEvent('released', resumed);
        complete(resumed);
        recordActivity(tool, args, 'web');
        return { ok: true };
      }
      case 'flow.kill': {
        const f = flowArg(args);
        const killed: FlowDetail = { ...f, intercept: 'killed', status: null, response: null, durationMs: null };
        flows.set(f.id, killed);
        flowEvent('killed', killed);
        recordActivity(tool, args, 'web');
        return { ok: true };
      }
      case 'flow.mutate': {
        const f = flowArg(args);
        const edits = (args.edits ?? {}) as Partial<{ method: string; path: string; headers: unknown; body: unknown }>;
        const original = f.original ?? { method: f.method, path: f.path, headers: f.request.headers, body: f.request.body };
        const headers = edits.headers
          ? Array.isArray(edits.headers)
            ? (edits.headers as { name: string; value: string }[])
            : Object.entries(edits.headers as Record<string, string>).map(([name, value]) => ({ name, value }))
          : f.request.headers;
        const bodyText = typeof edits.body === 'string' ? edits.body : f.request.body.text;
        const path = edits.path ?? `${f.path}${f.query ? `?${f.query}` : ''}`;
        const qi = path.indexOf('?');
        const mutated: FlowDetail = {
          ...f,
          method: edits.method ?? f.method,
          path: qi < 0 ? path : path.slice(0, qi),
          query: qi < 0 ? null : path.slice(qi + 1),
          edited: true,
          original,
          request: {
            headers,
            body: { ...f.request.body, text: bodyText, size: bodyText?.length ?? f.request.body.size },
          },
        };
        flows.set(f.id, mutated);
        flowEvent('mutated', mutated);
        recordActivity(tool, { id: f.id, edits: Object.keys(edits) }, 'web');
        return { ok: true };
      }
      case 'flow.replay': {
        const f = flowArg(args);
        seq++;
        const r = asAgentReplay(f, seq, Date.now(), 'human');
        recordActivity(tool, args, 'web');
        addFlow(r);
        return r.id;
      }
      case 'request.send': {
        // The bus takes the parts: {scheme?, authority, path?, method?, headers?, body?}.
        const authority = need(args, 'authority');
        const scheme = typeof args.scheme === 'string' ? args.scheme : 'https';
        const url = new URL(`${scheme}://${authority}${typeof args.path === 'string' ? args.path : '/'}`);
        if (![...scope].some((h) => h === url.hostname || (h.startsWith('*.') && url.hostname.endsWith(h.slice(1)))))
          throw new BusError(`host ${url.hostname} is out of scope`);
        seq++;
        const now = Date.now();
        const base = generateRequest({ rng, seq, now, armed: false, scope: [...scope] });
        const hdrs = (args.headers ?? {}) as Record<string, string> | { name: string; value: string }[];
        const headers = Array.isArray(hdrs) ? hdrs : Object.entries(hdrs).map(([name, value]) => ({ name, value }));
        const body = typeof args.body === 'string' ? args.body : '';
        const f: FlowDetail = {
          ...base,
          method: String(args.method ?? 'GET').toUpperCase(),
          scheme: url.protocol === 'http:' ? 'http' : 'https',
          authority: url.host,
          path: url.pathname,
          query: url.search ? url.search.slice(1) : null,
          client: { id: 'aitm-web', name: 'aitm-web' },
          origin: 'human',
          isReplay: false,
          inScope: true,
          tls: url.protocol === 'http:' ? 'plain' : 'mitm',
          request: {
            headers: [{ name: 'host', value: url.host }, ...headers],
            body: { text: body, contentType: headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? null, size: body.length, truncated: false },
          },
        };
        recordActivity(tool, { method: f.method, url: url.href }, 'web');
        addFlow(f);
        return f.id;
      }
      case 'scope.list':
        return [...scope].map((host) => ({ host, rate_limit: { rps: 10, burst: 20 }, backoff: { base_ms: 500, max_ms: 8000 } }));
      case 'agent.activity':
        return activity.slice(-200).map((a) => ({ ...a }));
      case 'scope.add':
        scope.add(need(args, 'host'));
        recordActivity(tool, args, 'web');
        return { ok: true, count: scope.size };
      case 'scope.remove':
        scope.delete(need(args, 'host'));
        recordActivity(tool, args, 'web');
        return { ok: true, count: scope.size };
      case 'poc.list':
        // A fresh array each call, as JSON decoding over the wire would give.
        return pocs.map((p) => ({ ...p }));
      case 'poc.get': {
        const p = pocs.find((x) => x.poc_path === need(args, 'poc_path'));
        if (!p) throw new BusError('unknown poc');
        return { ...p };
      }
      case 'poc.build': {
        const f = flowArg(args, 'flow_id');
        const name = need(args, 'name');
        const p: PocRun = {
          id: `poc_${pocs.length + 1}`,
          title: name,
          severity: 'medium',
          target: `https://${f.authority}`,
          passed: false,
          at: Date.now(),
          origin: 'human',
          poc_path: `/Users/matt/aitm/poc/${name}.yaml`,
          yaml: POC_YAML(name, f.authority, f.path),
          finding_capture: f.id,
          screenshot_path: null,
          evaluated: [],
        };
        pocs.unshift(p);
        recordActivity(tool, { flow_id: f.id, name }, 'web');
        // The core returns the YAML text (not a path); listing it afterwards is poc.list (F13).
        return p.yaml;
      }
      case 'poc.run': {
        const p = pocs.find((x) => x.poc_path === args.poc_path || x.id === args.id);
        if (!p) throw new BusError('unknown poc');
        await new Promise((r) => setTimeout(r, 600 + rng() * 800));
        const src = flows.get(p.finding_capture);
        let captureId = p.finding_capture;
        if (src) {
          seq++;
          const r = asAgentReplay(src, seq, Date.now(), 'human');
          const done = generateResponse(r, rng, Date.now() + 120);
          flows.set(done.id, done);
          flowEvent('created', done);
          flowEvent('response', done);
          captureId = done.id;
        }
        const passed = rng() > 0.3;
        const run: PocRun = {
          ...p,
          id: `poc_${pocs.length + 1}`,
          passed,
          at: Date.now(),
          origin: 'human',
          finding_capture: captureId,
          screenshot_path: p.poc_path.replace(/\.yaml$/, '.png'),
          evaluated: p.evaluated.length ? p.evaluated.map((e) => ({ ...e, matched: passed ? e.matched : rng() > 0.5 })) : [{ assertion: 'status == 200', matched: passed }],
        };
        pocs.unshift(run);
        recordActivity(tool, { poc_path: p.poc_path }, 'web');
        return run;
      }
      case 'poc.artifact': {
        // Bare base64 of the file's bytes, as the bus returns it (the caller knows the type from the path).
        const path = need(args, 'path');
        if (path.endsWith('.png')) return await screenshotPng(browserUrl);
        const p = pocs.find((x) => x.poc_path === path);
        if (!p) throw new BusError(`no artifact at ${path}`);
        return btoa(String.fromCharCode(...new TextEncoder().encode(p.yaml)));
      }
      case 'browser.tabs':
        return [{ id: 'tab_1', url: browserUrl, title: 'Shop (staging)', active: true }];
      case 'browser.navigate': {
        browserUrl = need(args, 'url');
        recordActivity(tool, args, 'web');
        seq++;
        const now = Date.now();
        const u = new URL(browserUrl);
        const f = { ...generateRequest({ rng, seq, now, armed, scope: [...scope] }), method: 'GET', authority: u.host, path: u.pathname, query: u.search ? u.search.slice(1) : null, client: { id: 'obscura', name: 'obscura' } };
        addFlow(f);
        return { url: browserUrl, title: 'Shop (staging)' };
      }
      case 'browser.click':
        if (typeof args.selector !== 'string' && (typeof args.x !== 'number' || typeof args.y !== 'number'))
          throw new BusError('browser.click needs x and y, or a selector', -32602);
        recordActivity(tool, args, 'web');
        return { ok: true };
      case 'browser.type':
        need(args, 'selector');
        recordActivity(tool, args, 'web');
        return { ok: true };
      case 'browser.eval':
        need(args, 'expr');
        recordActivity(tool, args, 'web');
        return { result: `"${browserUrl}"` };
      case 'browser.get_dom':
        return `<html lang="en">\n  <head><title>Shop (staging)</title></head>\n  <body>\n    <header class="nav">Shop (staging)</header>\n    <main id="app">\n      <h1>Welcome back, ops@shop-staging.test</h1>\n      <ul class="grid">\n        <li class="card">Aurora Lamp <b>€49.00</b></li>\n        <li class="card">Kestrel Desk <b>€86.00</b></li>\n      </ul>\n    </main>\n  </body>\n</html>`;
      case 'browser.screenshot':
        return await screenshotPng(browserUrl);
      case 'agent.status':
        return { policy: agentPolicy, actions_last_minute: agentTimes.length, connected_clients: 1 };
      case 'agent.set': {
        const p = need(args, 'policy');
        if (p !== 'all' && p !== 'readonly' && p !== 'paused') throw new BusError(`unknown policy ${p}`);
        agentPolicy = p;
        recordActivity(tool, args, 'web');
        stateTick();
        return { policy: agentPolicy };
      }
      case 'proxy.status':
        // Listener state and capture state are separate on the bus.
        return { listening: true, address: '127.0.0.1:8080', capturing, intercept_armed: armed, paused: pausedCount(), flows: flows.size, protocol: 'HTTP/2' };
      case 'proxy.pause':
        capturing = false;
        recordActivity(tool, args, 'web');
        stateTick();
        return { listening: false };
      case 'proxy.resume':
        capturing = true;
        recordActivity(tool, args, 'web');
        stateTick();
        return { listening: true };
      case 'flow.clear':
        flows.clear();
        notify('notifications/aitm/flow', { event: 'cleared', id: '' } satisfies FlowNotification);
        recordActivity(tool, args, 'web');
        return { ok: true };
      case 'flow.mark': {
        const f = flowArg(args);
        if (!Array.isArray(args.marks)) throw new BusError("missing required parameter 'marks' (array)", -32602);
        const m = { ...f, mark: ((args.marks[0] as string | undefined) as FlowDetail['mark']) ?? null };
        flows.set(f.id, m);
        flowEvent('meta', m);
        return { ok: true };
      }
      case 'flow.comment': {
        const f = flowArg(args);
        const m = { ...f, comment: typeof args.text === 'string' && args.text ? args.text : null };
        flows.set(f.id, m);
        flowEvent('meta', m);
        return { ok: true };
      }
      case 'ca.status':
        // The core reports installed/trusted as yes | no | unknown.
        return { installed: 'yes', trusted: 'yes', fingerprint: 'SHA256:9F1C3B…', path: '~/Library/Application Support/aitmproxy/ca.pem', stores: { system: 'no', user: 'yes', firefox: 'unknown' } };
      case 'ca.export':
        return { pem: '-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n' };
      case 'config.get':
        return { listen: '127.0.0.1:8080', max_flows: 10000, mcp: { transport: { loopback_tcp: { port: 9090 } } }, browser: { engine: 'obscura' } };

      // ---- L4 (M5): raw packet sessions in the unified flow list ----
      case 'l4.flow.list':
        return l4Flows.map((f) => f.id);
      case 'l4.flow.get': {
        const f = l4Flows.find((x) => x.id === need(args, 'id'));
        if (!f) throw new BusError(`unknown l4 flow ${args.id}`);
        return l4Wire(f);
      }
      case 'l4.scope.list':
        return l4Scope.map((e) => ({ ...e }));
      case 'l4.capture.status':
        return l4Flows.filter((f) => f.kind === 'capture').map((f) => f.id);
      case 'l4.capture.start': {
        const iface = need(args, 'interface');
        const filter = typeof args.filter === 'string' && args.filter ? args.filter : null;
        const f: L4FlowFx = { id: `l4-cap-${l4Flows.length + 1}`, kind: 'capture', interface: iface, filter, queue: null, injected_count: 0, packets: [] };
        l4Flows.push(f);
        recordActivity(tool, args, 'web');
        return { id: f.id };
      }
      case 'l4.interfaces':
        return [{ name: 'lo0' }, { name: 'en0' }];
      case 'l4.agent.status':
        return { ...l4Gates };
      case 'l4.agent.set': {
        const cap = need(args, 'capability') as keyof typeof l4Gates;
        if (!(cap in l4Gates)) throw new BusError(`unknown capability ${cap}`, -32602);
        l4Gates = { ...l4Gates, [cap]: !!args.allowed };
        recordActivity(tool, args, 'web');
        return { ...l4Gates };
      }
      case 'l4.craft': {
        // A crafted packet's bytes + decoded summary; the only path that yields hex (l4.flow.get has none).
        const spec = (args.spec ?? {}) as { layers?: unknown[] };
        const layers = Array.isArray(spec.layers) ? spec.layers.map((l) => Object.keys(l as object)[0] ?? 'raw') : [];
        l4CraftSeq++;
        const length = 20 + l4CraftSeq;
        const bytes = btoa(String.fromCharCode(...Array.from({ length }, (_, i) => (i * 7 + l4CraftSeq) & 0xff)));
        return { length, bytes, summary: { layers, length } };
      }
      case 'l4.inject': {
        // Operator confirm-over-the-wire: first call → needs_confirmation; `_confirm` → sent.
        const iface = need(args, 'interface');
        if (!l4Scope.some((e) => e.interface === iface || e.interface === '*' || e.interface === 'any'))
          throw new BusError(`out of L4 scope: no scope entry covers interface ${iface}`);
        if (typeof args._confirm === 'string') {
          const count = typeof args.count === 'number' ? args.count : 1;
          const craft = l4Flows.find((f) => f.id === 'l4-craft-1');
          if (craft) {
            craft.injected_count += count;
            craft.packets.push({ dir: 'outbound', length: 33, injected: true, layers: ['IPv4', 'UDP', 'Raw'] });
          }
          recordActivity(tool, { interface: iface, dst: args.dst }, 'web');
          return { flow_id: 'l4-craft-1', sent: count };
        }
        return { status: 'needs_confirmation', prompt: `Inject ${args.count ?? 1} packet(s) to ${args.dst} on ${iface}. This writes to the wire.`, confirm_token: `l4-${Date.now()}` };
      }
      case 'l4.intercept.status':
        return l4Flows.filter((f) => f.kind === 'intercept').map((f) => ({ id: f.id, parked: 0 }));
      case 'l4.intercept.list':
        return [];
      case 'l4.intercept.forward':
      case 'l4.intercept.drop':
        if (typeof args._confirm === 'string') {
          recordActivity(tool, args, 'web');
          return { ok: true };
        }
        return { status: 'needs_confirmation', prompt: `${tool === 'l4.intercept.drop' ? 'Drop' : 'Forward'} the parked packet.`, confirm_token: `l4-${Date.now()}` };

      default:
        throw new BusError(`unknown tool ${tool}`, -32602);
    }
  }

  const TOOLS: ToolDef[] = [
    ['flow.list', 'List captured flow ids, oldest first.', {}],
    ['flow.get', 'Summary of one flow.', { id: { type: 'string', 'x-aitm': 'FlowId', description: 'Flow id' } }, ['id']],
    ['flow.detail', 'Headers, bodies, connection and timing of one flow.', { id: { type: 'string', 'x-aitm': 'FlowId' }, body: { type: 'string', enum: ['none', 'inline', 'range'] }, offset: { type: 'integer' }, length: { type: 'integer' } }, ['id']],
    ['flow.intercept', 'Arm or disarm interception of every request.', { enabled: { type: 'boolean', description: 'Arm when true; omit to read.' } }],
    ['flow.resume', 'Release a paused flow to upstream.', { id: { type: 'string', 'x-aitm': 'FlowId' } }, ['id']],
    ['flow.kill', 'Abort a flow; the client sees a reset.', { id: { type: 'string', 'x-aitm': 'FlowId' }, mode: { type: 'string', enum: ['reset', '429', '503'] } }, ['id']],
    ['flow.mutate', 'Edit a paused request before it continues.', { id: { type: 'string', 'x-aitm': 'FlowId' }, edits: { type: 'object', description: 'method, path, headers, body' } }, ['id', 'edits']],
    ['flow.replay', 'Send a captured request again.', { id: { type: 'string', 'x-aitm': 'FlowId' } }, ['id']],
    ['flow.mark', 'Replace the marks of a flow.', { id: { type: 'string', 'x-aitm': 'FlowId' }, marks: { type: 'array', items: { type: 'string' } } }, ['id', 'marks']],
    ['flow.comment', 'Set the comment on a flow.', { id: { type: 'string', 'x-aitm': 'FlowId' }, text: { type: 'string' } }, ['id']],
    ['flow.clear', 'Remove every captured flow.', {}],
    ['request.send', 'Send a crafted request through the proxy (scope and rate guarded).', { scheme: { type: 'string' }, authority: { type: 'string' }, path: { type: 'string' }, method: { type: 'string' }, headers: { type: 'object' }, body: { type: 'string' } }, ['authority']],
    ['scope.list', 'Hosts the operator authorised.', {}],
    ['scope.add', 'Authorise a host (host, host:port or *.wildcard).', { host: { type: 'string' } }, ['host']],
    ['scope.remove', 'Withdraw authorisation for a host.', { host: { type: 'string' } }, ['host']],
    ['browser.tabs', 'Open tabs of the embedded browser.', {}],
    ['browser.navigate', 'Navigate the embedded browser.', { url: { type: 'string' } }, ['url']],
    ['browser.click', 'Click a point (x, y) or an element by CSS selector.', { x: { type: 'number' }, y: { type: 'number' }, selector: { type: 'string' } }],
    ['browser.type', 'Type into an element; ":focus" addresses the focused one.', { selector: { type: 'string' }, text: { type: 'string' } }, ['selector', 'text']],
    ['browser.eval', 'Evaluate a JavaScript expression in the page.', { expr: { type: 'string' } }, ['expr']],
    ['browser.get_dom', 'Serialised DOM of the current page.', {}],
    ['browser.screenshot', 'PNG screenshot of the current page.', {}],
    ['poc.list', 'PoC runs and findings.', {}],
    ['poc.get', 'One PoC with its YAML and results.', { poc_path: { type: 'string' } }, ['poc_path']],
    ['poc.build', 'Build a PoC YAML from a captured flow.', { flow_id: { type: 'string', 'x-aitm': 'FlowId' }, name: { type: 'string' }, param: { type: 'string' } }, ['flow_id', 'name']],
    ['poc.run', 'Run a PoC against a target.', { poc_path: { type: 'string' }, target: { type: 'string' }, vars: { type: 'object' } }, ['poc_path']],
    ['poc.artifact', 'Read a PoC artifact (YAML or PNG) from the PoC directory.', { path: { type: 'string' } }, ['path']],
    ['ca.status', 'Root CA presence and trust per store.', {}],
    ['ca.export', 'Export the root CA (PEM or DER).', { format: { type: 'string', enum: ['pem', 'der'] } }],
    ['ca.install', 'Install the root CA into a trust store.', { store: { type: 'string' } }],
    ['ca.uninstall', 'Remove the root CA from a trust store.', { store: { type: 'string' } }],
    ['agent.status', 'Agent policy and recent activity.', {}],
    ['agent.set', 'Set the agent policy: all, readonly or paused.', { policy: { type: 'string', enum: ['all', 'readonly', 'paused'] } }, ['policy']],
    ['agent.activity', 'Recent command invocations from every frontend.', {}],
    ['proxy.status', 'Listener state.', {}],
    ['proxy.pause', 'Stop capturing new flows.', {}],
    ['proxy.resume', 'Resume capturing.', {}],
    ['config.get', 'Effective configuration.', {}],
    ['l4.flow.list', 'List L4 session ids (capture / craft / intercept).', {}],
    ['l4.flow.get', 'One L4 session with its packets.', { id: { type: 'string' } }, ['id']],
    ['l4.scope.list', 'L4 scope entries that authorise capture / inject / intercept.', {}],
    ['l4.capture.status', 'Active L4 capture session ids.', {}],
    ['l4.capture.start', 'Start an L4 capture on an interface (optional BPF filter).', { interface: { type: 'string' }, filter: { type: 'string' } }, ['interface']],
    ['l4.interfaces', 'Interfaces available for L4 capture.', {}],
    ['l4.agent.status', 'Per-capability L4 agent (MCP) gate states.', {}],
    ['l4.agent.set', 'Set one L4 agent gate (operator only).', { capability: { type: 'string' }, allowed: { type: 'boolean' } }, ['capability', 'allowed']],
    ['l4.craft', 'Build a packet from a PacketSpec; returns bytes + decoded summary.', { spec: { type: 'object' } }, ['spec']],
    ['l4.inject', 'Inject a crafted packet to the wire (operator confirm-gated).', { spec: { type: 'object' }, dst: { type: 'string' }, interface: { type: 'string' }, port: { type: 'integer' }, count: { type: 'integer' } }, ['spec', 'dst', 'interface']],
    ['l4.intercept.status', 'In-path L4 intercept sessions and their parked packet counts.', {}],
    ['l4.intercept.list', 'Parked L4 packets awaiting a decision.', {}],
    ['l4.intercept.forward', 'Forward a parked L4 packet (confirm-gated).', { id: { type: 'string' } }, ['id']],
    ['l4.intercept.drop', 'Drop a parked L4 packet (confirm-gated).', { id: { type: 'string' } }, ['id']],
  ].map(([name, description, properties, required]) => ({
    name: name as string,
    description: description as string,
    inputSchema: {
      type: 'object',
      properties: properties as NonNullable<ToolDef['inputSchema']['properties']>,
      ...(required ? { required: required as string[] } : {}),
    },
    mutates: !/\.(list|get|detail|status|tabs|get_dom|screenshot|activity|artifact|export)$/.test(name as string),
    confirm: /^ca\.(un)?install$/.test(name as string) ? 'This changes the system trust store.' : null,
  }));

  seed();

  return {
    address: 'fixtures',
    state,
    lastError,
    connect() {
      if (state() === 'open') return;
      setState('open');
      startLoops();
      stateTick();
    },
    close() {
      stopLoops();
      for (const t of timers) clearTimeout(t);
      timers.clear();
      setState('closed');
    },
    async tools() {
      return TOOLS;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      return (await call(tool, args)) as T;
    },
    onNotification(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    setRate(n) {
      rate = Math.max(0, n);
    },
    rate: () => rate,
    flowsById: () => flows,
  };
}
