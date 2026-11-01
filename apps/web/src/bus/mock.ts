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

/** The `version` the fixture bus's `proxy.status` reports — synthetic, so it never passes for a real build. */
const MOCK_VERSION = '0.0.0-fixtures';

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

  // ---- Rhai scripts (F8): an in-memory `script.*` -------------------------------------------------
  // Mirrors crates/aitm-plugin-rhai/src/commands.rs — list / enable / disable / reload / validate /
  // save / findings with the core's reply shapes and refusal text — so the Scripts panel works in the
  // dev UI and in tests. Validation is a small static scan (NAME/API consts, hook functions,
  // `reg.command`/`reg.option` names, bracket balance), not a Rhai compile.
  interface ScriptFx {
    name: string;
    path: string;
    api: string;
    hooks: string[];
    enabled: boolean;
    last_error: string | null;
  }
  const SCRIPT_DIR = '/home/operator/.aitm/scripts';
  const SCRIPT_HOOKS = ['on_request_headers', 'on_request', 'on_response_headers', 'on_response', 'on_ws_start', 'on_ws_message', 'on_ws_end', 'on_error'];
  const scriptFx: ScriptFx[] = [
    { name: 'redact-auth', path: `${SCRIPT_DIR}/redact-auth.rhai`, api: '1', hooks: ['on_request', 'on_response'], enabled: true, last_error: null },
    { name: 'tag-admin', path: `${SCRIPT_DIR}/tag-admin.rhai`, api: '1', hooks: ['on_request'], enabled: false, last_error: null },
    {
      name: 'flaky-parser',
      path: `${SCRIPT_DIR}/flaky-parser.rhai`,
      api: '1',
      hooks: ['on_response'],
      enabled: true,
      last_error: 'on_response: Property not found: content_type (line 12)',
    },
  ];
  // Oldest first, as the core's in-memory sink returns them.
  const scriptFindings = [
    { name: 'Bearer token sent over cleartext HTTP', severity: 'high', flow_id: 'flow_0007', detail: 'Authorization header on http://api.shop-staging.test/v1/cart', tags: ['auth', 'cleartext'], source: 'redact-auth', at: Date.now() - 300_000 },
    { name: 'Admin path probed', severity: 'info', flow_id: null, detail: null, tags: ['admin'], source: 'tag-admin', at: Date.now() - 120_000 },
    { name: 'Verbose error body', severity: 'medium', flow_id: 'flow_0031', detail: 'Stack trace in a 500 response', tags: [], source: 'flaky-parser', at: Date.now() - 30_000 },
  ];
  function scriptNamed(name: string): ScriptFx {
    const s = scriptFx.find((x) => x.name === name);
    if (!s) throw new BusError(`no loaded script is named \`${name}\`; loaded: ${scriptFx.length ? scriptFx.map((x) => x.name).join(', ') : '(none)'}`);
    return s;
  }
  /** The core's pinned compile-error shape, for the mistakes the scan can see: unbalanced brackets and an open string. */
  function scriptCompileError(source: string): string | null {
    const closes: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
    const stack: { ch: string; line: number; col: number }[] = [];
    const fail = (line: number, col: number, what: string, reason: string, help: string) => `error: <source>:${line}:${col} — ${what}\n  reason: ${reason}\n  help: ${help}`;
    let line = 1;
    let col = 0;
    let inString = false;
    let inComment = false;
    for (let i = 0; i < source.length; i++) {
      const ch = source[i]!;
      if (ch === '\n') {
        line++;
        col = 0;
        inComment = false;
        continue;
      }
      col++;
      if (inComment) continue;
      if (inString) {
        if (ch === '\\') i++;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === '/' && source[i + 1] === '/') inComment = true;
      else if (ch in closes) stack.push({ ch, line, col });
      else if (ch === ')' || ch === ']' || ch === '}') {
        const top = stack.pop();
        if (!top) return fail(line, col, `unexpected '${ch}'`, `it closes nothing`, `remove it, or add the matching opener`);
        if (closes[top.ch] !== ch) return fail(line, col, `expecting '${closes[top.ch]}' but found '${ch}'`, `the '${top.ch}' opened at ${top.line}:${top.col} is still open`, `match each opener with its own closer`);
      }
    }
    if (inString) return fail(line, col + 1, 'unterminated string', 'the source ends inside a string literal', 'the file ends mid-statement; look for an unclosed brace, bracket, or string');
    const open = stack.pop();
    if (open) return fail(line, col + 1, `expecting '${closes[open.ch]}' to end the block opened at ${open.line}:${open.col}`, 'the source ends before the block closes', 'the file ends mid-statement; look for an unclosed brace, bracket, or string');
    return null;
  }
  /** What the core reports about a script's text: name, API, hooks and the `registers` scan. */
  function scriptReport(source: string) {
    const names = (re: RegExp) => [...source.matchAll(re)].map((m) => m[1]!);
    return {
      name: /\bconst\s+NAME\s*=\s*"([^"]+)"/.exec(source)?.[1] ?? '<source>',
      api: /\bconst\s+API\s*=\s*"([^"]+)"/.exec(source)?.[1] ?? '1',
      hooks: SCRIPT_HOOKS.filter((h) => new RegExp(`\\bfn\\s+${h}\\s*\\(`).test(source)),
      registers: { commands: names(/\breg\.command\(\s*"([^"]+)"/g), options: names(/\breg\.option\(\s*"([^"]+)"/g) },
    };
  }

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

  // ---- Scanner v2 (D3, spec D-T8.11): the `scan.*` verbs and a simulated job --------------------
  //
  // DEVELOPMENT ONLY. Every reply below is a hand-written shape modelled on
  // `crates/aitm-scan-model/fixtures/*.json`, and the "job" is a chain of `later()` timers: no
  // request is sent, nothing is crawled, nothing is probed, and the two issues it reports are
  // literals with fresh ids. This exists so the Scan panel can be built and demonstrated with
  // `?bus=mock` while the engine lands. As the fixture pack's README says of the pack itself, a
  // green run against a shape proves the shape and nothing else: **a `?bus=mock` run is never
  // acceptance evidence** for the scanner (umbrella spec Verification). That proof is a live run
  // against a real core with a real target.

  /** `scanner.ceilings.probes` (D11 default). A bigger budget comes back `clamped`, never refused. */
  const SCAN_PROBE_CEILING = 20000;
  const SCAN_PROFILE_DIR = '/Users/operator/.aitmproxy/findings/scan/profiles';
  /** The engine reports a lane whose crate is absent as skipped, not as a refusal (D1/D5). */
  const SCAN_UNAVAILABLE_LANES = ['ws'];
  const SCAN_CANARY = { kind: 'flow', method: 'GET', path: '/account', expected_status: 200 };

  type ScanState = 'queued' | 'running' | 'cancelling' | 'done' | 'cancelled' | 'failed';
  type ScanPhase = 'queued' | 'crawling' | 'passive' | 'auditing' | 'reporting' | 'done';

  interface ScanIssueFx {
    id: string;
    job: string;
    check_id: string;
    class: string;
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: 'certain' | 'firm' | 'tentative';
    status: 'open' | 'confirmed' | 'false_positive';
    lane: string;
    target: { scheme: string; host: string; port: number };
    location: { method: string; path: string; path_template: string; kind: string; name: string; field_path: string | null; ws_path: string | null; l4: null };
    evidence: { payload: string; matched: string; probe_flows: string[]; baseline_flow: string | null; timing: null; diff: null; l4: null };
    first_seen: number;
    last_seen: number;
    occurrences: number;
    poc_ref: string | null;
    finding_id: string | null;
    description: string;
    remediation: string | null;
    note: string | null;
  }

  interface ScanJobFx {
    job: string;
    state: ScanState;
    phase: ScanPhase;
    profile_name: string;
    targets: string[];
    origin: string | null;
    started_at: number;
    finished_at: number | null;
    stopped_reason: string | null;
    probes: { sent: number; budget: number; errors: number; timeouts: number; rate_waits: number; by_lane: Record<string, number> };
    crawl: { pages: number; queued: number; depth: number; forms_submitted: number };
    points: { found: number; queued: number; audited: number; skipped: { ignored: number; frequent: number; limit: number } };
    checks: { scheduled: number; done: number; running: string[] };
    lanes: { requested: string[]; run: string[]; skipped: { lane: string; reason: string }[] };
    clamped: { field: string; requested: number; applied: number }[];
    /** Strictly increasing per job, as the engine's push sequence is. */
    seq: number;
  }

  /** The `standard` built-in, field for field as `scan.profile.get` answers it. */
  const SCAN_STANDARD_PROFILE: Record<string, unknown> = {
    name: 'standard',
    target: { origins: [], l4: [] },
    lanes: ['http', 'ws'],
    intensity: 'medium',
    speed: 'normal',
    accuracy: 'normal',
    checks: { include: [], exclude: [] },
    crawl: { strategy: 'normal', max_depth: 3, max_pages: 200, submit_forms: true, click_handlers: true, robots: true, sitemap: true, use_browser: 'auto' },
    audit: {
      kinds: ['query', 'body_param', 'json_value', 'xml_value', 'xml_attr', 'multipart_value', 'multipart_filename', 'header', 'cookie', 'path_segment', 'path_filename', 'param_name_query', 'param_name_body', 'entire_body', 'ws_json_value', 'ws_text', 'ws_form_param', 'ws_binary', 'ws_handshake_header', 'l4_field'],
      ignore: [{ kind: null, name_regex: null, trait: 'session' }],
      max_points_per_request: 64,
      frequent_point_threshold: 8,
    },
    session: { mode: 'observed', from_flow: null, on_lost: 'stop' },
    budget: { probes: 2000, time_s: 600, max_issues: 1024, check_timeout_s: 60, per_host_errors: { consecutive: 10, ratio: 0.5 } },
    http: { version: 'auto', record_probes: 'issues_only' },
    ws: { reply_window_ms: 1500, max_frame_bytes: 1048576 },
    l4: { cases: 500, reproduce_count: 3, liveness_every: 25, consecutive_timeouts: 20, max_bytes_per_s: 65536, seeds: [], dry_run: false },
  };

  /** The seven built-ins of `scan.profile.list`; the tree each one returns is `standard` retuned. */
  const SCAN_BUILTIN_PROFILES: { name: string; lanes: string[]; intensity: string; speed: string }[] = [
    { name: 'passive-only', lanes: ['http'], intensity: 'passive', speed: 'normal' },
    { name: 'map-only', lanes: ['http'], intensity: 'passive', speed: 'normal' },
    { name: 'light-http', lanes: ['http'], intensity: 'light', speed: 'fast' },
    { name: 'standard', lanes: ['http', 'ws'], intensity: 'medium', speed: 'normal' },
    { name: 'thorough', lanes: ['http', 'ws'], intensity: 'medium', speed: 'thorough' },
    { name: 'l4-stream-safe', lanes: ['l4_stream'], intensity: 'medium', speed: 'normal' },
    { name: 'l4-full', lanes: ['l4_packet', 'l4_stream'], intensity: 'medium', speed: 'normal' },
  ];

  const savedScanProfiles = new Map<string, Record<string, unknown>>();
  /** Newest first, as `scan.list` returns them. */
  const scanJobs: ScanJobFx[] = [];
  const scanIssues: ScanIssueFx[] = [];

  const scanClone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
  const scanDict = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
  const scanStrings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
  const scanNum = (v: unknown, dflt: number): number => (typeof v === 'number' && Number.isFinite(v) ? v : dflt);
  /** The core's error form: `scan: <code>: <detail>`, which every UI matches on the code token. */
  const scanError = (code: string, detail: string) => new BusError(`scan: ${code}: ${detail}`);
  const scanHex8 = () => Math.floor(rng() * 0xffffffff).toString(16).padStart(8, '0');

  function scanProfileTree(name: string): Record<string, unknown> {
    const saved = savedScanProfiles.get(name);
    if (saved) return scanClone(saved);
    const builtin = SCAN_BUILTIN_PROFILES.find((p) => p.name === name);
    if (!builtin) throw scanError('not_found', `no profile named ${name}`);
    // The tree agrees with the list summary: name, lanes, intensity and speed come from the entry.
    return { ...scanClone(SCAN_STANDARD_PROFILE), name: builtin.name, lanes: [...builtin.lanes], intensity: builtin.intensity, speed: builtin.speed };
  }

  function scanProfileEntry(name: string, tree: Record<string, unknown>, builtin: boolean) {
    return {
      name,
      builtin,
      summary: {
        lanes: scanStrings(tree.lanes),
        intensity: typeof tree.intensity === 'string' ? tree.intensity : 'medium',
        speed: typeof tree.speed === 'string' ? tree.speed : 'normal',
      },
    };
  }

  /** The whole-profile launch the Scan surface sends: `{ profile }`, nothing else. */
  function scanProfileArg(args: Record<string, unknown>): Record<string, unknown> {
    const p = args.profile;
    if (typeof p !== 'object' || p === null || Array.isArray(p)) throw scanError('invalid_profile', 'the fixture bus takes a whole `profile`');
    return p as Record<string, unknown>;
  }

  function scanTargetsOf(p: Record<string, unknown>): { origins: string[]; l4: string[] } {
    const t = scanDict(p.target);
    const l4 = (Array.isArray(t.l4) ? t.l4 : []).map((x) => {
      const o = scanDict(x);
      return `${typeof o.ip === 'string' ? o.ip : '?'}:${scanNum(o.port, 0)}`;
    });
    return { origins: scanStrings(t.origins), l4 };
  }

  function scanCheckScope(origins: string[]) {
    for (const o of origins) {
      let host = '';
      let hostPort = '';
      try {
        const u = new URL(o);
        host = u.hostname;
        hostPort = u.host;
      } catch {
        throw scanError('out_of_scope', `${o} is not in scope`);
      }
      if (![...scope].some((h) => h === host || h === hostPort || (h.startsWith('*.') && host.endsWith(h.slice(1)))))
        throw scanError('out_of_scope', `${o} is not in scope`);
    }
  }

  const scanJobOf = (id: string): ScanJobFx => {
    const j = scanJobs.find((x) => x.job === id);
    if (!j) throw scanError('not_found', `no job ${id}`);
    return j;
  };
  const scanRunning = (j: ScanJobFx) => j.state === 'queued' || j.state === 'running';
  const scanElapsed = (j: ScanJobFx) => (j.finished_at ?? Date.now()) - j.started_at;
  const scanIssuesOf = (job: string) => scanIssues.filter((i) => i.job === job);

  function scanIssueCounters(job: string) {
    const rows = scanIssuesOf(job);
    const by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const by_confidence = { certain: 0, firm: 0, tentative: 0 };
    for (const r of rows) {
      by_severity[r.severity]++;
      by_confidence[r.confidence]++;
    }
    return { total: rows.length, by_severity, by_confidence };
  }

  /** The summary fields a `scan.list` row and every push line carry. */
  function scanSummaryWire(j: ScanJobFx) {
    return {
      job: j.job,
      state: j.state,
      phase: j.phase,
      elapsed_ms: scanElapsed(j),
      probes: { ...j.probes, by_lane: { ...j.probes.by_lane } },
      points: { ...j.points, skipped: { ...j.points.skipped } },
      issues: scanIssueCounters(j.job),
    };
  }

  /** The full `JobStatus` of `scan.status`, `scan.cancel` and the `scan.start` result. */
  function scanStatusWire(j: ScanJobFx) {
    const l4Lane = j.lanes.run.some((l) => l.startsWith('l4'));
    return {
      ...scanSummaryWire(j),
      profile_name: j.profile_name,
      targets: [...j.targets],
      started_by: { frontend: 'operator', client_label: 'web-ui' },
      started_at: j.started_at,
      finished_at: j.finished_at,
      stopped_reason: j.stopped_reason,
      crawl: { ...j.crawl },
      checks: { ...j.checks, running: [...j.checks.running] },
      l4: l4Lane ? { cases: j.probes.sent, crashes: 0, liveness_failures: 0, retired_elements: 0 } : null,
      session: j.origin ? { reused: true, lost: false, canary: { ...SCAN_CANARY }, browser_partial: false } : null,
      lanes: { requested: [...j.lanes.requested], run: [...j.lanes.run], skipped: j.lanes.skipped.map((s) => ({ ...s })) },
      clamped: j.clamped.map((c) => ({ ...c })),
      error: null,
    };
  }

  const scanIssueSummaryWire = (i: ScanIssueFx) => {
    const { evidence: _e, description: _d, remediation: _r, note: _n, ...summary } = scanClone(i);
    return summary;
  };

  /** One `notifications/aitm/job` line. `seq` is strictly increasing per job. */
  function scanPush(j: ScanJobFx, event: string, issue?: ScanIssueFx) {
    j.seq++;
    notify('notifications/aitm/job', {
      job: j.job,
      kind: 'scan',
      event,
      seq: j.seq,
      ts_ms: Date.now(),
      status: scanSummaryWire(j),
      ...(issue ? { issue: scanIssueSummaryWire(issue) } : {}),
    });
  }

  /** Two flows of the fixture set to stand in for probe flows, so the inspector links resolve. */
  function scanProbeFlows(): string[] {
    const ids = [...flows.keys()].slice(-2);
    return ids.length === 2 ? ids : ['550e8400-e29b-41d4-a716-446655440000', '7c9e6679-7425-40de-944b-e07fc1f90ae7'];
  }

  function scanFindIssue(j: ScanJobFx, which: 0 | 1) {
    if (!scanRunning(j)) return;
    const u = ((): URL | null => {
      try {
        return j.origin ? new URL(j.origin) : null;
      } catch {
        return null;
      }
    })();
    const target = {
      scheme: u?.protocol === 'http:' ? 'http' : 'https',
      host: u?.hostname ?? '127.0.0.1',
      port: Number(u?.port || (u?.protocol === 'http:' ? 80 : 443)) || 8080,
    };
    const [xss, redirect] = scanProbeFlows();
    const fx: ScanIssueFx[] = [
      {
        id: `issue-${scanHex8()}`,
        job: j.job,
        check_id: 'http.reflected-xss',
        class: 'reflected-xss',
        name: 'Reflected cross-site scripting',
        severity: 'high',
        confidence: 'certain',
        status: 'open',
        lane: 'http',
        target,
        location: { method: 'GET', path: '/search', path_template: '/search', kind: 'query', name: 'q', field_path: null, ws_path: null, l4: null },
        evidence: {
          payload: '<script>aitm-canary()</script>',
          matched: 'reflected marker aitm-canary in an HTML text node',
          probe_flows: [xss ?? '', redirect ?? ''].filter((x) => x !== ''),
          baseline_flow: xss ?? null,
          timing: null,
          diff: null,
          l4: null,
        },
        first_seen: Date.now(),
        last_seen: Date.now(),
        occurrences: 1,
        poc_ref: pocs[0]?.id ?? null,
        finding_id: null,
        description: 'A request parameter is reflected into the response unescaped.',
        remediation: 'Contextually encode output and set a strict CSP.',
        note: null,
      },
      {
        id: `issue-${scanHex8()}`,
        job: j.job,
        check_id: 'http.open-redirect',
        class: 'open-redirect',
        name: 'Open redirect',
        severity: 'medium',
        confidence: 'firm',
        status: 'open',
        lane: 'http',
        target,
        location: { method: 'GET', path: '/go', path_template: '/go', kind: 'query', name: 'next', field_path: null, ws_path: null, l4: null },
        evidence: {
          payload: 'https://aitm.invalid/',
          matched: 'Location header points at the injected host',
          probe_flows: [redirect ?? ''].filter((x) => x !== ''),
          baseline_flow: null,
          timing: null,
          diff: null,
          l4: null,
        },
        first_seen: Date.now(),
        last_seen: Date.now(),
        occurrences: 1,
        poc_ref: null,
        finding_id: null,
        description: 'The redirect target comes from a request parameter without an allow-list.',
        remediation: 'Redirect only to paths of this origin, or to an allow-listed host.',
        note: null,
      },
    ];
    const issue = fx[which];
    if (!issue) return;
    scanIssues.push(issue);
    scanPush(j, 'issue', issue);
  }

  /** `progress` every 250 ms while auditing: at most four lines a second, as D3 requires. */
  function scanProgressTick(j: ScanJobFx) {
    later(250, () => {
      if (!scanRunning(j) || j.phase !== 'auditing') return;
      j.probes.sent = Math.min(j.probes.budget, j.probes.sent + 7);
      for (const lane of j.lanes.run) j.probes.by_lane[lane] = j.probes.sent;
      j.points.audited = Math.min(j.points.found, j.points.audited + 4);
      j.points.queued = Math.max(0, j.points.found - j.points.audited);
      j.checks.done = Math.min(j.checks.scheduled, j.checks.done + 6);
      scanPush(j, 'progress');
      scanProgressTick(j);
    });
  }

  /** The whole simulated run: phases on a timer, two issues, then `done`. A cancel ends it early. */
  function scanRun(j: ScanJobFx) {
    later(500, () => {
      if (!scanRunning(j)) return;
      j.state = 'running';
      j.phase = 'crawling';
      j.crawl = { pages: 12, queued: 25, depth: 2, forms_submitted: 1 };
      scanPush(j, 'started');
    });
    later(2000, () => {
      if (!scanRunning(j)) return;
      j.phase = 'passive';
      j.crawl = { pages: 37, queued: 0, depth: 3, forms_submitted: 4 };
      j.points = { found: 120, queued: 120, audited: 0, skipped: { ignored: 5, frequent: 3, limit: 0 } };
      scanPush(j, 'phase');
    });
    later(3000, () => {
      if (!scanRunning(j)) return;
      j.phase = 'auditing';
      j.checks = { scheduled: 240, done: 0, running: ['http.reflected-xss', 'http.sqli-error'] };
      scanPush(j, 'phase');
      scanProgressTick(j);
    });
    later(4000, () => scanFindIssue(j, 0));
    later(6000, () => scanFindIssue(j, 1));
    later(8000, () => {
      if (!scanRunning(j)) return;
      j.phase = 'reporting';
      j.checks = { ...j.checks, done: j.checks.scheduled, running: [] };
      scanPush(j, 'phase');
    });
    later(9000, () => {
      if (!scanRunning(j)) return;
      j.state = 'done';
      j.phase = 'done';
      j.finished_at = Date.now();
      scanPush(j, 'finished');
    });
  }

  function scanStart(tool: 'scan.start' | 'scan.map', args: Record<string, unknown>): unknown {
    const p = scanProfileArg(args);
    const isMap = tool === 'scan.map';
    const requestedLanes = isMap ? ['http'] : scanStrings(p.lanes);
    const lanes = requestedLanes.length ? requestedLanes : ['http'];
    const intensity = isMap ? 'passive' : typeof p.intensity === 'string' ? p.intensity : 'medium';
    const { origins, l4 } = scanTargetsOf(p);
    scanCheckScope(origins);
    const targets = [...origins, ...(isMap ? [] : l4)];
    if (!targets.length) throw scanError('invalid_profile', 'the profile has no origin and no L4 target');

    // Confirm over the wire for the dangerous shapes, exactly as `l4.inject` does (D-T8.6).
    const l4Lane = lanes.some((l) => l.startsWith('l4'));
    if ((l4Lane || intensity === 'intrusive') && typeof args._confirm !== 'string')
      return {
        status: 'needs_confirmation',
        prompt: `This scan sends malformed traffic to ${targets.join(', ')} and may disrupt the target. Continue?`,
        confirm_token: `scan-${scanHex8()}`,
      };

    const wanted = scanNum(scanDict(p.budget).probes, 2000);
    const budget = isMap ? 0 : Math.min(wanted, SCAN_PROBE_CEILING);
    const clamped = !isMap && wanted > SCAN_PROBE_CEILING ? [{ field: 'budget.probes', requested: wanted, applied: SCAN_PROBE_CEILING }] : [];
    const skipped = lanes.filter((l) => SCAN_UNAVAILABLE_LANES.includes(l)).map((lane) => ({ lane, reason: 'lane not available on this build' }));
    const run = lanes.filter((l) => !SCAN_UNAVAILABLE_LANES.includes(l));
    if (!run.length) throw scanError('lane_unavailable', `no requested lane is available: ${lanes.join(', ')}`);

    const job: ScanJobFx = {
      job: `scan-${scanHex8()}`,
      state: 'queued',
      phase: 'queued',
      profile_name: typeof p.name === 'string' && p.name ? p.name : 'standard',
      targets,
      origin: origins[0] ?? null,
      started_at: Date.now(),
      finished_at: null,
      stopped_reason: null,
      probes: { sent: 0, budget, errors: 0, timeouts: 0, rate_waits: 0, by_lane: {} },
      crawl: { pages: 0, queued: 0, depth: 0, forms_submitted: 0 },
      points: { found: 0, queued: 0, audited: 0, skipped: { ignored: 0, frequent: 0, limit: 0 } },
      checks: { scheduled: 0, done: 0, running: [] },
      lanes: { requested: lanes, run, skipped },
      clamped,
      seq: 0,
    };
    scanJobs.unshift(job);
    scanRun(job);
    recordActivity(tool, { profile: job.profile_name, targets }, 'web');
    return {
      job: job.job,
      status: scanStatusWire(job),
      clamped: job.clamped.map((c) => ({ ...c })),
      lanes: { requested: [...lanes], run: [...run], skipped: skipped.map((s) => ({ ...s })) },
      // Present only for a profile with an L4 lane (D3); absent is not `false`.
      ...(l4Lane ? { dry_run: scanDict(p.l4).dry_run === true } : {}),
    };
  }

  /** Two site-map nodes and three insertion points, modelled on `scan.sitemap.json`. */
  function scanSitemapWire(j: ScanJobFx | null) {
    let scheme = 'http';
    let host = '127.0.0.1';
    let port = 8080;
    try {
      if (j?.origin) {
        const u = new URL(j.origin);
        scheme = u.protocol === 'http:' ? 'http' : 'https';
        host = u.hostname;
        port = Number(u.port || (u.protocol === 'http:' ? 80 : 443));
      }
    } catch {
      /* keep the defaults */
    }
    const [a, b] = scanProbeFlows();
    const flowA = a ?? '550e8400-e29b-41d4-a716-446655440000';
    const flowB = b ?? '7c9e6679-7425-40de-944b-e07fc1f90ae7';
    return {
      nodes: [
        { id: 'node-1', method: 'GET', scheme, host, port, path_template: '/account/{id}', flows: [flowA], params: [{ kind: 'query', name: 'tab' }], auth: true, points: 2, audited: true },
        { id: 'node-2', method: 'GET', scheme, host, port, path_template: '/search', flows: [flowB], params: [{ kind: 'query', name: 'q' }], auth: false, points: 1, audited: j !== null },
      ],
      points: [
        { id: 'point-json-1', lane: 'http', kind: 'json_value', name: 'city', path: 'profile.address.city', example: 'Lisbon', flow: flowA, site_node: 'node-1', traits: ['json'], frequency: 3, method: 'POST', url: `${scheme}://${host}:${port}/account` },
        // The engine redacts a session-ish example before it reaches the wire (D7).
        { id: 'point-cookie-1', lane: 'http', kind: 'cookie', name: 'theme', path: null, example: '<redacted>', flow: flowB, site_node: 'node-1', traits: ['id'], frequency: 9, method: 'GET', url: `${scheme}://${host}:${port}/account` },
        { id: 'point-query-1', lane: 'http', kind: 'query', name: 'q', path: null, example: 'lamp', flow: flowB, site_node: 'node-2', traits: [], frequency: 12, method: 'GET', url: `${scheme}://${host}:${port}/search` },
      ],
      next_cursor: null,
    };
  }

  /** The three checks of `scan.checks.json`: one native, one bundled, one operator-authored. */
  const SCAN_CHECKS = [
    { id: 'http.reflected-xss', name: 'reflected-xss check', class: 'reflected-xss', lanes: ['http'], kinds: ['query', 'body_param'], intensity: 'medium', cost: 'light', technique: 'reflected', severity: 'high', confidence_max: 'certain', needs_baseline: false, wants_traits: null, targets_session: false, cwe: 79, description: 'Detects reflected-xss.', remediation: 'Validate and encode untrusted input.', origin: { kind: 'native' } },
    { id: 'http.sqli-error', name: 'Error-based SQL injection', class: 'sqli-error', lanes: ['http'], kinds: ['query', 'body_param', 'cookie', 'json_value'], intensity: 'medium', cost: 'light', technique: 'error', severity: 'high', confidence_max: 'firm', needs_baseline: true, wants_traits: null, targets_session: false, cwe: 89, description: 'Sends SQL metacharacters into the point and matches the response against database error signatures.', remediation: 'Use parameterised queries for every database call.', origin: { kind: 'bundled', path: 'scripts/bundled/active/sqli.rhai' } },
    { id: 'http.custom-marker', name: 'Debug marker header exposure', class: 'information-disclosure', lanes: ['http'], kinds: ['header'], intensity: 'passive', cost: 'light', technique: 'passive', severity: 'low', confidence_max: 'certain', needs_baseline: false, wants_traits: null, targets_session: false, cwe: 200, description: 'An operator-authored passive check: flags responses carrying the in-house X-Debug-Marker header.', remediation: 'Strip the debug header at the edge for production builds.', origin: { kind: 'custom', path: '~/.aitmproxy/scripts/marker.rhai' } },
  ];

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
        return { listening: true, address: '127.0.0.1:8080', capturing, intercept_armed: armed, paused: pausedCount(), flows: flows.size, protocol: 'HTTP/2', version: MOCK_VERSION };
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

      // ---- Scanner v2 (D3): see the `scan*` fixtures above. Development only, never evidence. ----
      case 'scan.start':
      case 'scan.map':
        return scanStart(tool, args);
      case 'scan.status':
        return scanStatusWire(scanJobOf(need(args, 'job')));
      case 'scan.list': {
        const active = args.active_only === true;
        const limit = scanNum(args.limit, scanJobs.length);
        return { jobs: scanJobs.filter((j) => !active || scanRunning(j) || j.state === 'cancelling').slice(0, Math.max(0, limit)).map(scanSummaryWire) };
      }
      case 'scan.cancel': {
        // Two-step and idempotent, as the engine is: `cancelling` now, `cancelled` once it lands.
        const j = scanJobOf(need(args, 'job'));
        if (!scanRunning(j)) return scanStatusWire(j);
        j.state = 'cancelling';
        j.stopped_reason = 'cancelled';
        later(300, () => {
          if (j.state !== 'cancelling') return;
          j.state = 'cancelled';
          j.phase = 'done';
          j.finished_at = Date.now();
          j.checks = { ...j.checks, running: [] };
          scanPush(j, 'cancelled');
        });
        recordActivity(tool, args, 'web');
        return scanStatusWire(j);
      }
      case 'scan.issues': {
        const job = typeof args.job === 'string' ? args.job : null;
        if (job !== null) scanJobOf(job);
        const all = job === null ? scanIssues : scanIssuesOf(job);
        const rows = all.filter(
          (i) =>
            (typeof args.status !== 'string' || i.status === args.status) &&
            (typeof args.lane !== 'string' || i.lane === args.lane) &&
            (typeof args.class !== 'string' || i.class === args.class),
        );
        const limit = Math.min(scanNum(args.limit, 1024), 1024);
        const by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const r of rows) by_severity[r.severity]++;
        // One page: the fixture bus never invents more issues than it found.
        return { issues: rows.slice(0, Math.max(0, limit)).map(scanIssueSummaryWire), next_cursor: null, by_severity };
      }
      case 'scan.issue': {
        const id = need(args, 'id');
        const issue = scanIssues.find((i) => i.id === id);
        if (!issue) throw scanError('not_found', `no issue ${id}`);
        return scanClone(issue);
      }
      case 'scan.issue.update': {
        const id = need(args, 'id');
        const issue = scanIssues.find((i) => i.id === id);
        if (!issue) throw scanError('not_found', `no issue ${id}`);
        const status = need(args, 'status');
        if (status !== 'open' && status !== 'confirmed' && status !== 'false_positive') throw scanError('invalid_profile', `unknown issue status ${status}`);
        issue.status = status;
        if (args.note !== undefined) issue.note = typeof args.note === 'string' && args.note ? args.note : null;
        recordActivity(tool, { id, status }, 'web');
        return scanClone(issue);
      }
      case 'scan.sitemap':
        return scanSitemapWire(typeof args.job === 'string' ? scanJobOf(args.job) : null);
      case 'scan.checks':
        return {
          checks: scanClone(SCAN_CHECKS).filter(
            (c) =>
              (typeof args.lane !== 'string' || c.lanes.includes(args.lane)) &&
              (typeof args.class !== 'string' || c.class === args.class) &&
              (typeof args.origin !== 'string' || c.origin.kind === args.origin),
          ),
        };
      case 'scan.profile.list':
        return {
          profiles: [
            ...SCAN_BUILTIN_PROFILES.map((p) => scanProfileEntry(p.name, { lanes: p.lanes, intensity: p.intensity, speed: p.speed }, true)),
            ...[...savedScanProfiles.entries()].map(([name, tree]) => scanProfileEntry(name, tree, false)),
          ],
        };
      case 'scan.profile.get':
        return scanProfileTree(need(args, 'name'));
      case 'scan.profile.save': {
        const p = scanProfileArg(args);
        const name = typeof p.name === 'string' ? p.name : '';
        if (!name) throw scanError('invalid_profile', 'the profile needs a name');
        if (SCAN_BUILTIN_PROFILES.some((b) => b.name === name)) throw scanError('invalid_profile', `${name} is a built-in profile`);
        savedScanProfiles.set(name, scanClone(p));
        recordActivity(tool, { name }, 'web');
        return { saved: name, path: `${SCAN_PROFILE_DIR}/${name}.yaml` };
      }
      case 'scan.profile.delete': {
        const name = need(args, 'name');
        if (SCAN_BUILTIN_PROFILES.some((b) => b.name === name)) throw scanError('invalid_profile', `${name} is a built-in profile`);
        const deleted = savedScanProfiles.delete(name);
        recordActivity(tool, { name }, 'web');
        return { deleted };
      }
      case 'scan.session.preview': {
        // Names only: no verb, push or file of the scanner ever carries a session value (D7).
        const target = need(args, 'target');
        const source = [...flows.values()].find((f) => f.inScope && f.kind === 'http')?.id ?? null;
        return { origin: target, cookies: ['sid'], headers: ['authorization'], source_flow: source, observed_at: Date.now(), canary: { ...SCAN_CANARY } };
      }

      // ---- Rhai scripts (F8): see the `script*` fixtures above ----
      case 'script.list':
        return scriptFx.map((s) => ({ ...s, hooks: [...s.hooks] }));
      case 'script.enable':
      case 'script.disable': {
        const s = scriptNamed(need(args, 'name'));
        s.enabled = tool === 'script.enable';
        recordActivity(tool, args, 'web');
        return { name: s.name, enabled: s.enabled };
      }
      case 'script.reload': {
        const s = scriptNamed(need(args, 'name'));
        s.last_error = null;
        recordActivity(tool, args, 'web');
        return { name: s.name, api: s.api, path: s.path, hooks: [...s.hooks] };
      }
      case 'script.validate': {
        const hasPath = typeof args.path === 'string';
        const hasSource = typeof args.source === 'string';
        if (hasPath && hasSource) throw new BusError('script.validate takes exactly one of `path` or `source`, got both');
        if (!hasPath && !hasSource) throw new BusError('script.validate takes exactly one of `path` or `source`, got neither');
        if (hasPath) throw new BusError('the fixture bus has no script files to read; pass `source`');
        const source = args.source as string;
        const err = scriptCompileError(source);
        if (err) throw new BusError(err);
        return scriptReport(source);
      }
      case 'script.save': {
        const name = typeof args.name === 'string' ? args.name : '';
        if (!/^[A-Za-z0-9_-]+$/.test(name))
          throw new BusError(`\`name\` must be a single path segment matching [A-Za-z0-9_-]+ (no separators, dots or spaces), got ${JSON.stringify(name)}`);
        const source = need(args, 'source');
        if (args.enable != null && typeof args.enable !== 'boolean') throw new BusError('`enable` must be a boolean');
        const enable = typeof args.enable === 'boolean' ? args.enable : true;
        const err = scriptCompileError(source);
        if (err) throw new BusError(err);
        const { api, hooks, registers } = scriptReport(source);
        const path = `${SCRIPT_DIR}/${name}.rhai`;
        const loaded = scriptFx.find((s) => s.name === name);
        if (loaded) Object.assign(loaded, { api, hooks, enabled: enable, last_error: null });
        else scriptFx.push({ name, path, api, hooks, enabled: enable, last_error: null });
        recordActivity(tool, { name, enable }, 'web');
        return { name, path, api, hooks, registers, restart_required: registers.commands.length > 0 || registers.options.length > 0 };
      }
      case 'script.findings': {
        const keep = typeof args.limit === 'number' ? Math.max(0, args.limit) : scriptFindings.length;
        return { findings: scriptFindings.slice(Math.max(0, scriptFindings.length - keep)).map((f) => ({ ...f, tags: [...f.tags] })), dropped: 0 };
      }

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
    ['script.list', 'List the loaded scripts in chain order: name, path, API, hooks, whether enabled, and the most recent hook error (null if none).', {}],
    ['script.validate', 'Compile a .rhai script without loading it; reports its name, API, hooks and the commands/options its load(reg) registers, or the positioned compile error. Give exactly one of `path` or `source`.', { path: { type: 'string', description: 'path to the .rhai file to check; exactly one of `path` or `source`' }, source: { type: 'string', description: 'the script text to check; exactly one of `path` or `source`' } }],
    ['script.reload', 'Recompile a loaded script from its file and swap its hooks live; a failed recompile keeps the previous version.', { name: { type: 'string', description: "the script's NAME (or file stem) as loaded" } }, ['name']],
    ['script.enable', "Turn a loaded script's hooks back on live. Idempotent. Answers { name, enabled }.", { name: { type: 'string', description: "the script's NAME (or file stem) as loaded" } }, ['name']],
    ['script.disable', "Turn a loaded script's hooks off live without unloading it. Idempotent. Answers { name, enabled }.", { name: { type: 'string', description: "the script's NAME (or file stem) as loaded" } }, ['name']],
    ['script.save', 'Write a script to <scripts_dir>/<name>.rhai after checking it compiles. Its hooks go live immediately; restart_required is true only when it registers commands or options.', { name: { type: 'string', description: "the script's file stem: letters, digits, `_` and `-` only" }, source: { type: 'string', description: 'the script text' }, enable: { type: 'boolean', description: "sets the saved script's live enabled flag (default true)" } }, ['name', 'source']],
    ['script.findings', 'Findings scripts emitted with finding(...) this run (in-memory, not persisted), oldest first, plus how many the bounded sink dropped.', { limit: { type: 'integer', description: 'return only the newest N findings' } }],
    ['scan.start', 'Start a scan job from a whole ScanProfile; returns immediately with the job id. An L4 lane or intensity: intrusive needs the operator confirm handshake.', { profile: { type: 'object', description: 'the whole ScanProfile to run' } }, ['profile']],
    ['scan.map', 'Map a target: crawl and passive only (lanes http, intensity passive), no probes. The job-model successor of scan.discover.', { profile: { type: 'object', description: 'the whole ScanProfile; the lanes and intensity are forced' } }, ['profile']],
    ['scan.status', 'Full counters of one scan job.', { job: { type: 'string', description: 'job id from scan.start' } }, ['job']],
    ['scan.list', 'Scan jobs, newest first.', { active_only: { type: 'boolean' }, limit: { type: 'integer' } }],
    ['scan.cancel', 'Cancel a scan job; idempotent, answers cancelling then the job turns cancelled.', { job: { type: 'string' } }, ['job']],
    ['scan.issues', 'Issues of a job (or of every job), with the counts by severity.', { job: { type: 'string' }, status: { type: 'string', enum: ['open', 'confirmed', 'false_positive'] }, lane: { type: 'string' }, class: { type: 'string' }, limit: { type: 'integer' }, cursor: { type: 'string' } }],
    ['scan.issue', 'One issue with its evidence, probe flows, PoC ref and finding link.', { id: { type: 'string' } }, ['id']],
    ['scan.issue.update', 'Set the triage status and note of an issue.', { id: { type: 'string' }, status: { type: 'string', enum: ['open', 'confirmed', 'false_positive'] }, note: { type: 'string' } }, ['id', 'status']],
    ['scan.sitemap', 'Site map nodes and insertion points discovered by a job.', { job: { type: 'string' }, target: { type: 'string' }, limit: { type: 'integer' }, cursor: { type: 'string' } }],
    ['scan.checks', 'The check catalogue as loaded: native, bundled and custom.', { lane: { type: 'string' }, class: { type: 'string' }, origin: { type: 'string', enum: ['native', 'bundled', 'custom'] } }],
    ['scan.profile.list', 'Scan profiles: the built-ins and the operator-saved ones.', {}],
    ['scan.profile.get', 'One scan profile, whole.', { name: { type: 'string' } }, ['name']],
    ['scan.profile.save', 'Save an operator scan profile (its name may not be a built-in one).', { profile: { type: 'object', description: 'the whole ScanProfile; name required' } }, ['profile']],
    ['scan.profile.delete', 'Delete an operator scan profile.', { name: { type: 'string' } }, ['name']],
    ['scan.session.preview', 'Session material the engine would reuse for a target: cookie and header NAMES only, never a value.', { target: { type: 'string' } }, ['target']],
  ].map(([name, description, properties, required]) => ({
    name: name as string,
    description: description as string,
    inputSchema: {
      type: 'object',
      properties: properties as NonNullable<ToolDef['inputSchema']['properties']>,
      ...(required ? { required: required as string[] } : {}),
    },
    mutates: !/\.(list|get|detail|status|tabs|get_dom|screenshot|activity|artifact|export|validate|findings|issue|issues|sitemap|checks|preview)$/.test(name as string),
    confirm: /^ca\.(un)?install$/.test(name as string) ? 'This changes the system trust store.' : null,
  }));

  seed();

  return {
    address: 'fixtures',
    state,
    lastError,
    role: () => 'operator', // fixtures run the full command set, so the mock is always operator.
    expectRole: null,
    roleMismatch: () => false,
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
