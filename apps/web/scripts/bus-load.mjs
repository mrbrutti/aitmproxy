#!/usr/bin/env node
// Measures how often the web UI calls the core (spec D9 of 2026-10-30-web-ui-bus-push-design.md).
// Node >= 22 (global WebSocket), no dependencies, same style as bus-probe.mjs.
//
//   node apps/web/scripts/bus-load.mjs --token T [--label before|after|...] [--json out.json]
//   node apps/web/scripts/bus-load.mjs --seed 500 [--proxy 127.0.0.1:8080]   # fill the store, no windows
//   node apps/web/scripts/bus-load.mjs --selftest                             # pure counters, no network
//   node apps/web/scripts/bus-load.mjs --help
//
// INSTRUMENT. The server audits every tool call (crates/aitm-core/src/audit.rs: `at` epoch ms,
// `origin`, `command`, ...) and pushes each entry as a `notifications/aitm/agent` line to every
// subscribed connection. This script is a SEPARATE bridge connection that subscribes once with
// `flow.subscribe {}` and then just listens, so it counts the UI's calls from that stream. It does
// NOT read `agent.activity`: over `aitm web` that ring is empty, because the web server is a second
// McpServer with its own audit ring while `AgentActivity` reads the primary server's ring
// (crates/aitm/src/main.rs:429 attaches the ring to the primary only). The script's own calls are
// `flow.subscribe` (not audited; pinned by the e2e contract) and one `flow.list` after the last
// window (its line is stamped after the window end, so the time filter drops it); nothing it does
// lands inside a window.
//
// Two windows, each attributed by the UI's audit `origin` (--ui-origin, default `mcp`: the page
// opened at `aitm web`'s default URL is an agent-token bridge connection):
//   idle     page open, no traffic, --idle-secs (30; 0 skips)
//   traffic  --rate (20) plain-HTTP req/s for --traffic-secs (30; 0 skips) through --proxy to a
//            loopback origin this script starts, plus a 1 s settle
// Window bounds are this process's clock; lines are stamped by the server at record time and
// filtered on `at`. The script, the proxy and the browser share one host (the origin is
// loopback), so that is one clock. After each window the script waits RECEIVE_GRACE_MS for lines
// stamped inside the window that are still in flight; the bound itself is not widened.
//
// SETUP. The proxy is deny-by-default (ingress.rs: an out-of-scope authority is refused before
// any work), and a plain-HTTP loopback origin's authority is its IP, so `127.0.0.1` must be a
// scope entry (a port-less entry matches every port). `aitm web` takes scope from the config
// file only, and `--config` must be the FIRST argument:
//
//   printf 'listen: 127.0.0.1:8080\nscope:\n  entries:\n    - "127.0.0.1"\n' > $TMPDIR/aitm-load.yaml
//   aitm --config $TMPDIR/aitm-load.yaml web --listen 127.0.0.1:8082 --token T --no-open
//
// Keep that `aitm` in a foreground Terminal tab (it exits when its stdin closes). Open the
// printed `web UI (agent)` URL in a real browser and leave the page open. Seed the store
// (`--seed 500`) so `flow.list` has a real cost, then run the measurement. If the page was opened
// at the `web UI (operator)` URL, pass that URL's `t=` token as --token and `--ui-origin operator`.
import { createServer, request as httpRequest, Agent } from 'node:http';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const NOTIFICATION_PREFIX = 'notifications/aitm/';
/** Lines stamped inside a window may still be in flight when it closes; wait this long before counting. */
const RECEIVE_GRACE_MS = 250;
/** Collected audit lines are bounded so a runaway stream cannot grow the process without limit. */
const COLLECTOR_CAP = 200_000;
/** The traffic window keeps running this long after the last request, so the UI's reaction to the tail counts. */
const SETTLE_MS = 1000;
const MAX_IN_FLIGHT = 64;
const SEED_CONCURRENCY = 10;
const RPC_TIMEOUT_MS = 30000;
const REQUEST_TIMEOUT_MS = 15000;

// ---------------------------------------------------------------------------------------------
// Pure helpers (covered by --selftest)
// ---------------------------------------------------------------------------------------------

/**
 * Counts the UI's audited calls inside (startMs, endMs]. Keeps entries whose `origin` is
 * `uiOrigin` and counts them by `command`; entries of other origins are tallied in
 * `otherOrigins` so a wrong `--ui-origin` is visible rather than silent. The entry shape is the
 * server's audit shape (`at` epoch ms, `origin`, `command`, ...), identical on the wire and on
 * the ring.
 */
export function summarize(entries, uiOrigin, startMs, endMs) {
  const windowMs = endMs - startMs;
  if (!(windowMs > 0)) throw new RangeError(`summarize: empty window (${startMs}..${endMs})`);
  const perCommand = {};
  const otherOrigins = {};
  let total = 0;
  for (const e of entries) {
    if (typeof e?.at !== 'number' || e.at <= startMs || e.at > endMs) continue;
    if (e.origin !== uiOrigin) {
      const o = String(e.origin);
      otherOrigins[o] = (otherOrigins[o] ?? 0) + 1;
      continue;
    }
    const cmd = String(e.command);
    perCommand[cmd] = (perCommand[cmd] ?? 0) + 1;
    total++;
  }
  return { perCommand, total, otherOrigins, windowMs };
}

/** The per-window table: one line per command (busiest first) and `total`, as rates over the window. */
export function renderWindow(summary) {
  const secs = summary.windowMs / 1000;
  const row = (name, count) => `${name.padEnd(14)} ${(count / secs).toFixed(2)}/s`;
  const byCount = Object.entries(summary.perCommand).sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
  const lines = byCount.map(([cmd, n]) => row(cmd, n));
  lines.push(row('total', summary.total));
  return lines;
}

/** An audit line as audit.rs renders it; `approval_requested` events share the method but carry `event`. */
export function isAuditLine(p) {
  return (
    p != null &&
    typeof p === 'object' &&
    Number.isFinite(p.at) &&
    typeof p.origin === 'string' &&
    typeof p.command === 'string' &&
    p.event === undefined
  );
}

/**
 * Keeps every `notifications/aitm/agent` audit line the subscription delivers, in the server's
 * entry shape, and counts notifications per kind. `on` takes a parsed JSON-RPC notification.
 */
export function newCollector(cap = COLLECTOR_CAP) {
  const entries = [];
  const counts = { flow: 0, agent: 0, state: 0, other: 0, lagged: 0, nonAudit: 0, dropped: 0 };
  return {
    entries,
    on(m) {
      const method = typeof m?.method === 'string' ? m.method : '';
      const kind = method.startsWith(NOTIFICATION_PREFIX) ? method.slice(NOTIFICATION_PREFIX.length) : 'other';
      const p = m?.params;
      switch (kind) {
        case 'flow':
          counts.flow++;
          break;
        case 'state':
          counts.state++;
          if (p?.lagged === true) counts.lagged++;
          break;
        case 'agent':
          counts.agent++;
          if (!isAuditLine(p)) counts.nonAudit++;
          else if (entries.length >= cap) counts.dropped++;
          else entries.push({ at: p.at, origin: p.origin, client_label: p.client_label ?? null, command: p.command, args: p.args, result: p.result });
          break;
        default:
          counts.other++;
      }
    },
    snapshot() {
      return { ...counts };
    },
  };
}

// ---------------------------------------------------------------------------------------------
// --selftest: the canned window from the plan (Task 0) and the collector, exact lines, exit code
// ---------------------------------------------------------------------------------------------

function selftest() {
  const failures = [];
  const expectEq = (what, got, want) => {
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      failures.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
  };
  const expectLine = (lines, want) => {
    if (!lines.includes(want)) failures.push(`missing line ${JSON.stringify(want)}`);
  };
  const run = (name, fn) => {
    console.log(`-- ${name}`);
    try {
      fn();
    } catch (e) {
      failures.push(`${name} threw: ${e.message}`);
    }
  };
  // Server shape (audit.rs to_value, identical on the ring and on the wire): at = epoch ms,
  // origin cli|mcp|operator, client_label, command, args string, result 'ok' | {error}.
  const audit = (at, command, origin, extra = {}) => ({ at, origin, client_label: null, command, args: '{}', result: 'ok', ...extra });

  run('canned window (plan Task 0)', () => {
    const startMs = 1_730_000_000_000;
    const endMs = startMs + 30_000;
    const spread = (i) => startMs + 1 + Math.floor((i * 29_000) / 60);
    const entries = [];
    for (let i = 0; i < 60; i++) entries.push(audit(spread(i), 'flow.list', 'mcp'));
    for (let i = 0; i < 15; i++) entries.push(audit(spread(i * 4), 'proxy.status', 'mcp'));
    // The UI's own `agent.activity` calls are UI calls: this script never makes one.
    for (let i = 0; i < 3; i++) entries.push(audit(spread(i * 20), 'agent.activity', 'mcp'));
    for (let i = 0; i < 5; i++) entries.push(audit(spread(i * 12), 'flow.kill', 'operator'));
    // Bounds: (startMs, endMs]. The start instant itself and anything after the end (the
    // script's own final `flow.list`, say) must not count.
    entries.push(audit(startMs, 'flow.list', 'mcp'));
    entries.push(audit(endMs + 1, 'flow.list', 'mcp'));

    const s = summarize(entries, 'mcp', startMs, endMs);
    const lines = renderWindow(s);
    for (const l of lines) console.log(l);
    expectLine(lines, 'flow.list      2.00/s');
    expectLine(lines, 'proxy.status   0.50/s');
    expectLine(lines, 'agent.activity 0.10/s');
    expectLine(lines, 'total          2.60/s');
    expectEq('perCommand', s.perCommand, { 'flow.list': 60, 'proxy.status': 15, 'agent.activity': 3 });
    expectEq('total', s.total, 78);
    expectEq('otherOrigins', s.otherOrigins, { operator: 5 });
    expectEq('windowMs', s.windowMs, 30_000);
    expectEq('no excluded bucket', 'excluded' in s, false);
  });

  run('collector: notification lines to window entries', () => {
    const startMs = 1_730_000_000_000;
    const endMs = startMs + 10_000;
    const note = (kind, params) => ({ jsonrpc: '2.0', method: `${NOTIFICATION_PREFIX}${kind}`, params });
    const c = newCollector();
    c.on(note('agent', audit(startMs + 100, 'flow.list', 'mcp')));
    c.on(note('flow', { event: 'created', id: 'f_1', summary: { id: 'f_1', kind: 'http', method: 'GET', authority: 'x', path: '/', status: null } }));
    c.on(note('agent', audit(startMs + 2_600, 'flow.list', 'mcp')));
    c.on(note('agent', audit(startMs + 4_000, 'proxy.status', 'mcp', { result: { error: 'refused' } })));
    c.on(note('state', { lagged: true }));
    c.on(note('agent', { event: 'approval_requested', command: 'ca.install', args_summary: '{}', prompt: 'x', request_id: 'apr_1' }));
    c.on(note('agent', audit(startMs + 5_000, 'flow.kill', 'operator')));
    c.on(note('agent', audit(endMs + 50, 'flow.list', 'mcp'))); // the script's own final flow.list
    c.on({ jsonrpc: '2.0', method: 'notifications/other/thing', params: {} });

    // Six `agent` lines arrived: five audit lines (collected) and one approval event (not).
    expectEq('kinds', c.snapshot(), { flow: 1, agent: 6, state: 1, other: 1, lagged: 1, nonAudit: 1, dropped: 0 });
    expectEq('collected', c.entries.length, 5);
    expectEq('entry shape', c.entries[0], audit(startMs + 100, 'flow.list', 'mcp'));
    const s = summarize(c.entries, 'mcp', startMs, endMs);
    const lines = renderWindow(s);
    for (const l of lines) console.log(l);
    expectLine(lines, 'flow.list      0.20/s');
    expectLine(lines, 'proxy.status   0.10/s');
    expectLine(lines, 'total          0.30/s');
    expectEq('otherOrigins', s.otherOrigins, { operator: 1 });
  });

  if (failures.length) {
    console.error('selftest FAILED');
    for (const f of failures) console.error('  ' + f);
    return 1;
  }
  console.log('selftest ok');
  return 0;
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

const HELP = `usage: node apps/web/scripts/bus-load.mjs --token T [options]
       node apps/web/scripts/bus-load.mjs --seed N [--proxy HOST:PORT] [--label L]

  --url URL            bus URL (default ws://127.0.0.1:8082/bus)
  --token T            bridge token (or AITM_WEB_TOKEN); the agent token unless --ui-origin operator
  --ui-origin ORIGIN   audit origin the UI's calls carry: mcp (default) or operator
  --idle-secs N        idle window length (default 30; 0 skips it)
  --traffic-secs N     traffic window length (default 30; 0 skips it)
  --rate N             requests per second through the proxy in the traffic window (default 20)
  --proxy HOST:PORT    the proxy listener (default 127.0.0.1:8080)
  --label L            free-form tag for the table, the JSON and the request paths (default none)
  --json PATH          also write every number as JSON to PATH
  --seed N             send N requests through the proxy (${SEED_CONCURRENCY} at a time) and exit; no bus, no windows
  --selftest           run the pure counters on canned input and exit (no network)
  --help               this text

Setup (the loopback origin must be in scope; --config is the FIRST aitm argument):
  printf 'listen: 127.0.0.1:8080\\nscope:\\n  entries:\\n    - "127.0.0.1"\\n' > $TMPDIR/aitm-load.yaml
  aitm --config $TMPDIR/aitm-load.yaml web --listen 127.0.0.1:8082 --token T --no-open
Open the printed web UI URL in a real browser, leave the page open, --seed 500, then measure.
`;

function parseArgs(argv) {
  const args = [...argv];
  const opt = (name, dflt) => {
    const i = args.indexOf(`--${name}`);
    if (i < 0) return dflt;
    const v = args[i + 1];
    if (v === undefined) throw new Error(`--${name} needs a value`);
    args.splice(i, 2);
    return v;
  };
  const flag = (name) => {
    const i = args.indexOf(`--${name}`);
    if (i < 0) return false;
    args.splice(i, 1);
    return true;
  };
  const num = (name, dflt) => {
    const v = opt(name, null);
    if (v == null) return dflt;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error(`--${name} must be a non-negative number, got ${v}`);
    return n;
  };
  const o = {
    help: flag('help') || flag('h'),
    selftest: flag('selftest'),
    url: opt('url', 'ws://127.0.0.1:8082/bus'),
    token: opt('token', process.env.AITM_WEB_TOKEN),
    uiOrigin: opt('ui-origin', 'mcp'),
    idleSecs: num('idle-secs', 30),
    trafficSecs: num('traffic-secs', 30),
    rate: num('rate', 20),
    proxy: opt('proxy', '127.0.0.1:8080'),
    label: opt('label', null),
    json: opt('json', null),
    seed: num('seed', null),
  };
  if (args.length) throw new Error(`unknown argument(s): ${args.join(' ')}`);
  if (!['mcp', 'operator'].includes(o.uiOrigin)) throw new Error(`--ui-origin must be mcp or operator, got ${o.uiOrigin}`);
  return o;
}

// ---------------------------------------------------------------------------------------------
// Bus client: token line, initialize, notifications/initialized, newline-delimited JSON-RPC.
// The bridge runs frames concurrently, so every caller awaits a reply before the next request.
// ---------------------------------------------------------------------------------------------

async function connectBus(url, token, onNotification) {
  const ws = new WebSocket(url, { headers: { Origin: `http://${new URL(url).host}` } });
  let nextId = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    for (const line of String(ev.data).split('\n')) {
      if (!line.trim()) continue;
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof m.method === 'string' && m.id === undefined) {
        onNotification(m);
        continue;
      }
      if (m.id != null && pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        clearTimeout(p.timer);
        if (m.error) p.reject(new Error(`rpc ${p.method}: ${JSON.stringify(m.error)}`));
        else p.resolve({ result: m.result, frameBytes: Buffer.byteLength(line) });
      }
    }
  };
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = (e) => rej(new Error(`bus connect failed: ${e?.message ?? url}`));
    ws.onclose = (ev) => rej(new Error(`bus closed during connect (${ev.code})`));
  });
  ws.onclose = (ev) => {
    for (const [, p] of pending) p.reject(new Error(`bus closed (${ev.code}) during ${p.method}`));
    pending.clear();
  };
  ws.onerror = () => {};
  ws.send(JSON.stringify({ token }) + '\n');
  const send = (obj) => ws.send(JSON.stringify(obj) + '\n');
  const rpc = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`rpc ${method}: no reply in ${RPC_TIMEOUT_MS} ms`));
      }, RPC_TIMEOUT_MS);
      pending.set(id, { resolve, reject, method, timer });
      send({ jsonrpc: '2.0', id, method, params });
    });
  const init = await rpc('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'aitm-bus-load', version: '0' },
  });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  /** Unwraps a tools/call reply the way the UI's ws.ts does; throws on isError. */
  const callRaw = async (name, args = {}) => {
    const { result: r, frameBytes } = await rpc('tools/call', { name, arguments: args });
    if (r?.isError) throw new Error(`${name}: ${r.content?.[0]?.text ?? 'tool error'}`);
    let value;
    if (r?.structuredContent !== undefined) value = r.structuredContent;
    else {
      const text = r?.content?.[0]?.text ?? '';
      try {
        value = JSON.parse(text);
      } catch {
        value = text;
      }
    }
    return { value, frameBytes };
  };
  const call = async (name, args = {}) => (await callRaw(name, args)).value;
  return { init: init.result, call, callRaw, close: () => ws.close() };
}

// ---------------------------------------------------------------------------------------------
// Traffic: a loopback origin, requests through the proxy in absolute-URI form
// ---------------------------------------------------------------------------------------------

function startOrigin() {
  const server = createServer((req, res) => {
    const body = JSON.stringify({ ok: true, path: req.url, at: Date.now() });
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store' });
    res.end(body);
  });
  return new Promise((res, rej) => {
    server.on('error', rej);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      res({ host: `127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function splitHostPort(s) {
  const i = s.lastIndexOf(':');
  if (i < 0) throw new Error(`--proxy wants HOST:PORT, got ${s}`);
  const port = Number(s.slice(i + 1));
  if (!Number.isInteger(port) || port <= 0) throw new Error(`--proxy wants HOST:PORT, got ${s}`);
  return { host: s.slice(0, i), port };
}

/** One GET through the proxy (absolute URI in the request line, `Host` = the origin). */
function viaProxy(proxy, agent, url) {
  return new Promise((res, rej) => {
    const u = new URL(url);
    const req = httpRequest(
      { host: proxy.host, port: proxy.port, method: 'GET', path: url, agent, headers: { host: u.host }, timeout: REQUEST_TIMEOUT_MS },
      (r) => {
        r.resume();
        r.on('end', () => res(r.statusCode));
        r.on('error', rej);
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout through proxy')));
    req.on('error', rej);
    req.end();
  });
}

/** Shared request accounting for the generator and the seeder. */
function newTally(extra = {}) {
  const t = { ...extra, sent: 0, ok: 0, failed: 0, skipped: 0, firstError: null };
  t.settle = (p) =>
    p.then(
      (status) => {
        if (status >= 200 && status < 400) t.ok++;
        else {
          t.failed++;
          t.firstError ??= `HTTP ${status} from the proxy (is 127.0.0.1 in scope?)`;
        }
      },
      (e) => {
        t.failed++;
        t.firstError ??= e.message;
      },
    );
  return t;
}

const requestUrl = (originHost, label, n) => `http://${originHost}/load/${encodeURIComponent(label ?? 'run')}/${n}`;

/**
 * Sends `rate` req/s for `secs` to `originHost` through the proxy, then drains in-flight
 * requests. A 10 ms scheduler sends the deficit against the ideal count, so the average rate is
 * exact; more than MAX_IN_FLIGHT outstanding means the proxy is not keeping up and further sends
 * are skipped (counted) rather than piled up.
 */
async function generateTraffic({ proxy, originHost, rate, secs, label }) {
  const agent = new Agent({ keepAlive: true, maxSockets: 16 });
  const tally = newTally({ rate, secs });
  let inFlight = 0;
  const t0 = Date.now();
  const total = Math.round(rate * secs);
  const fire = () => {
    const n = tally.sent + tally.skipped;
    if (inFlight >= MAX_IN_FLIGHT) {
      tally.skipped++;
      return;
    }
    tally.sent++;
    inFlight++;
    tally.settle(viaProxy(proxy, agent, requestUrl(originHost, label, n))).finally(() => inFlight--);
  };
  await new Promise((done) => {
    const tick = setInterval(() => {
      const ideal = Math.min(total, Math.floor(((Date.now() - t0) / 1000) * rate));
      while (tally.sent + tally.skipped < ideal) fire();
      if (tally.sent + tally.skipped >= total) {
        clearInterval(tick);
        done();
      }
    }, 10);
  });
  const drainUntil = Date.now() + REQUEST_TIMEOUT_MS + 1000;
  while (inFlight > 0 && Date.now() < drainUntil) await sleep(20);
  agent.destroy();
  tally.elapsedMs = Date.now() - t0;
  return tally;
}

/** Sends `n` requests through the proxy with `concurrency` workers, as fast as the proxy answers. */
async function seedTraffic({ proxy, originHost, n, concurrency, label }) {
  const agent = new Agent({ keepAlive: true, maxSockets: concurrency });
  const tally = newTally({ n, concurrency });
  const t0 = Date.now();
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= n) return;
      tally.sent++;
      await tally.settle(viaProxy(proxy, agent, requestUrl(originHost, label, i)));
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, n)) }, worker));
  agent.destroy();
  tally.elapsedMs = Date.now() - t0;
  return tally;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------------------------

async function seed(o) {
  const proxy = splitHostPort(o.proxy);
  const origin = await startOrigin();
  try {
    console.log(`seed: ${o.seed} requests via ${o.proxy} to http://${origin.host}/, ${SEED_CONCURRENCY} at a time`);
    const r = await seedTraffic({ proxy, originHost: origin.host, n: o.seed, concurrency: SEED_CONCURRENCY, label: o.label ?? 'seed' });
    console.log(`seed: ${r.sent} sent · ${r.ok} ok · ${r.failed} failed in ${(r.elapsedMs / 1000).toFixed(1)} s`);
    if (r.failed) console.error(`WARNING: ${r.failed} requests failed; first error: ${r.firstError}`);
    return r.ok > 0 ? 0 : 1;
  } finally {
    await origin.close();
  }
}

function diffCounts(before, after, secs) {
  const count = {};
  const perSec = {};
  for (const k of Object.keys(after)) {
    count[k] = after[k] - before[k];
    perSec[k] = secs > 0 ? count[k] / secs : 0;
  }
  return { count, perSec };
}

function renderNotifications(n) {
  const kinds = ['flow', 'agent', 'state'].map((k) => `${k} ${n.perSec[k].toFixed(2)}/s`).join(' · ');
  const extras = [n.count.other ? `other ${n.count.other}` : '', n.count.nonAudit ? `non-audit agent ${n.count.nonAudit}` : '', n.count.lagged ? `LAGGED x${n.count.lagged}` : ''].filter(Boolean);
  return `${'notifications'.padEnd(14)} ${[kinds, ...extras].join(' · ')}`;
}

const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);

async function main(o) {
  if (!o.token) {
    console.error('need --token (or AITM_WEB_TOKEN); --help for the setup');
    return 2;
  }
  const proxy = splitHostPort(o.proxy);
  const collector = newCollector();
  const bus = await connectBus(o.url, o.token, collector.on);
  const out = {
    label: o.label,
    at: new Date().toISOString(),
    url: o.url,
    proxy: o.proxy,
    uiOrigin: o.uiOrigin,
    server: bus.init?.serverInfo ?? null,
    role: bus.init?.role ?? null,
    subId: null,
    idle: null,
    traffic: null,
    flowList: null,
  };
  console.log(`bus-load${o.label ? ` (${o.label})` : ''} · ui origin ${o.uiOrigin} · bus ${o.url} · proxy ${o.proxy} · script role ${out.role ?? '?'}`);
  try {
    // The audit stream only reaches subscribed connections (server.rs push_agent -> fanout_state),
    // so without this subscription there is nothing to count.
    const sub = await bus.call('flow.subscribe', {});
    out.subId = sub?.sub_id ?? null;
    console.log(`subscribed: sub_id ${out.subId}`);

    const measureWindow = async (name, startMs, before) => {
      const endMs = Date.now();
      await sleep(RECEIVE_GRACE_MS);
      const after = collector.snapshot();
      const s = summarize(collector.entries, o.uiOrigin, startMs, endMs);
      const secs = s.windowMs / 1000;
      const notifications = diffCounts(before, after, secs);
      const ratePerSec = Object.fromEntries(Object.entries(s.perCommand).map(([k, v]) => [k, v / secs]));
      console.log('');
      console.log(`${name} window: ${secs.toFixed(1)} s · ${s.total} ui calls (origin ${o.uiOrigin}) · ${sum(s.otherOrigins)} other-origin${notifications.count.lagged ? ' · SUBSCRIPTION LAGGED' : ''}`);
      for (const l of renderWindow(s)) console.log(l);
      console.log(renderNotifications(notifications));
      if (notifications.count.lagged) console.error(`WARNING: the script's own subscription lagged ${notifications.count.lagged}x during the ${name} window; audit lines were dropped and the counts are a floor`);
      if (s.total + sum(s.otherOrigins) === 0) console.error(`WARNING: no audit lines arrived during the ${name} window: is the page open and connected to THIS server (${o.url})?`);
      else if (s.total === 0) console.error(`WARNING: audit lines arrived but none with origin ${o.uiOrigin} (seen: ${JSON.stringify(s.otherOrigins)}); check --ui-origin`);
      return { startMs, endMs, secs, ...s, ratePerSec, totalPerSec: s.total / secs, notifications: notifications.count, notificationsPerSec: notifications.perSec };
    };

    if (o.idleSecs > 0) {
      const startMs = Date.now();
      const before = collector.snapshot();
      console.log(`\nidle: ${o.idleSecs} s, hands off the page`);
      await sleep(o.idleSecs * 1000);
      out.idle = await measureWindow('idle', startMs, before);
    }

    if (o.trafficSecs > 0 && o.rate > 0) {
      const origin = await startOrigin();
      try {
        const startMs = Date.now();
        const before = collector.snapshot();
        console.log(`\ntraffic: ${o.rate} req/s for ${o.trafficSecs} s via ${o.proxy} to http://${origin.host}/`);
        const requests = await generateTraffic({ proxy, originHost: origin.host, rate: o.rate, secs: o.trafficSecs, label: o.label });
        await sleep(SETTLE_MS);
        const w = await measureWindow('traffic', startMs, before);
        const detail = w.perCommand['flow.detail'] ?? 0;
        w.requests = requests;
        w.flowDetailPerRequest = requests.ok > 0 ? detail / requests.ok : null;
        console.log(`${'requests'.padEnd(14)} ${requests.sent} sent · ${requests.ok} ok · ${requests.failed} failed · ${requests.skipped} skipped (window includes a ${SETTLE_MS} ms settle)`);
        if (requests.failed) console.error(`WARNING: ${requests.failed} requests failed; first error: ${requests.firstError}`);
        if (requests.ok === 0) console.error('WARNING: no request succeeded through the proxy; the traffic numbers are meaningless (check --proxy and the 127.0.0.1 scope entry)');
        console.log(`${'flow.detail'.padEnd(14)} ${w.flowDetailPerRequest == null ? 'n/a' : w.flowDetailPerRequest.toFixed(2)} per new flow (spec R3 threshold 2.5)`);
        out.traffic = w;
      } finally {
        await origin.close();
      }
    }

    {
      // The one call this script makes after the windows; its audit line is stamped after the
      // last window's end and so never counts.
      const { value, frameBytes } = await bus.callRaw('flow.list', {});
      const ids = Array.isArray(value) ? value : Array.isArray(value?.ids) ? value.ids : null;
      if (!ids) throw new Error(`flow.list returned an unexpected shape: ${JSON.stringify(value).slice(0, 120)}`);
      out.flowList = { ids: ids.length, bytes: Buffer.byteLength(JSON.stringify(value)), frameBytes };
      console.log(`\nflow.list now: ${ids.length} ids · ${out.flowList.bytes} bytes (result JSON) · ${frameBytes} bytes (reply frame)`);
    }
    out.collected = { auditLines: collector.entries.length, ...collector.snapshot() };
  } finally {
    bus.close();
  }
  if (o.json) {
    writeFileSync(o.json, JSON.stringify(out, null, 2) + '\n');
    console.log(`json: ${o.json}`);
  }
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  let o;
  try {
    o = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e.message);
    console.error(HELP);
    process.exit(2);
  }
  if (o.help) {
    console.log(HELP);
    process.exit(0);
  }
  if (o.selftest) process.exit(selftest());
  (o.seed != null ? seed(o) : main(o)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`bus-load: ${e.message}`);
      process.exit(1);
    },
  );
}
