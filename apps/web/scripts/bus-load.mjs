#!/usr/bin/env node
// Measures how often the web UI calls the core, using the server's own audit ring as the
// instrument (spec D9 of 2026-10-30-web-ui-bus-push-design.md). A SEPARATE bus connection:
// it subscribes once (to count what a subscriber is sent) and from then on calls only
// `agent.activity`, so it cannot disturb what it measures. Node >= 22 (global WebSocket),
// no dependencies, same style as bus-probe.mjs.
//
//   node apps/web/scripts/bus-load.mjs --token T [--label before|after] [--json out.json]
//   node apps/web/scripts/bus-load.mjs --selftest        # pure summarize(), no network
//   node apps/web/scripts/bus-load.mjs --help
//
// Two windows, each attributed by the UI's audit `origin` (--ui-origin, default `mcp`: the
// UI opened at `aitm web`'s default URL is an agent-token bridge connection):
//   idle     page open, no traffic, --idle-secs (30)
//   traffic  --rate (20) plain-HTTP req/s for --traffic-secs (30) through --proxy to a loopback
//            origin this script starts
// Then one `flow.list` (ids + bytes) and the subscriber notification rates per kind.
//
// SETUP. The proxy is deny-by-default (ingress.rs: an out-of-scope authority is refused before
// any work), and a plain-HTTP loopback origin's authority is its IP, so `127.0.0.1` must be a
// scope entry (a port-less entry matches every port). `aitm web` takes scope from the config
// file only, and `--config` must be the FIRST argument:
//
//   cat > $TMPDIR/aitm-load.yaml <<'EOF'
//   listen: 127.0.0.1:8080
//   scope:
//     entries:
//       - "127.0.0.1"
//   EOF
//   aitm --config $TMPDIR/aitm-load.yaml web --listen 127.0.0.1:8082 --token T --no-open
//
// Keep that `aitm` in a foreground Terminal tab (it exits when its stdin closes). Open the
// printed `web UI (agent)` URL in a real browser and leave the page open; seed the store first
// (about 500 requests through the proxy, e.g. a short run of this script's traffic generator:
// `--idle-secs 0 --traffic-secs 25`) so `flow.list` has a real cost; then run the measurement.
// If the page was opened at the `web UI (operator)` URL, pass that URL's `t=` token as --token
// and `--ui-origin operator`. The script, the proxy and the browser share one host (the origin
// is loopback), so the server's `at` and this process's clock are the same clock.
import { createServer, request as httpRequest, Agent } from 'node:http';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/** `DEFAULT_AUDIT_CAPACITY` in crates/aitm-core/src/audit.rs: a read this long may have wrapped. */
const RING_CAPACITY = 4096;
const NOTIFICATION_PREFIX = 'notifications/aitm/';
const NOTIFICATION_KINDS = ['flow', 'agent', 'state', 'other', 'lagged'];
/** The script's own read, never the UI's; reported separately so the table says what was dropped. */
const OWN_COMMAND = 'agent.activity';
/** Seconds the traffic window keeps running after the last request, so the UI's reaction to the tail counts. */
const SETTLE_MS = 1000;
const MAX_IN_FLIGHT = 64;
const RPC_TIMEOUT_MS = 30000;
const REQUEST_TIMEOUT_MS = 15000;

// ---------------------------------------------------------------------------------------------
// Pure helpers (covered by --selftest)
// ---------------------------------------------------------------------------------------------

/**
 * Counts the UI's audited calls inside (startMs, endMs]. Keeps entries whose `origin` is
 * `uiOrigin`, drops the script's own `agent.activity` reads (reported in `excluded`), counts the
 * rest by `command`. Entries of other origins are tallied in `otherOrigins` so a wrong
 * `--ui-origin` is visible rather than silent.
 */
export function summarize(entries, uiOrigin, startMs, endMs) {
  const windowMs = endMs - startMs;
  if (!(windowMs > 0)) throw new RangeError(`summarize: empty window (${startMs}..${endMs})`);
  const perCommand = {};
  const excluded = {};
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
    if (cmd === OWN_COMMAND) {
      excluded[cmd] = (excluded[cmd] ?? 0) + 1;
      continue;
    }
    perCommand[cmd] = (perCommand[cmd] ?? 0) + 1;
    total++;
  }
  return { perCommand, total, excluded, otherOrigins, windowMs };
}

/** The per-window table: one line per command, `total`, `excluded`; rates over the window length. */
export function renderWindow(summary) {
  const secs = summary.windowMs / 1000;
  const row = (name, count) => `${name.padEnd(14)} ${(count / secs).toFixed(2)}/s`;
  const byCount = Object.entries(summary.perCommand).sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
  const lines = byCount.map(([cmd, n]) => row(cmd, n));
  lines.push(row('total', summary.total));
  const dropped = Object.entries(summary.excluded).map(([cmd, n]) => `${cmd} x${n}`);
  lines.push(`${'excluded'.padEnd(14)} ${dropped.length ? dropped.join(', ') : 'none'}`);
  return lines;
}

// ---------------------------------------------------------------------------------------------
// --selftest: the canned window from the plan (Task 0), exact lines, exit code
// ---------------------------------------------------------------------------------------------

function selftest() {
  const startMs = 1_730_000_000_000;
  const endMs = startMs + 30_000;
  // Server shape (audit.rs to_value): at = epoch ms, origin cli|mcp|operator, client_label,
  // command, args string, result 'ok' | {error}.
  const line = (i, command, origin) => ({
    at: startMs + 1 + Math.floor((i * 29_000) / 60),
    origin,
    client_label: null,
    command,
    args: '{}',
    result: 'ok',
  });
  const entries = [];
  for (let i = 0; i < 60; i++) entries.push(line(i, 'flow.list', 'mcp'));
  for (let i = 0; i < 15; i++) entries.push(line(i * 4, 'proxy.status', 'mcp'));
  for (let i = 0; i < 3; i++) entries.push(line(i * 20, OWN_COMMAND, 'mcp'));
  for (let i = 0; i < 5; i++) entries.push(line(i * 12, 'flow.kill', 'operator'));
  // Bounds: `since` is strictly after the start marker, and anything after the end is the race
  // between the sleep ending and the server handling the read. Neither may count.
  entries.push({ ...line(0, 'flow.list', 'mcp'), at: startMs });
  entries.push({ ...line(0, 'flow.list', 'mcp'), at: endMs + 1 });

  const s = summarize(entries, 'mcp', startMs, endMs);
  const lines = renderWindow(s);
  for (const l of lines) console.log(l);

  const failures = [];
  const expectLine = (want) => {
    if (!lines.includes(want)) failures.push(`missing line ${JSON.stringify(want)}`);
  };
  expectLine('flow.list      2.00/s');
  expectLine('proxy.status   0.50/s');
  expectLine('total          2.50/s');
  expectLine('excluded       agent.activity x3');
  const expectEq = (what, got, want) => {
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      failures.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
  };
  expectEq('perCommand', s.perCommand, { 'flow.list': 60, 'proxy.status': 15 });
  expectEq('total', s.total, 75);
  expectEq('excluded', s.excluded, { [OWN_COMMAND]: 3 });
  expectEq('otherOrigins', s.otherOrigins, { operator: 5 });
  expectEq('windowMs', s.windowMs, 30_000);

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

  --url URL            bus URL (default ws://127.0.0.1:8082/bus)
  --token T            bridge token (or AITM_WEB_TOKEN); the agent token unless --ui-origin operator
  --ui-origin ORIGIN   audit origin the UI's calls carry: mcp (default) or operator
  --idle-secs N        idle window length (default 30; 0 skips it)
  --traffic-secs N     traffic window length (default 30; 0 skips it)
  --rate N             requests per second through the proxy in the traffic window (default 20)
  --proxy HOST:PORT    the proxy listener (default 127.0.0.1:8080)
  --label before|after tag for the table and the JSON (default none)
  --json PATH          also write every number as JSON to PATH
  --selftest           run summarize() on a canned window and exit (no network)
  --help               this text

Setup (the loopback origin must be in scope; --config is the FIRST aitm argument):
  printf 'listen: 127.0.0.1:8080\\nscope:\\n  entries:\\n    - "127.0.0.1"\\n' > $TMPDIR/aitm-load.yaml
  aitm --config $TMPDIR/aitm-load.yaml web --listen 127.0.0.1:8082 --token T --no-open
Open the printed web UI URL in a real browser, leave the page open, seed ~500 flows, then run.
`;

function parseArgs(argv) {
  const args = [...argv];
  const flags = new Set();
  const opt = (name, dflt) => {
    const i = args.indexOf(`--${name}`);
    if (i < 0) return dflt;
    const v = args[i + 1];
    args.splice(i, 2);
    return v;
  };
  const flag = (name) => {
    const i = args.indexOf(`--${name}`);
    if (i < 0) return false;
    args.splice(i, 1);
    flags.add(name);
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
  };
  if (args.length) throw new Error(`unknown argument(s): ${args.join(' ')}`);
  if (!['mcp', 'operator'].includes(o.uiOrigin)) throw new Error(`--ui-origin must be mcp or operator, got ${o.uiOrigin}`);
  if (o.label != null && !['before', 'after'].includes(o.label)) throw new Error(`--label must be before or after, got ${o.label}`);
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
// Traffic generator: a loopback origin, requests through the proxy in absolute-URI form
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

/**
 * Sends `rate` req/s for `secs` to `originHost` through the proxy, then drains in-flight
 * requests. A 10 ms scheduler sends the deficit against the ideal count, so the average rate is
 * exact; more than MAX_IN_FLIGHT outstanding means the proxy is not keeping up and further sends
 * are skipped (counted) rather than piled up.
 */
async function generateTraffic({ proxy, originHost, rate, secs, label }) {
  const agent = new Agent({ keepAlive: true, maxSockets: 16 });
  const counts = { rate, secs, sent: 0, ok: 0, failed: 0, skipped: 0, firstError: null };
  let inFlight = 0;
  const t0 = Date.now();
  const total = Math.round(rate * secs);
  const fire = () => {
    const n = counts.sent + counts.skipped;
    if (inFlight >= MAX_IN_FLIGHT) {
      counts.skipped++;
      return;
    }
    counts.sent++;
    inFlight++;
    viaProxy(proxy, agent, `http://${originHost}/load/${label ?? 'run'}/${n}`)
      .then((status) => {
        if (status >= 200 && status < 400) counts.ok++;
        else {
          counts.failed++;
          counts.firstError ??= `HTTP ${status} from the proxy (is 127.0.0.1 in scope?)`;
        }
      })
      .catch((e) => {
        counts.failed++;
        counts.firstError ??= e.message;
      })
      .finally(() => inFlight--);
  };
  await new Promise((done) => {
    const tick = setInterval(() => {
      const ideal = Math.min(total, Math.floor(((Date.now() - t0) / 1000) * rate));
      while (counts.sent + counts.skipped < ideal) fire();
      if (counts.sent + counts.skipped >= total) {
        clearInterval(tick);
        done();
      }
    }, 10);
  });
  const drainUntil = Date.now() + REQUEST_TIMEOUT_MS + 1000;
  while (inFlight > 0 && Date.now() < drainUntil) await sleep(20);
  agent.destroy();
  counts.elapsedMs = Date.now() - t0;
  return counts;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------------------------

function newNotificationCounter() {
  const counts = Object.fromEntries(NOTIFICATION_KINDS.map((k) => [k, 0]));
  return {
    counts,
    on(m) {
      const kind = m.method.startsWith(NOTIFICATION_PREFIX) ? m.method.slice(NOTIFICATION_PREFIX.length) : 'other';
      counts[kind in counts && kind !== 'lagged' ? kind : 'other']++;
      if (kind === 'state' && m.params?.lagged === true) counts.lagged++;
    },
    snapshot() {
      return { ...counts };
    },
  };
}

function diffNotifications(before, after, secs) {
  const perSec = {};
  const count = {};
  for (const k of NOTIFICATION_KINDS) {
    count[k] = after[k] - before[k];
    perSec[k] = secs > 0 ? count[k] / secs : 0;
  }
  return { count, perSec };
}

function renderNotifications(n) {
  return `${'notifications'.padEnd(14)} ` + ['flow', 'agent', 'state'].map((k) => `${k} ${n.perSec[k].toFixed(2)}/s`).join(' · ') + (n.count.other ? ` · other ${n.count.other}` : '') + (n.count.lagged ? ` · LAGGED x${n.count.lagged}` : '');
}

async function main(o) {
  if (!o.token) {
    console.error('need --token (or AITM_WEB_TOKEN); --help for the setup');
    return 2;
  }
  const proxy = splitHostPort(o.proxy);
  const notif = newNotificationCounter();
  const bus = await connectBus(o.url, o.token, notif.on);
  const out = {
    label: o.label,
    at: new Date().toISOString(),
    url: o.url,
    proxy: o.proxy,
    uiOrigin: o.uiOrigin,
    server: bus.init?.serverInfo ?? null,
    role: bus.init?.role ?? null,
    subscribed: false,
    subId: null,
    idle: null,
    traffic: null,
    flowList: null,
  };
  const head = `bus-load${o.label ? ` (${o.label})` : ''} · ui origin ${o.uiOrigin} · bus ${o.url} · proxy ${o.proxy} · role ${out.role ?? '?'}`;
  console.log(head);
  try {
    try {
      const sub = await bus.call('flow.subscribe', {});
      out.subscribed = true;
      out.subId = sub?.sub_id ?? null;
      console.log(`subscribed: sub_id ${out.subId}`);
    } catch (e) {
      console.error(`WARNING: flow.subscribe failed (${e.message}); notification rates below are from an UNSUBSCRIBED connection`);
    }

    /** `agent.activity` (the only thing this script calls while measuring), with the ring-wrap check. */
    const readRing = async (args) => {
      const r = await bus.call(OWN_COMMAND, args);
      if (!Array.isArray(r)) throw new Error(`agent.activity returned ${typeof r}, expected an array`);
      const wrapped = r.length >= RING_CAPACITY;
      if (wrapped) console.error(`WARNING: agent.activity returned ${r.length} entries (ring capacity ${RING_CAPACITY}): the ring WRAPPED, counts below are a floor`);
      return { entries: r, wrapped };
    };
    /** Window start = the newest ring entry's `at` (server clock). An empty ring falls back to now (same host, same clock). */
    const markStart = async () => {
      const { entries } = await readRing({ limit: 1 });
      const at = entries.at(-1)?.at;
      return Number.isFinite(at) ? at : Date.now();
    };
    const measureWindow = async (name, startMs, before) => {
      const endMs = Date.now();
      const after = notif.snapshot();
      const { entries, wrapped } = await readRing({ since: Math.floor(startMs) });
      const s = summarize(entries, o.uiOrigin, startMs, endMs);
      const secs = s.windowMs / 1000;
      const notifications = diffNotifications(before, after, secs);
      const ratePerSec = Object.fromEntries(Object.entries(s.perCommand).map(([k, v]) => [k, v / secs]));
      console.log('');
      console.log(`${name} window: ${secs.toFixed(1)} s · ${s.total} ui calls (origin ${o.uiOrigin}) · ${Object.values(s.otherOrigins).reduce((a, b) => a + b, 0)} other-origin · ${Object.values(s.excluded).reduce((a, b) => a + b, 0)} excluded${wrapped ? ' · RING WRAPPED' : ''}`);
      for (const l of renderWindow(s)) console.log(l);
      console.log(renderNotifications(notifications));
      return { startMs, endMs, secs, ...s, ratePerSec, totalPerSec: s.total / secs, ringWrapped: wrapped, notifications: notifications.count, notificationsPerSec: notifications.perSec };
    };

    if (o.idleSecs > 0) {
      const start = await markStart();
      const before = notif.snapshot();
      console.log(`\nidle: ${o.idleSecs} s, hands off the page`);
      await sleep(o.idleSecs * 1000);
      out.idle = await measureWindow('idle', start, before);
    }

    if (o.trafficSecs > 0) {
      const origin = await startOrigin();
      try {
        const start = await markStart();
        const before = notif.snapshot();
        console.log(`\ntraffic: ${o.rate} req/s for ${o.trafficSecs} s via ${o.proxy} to http://${origin.host}/`);
        const requests = await generateTraffic({ proxy, originHost: origin.host, rate: o.rate, secs: o.trafficSecs, label: o.label });
        await sleep(SETTLE_MS);
        const w = await measureWindow('traffic', start, before);
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
      const { value, frameBytes } = await bus.callRaw('flow.list', {});
      const ids = Array.isArray(value) ? value : Array.isArray(value?.ids) ? value.ids : null;
      if (!ids) throw new Error(`flow.list returned an unexpected shape: ${JSON.stringify(value).slice(0, 120)}`);
      out.flowList = { ids: ids.length, bytes: Buffer.byteLength(JSON.stringify(value)), frameBytes };
      console.log(`\nflow.list now: ${ids.length} ids · ${out.flowList.bytes} bytes (result JSON) · ${frameBytes} bytes (reply frame)`);
    }
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
  main(o).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`bus-load: ${e.message}`);
      process.exit(1);
    },
  );
}
