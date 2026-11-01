// Shared live-test environment: free ports, a local HTTP target with the shapes the operator
// workflow needs, a spawned `aitm web`, and a bus client over the /bus bridge. Used by
// selftest-live.mjs (agent path) and cua-live.mjs (human path). Node ≥ 22, no dependencies.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as createTcp } from 'node:net';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request as httpRequest } from 'node:http';

const here = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(here, '../../..');

export function freePort() {
  return new Promise((res, rej) => {
    const s = createTcp();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
    s.on('error', rej);
  });
}

/**
 * Render an `l4:` config block from an options object (§M5/L4OPS). `enabled` turns the surface on;
 * the `allow_agent_*` flags open per-capability agent gates; `scope` pre-declares L4 scope entries
 * (the `L4ScopeEntry` YAML shape — see aitm-proto-l4/src/config.rs). Everything else fails closed.
 */
function l4Block(l4) {
  const lines = ['l4:', `  enabled: ${l4.enabled !== false}`];
  for (const flag of ['allow_agent_widen', 'allow_agent_inject', 'allow_agent_capture', 'allow_agent_intercept']) {
    if (l4[flag] != null) lines.push(`  ${flag}: ${!!l4[flag]}`);
  }
  if (Array.isArray(l4.scope) && l4.scope.length) {
    lines.push('  scope:');
    for (const e of l4.scope) {
      lines.push(
        `    - cidr:`,
        `        addr: ${e.addr}`,
        `        prefix: ${e.prefix}`,
        `      ports:`,
        `        lo: ${e.portLo ?? 0}`,
        `        hi: ${e.portHi ?? 65535}`,
        `      interface: ${e.interface}`,
        `      direction: ${e.direction ?? 'outbound'}`,
        `      capability: ${e.capability}`,
        `      inject_rate:`,
        `        pps: ${e.pps ?? 100}`,
        `        burst: ${e.burst ?? 100}`,
      );
    }
  }
  return lines;
}

/** A local target: JSON + cookies, a body/header echo, and a reflecting search page for PoCs. */
export function startTarget() {
  const hits = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      hits.push({ method: req.method, url: req.url, headers: req.headers, body });
      if (url.pathname === '/api/me') {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': 'session=s3cr3t; Path=/; HttpOnly',
          'cache-control': 'no-store',
        });
        res.end(JSON.stringify({ id: 1042, email: 'ops@target.test', role: 'admin', mfa_enrolled: false }));
      } else if (url.pathname === '/api/echo') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ method: req.method, path: req.url, headers: req.headers, body }));
      } else if (url.pathname === '/search') {
        const q = url.searchParams.get('q') ?? '';
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(`<!doctype html><html><body><h1>Results for ${q}</h1><p>0 hits</p></body></html>`);
      } else if (url.pathname === '/big.json') {
        const items = Array.from({ length: 2000 }, (_, i) => ({ id: i, name: `item ${i}`, price: i * 1.5 }));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ items }));
      } else if (url.pathname === '/image.png') {
        // 1×1 PNG
        const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
        res.writeHead(200, { 'content-type': 'image/png', 'content-length': png.length });
        res.end(png);
      } else {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
      }
    });
  });
  return new Promise((res) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      res({ server, port, host: `127.0.0.1:${port}`, base: `http://127.0.0.1:${port}`, hits, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

/** Sends one HTTP request THROUGH the proxy (absolute-URI form). Resolves {status, headers, body}. */
export function viaProxy(proxyPort, method, url, { headers = {}, body = null, timeoutMs = 15000 } = {}) {
  return new Promise((res, rej) => {
    const u = new URL(url);
    const req = httpRequest(
      { host: '127.0.0.1', port: proxyPort, method, path: url, headers: { host: u.host, ...headers }, timeout: timeoutMs },
      (r) => {
        let data = '';
        r.on('data', (d) => (data += d));
        r.on('end', () => res({ status: r.statusCode, headers: r.headers, body: data }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout through proxy')));
    req.on('error', rej);
    if (body != null) req.write(body);
    req.end();
  });
}

/**
 * Spawns `aitm web` with its own config (all ports free, scope widening on, PoC dirs set).
 * Resolves once the bridge is up. `env.stop()` kills it.
 */
export async function startAitm({ scope = [], l4 = null, aitmBin = process.env.AITM_BIN ?? join(REPO, 'target/debug/aitm'), log = () => {} } = {}) {
  if (!existsSync(aitmBin)) throw new Error(`aitm binary not found at ${aitmBin} — run: cargo build -p aitm (after npm run build in apps/web)`);
  const [proxyPort, browserProxyPort, webPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const dir = mkdtempSync(join(tmpdir(), 'aitm-live-'));
  const token = 'live-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  // Configuring `mcp.operator_token` (any non-empty secret) ENABLES operator access: the server then
  // mints a FRESH per-run operator *bridge* token and prints it in its stdout start-up block
  // (`web::startup_summary`) on the line `  Operator   http://…/#t=<tok>&expect=operator`, next to
  // the agent `  Web UI     http://…/#t=<tok>` line; the secret itself never appears in a URL/log.
  // We parse that URL + token below so a script can connect to /bus as a real `Frontend::Operator`
  // (vs the agent `--token` = Mcp), exactly as the UI opened from that URL does.
  const operatorSecret = 'opsecret-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  const pocDir = join(dir, 'poc');
  const pocOut = join(dir, 'poc-out');
  const cfg = join(dir, 'config.yaml');
  writeFileSync(
    cfg,
    [
      `listen: 127.0.0.1:${proxyPort}`,
      `browser:`,
      `  proxy_addr: 127.0.0.1:${browserProxyPort}`,
      `scope:`,
      `  allow_agent_widen: true`,
      ...(scope.length ? [`  entries:`, ...scope.map((s) => `    - "${s}"`)] : []),
      `poc:`,
      `  dir: ${pocDir}`,
      `  out_dir: ${pocOut}`,
      `mcp:`,
      `  operator_token: ${operatorSecret}`,
      `  transport:`,
      `    loopback_tcp:`,
      `      port: 0`,
      `      token: ${token}-mcp`,
      ...(l4 ? l4Block(l4) : []),
      '',
    ].join('\n'),
  );
  for (const d of [pocDir, pocOut]) if (!existsSync(d)) spawn('mkdir', ['-p', d]);
  const child = spawn(aitmBin, ['--config', cfg, 'web', '--listen', `127.0.0.1:${webPort}`, '--token', token], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' },
  });
  let stderr = '';
  let out = '';
  let operatorUiUrl = null;
  // The `Operator` line of the stdout start-up block (see the comment above `operatorSecret`).
  const opMatch = () => out.match(/^\s*Operator\s+(https?:\/\/\S+)/m);
  child.stderr.on('data', (d) => {
    stderr += d;
    log(String(d).trimEnd());
  });
  await new Promise((res, rej) => {
    // Readiness: the server logs "web UI listening" via tracing (stderr) and prints the start-up
    // block with the `Web UI` and `Operator` URLs on stdout. Resolve once the operator URL is
    // captured, or on the listening log / the `Web UI` line (operator access not configured).
    const check = () => {
      const m = opMatch();
      if (m) operatorUiUrl = m[1];
      if (operatorUiUrl || /web UI listening/i.test(stderr) || /^\s*Web UI\s+https?:\/\//m.test(out)) res();
    };
    child.stdout.on('data', (d) => {
      out += d;
      check();
    });
    child.stderr.on('data', check);
    child.on('exit', (code) => rej(new Error(`aitm exited ${code}\n${stderr}`)));
    setTimeout(() => rej(new Error('aitm did not start in 20 s\n' + stderr)), 20000);
  });
  // The operator URL println can trail the stderr "listening" log we resolved on; give stdout a beat.
  for (let i = 0; i < 20 && !operatorUiUrl; i++) {
    const m = opMatch();
    if (m) operatorUiUrl = m[1];
    else await new Promise((r) => setTimeout(r, 50));
  }
  // The operator URL fragment is query-shaped: `#t=<token>&expect=operator`. The bus token is only `t`.
  const opHash = operatorUiUrl ? new URL(operatorUiUrl).hash.replace(/^#/, '') : '';
  const operatorToken = opHash ? new URLSearchParams(opHash).get('t') : null;
  return {
    child,
    dir,
    cfg,
    token,
    operatorToken, // the fresh per-run operator BRIDGE token parsed from stdout (not the mcp secret)
    proxyPort,
    webPort,
    pocDir,
    pocOut,
    webUrl: `http://127.0.0.1:${webPort}/`,
    uiUrl: `http://127.0.0.1:${webPort}/#t=${token}`,
    operatorUiUrl,
    busUrl: `ws://127.0.0.1:${webPort}/bus`,
    stderr: () => stderr,
    stop: () =>
      new Promise((r) => {
        child.once('exit', () => r());
        child.kill('SIGINT');
        setTimeout(() => child.kill('SIGKILL'), 3000);
      }),
  };
}

/**
 * Minimal JSON-RPC client over the /bus bridge (same wire as the UI's ws.ts). `token` is a bridge
 * token: the agent one (`startAitm().token`) connects as `Frontend::Mcp`, the operator one
 * (`startAitm().operatorToken`) as `Frontend::Operator`. `role` is the role the server echoed in
 * the `initialize` result (`"operator"` / `"mcp"` / …), the same field ws.ts reads; a refused token
 * (`{"id":null,"error":{"code":-32001,…}}` then a Policy close) fails every call in flight with
 * the bridge's text instead of hanging `initialize`.
 */
export async function connectBus(busUrl, token) {
  const ws = new WebSocket(busUrl, { headers: { Origin: `http://${new URL(busUrl).host}` } });
  let id = 0;
  const pending = new Map();
  const notifications = [];
  const failAll = (why) => {
    for (const [n, p] of pending) {
      pending.delete(n);
      p.reject(new Error(`rpc ${p.method}: ${why}`));
    }
  };
  ws.onmessage = (ev) => {
    for (const line of String(ev.data).split('\n')) {
      if (!line.trim()) continue;
      const m = JSON.parse(line);
      if (m.id != null && pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        m.error ? p.reject(new Error(`rpc ${p.method}: ${JSON.stringify(m.error)}`)) : p.resolve(m.result);
      } else if (m.id === null && m.error) {
        // The bridge's reply to a bad token line is addressed to no request and the connection
        // ends right after it.
        failAll(`bus refused the token: ${JSON.stringify(m.error)}`);
      } else notifications.push(m);
    }
  };
  ws.onclose = (ev) => failAll(`bus closed (code ${ev.code}${ev.reason ? `, ${ev.reason}` : ''})`);
  await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = () => j(new Error('bus connect failed')))));
  ws.send(JSON.stringify({ token }) + '\n');
  const rpc = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      pending.set(n, { resolve, reject, method });
      ws.send(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n');
    });
  const info = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'live-env', version: '0' } });
  const role = typeof info?.role === 'string' ? info.role : null;
  const tools = async () => (await rpc('tools/list', {})).tools;
  /** Calls a tool; throws on isError with the tool's message. Returns structuredContent (or text). */
  const call = async (name, args = {}) => {
    const r = await rpc('tools/call', { name, arguments: args });
    if (r.isError) throw new Error(`${name}: ${r.content?.[0]?.text ?? 'error'}`);
    if (r.structuredContent !== undefined) return r.structuredContent;
    const t = r.content?.[0]?.text ?? '';
    try {
      return JSON.parse(t);
    } catch {
      return t;
    }
  };
  return { rpc, call, tools, notifications, role, close: () => ws.close() };
}

/** Polls `fn` until it returns a truthy value or the deadline passes. */
export async function waitFor(fn, { timeoutMs = 10000, everyMs = 150, what = 'condition' } = {}) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
