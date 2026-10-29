// Talks to a running `aitm web` /bus bridge from Node (no browser): dumps tools/list or calls
// one tool. Used to verify the client's wiring against the real core.
//
//   node scripts/bus-probe.mjs --token T [--url ws://127.0.0.1:8082/bus] tools
//   node scripts/bus-probe.mjs --token T call flow.list '{}'
//   node scripts/bus-probe.mjs --token T schema flow.detail
const argv = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  if (i < 0) return dflt;
  const v = argv[i + 1];
  argv.splice(i, 2);
  return v;
};
const url = opt('url', 'ws://127.0.0.1:8082/bus');
const token = opt('token', process.env.AITM_WEB_TOKEN);
const [cmd = 'tools', a1, a2] = argv;
if (!token) {
  console.error('need --token (or AITM_WEB_TOKEN)');
  process.exit(2);
}

const ws = new WebSocket(url, { headers: { Origin: `http://${new URL(url).host}` } });
let id = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  for (const line of String(ev.data).split('\n')) {
    if (!line.trim()) continue;
    const m = JSON.parse(line);
    if (m.id != null && pending.has(m.id)) {
      const p = pending.get(m.id);
      pending.delete(m.id);
      m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result);
    } else console.log('notification:', line);
  }
};
const rpc = (method, params) =>
  new Promise((resolve, reject) => {
    const n = ++id;
    pending.set(n, { resolve, reject });
    ws.send(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n');
  });

await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = (e) => j(new Error(String(e.message ?? e))))));
ws.send(JSON.stringify({ token }) + '\n');
const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bus-probe', version: '0' } });
try {
  if (cmd === 'tools') {
    const { tools } = await rpc('tools/list', {});
    console.log(`server ${init.serverInfo?.name ?? '?'} ${init.serverInfo?.version ?? ''} · ${tools.length} tools`);
    for (const t of tools) {
      const props = t.inputSchema?.properties ?? {};
      const req = new Set(t.inputSchema?.required ?? []);
      const params = Object.entries(props)
        .map(([k, v]) => `${k}${req.has(k) ? '' : '?'}:${v.type ?? '?'}${v.enum ? `[${v.enum.join('|')}]` : ''}`)
        .join(', ');
      console.log(`  ${t.name.padEnd(18)} (${params})`);
    }
  } else if (cmd === 'schema') {
    const { tools } = await rpc('tools/list', {});
    console.log(JSON.stringify(tools.find((t) => t.name === a1), null, 2));
  } else if (cmd === 'call') {
    const res = await rpc('tools/call', { name: a1, arguments: a2 ? JSON.parse(a2) : {} });
    if (res.isError) console.log('tool error:', res.content?.[0]?.text);
    else console.log(JSON.stringify(res.structuredContent ?? res.content?.[0]?.text, null, 2));
  }
} finally {
  ws.close();
}
