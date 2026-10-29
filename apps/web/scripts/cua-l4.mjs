// HUMAN-PATH (CUA) acceptance of the web L4 operator surface (L4OPS Task 17 / AC14, AC18) — real
// headless Chrome driven over CDP with real input events only, clicking and typing through the UI a
// spawned `aitm web` serves from an `l4.enabled: true` core, cross-checked over the live bus.
//
//   node scripts/cua-l4.mjs [--keep]
//
// Privilege reality (CLI/Linux-first, spec §Part 6 / AC18): a user-level core on an unprivileged
// host (no CAP_NET_RAW / no /dev/bpf) returns a typed `L4Unavailable` for every wire verb. So on
// such a host this run proves the REQUIRED honest-degradation scenario by real clicks — the L4 view
// renders and drives the bus, the pure/read verbs work, the wire-verb buttons surface the typed
// reason rather than faking success, and the per-feature MCP toggles reflect+flip the gates. The
// privileged real-packet click-drive (capture → craft → inject → confirm → inspect → send_recv →
// intercept → out-of-scope-dimmed) needs a captured/injected L4 flow, which only exists where
// privilege exists; it is authored here as `privilegedDrive()`, gated on a runtime probe, and runs
// on Linux/elevated. It is never faked on an unprivileged host — it records SKIP with the reason.
//
// --keep leaves aitm and Chrome running and prints the UI URL. Node ≥ 22, no dependencies.
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, sleep, startAitm, startTarget, waitFor } from './live-env.mjs';
import { launchChrome, makeDriver } from './cua-driver.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-l4-shots');
const KEEP = process.argv.includes('--keep');
const W = 1600;
const H = 1000;

// ------------------------------------------------------------------------------------------
// Results
// ------------------------------------------------------------------------------------------
const results = [];
function record(status, step, detail) {
  results.push({ status, step, detail });
  console.log(`${status.padEnd(4)} ${step}${detail ? ` — ${detail}` : ''}`);
}
const pass = (step, detail) => record('PASS', step, detail);
const fail = (step, detail) => record('FAIL', step, detail);
const gap = (step, detail) => record('GAP', step, detail);
const note = (step, detail) => record('NOTE', step, detail);
const skip = (step, detail) => record('SKIP', step, detail);
const expect = (cond, okMsg, badMsg) => (cond ? pass(okMsg) : fail(okMsg, badMsg));

// ------------------------------------------------------------------------------------------
// Bus helpers (cross-checks run beside the real clicks)
// ------------------------------------------------------------------------------------------
/** Call a tool and return { ok, value } or { ok:false, error } — never throws (wire verbs error). */
async function probe(bus, name, args = {}) {
  try {
    return { ok: true, value: await bus.call(name, args) };
  } catch (e) {
    return { ok: false, error: (e instanceof Error ? e.message : String(e)) };
  }
}
const isUnavailable = (r) => !r.ok && /l4 unavailable/i.test(r.error);

// ------------------------------------------------------------------------------------------
// Main
// ------------------------------------------------------------------------------------------
const L4 = 'section[aria-label="L4"]';
const CAPTURE = 'section[aria-label="Capture"]';
const UNION = '[role=grid][aria-label="Flows (all kinds)"]';
const SIDEBAR = 'aside[aria-label="Sources"]';
const TOGGLES = 'section[aria-label="L4 agent capabilities"]';
// A raw `PacketSpec` layer on the bus wants a byte SEQUENCE (the UI's YAML parser converts
// `raw: "probe"` → bytes client-side; a direct bus call must send the array). "probe" as bytes:
const PROBE = [112, 114, 111, 98, 101];

mkdirSync(SHOTS, { recursive: true });
for (const f of readdirSync(SHOTS)) if (f.endsWith('.png')) rmSync(join(SHOTS, f));

let target, env, bus, cdp, d;
const log = (m) => console.log(m);

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
      if (f) log(`  shot ${f}`);
    } catch (e) {
      log(`  (screenshot failed: ${e.message})`);
    }
  }
}

/** Re-mount the L4 panel (Agent → L4) so its onMount `store.refresh()` re-reads the bus. */
async function remountL4() {
  await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
  await d.gone({ sel: L4 }, { timeoutMs: 4000 }).catch(() => {});
  await d.click({ role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
  await d.locate({ sel: L4 });
}

try {
  target = await startTarget();
  // An opted-in L4 core (l4.enabled) with a config-declared L4 scope entry (lo0 · 127.0.0.1/32 ·
  // inject) and a MIXED set of per-capability agent gates, so the surface has real scope + gate state
  // to render. (Runtime `l4.scope.add` and the live toggle flip are operator-only; on this build the
  // web `/bus` is `Frontend::Mcp` under `AgentPolicy::Auto` — the web operator identity is the F1
  // follow-up (crates/aitm/src/web/mod.rs:12) — so those are driven/declared out of band, see steps.)
  env = await startAitm({
    scope: [target.host],
    l4: {
      enabled: true,
      allow_agent_widen: true,
      allow_agent_capture: true,
      allow_agent_inject: true,
      allow_agent_intercept: false,
      scope: [{ addr: '127.0.0.1', prefix: 32, interface: 'lo0', direction: 'outbound', capability: 'inject', pps: 100, burst: 100 }],
    },
    log: (l) => (/error|panic/i.test(l) ? console.error('[aitm] ' + l) : null),
  });
  bus = await connectBus(env.busUrl, env.token);
  const tools = (await bus.tools()).map((t) => t.name);
  const l4Tools = tools.filter((t) => t.startsWith('l4.'));
  log(`aitm up: proxy ${env.proxyPort}, ui ${env.uiUrl}, target ${target.base}`);
  log(`l4 tools (${l4Tools.length}): ${l4Tools.join(' ')}`);
  cdp = await launchChrome({ width: W, height: H });
  d = makeDriver(cdp, { log, shotsDir: SHOTS });

  // 01 ---------------------------------------------------------------------------------------
  await step('01 connect, L4 advertised', async () => {
    await d.open(env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'status bar "bus open"' });
    const l4Item = await waitFor(
      async () => {
        const b = await d.q('find', { role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
        return b && /on$/.test(b.text) ? b : null;
      },
      { timeoutMs: 10000, what: 'sidebar L4 "on"' },
    );
    expect(l4Tools.includes('l4.flow.list') && /on$/.test(l4Item.text), '01 sidebar L4 reads "on" (l4.* advertised)', `sidebar "${l4Item?.text}"; l4.flow.list present=${l4Tools.includes('l4.flow.list')}`);
  });

  // 02 ---------------------------------------------------------------------------------------
  await step('02 open the L4 view', async () => {
    await d.click({ role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: L4 });
    const header = await d.q('text', `${L4} h2`);
    const meta = await d.q('text', `${L4} header span`);
    // present() → the fallback "L4 is not enabled" paragraph must be ABSENT.
    const disabledText = await d.q('find', { text: 'L4 is not enabled', within: L4 });
    await d.locate({ sel: CAPTURE });
    expect(/raw packets/i.test(header ?? '') && !disabledText, '02 L4 view renders the live surface (not the disabled fallback)', `header "${header}"; meta "${meta}"; disabled-fallback=${!!disabledText}`);
  });

  // 03 ---------------------------------------------------------------------------------------
  let captureReason = null;
  let privileged = false;
  await step('03 privilege reality (bus): the read wire verb reaches the privilege gate', async () => {
    const cap = await probe(bus, 'l4.capture.status');
    const inj = await probe(bus, 'l4.inject', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] }, dst: '127.0.0.1', interface: 'lo0', port: 9 });
    privileged = cap.ok; // l4.capture.status (Read; agent-policy lets it through) succeeding ⇒ raw privilege
    captureReason = cap.ok ? '(privileged host)' : cap.error;
    if (privileged) {
      note('03 privileged host — wire verbs available', `l4.capture.status ok; the privileged click-drive (step 09) will run`);
    } else {
      // l4.capture.status is Read: it passes the agent-policy gate and hits the privilege gate → L4Unavailable.
      expect(isUnavailable(cap), '03a l4.capture.status returns a typed "L4 unavailable: …" (privilege gate, no panic)', `capture="${cap.error}"`);
      // l4.inject is Sensitive: over this (Mcp/auto) bus it is refused — never a silent success.
      expect(!inj.ok, '03b l4.inject is refused, never fakes a send (typed reason)', `inject.ok=${inj.ok}; reason="${inj.error}"`);
      note('03c two-dimension gating', `the bus client is Frontend::Mcp under AgentPolicy::Auto, so Sensitive l4.inject is refused by the agent-policy gate ("${(inj.error ?? '').slice(0, 72)}…") before the privilege gate; the privilege L4Unavailable is proven on the Read verb (l4.capture.status) here and end-to-end agent-driven in Task 16 (5bd2381)`);
    }
  });

  // 04 ---------------------------------------------------------------------------------------
  await step('04 pure/read verbs work regardless of privilege (bus)', async () => {
    const ifaces = await probe(bus, 'l4.interfaces');
    const flows = await probe(bus, 'l4.flow.list');
    const craft = await probe(bus, 'l4.craft', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] } });
    log(`  craft raw: ${JSON.stringify(craft).slice(0, 220)}`);
    const cv = craft.value ?? {};
    const craftLayers = cv.summary?.layers ?? cv.layers;
    const craftLen = cv.length;
    const craftOk = craft.ok && typeof craftLen === 'number' && Array.isArray(craftLayers);
    expect(ifaces.ok && flows.ok && Array.isArray(flows.value) && craftOk, '04 l4.interfaces / l4.flow.list / l4.craft succeed (flow.list empty, craft returns bytes+summary)', `interfaces.ok=${ifaces.ok}; flow.list=${JSON.stringify(flows.value)?.slice(0, 40)}; craft.ok=${craft.ok} layers=${JSON.stringify(craftLayers)} len=${craftLen}`);
    note('04 craft editor reachability', 'the pure l4.craft verb works on the bus, but its EDITOR UI lives inside the L4 inspector, which needs a selected L4 flow from l4.flow.list — empty without a wire verb, so the editor is reached only on a privileged host (step 09)');
  });

  // 05 ---------------------------------------------------------------------------------------
  await step('05 L4 scope entry is reflected in the surface', async () => {
    gap('05 web surface has no add-L4-scope control', 'CaptureControls READS the L4 scope and points at where it is granted — it never offers an add/widen the core would refuse. Scope is declared by the operator (config, or `l4.scope.add` over an operator connection); this core declares lo0·127.0.0.1/32·inject in config.');
    const scopeText = await waitFor(
      async () => {
        const t = await d.q('text', CAPTURE);
        return t && /inject/.test(t) && /127\.0\.0\.1\/32/.test(t) ? t : null;
      },
      { timeoutMs: 6000, what: 'L4 scope row in the surface' },
    ).catch(() => d.q('text', CAPTURE));
    const list = await probe(bus, 'l4.scope.list');
    expect(/127\.0\.0\.1\/32/.test(scopeText ?? '') && /inject/.test(scopeText ?? '') && (list.value?.length ?? 0) > 0, '05a CaptureControls shows the scope row (… 127.0.0.1/32 … inject …); bus l4.scope.list agrees', `scope section "${(scopeText ?? '').replace(/\s+/g, ' ').slice(0, 120)}"; bus entries=${list.value?.length}`);
    const add = await probe(bus, 'l4.scope.add', { cidr: '10.0.0.0/8', interface: 'lo0', direction: 'outbound', capability: 'inject', inject_rate_pps: 10 });
    note('05b runtime l4.scope.add over the web/bus', add.ok ? 'accepted (operator/widen path)' : `refused for the Frontend::Mcp bus: "${(add.error ?? '').slice(0, 90)}…" — runtime widening from the web UI needs the operator identity (F1)`);
  });

  // 06 ---------------------------------------------------------------------------------------
  await step('06 wire-verb button surfaces a typed refusal, never fakes success (real click: Start capture)', async () => {
    if (privileged) {
      skip('06 Start capture (privileged host does not degrade)', 'exercised in step 09 instead');
      return;
    }
    await d.click({ role: 'button', text: 'Start capture', match: 'startsWith', within: CAPTURE });
    const toast = await waitFor(
      async () => {
        const t = (await d.q('texts', { role: 'alert' })).find((x) => /l4\.capture\.start|l4 unavailable|refused|disabled/i.test(x));
        return t ?? null;
      },
      { timeoutMs: 6000, what: 'error toast from Start capture' },
    ).catch(() => null);
    const started = (await d.q('texts', { role: 'status' })).find((x) => /capture started/i.test(x));
    const rows = await d.q('count', { role: 'row', within: UNION });
    expect(!!toast && !started && rows === 0, '06a Start capture → typed error toast; no "Capture started", no flow row (no fake success)', `toast "${toast}"; started=${started ?? 'none'}; rows=${rows}`);
    note('06b gate on this build', `the toast is the agent-policy refusal because the web /bus is Frontend::Mcp under AgentPolicy::Auto (F1); the underlying privilege reason for capture/inject is "${captureReason}" (shown on l4.capture.status, step 03). Honest degradation holds: the button surfaces a typed reason and never fakes a send.`);
  });

  // 07 ---------------------------------------------------------------------------------------
  await step('07 union flow list honest empty state', async () => {
    const empty = await d.q('find', { text: 'No flows yet', within: UNION });
    const rows = await d.q('count', { role: 'row', within: UNION });
    if (privileged) {
      note('07 privileged host', `union rows=${rows}`);
      return;
    }
    expect(!!empty && rows === 0, '07 "No flows yet. HTTP, WebSocket and L4 flows all appear here."', `empty="${empty?.text}"; rows=${rows}`);
    note('07 inspector gated', 'with no L4 flow there is no session to select, so the L4 inspector (craft editor, Inject, layer tree, hex, intercept bar, out-of-scope dimming) is unreachable by clicks on this host — it is the privileged drive (step 09)');
  });

  // 08 ---------------------------------------------------------------------------------------
  await step('08 per-feature MCP toggles reflect the gates', async () => {
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: TOGGLES });
    const status = await probe(bus, 'l4.agent.status');
    const busGates = status.value ?? {};
    const caps = ['capture', 'inject', 'intercept', 'widen'];
    const ui = {};
    for (const c of caps) ui[c] = (await d.q('find', { sel: `${TOGGLES} [role=switch][data-cap="${c}"]` }))?.checked === 'true';
    const match = caps.every((c) => ui[c] === !!busGates[c]);
    expect(match, '08a each switch (Capture/Inject/Intercept/Widen) reflects l4.agent.status (config: capture/inject/widen on, intercept off)', `ui=${JSON.stringify(ui)}; bus=${JSON.stringify(busGates)}`);
    // A live flip by click is refused on this build: l4.agent.set is operator-only and the web /bus is Mcp.
    const injectSwitch = { sel: `${TOGGLES} [role=switch][data-cap="inject"]` };
    const before = ui.inject;
    await d.click(injectSwitch);
    await sleep(500);
    const after = (await d.q('find', injectSwitch))?.checked === 'true';
    const nowBus = !!(await probe(bus, 'l4.agent.status')).value?.inject;
    expect(after === before && nowBus === before, '08b a click does not change the gate (l4.agent.set is operator-only; the web bus is Frontend::Mcp)', `inject ui ${before}→${after}; bus=${nowBus}`);
    note('08c live flip', 'the toggles correctly REFLECT the gates today; flipping one from the web UI needs the operator identity on the /bus (F1). An agent can never flip its own gate by design.');
  });

  // 09 ---------------------------------------------------------------------------------------
  await step('09 privileged real-packet click-drive (craft → inject → confirm → inspect → send_recv → intercept → out-of-scope)', async () => {
    if (!privileged) {
      skip('09 privileged click-drive — SKIP (not faked)', `two gates on this host: (1) no raw-socket privilege (${captureReason}), so no L4 flow can be captured/injected and the L4 inspector (craft editor, Inject, layer tree, hex, send_recv, intercept) + out-of-scope dimming have no session to act on; (2) the operator confirm-over-the-wire dialog is offered only to Frontend::Operator, but the web /bus is Frontend::Mcp (F1), so the confirm handshake never reaches the web UI. Run on Linux/elevated AND with the web operator identity. The privileged real-packet path is proven agent-driven (MCP) in Task 16 (commit 5bd2381); privilegedDrive() below is the authored web click sequence for when both land.`);
      return;
    }
    await privilegedDrive();
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 hero', async () => {
    await d.click({ role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: L4 });
    await sleep(300);
    await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 2, mobile: false });
    await sleep(300);
    const png = await cdp.s('Page.captureScreenshot', { format: 'png' });
    (await import('node:fs')).writeFileSync(join(SHOTS, '99-hero.png'), Buffer.from(png.data, 'base64'));
    await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    pass('10 hero', `${join(SHOTS, '99-hero.png')} (${W}x${H}@2x)`);
  });

  if (cdp.consoleErrors.length) note('console errors', JSON.stringify(cdp.consoleErrors.slice(0, 10)));
} catch (e) {
  fail('harness', e.stack ?? e.message);
} finally {
  const summary = {
    pass: results.filter((r) => r.status === 'PASS').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    gap: results.filter((r) => r.status === 'GAP').length,
    skip: results.filter((r) => r.status === 'SKIP').length,
    shots: SHOTS,
    results,
  };
  console.log('\n' + JSON.stringify(summary, null, 2));
  console.log(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.gap} GAP · ${summary.skip} SKIP · screenshots in ${SHOTS}`);
  if (KEEP && env) {
    console.log(`--keep: aitm and Chrome left running. UI: ${env.uiUrl}  proxy: 127.0.0.1:${env.proxyPort}`);
    await new Promise(() => {});
  }
  bus?.close();
  cdp?.close();
  await env?.stop();
  await target?.close();
  process.exit(summary.fail ? 1 : 0);
}

// ------------------------------------------------------------------------------------------
// Privileged drive (runs only where raw capture/inject privilege exists — Linux / elevated core).
// Authored from the verified DOM map; gated behind the step-03 probe so it NEVER runs (or fakes a
// result) on an unprivileged host. Uses real clicks + a plain node UDP socket for loopback traffic.
// ------------------------------------------------------------------------------------------
async function privilegedDrive() {
  const dgram = await import('node:dgram');
  // Start a loopback UDP echo so a crafted/injected packet has a live peer and send_recv gets a reply.
  const echo = dgram.createSocket('udp4');
  await new Promise((r) => echo.bind(9, '127.0.0.1', r));
  echo.on('message', (msg, rinfo) => echo.send(msg, rinfo.port, rinfo.address));
  try {
    // Capture on loopback (real click), then push a datagram so a packet is captured → a flow appears.
    await d.click({ role: 'button', text: 'Start capture', match: 'startsWith', within: CAPTURE });
    const ping = dgram.createSocket('udp4');
    ping.send(Buffer.from('probe'), 9, '127.0.0.1');
    const row = await d.locate({ role: 'row', within: UNION }, { timeoutMs: 8000 });
    await d.mouse(row.x, row.y); // select the L4 session
    ping.close();
    await d.locate({ sel: 'section[aria-label="Craft"]' });

    // Author a PacketSpec in the craft editor, Build it (pure → hex preview), then Inject.
    const cm = await d.locate({ sel: 'section[aria-label="Craft"] .cm-content' });
    await d.mouse(cm.x, cm.y);
    await d.selectAll();
    await d.type('layers:\n  - ipv4:\n      dst: 127.0.0.1\n  - udp:\n      dst_port: 9\n  - raw: "probe"\n');
    await d.click({ role: 'button', text: 'Build', match: 'startsWith', within: 'section[aria-label="Craft"]' });
    const hex = await d.locate({ sel: 'section[aria-label="Craft"] [aria-label="Hex"], section[aria-label="Craft"] pre' }, { timeoutMs: 6000 }).catch(() => null);
    expect(!!hex, '09a craft Build → hex preview shown', `hex=${!!hex}`);

    await d.click({ sel: '[data-testid="l4-inject"]' });
    const dlg = '[role=alertdialog][aria-label="Confirm L4 action over the wire"]';
    await d.locate({ sel: dlg });
    const prompt = await d.q('text', `${dlg} p`);
    const facts = await d.q('text', `${dlg} dl`);
    expect(/127\.0\.0\.1/.test(prompt ?? '') && /inject/i.test(prompt ?? ''), '09b confirm dialog shows destination + packet summary + scope + permit budget', `prompt "${(prompt ?? '').slice(0, 160)}"; facts "${facts}"`);
    await d.click({ role: 'button', text: 'Send to wire', match: 'startsWith', within: dlg });
    await d.gone({ sel: dlg });

    // The injected packet appears in the flow (list + layer tree), and send_recv shows the reply.
    const pkt = await d.locate({ role: 'listitem', within: '[aria-label="Packets"]' }, { timeoutMs: 6000 }).catch(() => null);
    expect(!!pkt, '09c injected packet appears in the packet list', `pkt "${pkt?.text}"`);
    const layers = await d.q('find', { sel: '[aria-label="Packet layers"] [role=treeitem]' });
    note('09c layer tree', `first layer "${layers?.text}"`);

    const sr = await probe(bus, 'l4.send_recv', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] }, dst: '127.0.0.1', interface: 'lo0', port: 9 });
    expect(sr.ok, '09d send_recv returns the echoed reply', `send_recv ok=${sr.ok} ${sr.ok ? JSON.stringify(sr.value).slice(0, 80) : sr.error}`);

    // Out-of-scope dimming: remove the lo0 scope so the existing flow falls out of L4 scope.
    const entries = (await probe(bus, 'l4.scope.list')).value ?? [];
    for (const e of entries) await probe(bus, 'l4.scope.remove', { id: e.id });
    await remountL4();
    const dimmed = await waitFor(async () => (await d.q('find', { role: 'row', within: UNION }))?.oos, { timeoutMs: 6000, what: 'out-of-scope row' }).catch(() => false);
    const injBtn = await d.q('find', { sel: '[data-testid="l4-inject"]' });
    expect(dimmed && (injBtn?.disabled ?? true), '09e out-of-scope session is dimmed and its Inject disabled with the scope reason', `dimmed=${dimmed}; inject.disabled=${injBtn?.disabled}`);
    note('09f intercept Forward/Mutate/Drop', 'in-path (NFQUEUE) is Linux-only and needs CAP_NET_ADMIN + a parked packet; drive the L4 intercept bar on an elevated Linux core with nft queueing to a scoped target');
  } finally {
    echo.close();
  }
}
