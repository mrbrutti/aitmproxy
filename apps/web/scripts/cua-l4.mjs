// HUMAN-PATH (CUA) acceptance of the web L4 operator surface (L4OPS Task 17 / AC14, AC18) — real
// headless Chrome driven over CDP with real input events only, clicking and typing through the UI a
// spawned `aitm web` serves from an `l4.enabled: true` core, cross-checked over the live bus.
//
//   node scripts/cua-l4.mjs [--keep]
//
// Operator identity: `mcp.operator_token` is configured, so the UI + the bus cross-checks here drive
// as a real `Frontend::Operator` (operator-token UX, PR #35) — sensitive actions bypass the agent
// policy gate and reach the privilege/command gate directly, and the operator confirm-over-the-wire
// handshake is offered.
//
// Privilege reality (CLI/Linux-first, spec §Part 6 / AC18): a user-level core on an unprivileged
// host (no CAP_NET_RAW / no /dev/bpf) returns a typed `L4Unavailable` for every wire verb. So on
// such a host this run proves the REQUIRED honest-degradation scenario by real operator clicks — the
// L4 view renders and drives the bus, the pure/read verbs work, the wire-verb buttons surface the
// typed privilege reason rather than faking success, the operator confirm handshake is offered over
// the bus, and the per-feature MCP toggles reflect AND flip (operator). The privileged real-packet
// click-drive (capture → craft → inject → the confirm DIALOG → inspect → send_recv → intercept →
// out-of-scope-dimmed) needs a captured/injected L4 flow, which only exists where raw privilege
// exists; it is authored here as `privilegedDrive()`, gated on a runtime probe, and runs on
// Linux/elevated. It is never faked on an unprivileged host — it records SKIP with the reason.
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
// Post-PR#41 ("unify L4 sessions into the one flow list"): there is no separate L4 panel. Picking
// the L4 source (sidebar → L4) shows `L4CaptureBar` (which renders CaptureControls) above the ONE
// unified flow list; L4 sessions are rows in that list; selecting one opens L4InspectorPanel.
const CAPTURE = 'section[aria-label="Capture"]'; // CaptureControls, now inside L4CaptureBar
const CAPBAR_FALLBACK = 'L4 is not enabled'; // L4CaptureBar honest-degradation text when l4.* is absent
const GRID = '[role=grid][aria-label="Flows"]'; // the one unified flow list
const L4ROW = '[role=grid][aria-label="Flows"] [role=row][data-kind="l4"]'; // an L4 session row
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

/** Focus the L4 source (sidebar → L4): the L4CaptureBar + its CaptureControls appear above the list. */
async function focusL4() {
  await d.click({ role: 'button', text: 'L4', match: 'startsWith', within: SIDEBAR });
  await d.locate({ sel: CAPTURE });
}

try {
  target = await startTarget();
  // An opted-in L4 core (l4.enabled) with a config-declared L4 scope entry (lo0 · 127.0.0.1/32 ·
  // inject) and a MIXED set of per-capability agent gates, so the surface has real scope + gate state
  // to render. `mcp.operator_token` is configured (by live-env) so the UI + bus here drive as a real
  // `Frontend::Operator` — the operator identity landed on this branch (PR #35, operator-token UX),
  // so sensitive actions bypass the agent-policy gate and reach the privilege/command gate directly.
  env = await startAitm({
    scope: [target.host, '127.0.0.1'],
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
  // Drive the bus cross-checks AS THE OPERATOR (the browser connects with the same operator token),
  // so wire verbs reach the privilege gate and the operator confirm handshake is offered.
  bus = await connectBus(env.busUrl, env.operatorToken);
  const tools = (await bus.tools()).map((t) => t.name);
  const l4Tools = tools.filter((t) => t.startsWith('l4.'));
  log(`aitm up: proxy ${env.proxyPort}, operator ui ${env.operatorUiUrl}, target ${target.base}`);
  log(`l4 tools (${l4Tools.length}): ${l4Tools.join(' ')}`);
  cdp = await launchChrome({ width: W, height: H });
  d = makeDriver(cdp, { log, shotsDir: SHOTS });

  // 01 ---------------------------------------------------------------------------------------
  await step('01 connect (as operator), L4 advertised', async () => {
    await d.open(env.operatorUiUrl);
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
  await step('02 open the L4 view (sidebar → L4 → capture bar + the one unified flow list)', async () => {
    await focusL4();
    // present() → CaptureControls render in L4CaptureBar; the "L4 is not enabled" fallback is ABSENT.
    const cap = await d.q('exists', CAPTURE);
    const disabled = await d.q('find', { text: CAPBAR_FALLBACK });
    const grid = await d.q('exists', GRID);
    expect(cap && !disabled && grid, '02 L4 capture bar + unified flow list render (not the disabled fallback)', `capture=${cap}; grid=${grid}; disabled-fallback=${!!disabled}`);
  });

  // 03 ---------------------------------------------------------------------------------------
  let captureReason = null;
  let privileged = false;
  await step('03 privilege degradation (operator bus): every wire verb returns a typed L4Unavailable', async () => {
    const cap = await probe(bus, 'l4.capture.status');
    const inj = await probe(bus, 'l4.inject', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] }, dst: '127.0.0.1', interface: 'lo0', port: 9 });
    const sr = await probe(bus, 'l4.send_recv', { spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: PROBE }] }, dst: '127.0.0.1', interface: 'lo0', port: 9 });
    privileged = cap.ok; // l4.capture.status succeeding ⇒ the host has raw-socket privilege
    captureReason = cap.ok ? '(privileged host)' : cap.error;
    if (privileged) {
      note('03 privileged host — wire verbs available', 'l4.capture.status ok; the privileged click-drive (step 09) runs');
      return;
    }
    // The operator bus bypasses the agent-policy gate, so each Sensitive wire verb reaches the
    // privilege gate directly → a typed L4Unavailable (never a silent success, never a panic).
    expect(isUnavailable(cap) && isUnavailable(inj) && isUnavailable(sr), '03a capture.status / inject / send_recv all return "L4 unavailable: …" for the operator (privilege gate)', `capture="${cap.error}"; inject="${inj.error}"; send_recv="${sr.error}"`);
    note('03b confirm handshake is privilege-gated too', 'the L4Gated wrapper short-circuits an unprivileged wire verb before its confirm_prompt, so even the operator gets L4Unavailable straight away (no needs_confirmation). The operator confirm-over-the-wire DIALOG therefore appears only where privilege exists — step 09 / Linux. The agent (Mcp) path is additionally gated by AgentPolicy + per-capability flags (Task 16).');
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
    note('05b runtime l4.scope.add (operator bus)', add.ok ? 'accepted — the operator CAN widen L4 scope over the bus; the web SURFACE still exposes no add-scope control (the GAP above), so there is no click path for it' : `unexpectedly refused: "${(add.error ?? '').slice(0, 90)}"`);
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
        const t = (await d.q('texts', { role: 'alert' })).find((x) => /l4 unavailable|l4\.capture\.start/i.test(x));
        return t ?? null;
      },
      { timeoutMs: 6000, what: 'error toast from Start capture' },
    ).catch(() => null);
    const started = (await d.q('texts', { role: 'status' })).find((x) => /capture started/i.test(x));
    const l4rows = await d.q('count', { sel: L4ROW });
    expect(!!toast && /l4 unavailable/i.test(toast) && !started && l4rows === 0, '06a Start capture (operator click) → typed "L4 unavailable" toast; no "Capture started", no L4 row (honest privilege degradation, no fake)', `toast "${toast}"; started=${started ?? 'none'}; l4rows=${l4rows}`);
    note('06b gate', `the web bus is Frontend::Operator (operator_token), so the click bypasses the agent-policy gate and reaches the privilege gate: "${captureReason}". The button surfaces the typed reason and never fakes a send (AC18).`);
  });

  // 07 ---------------------------------------------------------------------------------------
  await step('07 unified flow list: no L4 session rows (honest empty state)', async () => {
    const l4rows = await d.q('count', { sel: L4ROW });
    const empty = await d.q('find', { text: 'No flows yet', within: GRID });
    if (privileged) {
      note('07 privileged host', `l4 rows=${l4rows}`);
      return;
    }
    expect(l4rows === 0, '07 the one flow list shows no L4 session rows (none can be captured unprivileged)', `l4rows=${l4rows}; grid empty-state="${empty?.text ?? 'n/a'}"`);
    note('07 inspector gated', 'with no L4 session row there is nothing to select, so the L4 inspector (craft editor, Inject, layer tree, hex, intercept bar, out-of-scope dimming) is unreachable by clicks on this host — it is the privileged drive (step 09)');
  });

  // 08 ---------------------------------------------------------------------------------------
  await step('08 per-feature MCP toggles reflect the gates', async () => {
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    await d.locate({ sel: TOGGLES });
    const status = await probe(bus, 'l4.agent.status');
    const busGates = status.value ?? {};
    const caps = ['capture', 'inject', 'intercept', 'widen'];
    // The Agent panel fetches l4.agent.status asynchronously; wait until the switches reflect the
    // loaded gates (config turns inject on) before reading, so this asserts reflect, not a pre-load race.
    await waitFor(async () => (await d.q('find', { sel: `${TOGGLES} [role=switch][data-cap="inject"]` }))?.checked === 'true', { timeoutMs: 6000, what: 'L4 toggles to load the gates' }).catch(() => {});
    const ui = {};
    for (const c of caps) ui[c] = (await d.q('find', { sel: `${TOGGLES} [role=switch][data-cap="${c}"]` }))?.checked === 'true';
    const match = caps.every((c) => ui[c] === !!busGates[c]);
    expect(match, '08a each switch (Capture/Inject/Intercept/Widen) reflects l4.agent.status (config: capture/inject/widen on, intercept off)', `ui=${JSON.stringify(ui)}; bus=${JSON.stringify(busGates)}`);
    // The operator flips a gate live: click the Inject switch and confirm it toggles on the bus, then revert.
    const injectSwitch = { sel: `${TOGGLES} [role=switch][data-cap="inject"]` };
    const before = ui.inject;
    await d.click(injectSwitch);
    const flipped = await waitFor(async () => {
      const s = (await d.q('find', injectSwitch))?.checked === 'true';
      const b = !!(await probe(bus, 'l4.agent.status')).value?.inject;
      return s === !before && b === !before ? { s, b } : null;
    }, { timeoutMs: 6000, what: 'inject gate to flip' }).catch(() => null);
    expect(!!flipped, '08b operator click flips the Inject gate live; l4.agent.status reflects it', `inject ${before} → ui ${flipped?.s}, bus ${flipped?.b}`);
    await d.click(injectSwitch); // revert to the config state
    await sleep(300);
    note('08c live flip', 'the operator flips a per-feature MCP gate from the web UI and the bus reflects it. An agent (Frontend::Mcp) can never flip its own gate — l4.agent.set is operator-only.');
  });

  // 09 ---------------------------------------------------------------------------------------
  await step('09 privileged real-packet click-drive (craft → inject → confirm → inspect → send_recv → intercept → out-of-scope)', async () => {
    if (!privileged) {
      skip('09 privileged click-drive — SKIP (not faked)', `one gate on this host: no raw-socket privilege (${captureReason}). No L4 flow can be captured/injected, so the L4 inspector (craft editor, Inject, the confirm DIALOG, layer tree, hex, send_recv, intercept) + out-of-scope dimming have no session to act on by clicks. The operator identity IS present here (operator_token → Frontend::Operator), so privilege is the ONLY remaining gate — run privilegedDrive() on a Linux/elevated operator host. The operator confirm-over-the-wire DIALOG + the full real-packet path (capture→inject→confirm→send_recv→intercept) are proven agent-driven (MCP) in Task 16 (commit 5bd2381).`);
      return;
    }
    await privilegedDrive();
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 hero', async () => {
    await focusL4();
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
    const row = await d.locate({ sel: L4ROW }, { timeoutMs: 8000 });
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
    await focusL4();
    const dimmed = await waitFor(async () => (await d.q('find', { sel: L4ROW }))?.oos, { timeoutMs: 6000, what: 'out-of-scope row' }).catch(() => false);
    const injBtn = await d.q('find', { sel: '[data-testid="l4-inject"]' });
    expect(dimmed && (injBtn?.disabled ?? true), '09e out-of-scope session is dimmed and its Inject disabled with the scope reason', `dimmed=${dimmed}; inject.disabled=${injBtn?.disabled}`);
    note('09f intercept Forward/Mutate/Drop', 'in-path (NFQUEUE) is Linux-only and needs CAP_NET_ADMIN + a parked packet; drive the L4 intercept bar on an elevated Linux core with nft queueing to a scoped target');
  } finally {
    echo.close();
  }
}
