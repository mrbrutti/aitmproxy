// HUMAN-PATH live check of the web operator UI: a real headless Chrome, driven over CDP with real
// input events only (Input.dispatchMouseEvent / dispatchKeyEvent / insertText — never synthetic
// DOM events, never app functions), clicking and typing through the UI served by a spawned
// `aitm web`, with real traffic through the real proxy. Every step takes a screenshot into
// .cua-shots/ and is cross-checked over the bus. Exit 1 on any FAIL.
//
//   node scripts/cua-live.mjs [--keep]
//
// --keep leaves aitm and Chrome running and prints the UI URL. Node ≥ 22, no dependencies.
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connectBus, sleep, startAitm, startTarget, viaProxy, waitFor } from './live-env.mjs';
import { launchChrome, makeDriver } from './cua-driver.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SHOTS = resolve(here, '../.cua-shots');
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

// ------------------------------------------------------------------------------------------
// Main
// ------------------------------------------------------------------------------------------
const REQ = 'section[aria-label="Request"]';
const RES = 'section[aria-label="Response"]';
const GRID = '[role=grid][aria-label="Flows"]';
const BAR = '[role=status]';
const EDITBAR = '[role=region][aria-label="Pending edits"]';
const SIDEBAR = 'aside[aria-label="Sources"]';

mkdirSync(SHOTS, { recursive: true });
for (const f of (await import('node:fs')).readdirSync(SHOTS)) if (f.endsWith('.png')) rmSync(join(SHOTS, f));

let target, env, bus, cdp, d;
const log = (m) => console.log(m);
const hdr = (h) => Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
const detailHeaders = (detail) => {
  const h = detail?.request?.headers;
  if (Array.isArray(h)) return hdr(Object.fromEntries(h.map((x) => (Array.isArray(x) ? x : [x.name, x.value]))));
  return hdr(h);
};

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
      log(`  shot ${f}`);
    } catch (e) {
      log(`  (screenshot failed: ${e.message})`);
    }
  }
}
const expect = (cond, okMsg, badMsg) => (cond ? pass(okMsg) : fail(okMsg, badMsg));

try {
  target = await startTarget();
  env = await startAitm({ scope: [target.host], log: (l) => (/error|panic/i.test(l) ? console.error('[aitm] ' + l) : null) });
  bus = await connectBus(env.busUrl, env.token);
  const tools = (await bus.tools()).map((t) => t.name);
  log(`aitm up: proxy ${env.proxyPort}, ui ${env.uiUrl}, target ${target.base}`);
  log(`bus tools: ${tools.join(' ')}`);
  cdp = await launchChrome({ width: W, height: H });
  d = makeDriver(cdp, { log, shotsDir: SHOTS });

  let meId = null;
  let meRowSpec = null;

  // 1 ----------------------------------------------------------------------------------------
  await step('01 connect', async () => {
    await d.open(env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'status bar "bus open"' });
    await d.locate({ sel: GRID });
    const empty = await d.q('find', { text: 'No flows yet', within: GRID });
    const busText = (await d.q('texts', { sel: 'span[title="bus open"]' }))[0];
    pass('01 connect', `status bar "${busText}"; empty state: ${empty ? `"${empty.text}"` : 'not shown'}`);
  });

  // 2 ----------------------------------------------------------------------------------------
  await step('02 capture and inspect', async () => {
    const r = await viaProxy(env.proxyPort, 'GET', `${target.base}/api/me`);
    if (r.status !== 200) throw new Error(`proxy GET /api/me → ${r.status}`);
    meRowSpec = { role: 'row', text: '/api/me', within: GRID };
    const row = await d.click(meRowSpec);
    meId = row.id;
    await d.locate({ sel: `${REQ} [role=table]` });
    // Request pane may still be on a non-Headers tab from a previous session; select Headers.
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    const host = await d.locate({ role: 'cell', text: 'host', match: 'exact', within: REQ });
    expect(!!host, '02a request Headers tab shows host', 'no host cell');
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: RES });
    const sc = await d.locate({ role: 'cell', text: 'set-cookie', match: 'exact', within: RES });
    expect(!!sc, '02b response Headers shows set-cookie row');
    await d.click({ role: 'tab', text: 'Set-Cookie', match: 'startsWith', within: RES });
    const cookie = await d.locate({ role: 'cell', text: 'session', match: 'exact', within: RES });
    expect(!!cookie, '02c response Set-Cookie shows cookie "session"');
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: RES });
    const body = await waitFor(async () => {
      const t = await d.q('cm', RES);
      return t && t.includes('ops@target.test') ? t : null;
    }, { what: 'response body in CodeMirror' });
    expect(body.includes('ops@target.test'), '02d response Body (.cm-content) contains ops@target.test');
    await d.click({ role: 'tab', text: 'Raw', match: 'startsWith', within: REQ });
    await sleep(400);
    const raw = (await d.q('cm', REQ)) ?? '';
    const rawPane = (await d.q('find', { text: 'No body', within: REQ }))?.text ?? raw.slice(0, 60);
    if (raw.trim().startsWith('GET /api/me')) pass('02e request Raw starts with "GET /api/me"', raw.slice(0, 60));
    else gap('02e request Raw does not show the request line/headers', `Request › Raw shows only the raw BODY ("${rawPane}") — the "GET /api/me HTTP/1.1 + headers" document exists only while editing a paused request; a human cannot see the raw request of a completed flow`);
    const summary = await d.q('text', '[role=region][aria-label="Flow summary"]');
    expect(/\b200\b/.test(summary ?? ''), '02f summary strip shows 200', `strip: "${summary}"`);
  });

  // 3 ----------------------------------------------------------------------------------------
  await step('03 arm by keyboard (i)', async () => {
    const focus = await d.focusList();
    await d.key('i');
    const bar = await d.locate({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(bar && st.intercept_armed === true, '03 "i" arms intercept', `focus was ${focus}; bar "${bar?.text}"; proxy.status.intercept_armed=${st.intercept_armed}`);
  });

  // 4 ----------------------------------------------------------------------------------------
  let pausedId = null;
  await step('04 intercept, edit headers by clicking, Apply & Resume', async () => {
    const pending = viaProxy(env.proxyPort, 'POST', `${target.base}/api/echo`, { headers: { 'x-orig': 'a', 'content-type': 'application/json' }, body: '{"n":1}', timeoutMs: 60000 });
    pending.catch(() => {});
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    pausedId = row.id;
    const bar = await d.locate({ role: 'status', text: '1 paused' });
    pass('04a paused row + bar', `row "${row.text}"; bar "${bar.text.slice(0, 80)}"`);
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    await d.click({ role: 'button', text: 'Add header', match: 'exact', within: REQ }, { timeoutMs: 10000 });
    // The new row is the last name input (empty, placeholder "name"). Type like a human: one key at a time.
    const nameSpec = { role: 'input', text: 'name', match: 'exact', within: `${REQ} [role=table]`, nth: -1 };
    await d.click(nameSpec);
    const focusBefore = await d.q('active');
    let lostFocusAt = null;
    for (const ch of 'x-cua') {
      await d.type(ch);
      const now = await d.q('active');
      if (now !== focusBefore) {
        lostFocusAt ??= { ch, now };
        await d.click(nameSpec); // a human has to click back into the field after every keystroke
        await d.key('End');
      }
    }
    const nameNow = await d.q('find', nameSpec);
    if (lostFocusAt) fail('04b-focus typing a header name keeps focus', `focus left the input after the first keystroke "${lostFocusAt.ch}" (went to ${lostFocusAt.now}); every keystroke re-renders the header rows (setHeaders → new objects → <For> rebuilds the inputs), so a human cannot type a header name without clicking back in after each character. Name input now reads "${nameNow?.value}"`);
    else pass('04b-focus typing a header name keeps focus');
    // Tab is unreliable once focus was lost; click the value cell as a human would.
    const valueSpec = { role: 'input', text: 'value', match: 'exact', within: `${REQ} [role=table]`, nth: -1 };
    await d.click(valueSpec);
    for (const ch of 'yes') {
      await d.type(ch);
      if ((await d.q('active')) === 'body') {
        await d.click(valueSpec);
        await d.key('End');
      }
    }
    const added = await waitFor(() => d.q('headerValueInput', 'x-cua'), { what: 'x-cua header row' });
    expect(added.value === 'yes', '04b Add header → x-cua: yes present in the draft', `name "${nameNow?.value}" value "${added.value}"`);
    const orig = await d.locate({ sel: 'input', text: 'a', match: 'exact', within: `${REQ} [role=table]` });
    const origInput = await d.q('headerValueInput', 'x-orig');
    if (!origInput) throw new Error('no editable x-orig row');
    await d.mouse(origInput.x, origInput.y);
    await d.selectAll();
    await d.type('b');
    const changed = await waitFor(async () => {
      const v = await d.q('headerValueInput', 'x-orig');
      return v && v.value === 'b' ? v : null;
    }, { what: 'x-orig value to read b', timeoutMs: 3000 }).catch(() => d.q('headerValueInput', 'x-orig'));
    expect(changed?.value === 'b', '04c existing header x-orig: a → b (⌘A + type)', `value input reads "${changed?.value}" (was "${orig?.value}")`);
    const hint = await d.q('text', EDITBAR);
    note('04 edit bar', `"${hint}"`);
    await d.click({ role: 'button', text: 'Apply & Resume', match: 'startsWith', within: EDITBAR });
    const res = await pending;
    let echo = null;
    try {
      echo = JSON.parse(res.body);
    } catch {}
    const eh = hdr(echo?.headers);
    expect(res.status === 200 && eh['x-cua'] === 'yes' && eh['x-orig'] === 'b', '04d upstream saw the operator edit (echo x-cua: yes, x-orig: b)', `status ${res.status}; echo headers x-cua=${eh['x-cua']} x-orig=${eh['x-orig']}`);
    const info = await waitFor(async () => {
      const i = await d.q('rowInfo', pausedId);
      return i && /\b200\b/.test(i.text) && i.edited ? i : null;
    }, { what: 'row to show 200 + Edited marker', timeoutMs: 6000 }).catch(() => d.q('rowInfo', pausedId));
    expect(/\b200\b/.test(info?.text ?? '') && info?.edited, '04e row shows 200 and the Edited marker', `row "${info?.text}" edited=${info?.edited}`);
    const det = await bus.call('flow.detail', { id: pausedId, body: 'none' });
    const dh = detailHeaders(det);
    expect(det.edited === true && dh['x-cua'] === 'yes' && dh['x-orig'] === 'b', '04f bus flow.detail edited:true with the edited headers', `edited=${det.edited} x-cua=${dh['x-cua']} x-orig=${dh['x-orig']}`);
  });

  await step('04g intercept, edit body in the Body tab, Apply & Resume', async () => {
    const pending = viaProxy(env.proxyPort, 'POST', `${target.base}/api/echo`, { headers: { 'content-type': 'application/json' }, body: '{"n":1}', timeoutMs: 60000 });
    pending.catch(() => {});
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: REQ });
    await d.locate({ sel: EDITBAR }, { timeoutMs: 10000 });
    const before = await waitFor(() => d.q('cm', REQ), { what: 'editable request body' });
    const cm = await d.locate({ sel: `${REQ} .cm-content` });
    await d.mouse(cm.x, cm.y);
    await d.selectAll();
    await d.type('{"n":2}');
    const after = await waitFor(async () => {
      const t = await d.q('cm', REQ);
      return t && t.trim() === '{"n":2}' ? t : null;
    }, { what: 'body editor to read {"n":2}', timeoutMs: 3000 }).catch(() => d.q('cm', REQ));
    note('04g body editor', `before "${(before ?? '').trim()}" → after "${(after ?? '').trim()}"; edit bar "${await d.q('text', EDITBAR)}"`);
    await d.click({ role: 'button', text: 'Apply & Resume', match: 'startsWith', within: EDITBAR });
    const res = await pending;
    let echo = null;
    try {
      echo = JSON.parse(res.body);
    } catch {}
    expect(res.status === 200 && echo?.body === '{"n":2}', '04g upstream received the edited body {"n":2}', `status ${res.status}; echo body=${JSON.stringify(echo?.body)} content-length=${hdr(echo?.headers)['content-length']}`);
    const det = await bus.call('flow.detail', { id: row.id, body: 'none' });
    expect(det.edited === true, '04h bus flow.detail edited:true after body edit', `edited=${det.edited}`);
  });

  // 5 ----------------------------------------------------------------------------------------
  await step('05 disarm by clicking', async () => {
    await d.click({ role: 'button', text: 'Disarm', match: 'startsWith', within: BAR });
    await d.gone({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(st.intercept_armed === false, '05 Disarm → bar gone, intercept_armed false', `intercept_armed=${st.intercept_armed}`);
  });

  // 6 ----------------------------------------------------------------------------------------
  await step('06 kill a paused request', async () => {
    await d.focusList();
    await d.key('i');
    await d.locate({ role: 'status', text: 'Intercept armed' });
    const pending = viaProxy(env.proxyPort, 'GET', `${target.base}/api/me`, { timeoutMs: 20000 });
    let clientOutcome = null;
    pending.then((r) => (clientOutcome = `response ${r.status}`), (e) => (clientOutcome = `error: ${e.message}`));
    const row = await d.click({ role: 'row', text: 'Paused', within: GRID }, { timeoutMs: 10000 });
    await d.click({ role: 'button', text: 'Kill', match: 'startsWith', within: BAR });
    await d.click({ role: 'menuitem', text: 'Reset connection', match: 'startsWith' });
    const info = await waitFor(async () => {
      const i = await d.q('rowInfo', row.id);
      return i && /killed/i.test(i.text) ? i : null;
    }, { what: 'row to show killed', timeoutMs: 6000 }).catch(() => d.q('rowInfo', row.id));
    await waitFor(() => clientOutcome, { what: 'client outcome', timeoutMs: 15000 }).catch(() => (clientOutcome = 'still pending after 15 s'));
    const det = await bus.call('flow.detail', { id: row.id, body: 'none' });
    const killedUpstream = /^error/.test(clientOutcome ?? '') && det.intercept === 'killed';
    expect(
      /killed/i.test(info?.text ?? '') && killedUpstream,
      '06 Kill → Reset connection: row killed, client connection dropped, bus intercept=killed',
      `row "${info?.text}"; client ${clientOutcome}; bus flow.detail.intercept=${det.intercept}${
        !killedUpstream && det.intercept === 'resumed' ? ' — CORE BUG: the UI shows "killed" only from its optimistic patch; the request was forwarded and answered. chain.rs dispatch() sets InterceptState::Resumed unconditionally when the parked handle fires, overwriting the Killed state flow.kill wrote (crates/aitm-core/src/chain.rs ~L80-86), so proto-http never sees Killed' : ''
      }`,
    );
    await d.focusList();
    await d.key('i');
    await d.gone({ role: 'status', text: 'Intercept armed' });
    const st = await bus.call('proxy.status');
    expect(st.intercept_armed === false, '06b "i" again disarms', `intercept_armed=${st.intercept_armed}`);
  });

  // 7 ----------------------------------------------------------------------------------------
  await step('07 context menu: Replay, Mark, Comment', async () => {
    const hitsBefore = target.hits.filter((h) => h.url === '/api/me').length;
    const meRow = { sel: `[role=row][data-id="${meId}"]` };
    await d.rightClick(meRow);
    await d.locate({ role: 'menu', text: '', match: 'includes' });
    await d.click({ role: 'menuitem', text: 'Replay', match: 'startsWith' });
    const replayRow = await waitFor(() => d.q('find', { role: 'row', text: '↻', within: GRID }), { what: 'replay row with ↻', timeoutMs: 8000 });
    await waitFor(() => target.hits.filter((h) => h.url === '/api/me').length > hitsBefore, { what: 'target hit from replay' });
    pass('07a Replay → new ↻ row, target hits grew', `row "${replayRow.text}"; /api/me hits ${hitsBefore} → ${target.hits.filter((h) => h.url === '/api/me').length}`);

    await d.rightClick(meRow);
    await d.click({ role: 'menuitem', text: 'Mark', match: 'startsWith' });
    await d.click({ role: 'menuitem', text: 'Red', match: 'exact' });
    const marked = await waitFor(async () => {
      const i = await d.q('rowInfo', meId);
      return i?.mark ? i : null;
    }, { what: 'mark swatch on the row', timeoutMs: 5000 }).catch(() => d.q('rowInfo', meId));
    const menuStillOpen = (await d.q('count', { role: 'menu' })) > 0;
    if (menuStillOpen) {
      note('07b UX', 'picking a colour from the Mark ▸ submenu leaves the parent context menu open (closed with Esc)');
      await d.key('Escape');
      await d.gone({ role: 'menu' });
    }
    let det = await bus.call('flow.detail', { id: meId, body: 'none' });
    expect(marked?.mark === 'Marked red' && Array.isArray(det.meta?.marks) && det.meta.marks.length > 0, '07b Mark ▸ Red → swatch on the row, bus meta.marks non-empty', `row mark="${marked?.mark}" bus marks=${JSON.stringify(det.meta?.marks)}`);

    await d.rightClick(meRow);
    await d.click({ role: 'menuitem', text: 'Comment', match: 'startsWith' });
    await d.click({ role: 'input', text: 'Comment', match: 'exact', within: '[role=dialog][aria-label="Comment"]' });
    await d.type('cua note');
    await d.key('Enter');
    await d.gone({ sel: '[role=dialog][aria-label="Comment"]' });
    det = await waitFor(async () => {
      const x = await bus.call('flow.detail', { id: meId, body: 'none' });
      return x.meta?.comment === 'cua note' ? x : null;
    }, { what: 'bus comment', timeoutMs: 4000 }).catch(() => bus.call('flow.detail', { id: meId, body: 'none' }));
    expect(det.meta?.comment === 'cua note', '07c Comment… → type → Enter → bus meta.comment', `comment=${JSON.stringify(det.meta?.comment)}`);
  });

  // 8 ----------------------------------------------------------------------------------------
  await step('08 compose (n), send with ⌘⏎, out-of-scope host blocks Send', async () => {
    await d.focusList();
    await d.key('n');
    const dlg = '[role=dialog][aria-modal="true"]';
    await d.locate({ sel: dlg });
    await d.click({ role: 'input', text: 'URL', match: 'exact', within: dlg });
    await d.type(`${target.base}/api/echo?from=cua`);
    const foot = await waitFor(async () => {
      const t = await d.q('text', `${dlg} footer`);
      return t && /in scope/.test(t) ? t : null;
    }, { what: 'compose footer "in scope"', timeoutMs: 3000 }).catch(() => d.q('text', `${dlg} footer`));
    note('08 compose footer', `"${foot}"`);
    await d.key('Enter', { meta: true });
    await d.gone({ sel: dlg });
    const row = await d.locate({ role: 'row', text: 'from=cua', within: GRID }, { timeoutMs: 8000 });
    const hit = target.hits.find((h) => h.url === '/api/echo?from=cua');
    expect(!!row && !!hit, '08a compose GET …/api/echo?from=cua via ⌘⏎ → row + target hit', `row "${row?.text}"; hit ${hit ? `${hit.method} ${hit.url}` : 'none'}`);

    await d.focusList();
    await d.key('n');
    await d.locate({ sel: dlg });
    await d.click({ role: 'input', text: 'URL', match: 'exact', within: dlg });
    await d.type('http://not-in-scope.test/x');
    const foot2 = await waitFor(async () => {
      const t = await d.q('text', `${dlg} footer`);
      return t && /Out of scope/.test(t) ? t : null;
    }, { what: 'compose footer "Out of scope"', timeoutMs: 3000 }).catch(() => d.q('text', `${dlg} footer`));
    const send = await d.q('find', { role: 'button', text: 'Send', match: 'startsWith', within: `${dlg} footer` });
    const f = await d.shot('08b compose out of scope');
    log(`  shot ${f}`);
    expect(/Out of scope/.test(foot2 ?? '') && send?.disabled === true, '08b out-of-scope URL → footer says out of scope, Send disabled', `footer "${foot2}"; Send disabled=${send?.disabled}`);
    await d.key('Escape');
    await d.gone({ sel: dlg });
  });

  // 9 ----------------------------------------------------------------------------------------
  let pocYaml = null;
  await step('09 Build PoC from flow… → Findings', async () => {
    await viaProxy(env.proxyPort, 'GET', `${target.base}/search?q=probe`);
    const row = await d.locate({ role: 'row', text: '/search', within: GRID });
    await d.rightClick({ sel: `[role=row][data-id="${row.id}"]` });
    await d.click({ role: 'menuitem', text: 'Build PoC', match: 'startsWith' });
    const pop = '[role=dialog][aria-label="Build PoC from flow"]';
    await d.locate({ sel: pop });
    await d.click({ role: 'input', text: 'PoC name', match: 'exact', within: pop });
    await d.selectAll();
    await d.type('cua-reflected');
    await d.click({ role: 'input', text: 'Parameter', match: 'exact', within: pop });
    await d.type('q');
    await d.click({ role: 'button', text: 'Build', match: 'startsWith', within: pop });
    await d.gone({ sel: pop });
    await sleep(1200);
    const toast = (await d.q('texts', { role: 'status' })).concat(await d.q('texts', { role: 'alert' })).filter(Boolean);
    const listed = await d.q('find', { role: 'option', text: 'cua-reflected' });
    const pocList = await bus.call('poc.list').catch((e) => ({ error: e.message }));
    const lowerText = await d.q('text', '#aitm-lower');
    note('09 after Build', `toast ${JSON.stringify(toast)}; lower panel "${(lowerText ?? '').slice(0, 120)}"; bus poc.list=${JSON.stringify(pocList).slice(0, 200)}`);
    if (listed) {
      pass('09a finding listed after Build', listed.text);
    } else {
      gap('09a Build PoC from flow…', `poc.build returns YAML text only (never writes poc.dir); bus poc.list=${JSON.stringify(pocList)}. The UI switches to Findings, which shows "${(lowerText ?? '').slice(0, 80)}". Because poc.list exists the store treats the PoC as "listed" and does NOT copy the YAML to the clipboard either — the operator's PoC is discarded with no way to see or save it from the UI.`);
    }
    // Seed: a human who had the YAML (poc.build over the bus is the only way to get it) saves it into poc.dir and reloads.
    pocYaml = await bus.call('poc.build', { flow_id: row.id, name: 'cua-reflected', param: 'q' });
    if (typeof pocYaml !== 'string') pocYaml = pocYaml?.yaml ?? JSON.stringify(pocYaml);
    writeFileSync(join(env.pocDir, 'cua-reflected.yaml'), pocYaml);
    note('09 seeded', `wrote ${join(env.pocDir, 'cua-reflected.yaml')} (${pocYaml.length} bytes) by hand so the Findings path below can be exercised; reloading the UI`);
    await d.open(env.uiUrl);
    await waitFor(() => d.q('exists', 'span[title="bus open"]'), { timeoutMs: 15000, what: 'bus open after reload' });
    // Wait until the store has fetched poc.list (the sidebar count leaves 0) before clicking.
    await waitFor(async () => {
      const b = await d.q('find', { role: 'button', text: 'Findings', match: 'startsWith', within: SIDEBAR });
      return b && !/Findings\s*0$/.test(b.text) ? b : null;
    }, { timeoutMs: 10000, what: 'sidebar Findings count > 0' });
    await sleep(300);
    for (let attempt = 0; attempt < 2; attempt++) {
      await d.click({ role: 'button', text: 'Findings', match: 'startsWith', within: SIDEBAR });
      const ok = await waitFor(() => d.q('exists', '[role=listbox][aria-label="Findings"]'), { timeoutMs: 3000, what: 'Findings list' }).catch(() => false);
      if (ok) break;
      note('09 sidebar', 'first click on Findings did not switch the panel; clicked again');
    }
    const opt = await d.locate({ role: 'option', text: 'cua-reflected' }, { timeoutMs: 8000 });
    await d.mouse(opt.x, opt.y);
    const detail = await waitFor(() => d.q('text', '#aitm-lower'), { what: 'finding detail' });
    // The source arrives via poc.get a few ms after the click: wait for it like a human would.
    const yamlShown = await waitFor(() => d.q('find', { sel: '#aitm-lower pre[aria-label="PoC YAML"]' }), { timeoutMs: 5000, what: 'PoC YAML' }).catch(() => null);
    if (yamlShown) pass('09b (seeded file) finding listed and YAML visible', yamlShown.text.slice(0, 80));
    else gap('09b (seeded file) finding listed but YAML not visible', `poc.list summaries carry only {id,title,severity,poc_path}; the detail shows "${/No YAML for this run\./.test(detail) ? 'No YAML for this run.' : detail.slice(0, 100)}" and the UI never calls poc.get`);
    await d.click({ role: 'button', text: 'Run again', match: 'startsWith', within: '#aitm-lower' });
    const runPop = '[role=dialog][aria-label="Run again"]';
    await d.locate({ sel: runPop });
    await d.click({ role: 'input', text: 'https://host', match: 'exact', within: runPop });
    await d.type(target.base);
    await d.click({ role: 'button', text: 'Run', match: 'startsWith', within: runPop }); // the popover has only Cancel and Run ⏎
    await d.gone({ sel: runPop });
    await waitFor(async () => (await d.q('count', { text: 'Running…', within: '#aitm-lower' })) === 0, { what: 'run to finish', timeoutMs: 20000 });
    await sleep(500);
    const after = await d.q('text', '#aitm-lower');
    const alerts = await d.q('texts', { role: 'alert' });
    const statuses = await d.q('texts', { role: 'status' });
    const list2 = await bus.call('poc.list').catch((e) => ({ error: e.message }));
    const hitSearch = target.hits.filter((h) => h.url.startsWith('/search')).length;
    const verdict = /Passed|Failed/.test(after ?? '');
    if (verdict) pass('09c Run again → Run → verdict shown', `${(after.match(/Passed|Failed/) ?? [])[0]}; target /search hits=${hitSearch}; poc.list=${JSON.stringify(list2).slice(0, 160)}`);
    else gap('09c Run again → Run shows no verdict', `after run: no "Passed"/"Failed" in the detail; toasts ${JSON.stringify([...alerts, ...statuses])}; target /search hits=${hitSearch}; the panel re-reads poc.list (which lists files, not runs) so the run result is dropped unless its id matches a listed PoC; poc.list=${JSON.stringify(list2).slice(0, 160)}`);
  });

  // 10 ---------------------------------------------------------------------------------------
  await step('10 scope panel: add and remove a host', async () => {
    await d.click({ role: 'button', text: 'Scope', match: 'startsWith', within: SIDEBAR });
    const panel = 'section[aria-label="Scope"]';
    await d.locate({ sel: panel });
    await d.click({ role: 'input', text: 'Add host to scope', match: 'exact', within: panel });
    await d.type('example.test');
    await d.key('Enter');
    const cell = await d.locate({ role: 'cell', text: 'example.test', match: 'exact', within: '[role=table][aria-label="Hosts in scope"]' });
    let list = await bus.call('scope.list');
    const has = (l) => JSON.stringify(l).includes('example.test');
    expect(!!cell && has(list), '10a Add host example.test → row + scope.list', `scope.list=${JSON.stringify(list)}`);
    await d.click({ role: 'button', text: 'Remove example.test from scope', match: 'exact', within: panel });
    await d.gone({ role: 'cell', text: 'example.test', match: 'exact', within: '[role=table][aria-label="Hosts in scope"]' });
    list = await bus.call('scope.list');
    expect(!has(list), '10b remove × → row gone + scope.list', `scope.list=${JSON.stringify(list)}`);
  });

  // 11 ---------------------------------------------------------------------------------------
  await step('11a agent panel', async () => {
    await d.click({ role: 'button', text: 'Agent', match: 'startsWith', within: SIDEBAR });
    const group = await d.locate({ sel: '[role=radiogroup][aria-label="Agent policy"]' });
    const radios = await d.ev(`Array.from(document.querySelectorAll('[role=radiogroup][aria-label="Agent policy"] [role=radio]')).map(b => ({ label: b.innerText.trim(), disabled: b.disabled, checked: b.getAttribute('aria-checked') }))`);
    const title = await d.ev(`document.querySelector('[role=radiogroup][aria-label="Agent policy"]')?.getAttribute('title')`);
    const allDisabled = radios.length > 0 && radios.every((r) => r.disabled);
    expect(group.disabled && allDisabled, '11a Agent policy control present and disabled (no agent.set)', `radios=${JSON.stringify(radios)}; tooltip="${title}"; bus has agent.set=${tools.includes('agent.set')}`);
  });
  await step('11b browser panel', async () => {
    await d.click({ role: 'button', text: 'Browser', match: 'startsWith', within: SIDEBAR });
    await sleep(800);
    const empty = await d.q('find', { text: 'No embedded browser', within: '#aitm-lower' });
    const alerts = await d.q('texts', { role: 'alert' });
    const lower = await d.q('text', '#aitm-lower');
    gap('11b Browser panel (F14 / no engine)', `${empty ? `honest empty state: "${empty.text}"` : `no empty-state text; alerts ${JSON.stringify(alerts)}`}; bus browser.navigate present=${tools.includes('browser.navigate')}; panel text "${(lower ?? '').slice(0, 160)}"`);
  });

  // 12 ---------------------------------------------------------------------------------------
  await step('12 hero', async () => {
    await d.click({ sel: `[role=row][data-id="${meId}"]` });
    // Dismiss any lingering toast (the Browser panel's screenshot error) the way a human would: click it.
    const toast = await d.q('find', { role: 'alert' });
    if (toast) {
      await d.mouse(toast.x, toast.y);
      await d.gone({ role: 'alert' }, { timeoutMs: 3000 }).catch(() => {});
    }
    await d.click({ role: 'tab', text: 'Headers', match: 'startsWith', within: REQ });
    await d.click({ role: 'tab', text: 'Body', match: 'startsWith', within: RES });
    await waitFor(async () => (await d.q('cm', RES))?.includes('ops@target.test'), { what: 'hero response body' });
    await sleep(300);
    const r = await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 2, mobile: false });
    await sleep(300);
    const png = await cdp.s('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(SHOTS, '99-hero.png'), Buffer.from(png.data, 'base64'));
    await cdp.s('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
    pass('12 hero', `${join(SHOTS, '99-hero.png')} (${W}x${H}@2x)`);
  });

  if (cdp.consoleErrors.length) note('console errors', JSON.stringify(cdp.consoleErrors.slice(0, 10)));
} catch (e) {
  fail('harness', e.stack ?? e.message);
} finally {
  const summary = {
    pass: results.filter((r) => r.status === 'PASS').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    gap: results.filter((r) => r.status === 'GAP').length,
    shots: SHOTS,
    results,
  };
  console.log('\n' + JSON.stringify(summary, null, 2));
  console.log(`\n${summary.pass} PASS · ${summary.fail} FAIL · ${summary.gap} GAP · screenshots in ${SHOTS}`);
  if (KEEP && env) {
    console.log(`--keep: aitm and Chrome left running. UI: ${env.uiUrl}  proxy: 127.0.0.1:${env.proxyPort}  target: ${target?.base}  poc.dir: ${env.pocDir}`);
    await new Promise(() => {});
  }
  bus?.close();
  cdp?.close();
  await env?.stop();
  await target?.close();
  process.exit(summary.fail ? 1 : 0);
}
