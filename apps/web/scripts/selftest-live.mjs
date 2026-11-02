#!/usr/bin/env node
// Live check of the web operator UI stack: drives the real operator workflow end to end over
// the /bus bridge of a spawned `aitm web`, with real traffic through the real proxy against a
// local target. It connects as the OPERATOR — the bridge token from the `Operator` line of
// `aitm web`'s start-up block, the role the real UI gets when opened from that URL — so the
// sensitive steps (intercept, kill, scope.remove, poc.run, proxy.pause, flow.clear) run exactly
// as they do for the operator, not as an agent governed by the `auto` policy. Prints
// PASS/FAIL/SKIP per step, a table, and a JSON summary.
//
//   node scripts/selftest-live.mjs            # run everything, exit 1 if anything FAILs
//   node scripts/selftest-live.mjs --keep     # leave aitm running and print the UI URL
//   node scripts/selftest-live.mjs --verbose  # echo aitm's stderr
//
// Needs target/debug/aitm (cargo build -p aitm; AITM_BIN overrides) and Node ≥ 22. No dependencies.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { startTarget, viaProxy, startAitm, connectBus, waitFor, sleep } from './live-env.mjs';

const KEEP = process.argv.includes('--keep');
const VERBOSE = process.argv.includes('--verbose');

// ---------------------------------------------------------------- expected surface
// The exact tool set is pinned elsewhere (crates/aitm/tests/frontends.rs, the TUI's
// tui_live_bus); this script only requires that tools/list is non-empty and names every tool it
// calls, and prints the whole list so a run documents the core it ran against. `calledTools`
// records what the run actually invoked and the closing step checks it against this list, so
// the list cannot drift from the steps below.
const USED_TOOLS = [
  'agent.status',
  'browser.navigate',
  'findings.list',
  'flow.clear', 'flow.comment', 'flow.detail', 'flow.get', 'flow.intercept', 'flow.kill', 'flow.list',
  'flow.mark', 'flow.mutate', 'flow.replay', 'flow.resume',
  'poc.artifact', 'poc.build', 'poc.get', 'poc.list', 'poc.run',
  'proxy.pause', 'proxy.resume', 'proxy.status',
  'request.send',
  'scope.add', 'scope.list', 'scope.remove',
];

// ---------------------------------------------------------------- tiny harness
class Skip extends Error {}
/** Thrown when the run cannot continue (no operator bus): the report still prints, exit is 1. */
class Abort extends Error {}
const results = [];
const gaps = [];

/** Runs one named step; FAIL on throw, SKIP on `skip(...)`, PASS otherwise (detail = return value). */
async function step(name, fn) {
  const t0 = Date.now();
  let status, detail;
  try {
    const r = await fn();
    status = 'PASS';
    detail = r == null ? '' : String(r);
  } catch (e) {
    if (e instanceof Skip) {
      status = 'SKIP';
      detail = e.message;
    } else {
      status = 'FAIL';
      detail = (e && e.stack ? e.stack.split('\n').slice(0, 2).join(' ⏎ ') : String(e)).slice(0, 600);
    }
  }
  results.push({ name, status, detail, ms: Date.now() - t0 });
  console.log(`${status} ${name}${detail ? ` — ${detail}` : ''}`);
}
const skip = (msg) => {
  throw new Skip(msg);
};
/** A known gap between what the UI promises and what the core offers today: SKIP, tagged with its F-number. */
const gap = (f, msg) => {
  gaps.push(`${f}: ${msg}`);
  skip(`${f} ${msg}`);
};

const fail = (msg) => {
  throw new Error(msg);
};
const ok = (cond, msg) => cond || fail(msg);
const eq = (actual, expected, what) =>
  ok(actual === expected, `${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
const has = (obj, key, what = 'object') => ok(obj != null && Object.hasOwn(obj, key), `${what} lacks "${key}" (keys: ${obj ? Object.keys(obj).join(',') : obj})`);
const header = (pairs, name) => (pairs ?? []).find(([n]) => n.toLowerCase() === name.toLowerCase())?.[1];
const b64 = (s) => Buffer.from(s, 'base64').toString('utf8');
/** Returns the message of a tool error without throwing, or null if the call succeeded. */
const errorOf = async (p) => {
  try {
    await p;
    return null;
  } catch (e) {
    return String(e.message ?? e);
  }
};

// ---------------------------------------------------------------- environment
const target = await startTarget();
const aitm = await startAitm({ scope: [target.host], log: VERBOSE ? (l) => console.error('[aitm] ' + l) : () => {} });
console.log(`target ${target.base} · proxy 127.0.0.1:${aitm.proxyPort} · ui ${aitm.operatorUiUrl ?? aitm.uiUrl}`);

/** The operator bus; connected by the first step so a refused token is a FAIL line, not a hang. */
let bus = null;
const calledTools = new Set();
/** Calls a tool as the operator and records its name for the closing coverage step. */
const call = (name, args = {}) => {
  calledTools.add(name);
  return bus.call(name, args);
};

const newestFirst = async () => [...(await call('flow.list'))].reverse();
const detail = (id, body = 'inline') => call('flow.detail', { id, body });
/** Waits for the newest flow whose detail satisfies `pred`. */
const waitFlow = (pred, what, timeoutMs = 10000) =>
  waitFor(
    async () => {
      for (const id of (await newestFirst()).slice(0, 10)) {
        const d = await detail(id, 'none');
        if (pred(d)) return d;
      }
      return null;
    },
    { timeoutMs, what },
  );
/** Arms/disarms interception (`flow.intercept` → `{enabled, rules}`) and confirms proxy.status agrees. */
async function arm(enabled) {
  const r = await call('flow.intercept', { enabled });
  eq(r.enabled, enabled, 'flow.intercept.enabled');
  ok(Array.isArray(r.rules), `flow.intercept.rules should be an array, got ${JSON.stringify(r.rules)}`);
  const st = await call('proxy.status');
  eq(st.intercept_armed, enabled, 'proxy.status.intercept_armed');
}

let tools = [];
let meFlowId, searchFlowId;

try {
  // ------------------------------------------------------------ 1. bootstrap
  await step('bootstrap: /bus takes the operator bridge token from the start-up block and resolves role operator', async () => {
    ok(aitm.operatorUiUrl, 'aitm web printed no `Operator` line although mcp.operator_token is configured; stdout had no operator URL to connect with');
    ok(aitm.operatorToken, `the operator URL ${aitm.operatorUiUrl} carries no t= token`);
    bus = await connectBus(aitm.busUrl, aitm.operatorToken);
    eq(bus.role, 'operator', 'initialize.role');
    return `role=${bus.role}`;
  });
  if (!bus) throw new Abort('no operator bus; every later step needs one');

  await step('bootstrap: tools/list is non-empty and names every tool this script calls', async () => {
    tools = await bus.tools();
    const names = tools.map((t) => t.name).sort();
    ok(names.length > 0, 'tools/list is empty');
    const missing = USED_TOOLS.filter((n) => !names.includes(n));
    ok(missing.length === 0, `tools/list lacks tools this script calls: [${missing}] (${names.length} tools: ${names.join(' ')})`);
    return `${names.length} tools: ${names.join(' ')}`;
  });
  await step('bootstrap: proxy.status is sane', async () => {
    const st = await call('proxy.status');
    for (const k of ['listening', 'address', 'capturing', 'intercept_armed', 'paused', 'flows']) has(st, k, 'proxy.status');
    eq(st.listening, true, 'listening');
    eq(st.capturing, true, 'capturing');
    eq(st.intercept_armed, false, 'intercept_armed');
    eq(typeof st.paused, 'number', 'typeof paused');
    eq(st.flows, 0, 'flows at start');
    return `address=${st.address} flows=${st.flows} paused=${st.paused}`;
  });

  // ------------------------------------------------------------ 2. capture
  await step('capture: GET /api/me through the proxy lands in flow.list with full detail', async () => {
    const res = await viaProxy(aitm.proxyPort, 'GET', `${target.base}/api/me`, { headers: { 'x-probe': 'capture' } });
    eq(res.status, 200, 'client status');
    const ids = await waitFor(async () => {
      const l = await call('flow.list');
      return l.length > 0 ? l : null;
    }, { what: 'first flow in flow.list' });
    meFlowId = ids[ids.length - 1];
    const d = await detail(meFlowId);
    eq(d.id, meFlowId, 'detail.id');
    eq(d.intercept, 'observed', 'intercept state');
    eq(d.request.method, 'GET', 'request.method');
    eq(d.request.path, '/api/me', 'request.path');
    ok(header(d.request.headers, 'host'), 'request headers lack host');
    eq(header(d.request.headers, 'x-probe'), 'capture', 'x-probe request header');
    ok(d.response, 'no response in detail');
    eq(d.response.status, 200, 'response.status');
    ok(header(d.response.headers, 'set-cookie'), 'response headers lack set-cookie');
    const body = JSON.parse(b64(d.response.body));
    eq(body.email, 'ops@target.test', 'decoded body.email');
    ok(!Number.isNaN(Date.parse(d.meta.created)), `meta.created does not parse: ${d.meta.created}`);
    ok(d.client_conn?.peer, 'client_conn.peer missing');
    const summary = await call('flow.get', { id: meFlowId });
    eq(summary.id, meFlowId, 'flow.get id');
    return `id=${meFlowId} peer=${d.client_conn.peer} body_size=${d.response.body_size}`;
  });

  // ------------------------------------------------------------ 3. intercept → review → edit → resume
  await step('intercept: arm, park a POST, review, mutate, resume — upstream sees the edit', async () => {
    await arm(true);
    try {
      const client = viaProxy(aitm.proxyPort, 'POST', `${target.base}/api/echo`, {
        headers: { 'x-orig': 'a', 'content-type': 'application/json' },
        body: JSON.stringify({ original: true }),
      });
      client.catch(() => {});
      const parked = await waitFlow((d) => d.intercept === 'intercepted' && d.request.path.startsWith('/api/echo'), 'a parked /api/echo flow');
      // review
      eq(parked.request.method, 'POST', 'parked method');
      eq(parked.request.path, '/api/echo', 'parked path');
      eq(header(parked.request.headers, 'x-orig'), 'a', 'parked x-orig');
      const st = await call('proxy.status');
      ok(st.paused >= 1, `proxy.status.paused should count the parked flow, got ${st.paused}`);
      // edit
      await call('flow.mutate', {
        id: parked.id,
        edits: { path: '/api/echo?edited=1', headers: { 'x-edited': 'yes', 'x-orig': 'b' }, body: '{"edited":true}' },
      });
      await call('flow.resume', { id: parked.id });
      const res = await client;
      eq(res.status, 200, 'client status after resume');
      const echo = JSON.parse(res.body);
      ok(echo.path.includes('edited=1'), `upstream path lacks edit: ${echo.path}`);
      eq(echo.headers['x-edited'], 'yes', 'upstream x-edited');
      eq(echo.headers['x-orig'], 'b', 'upstream x-orig');
      eq(echo.body, '{"edited":true}', 'upstream body');
      const after = await detail(parked.id);
      eq(after.edited, true, 'detail.edited');
      eq(after.intercept, 'resumed', 'detail.intercept after resume');
      ok(after.request.path.includes('edited=1'), `detail path lacks edit: ${after.request.path}`);
      eq(header(after.request.headers, 'x-edited'), 'yes', 'detail x-edited');
      eq(b64(after.request.body), '{"edited":true}', 'detail request body');
      return `flow ${parked.id} edited and resumed; echo path=${echo.path}`;
    } finally {
      await arm(false);
    }
  });

  // ------------------------------------------------------------ 4. intercept → kill
  await step('intercept: arm, park a request, kill it — client fails, detail says killed', async () => {
    await arm(true);
    try {
      const client = viaProxy(aitm.proxyPort, 'GET', `${target.base}/api/me?kill=1`, { timeoutMs: 8000 }).then(
        (r) => ({ resolved: r }),
        (e) => ({ rejected: String(e.message ?? e) }),
      );
      const parked = await waitFlow((d) => d.intercept === 'intercepted' && d.request.path.includes('kill=1'), 'a parked flow to kill');
      const hitsBefore = target.hits.length;
      const label = await call('flow.kill', { id: parked.id });
      const outcome = await client;
      await sleep(200);
      const after = await detail(parked.id, 'none');
      const reachedTarget = target.hits.slice(hitsBefore).some((h) => h.url.includes('kill=1'));
      const clientSaw = outcome.resolved ? `HTTP ${outcome.resolved.status}` : `rejected (${outcome.rejected})`;
      const evidence = `flow.kill → ${JSON.stringify(label)}; client saw ${clientSaw}; detail.intercept=${after.intercept}; request ${reachedTarget ? 'REACHED' : 'did not reach'} the target`;
      ok(after.intercept === 'killed' && !reachedTarget && !(outcome.resolved && outcome.resolved.status < 400), `flow.kill did not kill: ${evidence}`);
      return evidence;
    } finally {
      await arm(false);
    }
  });

  // ------------------------------------------------------------ 5. mark / comment / replay
  await step('mark: flow.mark replaces the set and detail.meta.marks agrees', async () => {
    const marks = await call('flow.mark', { id: meFlowId, marks: ['red'] });
    eq(JSON.stringify(marks), '["red"]', 'flow.mark result');
    const d = await detail(meFlowId, 'none');
    eq(JSON.stringify(d.meta.marks), '["red"]', 'detail.meta.marks');
    const again = await call('flow.mark', { id: meFlowId, marks: ['red', 'review'] });
    eq(JSON.stringify(again), '["red","review"]', 'flow.mark replace');
    return 'marks=[red,review]';
  });
  await step('comment: flow.comment sets text and detail.meta.comment agrees', async () => {
    const t = await call('flow.comment', { id: meFlowId, text: 'looks like an auth endpoint' });
    eq(t, 'looks like an auth endpoint', 'flow.comment result');
    const d = await detail(meFlowId, 'none');
    eq(d.meta.comment, 'looks like an auth endpoint', 'detail.meta.comment');
    return 'comment set';
  });
  await step('replay: flow.replay re-sends /api/me, new flow is a replay, target saw it', async () => {
    const hitsBefore = target.hits.length;
    const newId = await call('flow.replay', { id: meFlowId });
    ok(newId && newId !== meFlowId, `expected a new id, got ${JSON.stringify(newId)}`);
    const d = await waitFor(async () => {
      const x = await detail(newId);
      return x.response ? x : null;
    }, { what: 'replayed flow response' });
    eq(d.meta.is_replay, true, 'meta.is_replay');
    eq(d.response.status, 200, 'replay response status');
    ok(target.hits.length > hitsBefore, `target hits did not grow (${hitsBefore} → ${target.hits.length})`);
    ok((await call('flow.list')).includes(newId), 'replay id not in flow.list');
    return `replay ${newId} status=${d.response.status} hits ${hitsBefore}→${target.hits.length}`;
  });

  // ------------------------------------------------------------ 6. compose (request.send) + scope
  await step('compose: request.send in scope creates a flow and reaches the target', async () => {
    const hitsBefore = target.hits.length;
    const id = await call('request.send', {
      scheme: 'http',
      authority: target.host,
      path: '/api/echo?compose=1',
      method: 'POST',
      headers: { 'x-compose': 'yes', 'content-type': 'application/json' },
      body: '{"from":"compose"}',
    });
    ok(typeof id === 'string' && id, `expected a flow id, got ${JSON.stringify(id)}`);
    const hit = await waitFor(() => target.hits.slice(hitsBefore).find((h) => h.url.includes('compose=1')), { what: 'composed request at target' });
    eq(hit.method, 'POST', 'target saw method');
    eq(hit.headers['x-compose'], 'yes', 'target saw header');
    eq(hit.body, '{"from":"compose"}', 'target saw body');
    const d = await detail(id);
    eq(d.response?.status, 200, 'composed flow response');
    return `flow ${id}`;
  });
  await step('compose: out-of-scope request.send is refused with a scope error; scope.list tracks it', async () => {
    const before = await call('scope.list');
    ok(before.includes(target.host), `scope.list should contain ${target.host}: ${JSON.stringify(before)}`);
    eq(await call('scope.remove', { host: target.host }), true, 'scope.remove');
    try {
      const during = await call('scope.list');
      ok(!during.includes(target.host), `scope.list still has host after remove: ${JSON.stringify(during)}`);
      const err = await errorOf(call('request.send', { scheme: 'http', authority: target.host, path: '/api/me?oos=1' }));
      ok(err, 'request.send out of scope did not error');
      ok(/scope/i.test(err), `error does not mention scope: ${err}`);
      return `refused: ${err.slice(0, 120)}`;
    } finally {
      await call('scope.add', { host: target.host });
      const after = await call('scope.list');
      ok(after.includes(target.host), `scope.add did not restore host: ${JSON.stringify(after)}`);
    }
  });

  // ------------------------------------------------------------ 7. PoC build → list → get → run → artifact
  let pocPath, runResult;
  await step('poc: capture /search?q=probe and poc.build returns YAML naming the path', async () => {
    const res = await viaProxy(aitm.proxyPort, 'GET', `${target.base}/search?q=probe`);
    eq(res.status, 200, 'client status');
    const d = await waitFlow((x) => x.request.path.startsWith('/search') && x.intercept === 'observed', 'the /search flow');
    searchFlowId = d.id;
    const yaml = await call('poc.build', { flow_id: searchFlowId, name: 'reflected-q', param: 'q' });
    ok(typeof yaml === 'string', `poc.build should return YAML text, got ${typeof yaml}`);
    ok(yaml.includes('/search'), `YAML lacks the path:\n${yaml}`);
    ok(/param/.test(yaml), 'YAML lacks the param variable');
    pocPath = join(aitm.pocDir, 'reflected-q.yaml');
    writeFileSync(pocPath, yaml);
    return `${yaml.split('\n').length} lines → ${pocPath}`;
  });
  await step('poc: poc.list sees the saved PoC and poc.get returns its source', async () => {
    ok(pocPath, 'no PoC written');
    const list = await call('poc.list');
    const entry = list.find((p) => p.poc_path === pocPath);
    ok(entry, `poc.list lacks ${pocPath}: ${JSON.stringify(list)}`);
    const got = await call('poc.get', { poc_path: pocPath });
    eq(got.poc_path, pocPath, 'poc.get path');
    ok(typeof got.yaml === 'string' && got.yaml.includes('/search'), 'poc.get source (yaml) missing or wrong');
    return `id=${entry.id} title=${entry.title} severity=${entry.severity}`;
  });
  await step('poc: poc.run executes against the target and anchors a finding flow', async () => {
    ok(pocPath, 'no PoC written');
    const err = await errorOf(call('poc.run', { poc_path: pocPath, target: target.base }).then((r) => (runResult = r)));
    if (err && /browser/i.test(err)) skip(`poc.run needs the embedded browser, unavailable here: ${err}`);
    ok(!err, `poc.run failed: ${err}`);
    for (const k of ['passed', 'finding_capture', 'poc_path', 'screenshot_path', 'evaluated']) has(runResult, k, 'poc.run result');
    ok(Array.isArray(runResult.evaluated) && runResult.evaluated.length > 0, 'evaluated is empty');
    for (const e of runResult.evaluated) ok('assertion' in e && 'matched' in e, `bad evaluated entry ${JSON.stringify(e)}`);
    ok((await call('flow.list')).includes(runResult.finding_capture), `finding_capture ${runResult.finding_capture} not in flow.list`);
    const d = await detail(runResult.finding_capture, 'none');
    eq(d.request.path.split('?')[0], '/search', 'finding flow path');
    const shot = runResult.screenshot_path ? `screenshot=${runResult.screenshot_path}` : 'no screenshot (PoC has no browser step; embedded browser unavailable here)';
    return `passed=${runResult.passed} evaluated=${runResult.evaluated.map((e) => `${e.assertion}:${e.matched}`).join(',')} finding=${runResult.finding_capture} ${shot}`;
  });
  await step('poc: poc.artifact returns the YAML copy under poc.out_dir as base64', async () => {
    ok(runResult?.poc_path, 'no poc.run result to read an artifact from');
    ok(runResult.poc_path.startsWith(aitm.pocOut), `artifact path ${runResult.poc_path} is not under out_dir ${aitm.pocOut}`);
    const art = await call('poc.artifact', { path: runResult.poc_path });
    ok(typeof art === 'string', `expected base64 string, got ${typeof art}`);
    const text = b64(art);
    ok(/steps|request|search/.test(text), `decoded artifact does not look like the PoC YAML:\n${text.slice(0, 200)}`);
    return `${art.length} b64 chars → ${text.split('\n').length} YAML lines`;
  });

  // ------------------------------------------------------------ 8. proxy control
  await step('proxy: proxy.pause stops capture but traffic still flows; proxy.resume restores it', async () => {
    const paused = await call('proxy.pause');
    eq(paused.capturing, false, 'proxy.pause.capturing');
    const flowsBefore = (await call('flow.list')).length;
    const res = await viaProxy(aitm.proxyPort, 'GET', `${target.base}/api/me?paused=1`);
    eq(res.status, 200, 'client status while paused');
    await sleep(400);
    const flowsAfter = (await call('flow.list')).length;
    const resumed = await call('proxy.resume');
    eq(resumed.capturing, true, 'proxy.resume.capturing');
    const st = await call('proxy.status');
    eq(st.capturing, true, 'proxy.status.capturing after resume');
    const captured = flowsAfter - flowsBefore;
    const res2 = await viaProxy(aitm.proxyPort, 'GET', `${target.base}/api/me?resumed=1`);
    eq(res2.status, 200, 'client status after resume');
    await waitFor(async () => (await call('flow.list')).length > flowsAfter, { what: 'a flow after resume' });
    return captured === 0
      ? 'paused request completed (200) and did not appear in flow.list (the store keeps it hidden — see flow.clear); resumed request captured'
      : `paused request completed (200) and WAS listed (+${captured} flow) — observed behaviour, not asserted`;
  });
  await step('proxy: flow.clear empties the store', async () => {
    const visible = (await call('flow.list')).length;
    const r = await call('flow.clear');
    has(r, 'cleared', 'flow.clear');
    // A flow captured while paused is stored but hidden from flow.list; clear removes it too,
    // so `cleared` may exceed the visible count by the number of hidden flows.
    ok(r.cleared >= visible, `flow.clear.cleared ${r.cleared} < visible ${visible}`);
    eq((await call('flow.list')).length, 0, 'flow.list after clear');
    eq((await call('proxy.status')).flows, 0, 'proxy.status.flows after clear');
    const hidden = r.cleared - visible;
    return `cleared ${r.cleared} (${visible} visible${hidden ? ` + ${hidden} hidden, captured while paused` : ''})`;
  });
  await step('findings: findings.list is an empty array (no findings.dir configured, nothing recorded)', async () => {
    const f = await call('findings.list');
    ok(Array.isArray(f), `findings.list should return an array of summaries, got ${JSON.stringify(f).slice(0, 160)}`);
    eq(f.length, 0, 'findings count');
    return 'findings=[]';
  });
  await step('browser: browser.* errors without the embedded browser', async () => {
    const err = await errorOf(call('browser.navigate', { url: `${target.base}/` }));
    ok(err, 'browser.navigate unexpectedly succeeded');
    skip(`no embedded browser in this environment: ${err.slice(0, 160)}`);
  });

  // ------------------------------------------------------------ 9. gaps the UI once promised beyond the core
  // A gap the core has since closed is a PASS that states the closure and probes it; one still
  // open stays a SKIP tagged with its F-number.
  const schemaOf = (name) => tools.find((t) => t.name === name)?.inputSchema ?? {};
  await step('gap F3 closed: response-phase intercept/edit — flow.intercept takes rules with a phase; flow.mutate edits carry status', async () => {
    const props = Object.keys(schemaOf('flow.intercept').properties ?? {});
    ok(props.includes('rules'), `flow.intercept has no rules param: {${props}}`);
    const ruleFields = Object.keys(schemaOf('flow.intercept').properties.rules.items?.properties ?? {});
    ok(ruleFields.includes('phase'), `flow.intercept rules carry no phase field: {${ruleFields}}`);
    const mutate = Object.keys(schemaOf('flow.mutate').properties?.edits?.properties ?? {});
    ok(mutate.includes('status'), `flow.mutate edits lack status: {${mutate}}`);
    // One round trip: an explicit empty rule set while disarmed leaves the state as it is and the
    // core must echo it back as `{enabled, rules}`.
    const r = await call('flow.intercept', { enabled: false, rules: [] });
    eq(r.enabled, false, 'flow.intercept.enabled');
    eq(JSON.stringify(r.rules), '[]', 'flow.intercept.rules');
    return `rule fields {${ruleFields}}; mutate edits {${mutate}}; flow.intercept {enabled:false, rules:[]} echoed`;
  });
  await step('gap F3 closed: kill modes — flow.kill takes mode reset|429|503', async () => {
    const props = Object.keys(schemaOf('flow.kill').properties ?? {});
    ok(props.includes('mode'), `flow.kill has no mode param: {${props}}`);
    // Two probes against no flow: the core parses `mode` before it looks the flow up, so the two
    // messages prove the parser and nothing is killed.
    const nil = '00000000-0000-0000-0000-000000000000';
    const bad = await errorOf(call('flow.kill', { id: nil, mode: 'bogus' }));
    ok(bad && bad.includes('unknown kill mode `bogus` (want reset, 429, or 503)'), `unexpected reply to mode=bogus: ${bad}`);
    const good = await errorOf(call('flow.kill', { id: nil, mode: '503' }));
    ok(good && good.includes(`no flow with id ${nil}`), `unexpected reply to mode=503 on no flow: ${good}`);
    return `flow.kill {${props}}; mode=bogus → ${bad.replace(/^flow\.kill: /, '')}; mode=503 on no flow → ${good.replace(/^flow\.kill: /, '')}`;
  });
  await step('gap F9 closed: WebSocket tools — ws.intercept, ws.frame and ws.send are served', async () => {
    const names = tools.map((t) => t.name);
    const want = ['ws.intercept', 'ws.frame', 'ws.send'];
    const missing = want.filter((n) => !names.includes(n));
    ok(missing.length === 0, `tools/list lacks ${missing}`);
    for (const n of want) eq(schemaOf(n).type, 'object', `${n} inputSchema.type`);
    return `ws.* = ${names.filter((n) => n.startsWith('ws.')).join(',')}`;
  });
  await step('gap: header deletion via flow.mutate', async () => {
    const h = schemaOf('flow.mutate').properties?.edits?.properties?.headers;
    ok(h, 'flow.mutate.edits.headers not in schema');
    const vt = h.additionalProperties?.type ?? h.additionalProperties;
    ok(vt !== undefined, 'headers value type unknown');
    const allowsNull = Array.isArray(vt) ? vt.includes('null') : vt === true;
    ok(!allowsNull, `headers now accepts null values: ${JSON.stringify(h)}`);
    gap('F3', `flow.mutate edits.headers is {name: ${JSON.stringify(vt)}} — replaces only, no removal form`);
  });
  await step('gap F4: push notifications over /bus', async () => {
    const n = bus.notifications.length;
    ok(n === 0, `received ${n} unsolicited notifications: ${JSON.stringify(bus.notifications.slice(0, 3))}`);
    gap('F4', `0 server notifications after ${results.length} steps of traffic — this script never calls flow.subscribe, so it sees no push; the core serves flow.subscribe / flow.unsubscribe and the UI subscribes. A subscribe probe is a follow-up`);
  });
  await step('gap F1 closed: agent tools — agent.status answers with the policy; agent.set, agent.activity and agent.approve are served', async () => {
    const names = tools.map((t) => t.name);
    const want = ['agent.status', 'agent.set', 'agent.activity', 'agent.approve'];
    const missing = want.filter((n) => !names.includes(n));
    ok(missing.length === 0, `tools/list lacks ${missing}`);
    const st = await call('agent.status');
    for (const k of ['policy', 'actions_last_minute', 'connected_clients']) has(st, k, 'agent.status');
    // live-env writes no `agent:` block, so the policy is the core's default.
    eq(st.policy, 'auto', 'agent.status.policy (default)');
    eq(typeof st.actions_last_minute, 'number', 'typeof agent.status.actions_last_minute');
    ok(Array.isArray(st.connected_clients), `connected_clients should be an array, got ${JSON.stringify(st.connected_clients)}`);
    return `policy=${st.policy} actions_last_minute=${st.actions_last_minute} connected_clients=${st.connected_clients.length}`;
  });
  await step('gap F14: browser.tabs', async () => {
    const names = tools.map((t) => t.name);
    ok(!names.includes('browser.tabs'), 'core now has browser.tabs');
    gap('F14', `no browser.tabs tool (browser.* = ${names.filter((n) => n.startsWith('browser.')).join(',')})`);
  });

  // ------------------------------------------------------------ 10. coverage
  await step('coverage: every tool this run called is declared in USED_TOOLS (so the tools/list check covered the whole run)', async () => {
    const undeclared = [...calledTools].filter((n) => !USED_TOOLS.includes(n));
    ok(undeclared.length === 0, `called but not in USED_TOOLS: [${undeclared}]`);
    return `${calledTools.size} distinct tools called`;
  });
} catch (e) {
  if (!(e instanceof Abort)) throw e;
  console.log(`\nABORT ${e.message}`);
} finally {
  // ------------------------------------------------------------ report
  const w = Math.max(...results.map((r) => r.name.length), 4);
  console.log('\n' + 'STATUS'.padEnd(6) + '  ' + 'STEP'.padEnd(w) + '  ms     DETAIL');
  for (const r of results) console.log(`${r.status.padEnd(6)}  ${r.name.padEnd(w)}  ${String(r.ms).padStart(5)}  ${r.detail}`);
  const count = (s) => results.filter((r) => r.status === s).length;
  const summary = { pass: count('PASS'), fail: count('FAIL'), skip: count('SKIP'), gaps };
  console.log('\n' + JSON.stringify(summary));

  if (KEEP) {
    console.log(`\n--keep: aitm is still running. UI (operator): ${aitm.operatorUiUrl ?? aitm.uiUrl}\n  proxy 127.0.0.1:${aitm.proxyPort} · target ${target.base} · poc dir ${aitm.pocDir}\nCtrl-C to stop.`);
    bus?.close();
    await new Promise((r) => process.once('SIGINT', r));
  }
  bus?.close();
  await aitm.stop();
  await target.close();
  process.exitCode = summary.fail > 0 ? 1 : 0;
}
