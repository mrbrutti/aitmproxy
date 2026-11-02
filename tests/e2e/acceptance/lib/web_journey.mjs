#!/usr/bin/env node
// Release acceptance, journey WEB (spec §D5, negatives §D7), the browser half: a REAL Google
// Chrome over CDP (apps/web/scripts/cua-driver.mjs) opens the Operator URL `aitm web` printed and
// reads the words.
//
//   ACCEPT_OP_URL=<operatorUrl> [ACCEPT_AGENT_URL=<webUiUrl>] node web_journey.mjs <outdir> <yesList> [manual]
// The URLs carry web bearers (#t=…): they travel in the environment, never argv, never stdout.
//
// Driven here: WEB-2, WEB-3 (+ N2-WEB read right after; a candidate host named in ACCEPT_PRE_SCOPE —
// the operator's config.yaml `scope:` block — or already shown on the page is pre-existing and is
// neither added nor removed), WEB-4/7 (`yes`, only when the yes list names them; `SET\tWEB-4` is
// printed right BEFORE the click so the wrapper arms its restore trap first; after WEB-4 the
// wrapper is asked to verify the bypass — `CHECK\tWEB-4` → `ok`/`bad` on stdin — and on `bad`
// the same menu item restores at once), WEB-5 and WEB-6b/c (hand steps:
// `PAUSE\t<text>` → the wrapper pauses and answers with a newline; the rows are then judged from
// the page, the web cell has no bus client), WEB-6a/6d, N5-WEB (the Web UI's agent URL with
// `&expect=operator`), and the Scope cleanup: exactly the host WEB-3 added is removed through its
// row's "Remove <host> from scope" button (unless ACCEPT_KEEP_SCOPE=1) and reported as
// `LEFTOVER\t<host>\t<removed|kept|failed>`. One `STEP\t<id>\t<result>\t<observed>` line per step.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { launchChrome, makeDriver } from '../../../../apps/web/scripts/cua-driver.mjs';
import { sleep } from '../../../../apps/web/scripts/live-env.mjs';

const [outdir, yesList = '', manual = ''] = process.argv.slice(2);
const url = process.env.ACCEPT_OP_URL;
const agentUrl = process.env.ACCEPT_AGENT_URL || '';
if (!url || !outdir) { console.error('usage: ACCEPT_OP_URL=<operatorUrl> web_journey.mjs <outdir> <yesList> [manual]'); process.exit(2); }
const YES = new Set(yesList.split(',').filter(Boolean));
const isManual = manual === 'manual';
const routeOpen = process.env.ACCEPT_ROUTE_OPEN === '1';
const keepScope = process.env.ACCEPT_KEEP_SCOPE === '1';
const preScope = new Set((process.env.ACCEPT_PRE_SCOPE || '').split(',').filter(Boolean));
const redact = (s) => String(s).replace(/#t=[^&\s"]+/g, '#t=<redacted>');
const log = (m) => console.error(`[web] ${redact(m)}`);
const step = (id, result, observed = '') => console.log(['STEP', id, result, redact(observed).replace(/\s+/g, ' ').slice(0, 300)].join('\t'));
const rl = createInterface({ input: process.stdin });
const lines = [];
const waiters = [];
rl.on('line', (l) => { const w = waiters.shift(); if (w) w(l); else lines.push(l); });
const readLine = () => (lines.length ? Promise.resolve(lines.shift()) : new Promise((r) => waiters.push(r)));
const ask = async (kind, text) => { console.log(`${kind}\t${text}`); return readLine(); };

const chrome = await launchChrome({ width: 1500, height: 950 });
if (typeof chrome.close !== 'function') { console.error('cua-driver changed: launchChrome() has no close(); refusing to run without a scoped cleanup'); process.exit(2); }
const d = makeDriver(chrome, { log, shotsDir: outdir });
const status = () => d.ev(`document.querySelector('[role=status]')?.textContent||''`);
const pillWord = () => d.ev(`document.body.innerText.match(/sys-proxy [^·\\n]+/)?.[0]||''`);
const gridRows = () => d.ev(`[...document.querySelectorAll('[role=grid][aria-label="Flows"] [role=row]')].map(r=>r.textContent.replace(/\\s+/g,' ').trim())`);
const openPillMenu = () => d.click({ role: 'button', text: 'aitmproxy · listening' }).catch(async () => d.click({ sel: 'button[aria-haspopup="menu"]' }));
const toScope = () => d.click({ role: 'button', text: 'Scope', within: 'aside[aria-label="Sources"]' }).catch(() => d.click({ role: 'button', text: 'Scope' }));
const hostListed = (h) => d.ev(`[...document.querySelectorAll('[role=table][aria-label="Hosts in scope"] [role=row], [role=table][aria-label="Hosts in scope"] tr')].some(r=>r.textContent.includes(${JSON.stringify(h)}))`);
let addedHost = '';
let rc = 0;
try {
  await d.open(url);
  await sleep(1200);
  // WEB-2 — banner, pill, status bar (`bus 127.0.0.1:8082`, tooltip `bus open`), empty grid.
  const banner = await d.ev(`document.body.innerText.includes('Operator session — sensitive commands are enabled.')`);
  const pill = await d.ev(`(document.querySelector('[data-testid=listen-pill],[aria-label*="listening"],button[title*="aitmproxy"]')||[...document.querySelectorAll('button,span,div')].find(e=>/aitmproxy · (listening|paused)/.test(e.textContent)))?.textContent?.trim()||''`);
  const busEl = await d.ev(`(e=>({text:e?.textContent?.trim()||'',title:e?.getAttribute('title')||''}))(document.querySelector('span[title^="bus "]'))`);
  const empty = await d.ev(`document.body.innerText.includes('No flows yet — point a client at 127.0.0.1:8080 or open the browser.')`);
  const rows = await d.ev(`document.querySelectorAll('[role=grid][aria-label="Flows"] [role=row]').length`);
  await d.shot('WEB-2');
  const okPill = /aitmproxy · listening 127\.0\.0\.1:8080 · sys-proxy (off|→ us|→ [0-9.:]+) · CA (trusted|untrusted)/.test(pill);
  const okBus = busEl.text.includes('bus 127.0.0.1:8082') && busEl.title === 'bus open';
  step('WEB-2', banner && okPill && okBus && (empty || rows > 1) ? 'PASS' : 'FAIL',
    `banner ${banner}; pill "${pill}"; status bar "${busEl.text}" tooltip "${busEl.title}"; empty-state verbatim ${empty}; rows ${rows}`);

  // WEB-3 — Scope add through the panel: the first candidate host not already listed, so the add
  // is real and the cleanup removes exactly it.
  await toScope();
  await sleep(500);
  const emptyScope = await d.ev(`document.body.innerText.includes('No hosts in scope — add the hosts you are authorised to test.')`);
  const candidates = [process.env.ACCEPT_HOST || 'example.com', 'httpbin.org', 'acceptance-web.invalid'];
  let host = '';
  const preListed = [];
  for (const c of candidates) { if (preScope.has(c) || await hostListed(c)) preListed.push(c); else { host = c; break; } }
  if (!host) {
    step('WEB-3', 'SKIP', `every candidate host is already in Scope (${preListed.join(', ')}; config.yaml or page); nothing added`);
  } else {
    await d.click({ sel: 'input[aria-label="Add host to scope"]' });
    await d.type(host);
    await d.key('Enter');
    await sleep(1500);
    const listed = await hostListed(host);
    if (listed) addedHost = host;
    const toast = await d.ev(`document.body.innerText.match(/scope: [^\\n]+/)?.[0]||''`);
    const inScope = await d.ev(`document.body.innerText.match(/\\d+ hosts? in scope/)?.[0]||''`);
    await d.shot('WEB-3');
    step('WEB-3', listed && !toast && inScope ? 'PASS' : 'FAIL', `host ${host}${preListed.length ? ` (already listed before: ${preListed.join(', ')})` : ''}; empty-state before ${emptyScope}; row listed ${listed}; status "${inScope}"; toast "${toast}"`);
  }
  // N2-WEB — a host in Scope, no route yet: the pill word and the empty grid words.
  const n2pill = await pillWord();
  const n2empty = await d.ev(`document.body.innerText.includes('No flows yet — point a client at 127.0.0.1:8080 or open the browser.')`);
  const n2rows = await d.ev(`document.querySelectorAll('[role=grid][aria-label="Flows"] [role=row]').length`);
  if (/sys-proxy off/.test(n2pill) && (addedHost || preListed.length)) step('N2-WEB', n2empty || n2rows <= 1 ? 'PASS' : 'FAIL', `pill "${n2pill.trim()}"; empty grid words ${n2empty}; rows ${n2rows} (zero rows is correct here)`);
  else step('N2-WEB', 'SKIP', `not the N2 state: pill "${n2pill.trim()}", hosts in scope ${addedHost || preListed.length ? 'yes' : 'no'}`);

  // WEB-4 — Set as system proxy (yes); the wrapper checks `scutil --proxy`'s ExceptionsList.
  let setByUs = false;
  if (!YES.has('WEB-4')) {
    step('WEB-4', 'SKIP', "needs Matt's yes (ACCEPT_YES=WEB-4)");
  } else {
    log(`window WEB-4 start ${new Date().toISOString()}`);
    await openPillMenu();
    console.log('SET\tWEB-4');   // the wrapper arms set_by_us BEFORE the click lands
    setByUs = true;
    await d.click({ role: 'menuitem', text: 'Set as system proxy' });
    let word = '';
    for (let i = 0; i < 30 && !/sys-proxy → us/.test(word); i++) { await sleep(500); word = await pillWord(); }
    await d.shot('WEB-4');
    const verdict = (await ask('CHECK', 'WEB-4')).trim();
    if (/sys-proxy → us/.test(word) && verdict === 'ok') {
      step('WEB-4', 'PASS', `pill word "${word.trim()}"; ExceptionsList carries the tooling (wrapper check ok)`);
    } else {
      // Restore at once through the same control, whatever the reason.
      await openPillMenu();
      await d.click({ role: 'menuitem', text: 'Set as system proxy' }).catch(() => {});
      let back = '';
      for (let i = 0; i < 30 && !/sys-proxy (off|→ 127)/.test(back); i++) { await sleep(500); back = await pillWord(); }
      setByUs = false;
      step('WEB-4', 'FAIL', verdict === 'ok' ? `pill word "${word.trim()}" never became → us; restored at once (pill "${back.trim()}")` : `bypass not applied: ExceptionsList lacks the tooling hosts; restored at once (pill "${back.trim()}")`);
    }
    log(`window WEB-4 end ${new Date().toISOString()}`);
  }

  // WEB-5 — a second real browser's rows (hand), judged from the page (no bus client here).
  if (!setByUs) {
    step('WEB-5', 'BLOCKED', 'WEB-4 did not set the route');
  } else if (!isManual) {
    step('WEB-5', 'SKIP', 'needs a hand: Safari visits http://example.com/ and https://httpbin.org/get (--manual)');
  } else {
    await ask('PAUSE', 'In Safari open http://example.com/ then https://httpbin.org/get, then press Enter in the wrapper');
    let rowsText = [];
    for (let i = 0; i < 20; i++) { rowsText = await gridRows(); if (rowsText.some((r) => /httpbin\.org/.test(r) && /GET/.test(r))) break; await sleep(500); }
    const ex = rowsText.find((r) => /example\.com/.test(r) && /\b200\b/.test(r)) || '';
    const hb = rowsText.find((r) => /httpbin\.org/.test(r) && /GET/.test(r)) || '';
    const decrypted = /decrypted/.test(hb) && !/passthrough/.test(hb);
    const domains = await d.ev(`document.body.innerText.match(/Domains\\s*\\d+/)?.[0]||''`);
    await d.shot('WEB-5');
    step('WEB-5', ex && hb && /\b200\b/.test(hb) && decrypted ? 'PASS' : 'FAIL', `judged from the page: example row "${ex.slice(0, 80)}"; httpbin GET row "${hb.slice(0, 80)}" decrypted ${decrypted}; ${domains}`);
  }

  // WEB-6a — arm: bar words + Disarm / Rules… buttons.
  await d.focusList().catch(() => {});
  await d.key('i');
  await sleep(600);
  const armedText = await status();
  const btnDisarm = await d.ev(`[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='Disarm')`);
  const btnRules = await d.ev(`[...document.querySelectorAll('button')].some(b=>b.textContent.trim().startsWith('Rules'))`);
  step('WEB-6a', armedText.includes('Intercept armed — every request pauses here') && btnDisarm && btnRules ? 'PASS' : 'FAIL', `status bar "${armedText.trim().slice(0, 120)}"; Disarm ${btnDisarm}; Rules… ${btnRules}`);
  if (isManual && routeOpen && setByUs) {
    await ask('PAUSE', 'Reload http://example.com/ in Safari, then press Enter in the wrapper');
    let paused = '';
    for (let i = 0; i < 30 && !/\d+ paused/.test(paused); i++) { await sleep(500); paused = await status(); }
    const rowPaused = await d.ev(`document.body.innerText.includes('Paused')`);
    const resumeOn = await d.ev(`[...document.querySelectorAll('button')].some(b=>/^(Resume|Apply & Resume)$/.test(b.textContent.trim())&&!b.disabled)`);
    step('WEB-6b', /1 paused/.test(paused) && rowPaused && resumeOn ? 'PASS' : 'FAIL', `status "${paused.trim().slice(0, 80)}"; row Paused ${rowPaused}; Resume enabled ${resumeOn}`);
    await d.click({ role: 'button', text: 'Resume' });
    await sleep(1500);
    const after = await status();
    const row200 = (await gridRows()).some((r) => /example\.com/.test(r) && /\b200\b/.test(r));
    step('WEB-6c', after.includes('Intercept armed — every request pauses here') && row200 ? 'PASS' : 'FAIL', `status "${after.trim().slice(0, 80)}"; row 200 ${row200}`);
  } else {
    step('WEB-6b', 'BLOCKED', setByUs ? 'needs a hand (reload in Safari)' : 'WEB-4');
    step('WEB-6c', 'BLOCKED', 'WEB-6b');
  }
  await d.click({ role: 'button', text: 'Disarm' }).catch(async () => d.key('i'));
  await sleep(600);
  const gone = !(await status()).includes('Intercept armed');
  step('WEB-6d', gone ? 'PASS' : 'FAIL', `bar gone ${gone}`);

  // WEB-7 — restore (yes, only if WEB-4 set it).
  if (!setByUs) {
    step('WEB-7', 'SKIP', YES.has('WEB-4') ? 'nothing to restore (WEB-4 did not set it, or it was restored at once)' : 'nothing to restore (WEB-4 did not run)');
  } else if (!YES.has('WEB-7')) {
    step('WEB-7', 'SKIP', "needs Matt's yes (ACCEPT_YES=WEB-7) — the wrapper's trap will restore");
  } else {
    await openPillMenu();
    const item = await d.ev(`[...document.querySelectorAll('[role=menuitem]')].map(e=>e.textContent.trim()).join('|')`);
    await d.click({ role: 'menuitem', text: 'Set as system proxy' });
    let word = '';
    for (let i = 0; i < 30 && !/sys-proxy (off|→ 127)/.test(word); i++) { await sleep(500); word = await pillWord(); }
    step('WEB-7', /sys-proxy (off|→ 127\.0\.0\.1:\d+)/.test(word) ? 'PASS' : 'FAIL', `pill word "${word.trim()}"; menu items "${item}"`);
  }

  // Scope cleanup — exactly the host WEB-3 added, through its row's own button.
  if (addedHost) {
    if (keepScope) {
      console.log(`LEFTOVER\t${addedHost}\tkept`);
    } else {
      await toScope();
      await sleep(500);
      let removed = false;
      try {
        await d.click({ sel: `button[aria-label="Remove ${addedHost} from scope"]` });
        for (let i = 0; i < 10 && !removed; i++) { await sleep(400); removed = !(await hostListed(addedHost)); }
      } catch (e) { log(`remove failed: ${e.message}`); }
      console.log(`LEFTOVER\t${addedHost}\t${removed ? 'removed' : 'failed'}`);
    }
  }
  writeFileSync(join(outdir, 'WEB-dom.txt'), redact(await d.ev('document.body.innerText')));

  // N5-WEB — the agent URL with &expect=operator must show the role-mismatch banner.
  if (!agentUrl) {
    step('N5-WEB', 'SKIP', 'no Web UI (agent) URL from the card');
  } else {
    await d.open(agentUrl + '&expect=operator');
    await sleep(1500);
    const want = 'Expected operator access, but this session connected as agent. Sensitive commands will be refused.';
    const shown = await d.ev(`document.body.innerText.includes(${JSON.stringify(want)})`);
    const bannerText = await d.ev(`(document.body.innerText.match(/Expected operator access[^\\n]*/)||[''])[0]`);
    await d.shot('N5-WEB');
    step('N5-WEB', shown ? 'PASS' : 'FAIL', shown ? 'banner verbatim' : `banner "${bannerText}"`);
  }
} catch (e) {
  log(`error: ${e.message}`);
  step('WEB-ERR', 'FAIL', e.message);
  if (addedHost) console.log(`LEFTOVER\t${addedHost}\tfailed`);
  rc = 1;
} finally {
  // close() SIGTERMs only the Chrome it spawned and removes its temp profile (which holds the
  // operator URL in History). Never signal our own process group.
  try { await d.open('about:blank'); } catch {}
  chrome.close();
  rl.close();
}
process.exit(rc);
