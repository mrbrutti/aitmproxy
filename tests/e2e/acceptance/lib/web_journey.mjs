#!/usr/bin/env node
// Release acceptance, journey WEB (spec §D5), the browser half: a REAL Google Chrome over CDP
// (apps/web/scripts/cua-driver.mjs) opens the Operator URL `aitm web` printed and reads the words.
//
//   ACCEPT_OP_URL=<operatorUrl> node web_journey.mjs <outdir> <yesList> [manual]
// The Operator URL carries the web bearer (#t=…): it travels in the environment, never argv.
//
// Steps WEB-2, WEB-3, WEB-6a (arm) / WEB-6d (disarm) are driven here; WEB-4/7 (system proxy,
// `yes`) are clicked only when the yes list names them; WEB-5 / WEB-6b-c (a second browser's
// traffic) are hand steps the Python wrapper handles. Prints one `STEP\t<id>\t<result>\t<observed>`
// line per step; the wrapper merges them with the bus truth. Never prints the token.
import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, makeDriver } from '../../../../apps/web/scripts/cua-driver.mjs';
import { sleep } from '../../../../apps/web/scripts/live-env.mjs';

const [outdir, yesList = '', manual = ''] = process.argv.slice(2);
const url = process.env.ACCEPT_OP_URL;
if (!url || !outdir) { console.error('usage: ACCEPT_OP_URL=<operatorUrl> web_journey.mjs <outdir> <yesList> [manual]'); process.exit(2); }
const YES = new Set(yesList.split(',').filter(Boolean));
const log = (m) => console.error(`[web] ${m.replace(/#t=[^&\s"]+/g, '#t=<redacted>')}`);
const step = (id, result, observed = '') => console.log(['STEP', id, result, observed.replace(/\s+/g, ' ').replace(/#t=[^&\s"]+/g, '#t=<redacted>').slice(0, 300)].join('\t'));

const chrome = await launchChrome({ width: 1500, height: 950 });
if (typeof chrome.close !== 'function') { console.error('cua-driver changed: launchChrome() has no close(); refusing to run without a scoped cleanup'); process.exit(2); }
const d = makeDriver(chrome, { log, shotsDir: outdir });
let rc = 0;
try {
  await d.open(url);
  await sleep(1200);
  // WEB-2 — banner, pill, status bar, empty grid.
  const banner = await d.ev(`document.body.innerText.includes('Operator session — sensitive commands are enabled.')`);
  const pill = await d.ev(`(document.querySelector('[data-testid=listen-pill],[aria-label*="listening"],button[title*="aitmproxy"]')||[...document.querySelectorAll('button,span,div')].find(e=>/aitmproxy · (listening|paused)/.test(e.textContent)))?.textContent?.trim()||''`);
  const busTitle = await d.ev(`document.querySelector('span[title^="bus "]')?.getAttribute('title')||''`);
  const empty = await d.ev(`document.body.innerText.includes('No flows yet — point a client at')`);
  const rows = await d.ev(`document.querySelectorAll('[role=grid][aria-label="Flows"] [role=row]').length`);
  await d.shot('WEB-2');
  const okPill = /aitmproxy · listening 127\.0\.0\.1:8080 · sys-proxy (off|→ us|→ [0-9.:]+) · CA (trusted|untrusted)/.test(pill);
  step('WEB-2', banner && okPill && busTitle === 'bus open' && (empty || rows > 1) ? 'PASS' : 'FAIL',
    `banner ${banner}; pill "${pill}"; bus "${busTitle}"; empty-state ${empty}; rows ${rows}`);

  // WEB-3 — Scope add through the panel.
  const host = process.env.ACCEPT_HOST || 'example.com';
  await d.click({ role: 'button', text: 'Scope', within: 'aside[aria-label="Sources"]' }).catch(() => d.click({ role: 'button', text: 'Scope' }));
  await sleep(500);
  const emptyScope = await d.ev(`document.body.innerText.includes('No hosts in scope — add the hosts you are authorised to test.')`);
  await d.click({ sel: 'input[aria-label="Add host to scope"]' });
  await d.type(host);
  await d.key('Enter');
  await sleep(1500);
  const listed = await d.ev(`[...document.querySelectorAll('[role=table][aria-label="Hosts in scope"] [role=row], [role=table][aria-label="Hosts in scope"] tr')].some(r=>r.textContent.includes(${JSON.stringify(host)}))`);
  const toast = await d.ev(`document.body.innerText.match(/scope: [^\\n]+/)?.[0]||''`);
  const inScope = await d.ev(`document.body.innerText.match(/\\d+ hosts? in scope/)?.[0]||''`);
  await d.shot('WEB-3');
  step('WEB-3', listed && !toast ? 'PASS' : 'FAIL', `empty-state before ${emptyScope}; row listed ${listed}; status "${inScope}"; toast "${toast}"`);

  // WEB-4 — Set as system proxy (yes).
  if (!YES.has('WEB-4')) {
    step('WEB-4', 'SKIP', "needs Matt's yes (ACCEPT_YES=WEB-4)");
  } else {
    log(`window WEB-4 start ${new Date().toISOString()}`);
    await d.click({ role: 'button', text: 'aitmproxy · listening' }).catch(async () => d.click({ sel: 'button[aria-haspopup="menu"]' }));
    await d.click({ role: 'menuitem', text: 'Set as system proxy' });
    let word = '';
    for (let i = 0; i < 30 && !/sys-proxy → us/.test(word); i++) { await sleep(500); word = await d.ev(`document.body.innerText.match(/sys-proxy [^·\\n]+/)?.[0]||''`); }
    await d.shot('WEB-4');
    step('WEB-4', /sys-proxy → us/.test(word) ? 'PASS' : 'FAIL', `pill word "${word.trim()}"`);
  }

  // WEB-6a — arm.
  await d.focusList().catch(() => {});
  await d.key('i');
  await sleep(600);
  const armedText = await d.ev(`document.querySelector('[role=status]')?.textContent||''`);
  step('WEB-6a', armedText.includes('Intercept armed — every request pauses here') ? 'PASS' : 'FAIL', `status bar "${armedText.trim().slice(0, 120)}"`);
  if (manual === 'manual' && process.env.ACCEPT_ROUTE_OPEN === '1') {
    console.log('PAUSE\tReload http://example.com/ in Safari, then press Enter in the wrapper');
    await new Promise((r) => process.stdin.once('data', r));
    let paused = '';
    for (let i = 0; i < 30 && !/\d+ paused/.test(paused); i++) { await sleep(500); paused = await d.ev(`document.querySelector('[role=status]')?.textContent||''`); }
    const rowPaused = await d.ev(`document.body.innerText.includes('Paused')`);
    step('WEB-6b', /1 paused/.test(paused) && rowPaused ? 'PASS' : 'FAIL', `status "${paused.trim().slice(0, 80)}"; row Paused ${rowPaused}`);
    await d.click({ role: 'button', text: 'Resume' });
    await sleep(1500);
    const after = await d.ev(`document.querySelector('[role=status]')?.textContent||''`);
    step('WEB-6c', after.includes('Intercept armed — every request pauses here') ? 'PASS' : 'FAIL', `status "${after.trim().slice(0, 80)}"`);
  } else {
    step('WEB-6b', 'BLOCKED', 'needs a route (WEB-4) and a hand (reload in Safari)');
    step('WEB-6c', 'BLOCKED', 'WEB-6b');
  }
  await d.click({ role: 'button', text: 'Disarm' }).catch(async () => d.key('i'));
  await sleep(600);
  const gone = await d.ev(`!(document.querySelector('[role=status]')?.textContent||'').includes('Intercept armed')`);
  step('WEB-6d', gone ? 'PASS' : 'FAIL', `bar gone ${gone}`);

  // WEB-7 — restore (yes, only if WEB-4 set it).
  if (YES.has('WEB-4') && YES.has('WEB-7')) {
    await d.click({ role: 'button', text: 'aitmproxy · listening' }).catch(async () => d.click({ sel: 'button[aria-haspopup="menu"]' }));
    const item = await d.ev(`[...document.querySelectorAll('[role=menuitem]')].map(e=>e.textContent.trim()).join('|')`);
    await d.click({ role: 'menuitem', text: /restore|unset|system proxy/i.test(item) ? item.split('|').find((t) => /system proxy/i.test(t)) : 'Set as system proxy' });
    let word = '';
    for (let i = 0; i < 30 && !/sys-proxy (off|→ 127)/.test(word); i++) { await sleep(500); word = await d.ev(`document.body.innerText.match(/sys-proxy [^·\\n]+/)?.[0]||''`); }
    step('WEB-7', /sys-proxy (off|→ 127\.0\.0\.1:9090)/.test(word) ? 'PASS' : 'FAIL', `pill word "${word.trim()}"; menu items "${item}"`);
  } else {
    step('WEB-7', 'SKIP', YES.has('WEB-4') ? "needs Matt's yes (ACCEPT_YES=WEB-7)" : 'nothing to restore (WEB-4 did not run)');
  }
  writeFileSync(join(outdir, 'WEB-dom.txt'), await d.ev('document.body.innerText'));
} catch (e) {
  log(`error: ${e.message}`);
  step('WEB-ERR', 'FAIL', e.message);
  rc = 1;
} finally {
  // close() SIGTERMs only the Chrome it spawned and removes its temp profile (which holds the
  // operator URL in History). Never signal our own process group.
  try { await d.open('about:blank'); } catch {}
  chrome.close();
}
process.exit(rc);
