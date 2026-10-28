// Headless-Chrome driver over CDP (no Playwright): screenshots and real-frame perf numbers.
//
//   node scripts/shot.mjs --url 'http://localhost:5173/?initial=60' --out shots/main-dark.png \
//        [--width 1600 --height 1000] [--scale 2] [--keys i,End] [--eval '<js>'] [--wait 2500] [--perf 10000]
//
// --keys sends real key presses (CDP Input) after load; --eval runs JS after the keys; --wait is the
// settle time before the capture; --perf N samples requestAnimationFrame for N ms and prints
// {frames,p50,p95,max,dropped} plus window.__aitmPerf if the app exposes it.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => {
    if (a.startsWith('--')) acc.push([a.slice(2), arr[i + 1]?.startsWith('--') || arr[i + 1] === undefined ? 'true' : arr[i + 1]]);
    return acc;
  }, []),
);
const url = args.url ?? 'http://localhost:5173/';
const out = args.out ?? 'shot.png';
const width = Number(args.width ?? 1600);
const height = Number(args.height ?? 1000);
const scale = Number(args.scale ?? 2);
const wait = Number(args.wait ?? 2000);
const perfMs = args.perf ? Number(args.perf) : 0;

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    '--hide-scrollbars',
    '--force-device-scale-factor=' + scale,
    `--window-size=${width},${height}`,
    '--user-data-dir=' + (process.env.TMPDIR ?? '/tmp') + '/aitm-shot-profile',
    'about:blank',
  ],
  { stdio: ['ignore', 'ignore', 'pipe'] },
);

const wsUrl = await new Promise((resolve, reject) => {
  let buf = '';
  chrome.stderr.on('data', (d) => {
    buf += d.toString();
    const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  chrome.on('exit', (code) => reject(new Error(`chrome exited ${code}\n${buf}`)));
  setTimeout(() => reject(new Error('chrome did not start\n' + buf)), 15000);
});

const browser = new WebSocket(wsUrl);
await new Promise((r) => (browser.onopen = r));
let nextId = 1;
const pending = new Map();
const events = new Map();
browser.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  } else if (msg.method && events.has(msg.method)) events.get(msg.method)(msg.params);
};
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    browser.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

try {
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const s = (m, p) => send(m, p, sessionId);
  await s('Page.enable');
  await s('Runtime.enable');
  await s('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile: false });
  const loaded = new Promise((r) => events.set('Page.loadEventFired', r));
  await s('Page.navigate', { url });
  await loaded;
  await new Promise((r) => setTimeout(r, 600));

  const keyNames = { Enter: 13, Escape: 27, End: 35, Home: 36, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, ' ': 32 };
  for (const key of (args.keys ?? '').split(',').filter(Boolean)) {
    const code = keyNames[key] ?? key.toUpperCase().charCodeAt(0);
    const base = { key, code: key.length === 1 ? `Key${key.toUpperCase()}` : key, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code };
    await s('Input.dispatchKeyEvent', { type: 'keyDown', ...base, ...(key.length === 1 ? { text: key } : {}) });
    await s('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
    await new Promise((r) => setTimeout(r, Number(args.keyDelay ?? 400)));
  }
  if (args.eval && args.eval !== 'true') {
    const r = await s('Runtime.evaluate', { expression: args.eval, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) console.error('eval failed:', r.exceptionDetails.text, r.exceptionDetails.exception?.description);
    else if (r.result.value !== undefined) console.log('eval:', JSON.stringify(r.result.value));
  }
  await new Promise((r) => setTimeout(r, wait));

  if (perfMs) {
    const r = await s('Runtime.evaluate', {
      awaitPromise: true,
      returnByValue: true,
      expression: `new Promise((resolve) => {
        const deltas = []; let last = performance.now(); const t0 = last;
        function tick(now) { deltas.push(now - last); last = now; if (now - t0 < ${perfMs}) requestAnimationFrame(tick); else done(); }
        function done() {
          const d = deltas.slice(1).sort((a, b) => a - b);
          const q = (p) => d[Math.min(d.length - 1, Math.floor(p * d.length))];
          resolve({ frames: d.length, p50: +q(0.5).toFixed(2), p95: +q(0.95).toFixed(2), max: +d[d.length - 1].toFixed(2), dropped: d.filter((x) => x > 20).length, app: globalThis.__aitmPerf ?? null });
        }
        requestAnimationFrame(tick);
      })`,
    });
    console.log('perf:', JSON.stringify(r.result.value));
  }

  const shot = await s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, Buffer.from(shot.data, 'base64'));
  console.log('wrote', out, `${width}x${height}@${scale}x`);
} finally {
  browser.close();
  chrome.kill('SIGTERM');
}
