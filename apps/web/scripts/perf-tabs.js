// Evaluated in the page by shot.mjs (--evalFile): selects the 5 MB catalog flow, then cycles the
// Response pane's tabs and times each switch from click to the second animation frame (i.e. the
// frame after the one that painted the change). Returns the per-switch timings plus the
// inspector's own marks when the app exposes them (?perf=1).
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const twoFrames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  // The list is virtualized: scroll its container until the catalog row is rendered.
  const findCatalog = () => [...document.querySelectorAll('[role=row]')].find((r) => r.textContent.includes('catalog.json'));
  let scroller = document.querySelector('[role=row]');
  while (scroller && !(scroller.scrollHeight > scroller.clientHeight + 10)) scroller = scroller.parentElement;
  let catalog = findCatalog();
  for (let top = 0; !catalog && scroller && top <= scroller.scrollHeight; top += scroller.clientHeight / 2) {
    scroller.scrollTop = top;
    await twoFrames();
    catalog = findCatalog();
  }
  if (!catalog) return { error: 'catalog flow not found', rows: document.querySelectorAll('[role=row]').length, scroller: !!scroller };
  const t0 = performance.now();
  catalog.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  await twoFrames();
  const selectMs = performance.now() - t0;
  await sleep(2500); // detail fetch + worker pretty-print
  const tablists = [...document.querySelectorAll('[role=tablist]')];
  const response = tablists.find((t) => t.textContent.includes('Set-Cookie')) ?? tablists[1];
  const tabByName = (name) => [...response.querySelectorAll('[role=tab]')].find((t) => t.textContent.trim().startsWith(name));
  const order = ['Raw', 'Body', 'JSON', 'Headers', 'Body', 'Raw', 'JSON', 'Body', 'Raw', 'Body'];
  const switches = [];
  for (const name of order) {
    const tab = tabByName(name);
    if (!tab) {
      switches.push({ tab: name, ms: null, missing: true });
      continue;
    }
    const start = performance.now();
    tab.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await twoFrames();
    switches.push({ tab: name, ms: +(performance.now() - start).toFixed(2) });
    await sleep(250);
  }
  const ms = switches.filter((s) => s.ms != null).map((s) => s.ms).sort((a, b) => a - b);
  return {
    selectMs: +selectMs.toFixed(2),
    switches,
    p50: ms[Math.floor(ms.length / 2)],
    max: ms[ms.length - 1],
    inspector: globalThis.__aitmInspectorPerf ?? null,
    longTasks: globalThis.__aitmLongTasks ?? null,
  };
})()
