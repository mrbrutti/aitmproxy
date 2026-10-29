// Dev-only frame probe: with `?perf=1`, sample requestAnimationFrame deltas for 10 s and report
// `{frames, p50, p95, max, dropped}` (dropped = frames over 20 ms) to the console and
// `window.__aitmPerf`. Used to check the §2.10(b) bar (50 appends/s, no jank).

export interface PerfReport {
  frames: number;
  p50: number;
  p95: number;
  max: number;
  dropped: number;
  seconds: number;
}

declare global {
  interface Window {
    __aitmPerf?: PerfReport | { running: true };
  }
}

export function summarize(deltas: number[], seconds: number): PerfReport {
  const sorted = [...deltas].sort((a, b) => a - b);
  const q = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))] ?? 0;
  const r = (n: number) => Math.round(n * 100) / 100;
  return {
    frames: deltas.length,
    p50: r(q(0.5)),
    p95: r(q(0.95)),
    max: r(sorted.at(-1) ?? 0),
    dropped: deltas.filter((d) => d > 20).length,
    seconds,
  };
}

export function startPerfProbe(seconds = 10): Promise<PerfReport> {
  window.__aitmPerf = { running: true };
  return new Promise((resolve) => {
    const deltas: number[] = [];
    let last = performance.now();
    const end = last + seconds * 1000;
    const tick = (now: number) => {
      deltas.push(now - last);
      last = now;
      if (now < end) requestAnimationFrame(tick);
      else {
        const report = summarize(deltas, seconds);
        window.__aitmPerf = report;
        console.info('[aitm perf]', JSON.stringify(report));
        resolve(report);
      }
    };
    requestAnimationFrame((t) => {
      last = t;
      requestAnimationFrame(tick);
    });
  });
}

export function maybeStartPerfProbe(): void {
  if (!import.meta.env.DEV) return;
  const params = new URLSearchParams(location.search);
  if (params.get('perf') !== '1') return;
  const delay = Number(params.get('perfDelay') ?? '1500');
  setTimeout(() => void startPerfProbe(Number(params.get('perfSeconds') ?? '10')), Number.isFinite(delay) ? delay : 1500);
}
