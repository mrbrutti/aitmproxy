// `?perf=1` dev probe: logs inspector timings to the console and to `window.__aitmInspectorPerf`
// (the shell's frame probe owns `window.__aitmPerf` with a different shape).

export const perfEnabled = typeof location !== 'undefined' && new URLSearchParams(location.search).has('perf');

export interface PerfEntry {
  name: string;
  ms: number;
  at: number;
  [k: string]: unknown;
}

declare global {
  interface Window {
    __aitmInspectorPerf?: PerfEntry[];
  }
}

export function perfMark(name: string, ms: number, extra?: Record<string, unknown>): void {
  if (!perfEnabled) return;
  (window.__aitmInspectorPerf ??= []).push({ name, ms: +ms.toFixed(2), at: Date.now(), ...extra });
  console.log(`[perf] ${name} ${ms.toFixed(1)} ms`, extra ?? '');
}
