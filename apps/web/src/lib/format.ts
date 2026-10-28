// Number/time formatting per §2.8: zero prints as zero, missing as a grey dash (the caller
// renders the dash), a real 0 B body is "0 B". Tabular figures come from the font setting.

export function fmtBytes(n: number | null | undefined): string | null {
  if (n == null) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fmtDuration(ms: number | null | undefined): string | null {
  if (ms == null) return null;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

const two = (n: number) => String(n).padStart(2, '0');
const three = (n: number) => String(n).padStart(3, '0');

/** `11:04:58.120` — local time with milliseconds, the flow list's Time column. */
export function fmtTime(epochMs: number): string {
  const d = new Date(epochMs);
  return `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}.${three(d.getMilliseconds())}`;
}

/** `11:04:58` — without milliseconds, for summaries and logs. */
export function fmtClock(epochMs: number): string {
  const d = new Date(epochMs);
  return `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}

export function fmtRate(bytesPerSec: number): string {
  return `${fmtBytes(bytesPerSec) ?? '0 B'}/s`;
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
