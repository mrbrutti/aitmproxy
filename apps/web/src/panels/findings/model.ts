// Pure helpers behind the Findings panel: ordering, filtering, counts, the "when" text and the
// Run-again `vars` round trip. Kept free of Solid so they test as plain functions.

import type { PocRun } from '~/bus/mock';
import { fmtClock } from '~/lib/format';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export function isSeverity(s: unknown): s is Severity {
  return typeof s === 'string' && (SEVERITIES as readonly string[]).includes(s);
}

/** Newest first (§2.7 list order); runs without a time sink to the bottom. */
export function sortNewest(runs: readonly PocRun[]): PocRun[] {
  return [...runs].sort((a, b) => (b.at ?? -Infinity) - (a.at ?? -Infinity));
}

/** Title/target substring match plus a severity allow-list (empty set = every severity). */
export function filterRuns(runs: readonly PocRun[], query: string, severities: ReadonlySet<Severity>): PocRun[] {
  const q = query.trim().toLowerCase();
  return runs.filter((r) => {
    if (severities.size && !severities.has(r.severity)) return false;
    if (!q) return true;
    return `${r.title ?? ''} ${r.target ?? ''}`.toLowerCase().includes(q);
  });
}

export type Verdict = 'passed' | 'failed' | 'not-run';

/**
 * The core keeps no run history, so a library entry has no verdict until `poc.run` happened in
 * this session (`ran`); a PoC built here but not saved (`local`) cannot have run. A run that
 * arrived with its own timestamp (fixtures, a future core) counts as run.
 */
export function verdictOf(r: Pick<PocRun, 'local' | 'ran' | 'at' | 'passed'>): Verdict {
  if (r.local) return 'not-run';
  if (!r.ran && !(r.at > 0)) return 'not-run';
  return r.passed ? 'passed' : 'failed';
}

/** The entry's time (run time, or build time for a local PoC); `null` when it never ran. */
export function whenOf(r: Pick<PocRun, 'at'>): number | null {
  return r.at > 0 ? r.at : null;
}

export function matchedCount(evaluated: PocRun['evaluated'] | null | undefined): { matched: number; total: number } {
  const list = evaluated ?? [];
  let matched = 0;
  for (const e of list) if (e.matched) matched++;
  return { matched, total: list.length };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Relative for the last day (`4 min ago`), then `27 Oct 11:05`; `null` when unknown. */
export function fmtWhen(at: number | null | undefined, now = Date.now()): string | null {
  if (at == null || !Number.isFinite(at)) return null;
  const diff = now - at;
  if (diff < 45_000) return 'just now';
  if (diff < 60 * 60_000) return `${Math.max(1, Math.round(diff / 60_000))} min ago`;
  if (diff < 24 * 60 * 60_000) return `${Math.round(diff / (60 * 60_000))} h ago`;
  const d = new Date(at);
  const clock = fmtClock(at).slice(0, 5);
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${clock}`;
}

/** Full local time for tooltips. */
export function fmtWhenFull(at: number | null | undefined): string | null {
  if (at == null || !Number.isFinite(at)) return null;
  const d = new Date(at);
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()} · ${fmtClock(at)}`;
}

/** `key=value` lines → vars; blank lines and lines without `=` are skipped. */
export function parseVars(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim();
    if (k) out[k] = line.slice(eq + 1).trim();
  }
  return out;
}

export function varsText(vars: Record<string, string> | null | undefined): string {
  return Object.entries(vars ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
}

/** A PoC's `vars` block, read from the YAML so Run-again can prefill (best effort, top-level only). */
export function varsFromYaml(yaml: string | null | undefined): Record<string, string> {
  if (!yaml) return {};
  const lines = yaml.split(/\r?\n/);
  const start = lines.findIndex((l) => /^vars:\s*$/.test(l));
  if (start < 0) return {};
  const out: Record<string, string> = {};
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (!/^\s+/.test(l)) break;
    const m = /^\s+([^\s:#][^:]*?)\s*:\s*(.*?)\s*$/.exec(l);
    if (m) out[m[1]!] = m[2]!.replace(/^(['"])(.*)\1$/, '$2');
  }
  return out;
}
