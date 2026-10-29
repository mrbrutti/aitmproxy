// Scope logic (foundation §2.7 "Scope panel", §3.9): the three entry forms, pattern matching
// against flow authorities, and the read-only rate-limit / back-off readouts. Pure functions so
// the panel stays a thin view and the rules are testable without the DOM.

import { fmtDuration } from '~/lib/format';

export interface ScopeEntry {
  host: string;
  rate_limit?: unknown;
  backoff?: unknown;
}

export type HostValidation = { ok: true; host: string } | { ok: false; error: string };

// One DNS label: 1–63 chars of [a-z0-9-], not starting or ending with a hyphen.
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const HOST_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const isHost = (s: string) => HOST_RE.test(s) || IPV4_RE.test(s);
const isPort = (s: string) => /^\d{1,5}$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;

const FORMS = 'Use host, host:port or *.wildcard';

/** Accepts `host`, `host:port` and `*.wildcard`; rejects URLs, paths, spaces and stray wildcards. */
export function validateHost(input: string): HostValidation {
  const raw = input.trim().toLowerCase();
  if (!raw) return { ok: false, error: 'Enter a host.' };
  if (/\s/.test(raw)) return { ok: false, error: 'Hosts contain no spaces.' };
  if (raw.includes('://')) return { ok: false, error: `${FORMS} — not a URL.` };
  if (raw.includes('/')) return { ok: false, error: `${FORMS} — no path.` };
  if (raw.includes('@') || raw.includes('?') || raw.includes('#')) return { ok: false, error: `${FORMS}.` };

  if (raw.startsWith('*.')) {
    const rest = raw.slice(2);
    if (rest.includes('*') || rest.includes(':')) return { ok: false, error: `${FORMS} — one leading *. only.` };
    if (!isHost(rest) || !rest.includes('.')) return { ok: false, error: '*.wildcard needs a domain after it, e.g. *.example.test.' };
    return { ok: true, host: raw };
  }
  if (raw.includes('*')) return { ok: false, error: `${FORMS} — the wildcard goes first, as *.example.test.` };

  const colon = raw.indexOf(':');
  if (colon >= 0) {
    const host = raw.slice(0, colon);
    const port = raw.slice(colon + 1);
    if (!isHost(host)) return { ok: false, error: `${FORMS}.` };
    if (!isPort(port)) return { ok: false, error: 'Port must be 1–65535.' };
    return { ok: true, host: raw };
  }
  if (!isHost(raw)) return { ok: false, error: `${FORMS}.` };
  return { ok: true, host: raw };
}

/** Does a flow authority (`host` or `host:port`) fall under a scope pattern? */
export function matchesScope(authority: string, pattern: string): boolean {
  const a = authority.toLowerCase();
  const p = pattern.toLowerCase();
  const aHost = a.includes(':') ? a.slice(0, a.indexOf(':')) : a;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.test"
    return aHost.endsWith(suffix) && aHost.length > suffix.length;
  }
  if (p.includes(':')) return a === p;
  return aHost === p;
}

export const inScope = (authority: string, scope: readonly { host: string }[]): boolean =>
  scope.some((s) => matchesScope(authority, s.host));

/** Flows seen per scope entry, wildcard matches included. */
export function countSeen(authorities: Iterable<string>, pattern: string): number {
  let n = 0;
  for (const a of authorities) if (matchesScope(a, pattern)) n++;
  return n;
}

/** Hosts seen on the wire that no scope entry covers, keeping the sidebar's count order. */
export function outOfScopeHosts(
  domains: readonly { host: string; count: number }[],
  scope: readonly { host: string }[],
): { host: string; count: number }[] {
  return domains.filter((d) => !inScope(d.host, scope));
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const rec = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' ? (v as Record<string, unknown>) : null);

/** `10 rps · burst 20`; null when the entry carries no limit (the caller draws the dash). */
export function fmtRateLimit(rl: unknown): string | null {
  if (rl == null) return null;
  const n = num(rl);
  if (n != null) return `${n} rps`;
  const r = rec(rl);
  if (!r) return null;
  const rps = num(r.rps) ?? num(r.rate) ?? num(r.per_second);
  const burst = num(r.burst);
  if (rps == null && burst == null) return null;
  const parts: string[] = [];
  if (rps != null) parts.push(`${rps} rps`);
  if (burst != null) parts.push(`burst ${burst}`);
  return parts.join(' · ');
}

/** `500 ms → 8 s`; null when absent. */
export function fmtBackoff(b: unknown): string | null {
  if (b == null) return null;
  const r = rec(b);
  if (!r) return null;
  const base = num(r.base_ms) ?? num(r.initial_ms) ?? num(r.min_ms);
  const max = num(r.max_ms);
  if (base == null && max == null) return null;
  if (base != null && max != null) return `${fmtDuration(base)} → ${fmtDuration(max)}`;
  return fmtDuration(base ?? max);
}
