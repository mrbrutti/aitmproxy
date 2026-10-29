// Activity-log logic (foundation §2.7 "Agent toggle", §4.8): origin labels, the compact args
// summary, and the All / Agent / Human / Errors filters. Pure, so the table stays a thin view.

import type { ActivityEntry, AgentPolicy } from '~/state/app';

export type ActivityKind = 'all' | 'agent' | 'human' | 'errors';

export const ACTIVITY_KINDS: readonly { id: ActivityKind; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'agent', label: 'Agent' },
  { id: 'human', label: 'Human' },
  { id: 'errors', label: 'Errors' },
];

/** The MCP transport is the agent; every other frontend is a human surface. */
export const isAgent = (e: Pick<ActivityEntry, 'origin'>): boolean => e.origin === 'mcp';

/** `mcp` reads as `agent` in the log; the human surfaces keep their names. */
export const originLabel = (origin: ActivityEntry['origin']): string => (origin === 'mcp' ? 'agent' : origin);

export const POLICY_OPTIONS: readonly { id: AgentPolicy; label: string; explain: string }[] = [
  { id: 'all', label: 'Allow all tools', explain: 'The agent may call every tool.' },
  { id: 'readonly', label: 'Read-only', explain: 'list/get/status only; mutating calls are refused.' },
  { id: 'paused', label: 'Paused', explain: 'Every agent call returns ‘paused by operator’.' },
];

/**
 * One-line compact JSON of the call's arguments: `{"id":"f_1k","mode":"429"}`. Empty when there
 * are none (the row draws a dash). Strings are kept as JSON so quoting stays unambiguous.
 */
export function summarizeArgs(args: unknown): string {
  if (args === undefined || args === null) return '';
  if (typeof args === 'object' && !Array.isArray(args) && Object.keys(args as object).length === 0) return '';
  if (Array.isArray(args) && args.length === 0) return '';
  try {
    return JSON.stringify(args) ?? '';
  } catch {
    return String(args);
  }
}

/** The full, indented form for the hover title. */
export function fullArgs(args: unknown): string {
  if (args === undefined || args === null) return '';
  try {
    return typeof args === 'object' ? (JSON.stringify(args, null, 2) ?? '') : String(args);
  } catch {
    return String(args);
  }
}

export interface ActivityFilter {
  kind: ActivityKind;
  /** Case-insensitive match on command, origin, args and detail. */
  query: string;
  /** "Clear view": hide entries with seq ≤ this (local, never deletes). */
  clearedThrough: number;
}

const matchesKind = (e: ActivityEntry, kind: ActivityKind): boolean => {
  switch (kind) {
    case 'all':
      return true;
    case 'agent':
      return isAgent(e);
    case 'human':
      return !isAgent(e);
    case 'errors':
      return e.result === 'error';
  }
};

/** Newest first, filtered. */
export function filterActivity(list: readonly ActivityEntry[], f: ActivityFilter): ActivityEntry[] {
  const q = f.query.trim().toLowerCase();
  const out: ActivityEntry[] = [];
  for (let i = list.length - 1; i >= 0; i--) {
    const e = list[i]!;
    if (e.seq <= f.clearedThrough) continue;
    if (!matchesKind(e, f.kind)) continue;
    if (q) {
      const hay = `${e.command} ${originLabel(e.origin)} ${summarizeArgs(e.args)} ${e.detail ?? ''}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    out.push(e);
  }
  return out;
}

/** Epoch ms from the entry's ISO `at`; NaN-safe (a bad timestamp renders as a dash). */
export const atMs = (e: Pick<ActivityEntry, 'at'>): number | null => {
  const t = Date.parse(e.at);
  return Number.isFinite(t) ? t : null;
};
