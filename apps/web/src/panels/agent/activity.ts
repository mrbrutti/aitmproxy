// Activity-log logic (foundation §2.7 "Agent toggle", §4.8): origin labels, the compact args
// summary, the All / Agent / Human / Errors filters, and the rule that drops the UI's own polling
// from the log. Pure, so the table stays a thin view.

import { CLIENT_INFO, type AgentNotification, type BusRole } from '~/bus/types';
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

/**
 * The reads the UI issues on timers or in bulk refreshes (push spec D7). Every call is audited and
 * echoed back to us, so a successful one of these from this connection is the UI watching itself.
 */
export const UI_BACKGROUND_READS: ReadonlySet<string> = new Set([
  'flow.list',
  'flow.get',
  'flow.detail',
  'proxy.status',
  'agent.status',
  'agent.activity',
  'scope.list',
  'poc.list',
  'l4.flow.list',
  'l4.flow.get',
  'l4.scope.list',
  'l4.capture.status',
  'l4.agent.status',
  'l4.intercept.status',
  'l4.intercept.list',
  'browser.tabs',
  'browser.screenshot',
]);

/** The audit `origin` the server records for calls made under this connection's role; unknown matches nothing. */
export function ownOriginOf(role: BusRole | null): 'operator' | 'mcp' | null {
  if (role === 'operator') return 'operator';
  if (role === 'agent') return 'mcp';
  return null;
}

/**
 * The flood rule (push spec D7): a line is dropped iff it succeeded, names a background read,
 * and is ours — labelled with our `clientInfo.name` (what a labelled bridge would send), or
 * unlabelled from our own origin (the bridge labels nothing today, so own-ness is inferred).
 * Everything else stays: every action, every error, every labelled client, other frontends' reads.
 */
export function isUiPollNoise(
  e: Pick<AgentNotification, 'origin' | 'command' | 'result' | 'clientLabel'>,
  own: { origin: AgentNotification['origin'] | null },
): boolean {
  if (e.result !== 'ok') return false;
  if (!UI_BACKGROUND_READS.has(e.command)) return false;
  if (e.clientLabel === CLIENT_INFO.name) return true;
  return e.clientLabel == null && own.origin !== null && e.origin === own.origin;
}
