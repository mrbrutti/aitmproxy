// Command palette model (§2.7): the query grammar (`>` commands only, `/` flows only), the
// grouped result list (Recent · Pinned · Commands · Flows · Setup) and the recent/pinned
// persistence. Pure, so grouping is tested with a stubbed tools list.

import type { ToolDef } from '~/bus/types';
import type { FlowEntry } from '~/state/app';
import { flowUrl } from '~/model/flow';
import { fuzzyRank } from '~/lib/fuzzy';
import type { IconName } from '~/components/Icon';

export interface SetupAction {
  id: string;
  label: string;
  icon: IconName;
  /** Secondary text. */
  hint?: string | undefined;
  /** When set, selecting the action selects this bus command (its form path) instead of `run`. */
  tool?: string | undefined;
  /** Initial arguments for `tool`'s form (the CA action's `{ scope: 'user' }` on macOS/Windows). */
  args?: Record<string, unknown> | undefined;
  run?: (() => void | Promise<unknown>) | undefined;
}

export type PaletteItem =
  | { kind: 'command'; key: string; tool: ToolDef; nameHits: number[] | null; descHits: number[] | null; pinned: boolean }
  | { kind: 'flow'; key: string; entry: FlowEntry; hits: number[] | null }
  | { kind: 'setup'; key: string; action: SetupAction; hits: number[] | null };

export type GroupId = 'recent' | 'pinned' | 'commands' | 'flows' | 'setup';

export interface PaletteGroup {
  id: GroupId;
  label: string;
  items: PaletteItem[];
}

export type QueryMode = 'all' | 'commands' | 'flows';

export function parseQuery(raw: string): { mode: QueryMode; text: string } {
  if (raw.startsWith('>')) return { mode: 'commands', text: raw.slice(1).trim() };
  if (raw.startsWith('/')) return { mode: 'flows', text: raw.slice(1).trim() };
  return { mode: 'all', text: raw.trim() };
}

export const commandKey = (name: string) => `cmd:${name}`;
export const setupKey = (id: string) => `setup:${id}`;

export interface BuildOptions {
  query: string;
  tools: readonly ToolDef[];
  /** Flows in capture order (oldest first); the palette shows the newest. */
  flows: readonly FlowEntry[];
  recent: readonly string[];
  pinned: readonly string[];
  setup: readonly SetupAction[];
  /** Cap on flow results (default 8 with a query, 6 without). */
  maxFlows?: number | undefined;
}

export function buildGroups(o: BuildOptions): PaletteGroup[] {
  const { mode, text } = parseQuery(o.query);
  const groups: PaletteGroup[] = [];
  const pinnedSet = new Set(o.pinned);
  const toolByName = new Map(o.tools.map((t) => [t.name, t]));
  const setupById = new Map(o.setup.map((s) => [s.id, s]));

  const commandItem = (t: ToolDef, nameHits: number[] | null = null, descHits: number[] | null = null): PaletteItem => ({
    kind: 'command',
    key: commandKey(t.name),
    tool: t,
    nameHits,
    descHits,
    pinned: pinnedSet.has(t.name),
  });

  if (mode === 'all' && !text) {
    const items: PaletteItem[] = [];
    for (const key of o.recent) {
      if (key.startsWith('cmd:')) {
        const t = toolByName.get(key.slice(4));
        if (t) items.push(commandItem(t));
      } else if (key.startsWith('setup:')) {
        const s = setupById.get(key.slice(6));
        if (s) items.push({ kind: 'setup', key, action: s, hits: null });
      }
    }
    if (items.length) groups.push({ id: 'recent', label: 'Recent', items });
  }

  if (mode !== 'flows') {
    const ranked = fuzzyRank(o.tools, text, (t) => [t.name, t.description]);
    const pinnedItems: PaletteItem[] = [];
    const rest: PaletteItem[] = [];
    for (const r of ranked) {
      const item = commandItem(r.item, r.matches[0] ?? null, r.matches[1] ?? null);
      (item.kind === 'command' && item.pinned ? pinnedItems : rest).push(item);
    }
    if (pinnedItems.length) groups.push({ id: 'pinned', label: 'Pinned', items: pinnedItems });
    if (rest.length) groups.push({ id: 'commands', label: 'Commands', items: rest });
  }

  if (mode !== 'commands') {
    const max = o.maxFlows ?? (text ? 8 : 6);
    const newest = o.flows.slice(Math.max(0, o.flows.length - 400)).reverse();
    const items: PaletteItem[] = [];
    for (const e of newest) {
      if (items.length >= max) break;
      const m = matchFlow(e, text);
      if (m) items.push({ kind: 'flow', key: `flow:${e.id}`, entry: e, hits: m });
    }
    if (items.length) groups.push({ id: 'flows', label: 'Flows', items });
  }

  if (mode === 'all') {
    const ranked = fuzzyRank(o.setup, text, (s) => [s.label, s.hint ?? '']);
    if (ranked.length) groups.push({ id: 'setup', label: 'Setup', items: ranked.map((r) => ({ kind: 'setup', key: setupKey(r.item.id), action: r.item, hits: r.matches[0] ?? null })) });
  }
  return groups;
}

/**
 * Flows match on substrings, not subsequences: URLs are long and almost any short query is a
 * subsequence of one. Every whitespace-separated term must appear in the URL, the method or the
 * status. Returns the URL indices to emphasise (empty array when only method/status matched).
 */
export function matchFlow(e: FlowEntry, text: string): number[] | null {
  if (!text) return [];
  const url = flowUrl(e.raw).toLowerCase();
  const meta = `${e.raw.kind === 'websocket' ? 'ws' : e.raw.method} ${e.raw.status ?? ''} ${e.raw.intercept === 'paused' ? 'paused' : ''}`.toLowerCase();
  const hits: number[] = [];
  for (const term of text.toLowerCase().split(/\s+/).filter(Boolean)) {
    const at = url.indexOf(term);
    if (at >= 0) {
      for (let i = at; i < at + term.length; i++) hits.push(i);
    } else if (!meta.includes(term)) return null;
  }
  return hits;
}

export const flatten = (groups: PaletteGroup[]): PaletteItem[] => groups.flatMap((g) => g.items);

// ---- persistence --------------------------------------------------------------------------

export const RECENT_KEY = 'aitm.palette.recent';
export const PINNED_KEY = 'aitm.palette.pinned';
export const RECENT_MAX = 6;

type Store = Pick<Storage, 'getItem' | 'setItem'>;
const storage = (): Store | null => (typeof localStorage === 'undefined' ? null : localStorage);

function readList(key: string, s: Store | null): string[] {
  try {
    const v = s?.getItem(key);
    const list = v ? (JSON.parse(v) as unknown) : [];
    return Array.isArray(list) ? list.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
function writeList(key: string, list: string[], s: Store | null) {
  try {
    s?.setItem(key, JSON.stringify(list));
  } catch {
    /* private mode */
  }
}

export const readRecent = (s: Store | null = storage()) => readList(RECENT_KEY, s);
export const readPinned = (s: Store | null = storage()) => readList(PINNED_KEY, s);

export function pushRecent(key: string, s: Store | null = storage()): string[] {
  const next = [key, ...readRecent(s).filter((k) => k !== key)].slice(0, RECENT_MAX);
  writeList(RECENT_KEY, next, s);
  return next;
}

export function togglePinned(name: string, s: Store | null = storage()): string[] {
  const cur = readPinned(s);
  const next = cur.includes(name) ? cur.filter((n) => n !== name) : [...cur, name];
  writeList(PINNED_KEY, next, s);
  return next;
}

/** Flow ids referenced by a tool result: a bare id string, or string values one level deep. */
export function flowIdsIn(result: unknown, has: (id: string) => boolean): { label: string | null; id: string }[] {
  if (typeof result === 'string') return has(result) ? [{ label: null, id: result }] : [];
  if (result && typeof result === 'object' && !Array.isArray(result)) {
    const out: { label: string | null; id: string }[] = [];
    for (const [k, v] of Object.entries(result as Record<string, unknown>)) if (typeof v === 'string' && has(v)) out.push({ label: k, id: v });
    return out;
  }
  return [];
}

/** Compact JSON for the inline result: at most `maxLines` lines, the rest elided. */
export function compactJson(value: unknown, maxLines = 8): { text: string; truncated: boolean } {
  let text: string;
  if (value === undefined) text = 'ok';
  else if (typeof value === 'string') text = value;
  else {
    try {
      text = JSON.stringify(value, null, 2) ?? String(value);
    } catch {
      text = String(value);
    }
  }
  const lines = text.split('\n');
  if (lines.length <= maxLines) return { text, truncated: false };
  return { text: lines.slice(0, maxLines).join('\n'), truncated: true };
}
