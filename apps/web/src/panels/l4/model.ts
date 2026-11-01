// The web L4 operator surface's client model (ui-ext Part 3 §3.1/§3.2, L4OPS Task 12).
//
// Pure wire types + mappers for the live `l4.*` bus. Every shape here mirrors a command result in
// `crates/aitm-proto-l4/src/commands/*` — nothing is invented. The surface feature-detects `l4.*`
// from `tools/list`; these functions are the kind-model the flow list and inspector render against
// so L4 is "data + renderers", never a rewrite, and an unknown/absent kind degrades honestly.

import { flowKinds } from '~/viewers/lang/defs.gen';

// ---- wire shapes (authoritative; see the hand-over note) ----------------------------------------

/** One packet in `l4.flow.get` — note: **no raw bytes** on the wire, only length + layer names. */
export interface L4PacketWire {
  dir: 'inbound' | 'outbound';
  length: number;
  injected: boolean;
  layers: string[];
}

/** `l4.flow.get {id}` result. */
export interface L4FlowWire {
  id: string;
  kind: 'capture' | 'craft' | 'send_recv' | 'intercept';
  interface: string;
  filter: string | null;
  queue: number | null;
  packet_count: number;
  injected_count: number;
  packets: L4PacketWire[];
}

/** One `l4.scope.list` entry. */
export interface L4ScopeEntryWire {
  id: string;
  cidr: string;
  ports: string;
  interface: string;
  direction: 'inbound' | 'outbound';
  capability: 'capture' | 'inject' | 'intercept';
  inject_rate: { pps: number; burst: number };
}

/** `l4.craft {spec}` result — `bytes` is base64 (decode with `lib/bytes.base64ToBytes`). */
export interface L4CraftResult {
  length: number;
  bytes: string;
  summary: { layers: string[]; length: number };
}

/** `l4.agent.status` / `l4.agent.set` result: the four per-capability agent gate states. */
export interface AgentGates {
  inject: boolean;
  capture: boolean;
  intercept: boolean;
  widen: boolean;
}

/** The per-feature MCP toggles, in the spec's display order (§3.5). */
export const AGENT_CAPS = ['capture', 'inject', 'intercept', 'widen'] as const;
export type AgentCap = (typeof AGENT_CAPS)[number];

export const AGENT_CAP_LABEL: Record<AgentCap, string> = {
  capture: 'Capture',
  inject: 'Inject',
  intercept: 'Intercept',
  widen: 'Widen',
};

// ---- the flow-kind model (ui-ext §3.1) ----------------------------------------------------------

export type FlowKind = 'http' | 'websocket' | 'l4';

/** The kinds the shared descriptor declares (`flow-kinds.json` → `defs.gen`). */
export const KNOWN_KINDS: readonly string[] = flowKinds.map((k) => k.kind);

export function isKnownKind(kind: string): kind is FlowKind {
  return KNOWN_KINDS.includes(kind);
}

/** The descriptor for one kind, or `undefined` when the kind is unknown/absent (→ placeholder). */
export function kindDescriptor(kind: string): (typeof flowKinds)[number] | undefined {
  return flowKinds.find((k) => k.kind === kind);
}

/** The list command a kind's rows come from (ui-ext `list_cmd` amendment). */
export function listCmd(kind: string): string | null {
  return kindDescriptor(kind)?.list_cmd ?? null;
}

// ---- L4 derivations -----------------------------------------------------------------------------

/** The `TCP`/`UDP`/`ICMP` sub-label from a packet's decoded layer names (§3.1). */
export function protoSubLabel(layers: readonly string[]): 'TCP' | 'UDP' | 'ICMP' | null {
  // Innermost transport wins; scan from the inside out so IPv4/UDP → UDP, not the network layer.
  for (let i = layers.length - 1; i >= 0; i--) {
    const l = layers[i]!.toLowerCase();
    if (l === 'tcp') return 'TCP';
    if (l === 'udp') return 'UDP';
    if (l === 'icmp' || l === 'icmpv6') return 'ICMP';
  }
  return null;
}

/** A flow's sub-label: the transport proto across all its packets (first that decodes one). */
export function flowSubLabel(flow: Pick<L4FlowWire, 'packets'>): 'TCP' | 'UDP' | 'ICMP' | null {
  for (const p of flow.packets) {
    const s = protoSubLabel(p.layers);
    if (s) return s;
  }
  return null;
}

const SESSION_STATE: Record<L4FlowWire['kind'], string> = {
  capture: 'capture',
  craft: 'craft',
  send_recv: 'send/recv',
  intercept: 'intercept',
};

export function l4SessionState(kind: L4FlowWire['kind']): string {
  return SESSION_STATE[kind];
}

/** The L4 target cell: `iface` + the scope-derived capture filter when one applies (§3.1). */
export function l4Target(flow: Pick<L4FlowWire, 'interface' | 'filter' | 'queue'>): string {
  const parts = [flow.interface];
  if (flow.filter) parts.push(flow.filter);
  if (flow.queue != null) parts.push(`queue ${flow.queue}`);
  return parts.join(' · ');
}

// ---- scope-as-authorization (§3.3) --------------------------------------------------------------

/** True iff a scope entry's interface authorizes `iface` (`*`/empty = any interface). */
export function scopeCoversInterface(entry: Pick<L4ScopeEntryWire, 'interface'>, iface: string): boolean {
  const i = entry.interface;
  return i === '' || i === '*' || i === 'any' || i === iface;
}

/**
 * Whether an L4 flow is in the operator's L4 scope, and the reason when it is not. The guard is the
 * real enforcement (the surface's dimming is a courtesy, spec Part 5); this drives the UI dimming.
 * A flow is in scope iff some scope entry covers its bind interface.
 */
export function flowScope(
  flow: Pick<L4FlowWire, 'interface'>,
  entries: readonly L4ScopeEntryWire[],
): { inScope: boolean; reason: string } {
  if (entries.some((e) => scopeCoversInterface(e, flow.interface))) {
    return { inScope: true, reason: '' };
  }
  return {
    inScope: false,
    reason: entries.length
      ? `Out of L4 scope: no scope entry covers interface ${flow.interface}. Add an L4 scope entry to authorize craft/inject/forward/drop here.`
      : `Out of L4 scope: no L4 scope is declared. Add an L4 scope entry (operator) to authorize any wire action.`,
  };
}

// ---- the union row the list renders -------------------------------------------------------------

export interface UnionRow {
  id: string;
  kind: string;
  /** Whether the kind is one the descriptor knows; `false` → labelled placeholder (AC7/AC12). */
  known: boolean;
  badge: string;
  /** The Badge `data-hue` for the kind (`l4` slate/indigo, method hues for http, `ws`, `grey`). */
  badgeHue: string;
  subLabel: string | null;
  /** The primary text cell: the URL for http/ws, the target for l4, the kind for a placeholder. */
  label: string;
  /** L4-only cells (absent for http/ws rows, which the existing HTTP renderer owns). */
  target?: string;
  state?: string;
  packetCount?: number;
  injectedCount?: number;
  inScope: boolean;
  scopeReason: string;
}

/** Map one `l4.flow.get` flow + the current L4 scope to a union row. */
export function l4Row(flow: L4FlowWire, scope: readonly L4ScopeEntryWire[]): UnionRow {
  const { inScope, reason } = flowScope(flow, scope);
  const target = l4Target(flow);
  return {
    id: flow.id,
    kind: 'l4',
    known: true,
    badge: 'L4',
    badgeHue: 'l4',
    subLabel: flowSubLabel(flow),
    label: target,
    target,
    state: l4SessionState(flow.kind),
    packetCount: flow.packet_count,
    injectedCount: flow.injected_count,
    inScope,
    scopeReason: reason,
  };
}

/** A row for a kind the surface does not know how to render — never nothing (AC7/AC12). */
export function placeholderRow(id: string, kind: string): UnionRow {
  return {
    id,
    kind,
    known: false,
    badge: kind ? kind.slice(0, 4).toUpperCase() : '??',
    badgeHue: 'grey',
    subLabel: null,
    label: kind ? `${kind} flow — this surface has no renderer for its kind yet` : 'unknown flow kind',
    inScope: true,
    scopeReason: '',
  };
}

// ---- human-friendly PacketSpec YAML (§3.2) ------------------------------------------------------
//
// The craft editor authors a `PacketSpec` as human-friendly YAML; this parses the constrained
// schema the bus accepts — `{ layers: [ {ipv4|ipv6|tcp|udp|icmp|ether: {k: v, ..}} | {raw: [..]} ] }`,
// outermost layer first — into the JSON object `l4.craft`/`l4.inject` take. It is deliberately a
// small, total parser for this one shape (block form, one-level-nested scalar fields, and `raw` as
// a byte array or a string), not a general YAML engine; anything outside the shape is a clear error
// the editor shows, never a silent misread.

export interface PacketSpec {
  layers: Record<string, unknown>[];
}

export type SpecParse = { spec: PacketSpec } | { error: string };

function parseScalar(raw: string): unknown {
  const t = raw.trim();
  if (t === '') return '';
  if (t === 'true') return true;
  if (t === 'false') return false;
  if (t === 'null' || t === '~') return null;
  if (/^-?\d+$/.test(t)) return Number(t);
  // A quoted string keeps its contents verbatim (so "08" stays a string, not octal).
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  // A bracketed inline array, e.g. raw: [1, 2, 3].
  if (t.startsWith('[') && t.endsWith(']')) {
    const inner = t.slice(1, -1).trim();
    if (inner === '') return [];
    return inner.split(',').map((x) => parseScalar(x));
  }
  return t;
}

/** `raw` accepts a byte array (`[..]`) or a string (→ its UTF-8 code units). */
function normalizeRaw(value: unknown): number[] | { error: string } {
  if (typeof value === 'string') return Array.from(new TextEncoder().encode(value));
  if (Array.isArray(value)) {
    const out: number[] = [];
    for (const b of value) {
      if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) {
        return { error: `raw bytes must be integers 0–255, got ${JSON.stringify(b)}` };
      }
      out.push(b);
    }
    return out;
  }
  return { error: 'raw must be a byte array or a string' };
}

export function parsePacketSpec(text: string): SpecParse {
  const lines = text.split('\n').map((l) => {
    // A whole-line comment becomes blank; a trailing ` # …` comment is trimmed (quoted `#` is
    // left for the scalar parser, which reads quotes first).
    if (l.trim().startsWith('#')) return '';
    return l.replace(/\s+#.*$/, '');
  });
  let i = 0;
  // Skip blanks/comments to the `layers:` key.
  while (i < lines.length && lines[i]!.trim() === '') i++;
  const header = lines[i]?.trim();
  if (header !== 'layers:' && header !== 'layers: []') {
    return { error: "expected a top-level `layers:` key (e.g. `layers:` then `  - ipv4:` …)" };
  }
  if (header === 'layers: []') return { spec: { layers: [] } };
  i++;

  const layers: Record<string, unknown>[] = [];
  let current: { name: string; fields: Record<string, unknown> } | null = null;
  const flush = () => {
    if (current) layers.push({ [current.name]: current.fields });
    current = null;
  };

  for (; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === '') continue;
    const dash = line.match(/^(\s*)-\s+(.*)$/);
    if (dash) {
      flush();
      const body = dash[2]!.trim();
      // `- raw: [..]` / `- raw: "text"` or `- ipv4:` (fields follow) or `- ipv4: {}`.
      const kv = body.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
      if (!kv) return { error: `malformed layer entry: "${body.trim()}"` };
      const name = kv[1]!;
      const rest = kv[2]!.trim();
      if (name === 'raw') {
        const norm = normalizeRaw(parseScalar(rest));
        if (!Array.isArray(norm)) return norm;
        layers.push({ raw: norm });
        current = null;
      } else if (rest === '' || rest === '{}') {
        current = { name, fields: {} };
      } else {
        return { error: `layer \`${name}\` fields must be nested on the following lines, not inline` };
      }
      continue;
    }
    // A nested `key: value` field of the current layer.
    const field = line.match(/^(\s+)([A-Za-z0-9_]+):\s*(.*)$/);
    if (field && current) {
      current.fields[field[2]!] = parseScalar(field[3]!);
      continue;
    }
    return { error: `unexpected line: "${line.trim()}"` };
  }
  flush();
  if (layers.length === 0) return { error: 'at least one layer is required' };
  return { spec: { layers } };
}

/** The default craft document the editor opens with (a scoped loopback UDP probe). */
export const DEFAULT_CRAFT_YAML = `# A scapy-style PacketSpec: outermost layer first.
# Omitted header fields auto-complete; a 'Some' value ships verbatim (even a forced-bad one).
layers:
  - ipv4:
      dst: 127.0.0.1
  - udp:
      dst_port: 9
  - raw: "probe"
`;
