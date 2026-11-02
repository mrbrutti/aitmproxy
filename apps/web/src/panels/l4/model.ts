// The web L4 operator surface's client model (ui-ext Part 3 §3.1/§3.2, L4OPS Task 12).
//
// Pure wire types + mappers for the live `l4.*` bus. Every shape here mirrors a command result in
// `crates/aitm-proto-l4/src/commands/*` — nothing is invented. The surface feature-detects `l4.*`
// from `tools/list`; these functions are the kind-model the flow list and inspector render against
// so L4 is "data + renderers", never a rewrite, and an unknown/absent kind degrades honestly.

import { flowKinds } from '~/viewers/lang/defs.gen';

// ---- wire shapes (authoritative; see the hand-over note) ----------------------------------------

/**
 * One packet in `l4.flow.get`. The four original fields are always present; the parity spec (§2)
 * adds the rest, all optional because an older core omits them and `bytes` is also per-caller
 * (§2.2: absent when the caller may not see the payload).
 */
export interface L4PacketWire {
  dir: 'inbound' | 'outbound';
  length: number;
  injected: boolean;
  layers: string[];
  /** On-wire bytes, standard padded base64 (decode with `lib/bytes.base64ToBytes`). */
  bytes?: string;
  /** Epoch milliseconds, UTC. */
  timestamp?: number;
  proto?: 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | string | null;
  src?: string | null;
  dst?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
}

/** `l4.flow.get {id, offset?, limit?}` result (spec §2: the window fields are optional, older cores omit them). */
export interface L4FlowWire {
  id: string;
  kind: 'capture' | 'craft' | 'send_recv' | 'intercept';
  interface: string;
  filter: string | null;
  queue: number | null;
  packet_count: number;
  injected_count: number;
  packets: L4PacketWire[];
  /** Flow creation, epoch ms. */
  started_at?: number;
  /** Flow-level addresses from the first decodable packet, so a list row needs no packets. */
  proto?: string | null;
  src?: string | null;
  dst?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  /** The window this reply starts at (`packet_count` stays the total). */
  offset?: number;
  /** True when the byte budget cut the window short; `next_offset` is then the next index. */
  truncated?: boolean;
  next_offset?: number | null;
}

/** One `l4.scope.list` entry; `source` arrives with the parity core (spec §3). */
export interface L4ScopeEntryWire {
  id: string;
  cidr: string;
  ports: string;
  interface: string;
  direction: 'inbound' | 'outbound';
  capability: 'capture' | 'inject' | 'intercept';
  inject_rate: { pps: number; burst: number };
  source?: 'config' | 'runtime';
}

/** One `l4.intercept.list` entry: a packet parked in-path awaiting a verdict (spec §4). */
export interface L4ParkedWire {
  id: string;
  flow: string;
  state: 'parked' | 'mutated';
  dir: 'inbound' | 'outbound';
  length: number;
  layers: string[];
  /** Epoch ms; the list is in arrival order, oldest first. */
  parked_at?: number;
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

/**
 * A flow's sub-label. The flow-level `proto` (spec §2, from the first decodable packet) wins, since
 * list rows are read with `limit: 0` and carry no packets; otherwise the first packet that decodes a
 * transport.
 */
export function flowSubLabel(flow: Pick<L4FlowWire, 'packets' | 'proto'>): 'TCP' | 'UDP' | 'ICMP' | null {
  if (flow.proto) {
    const s = protoSubLabel([flow.proto]);
    if (s) return s;
  }
  for (const p of flow.packets) {
    const s = protoSubLabel(p.layers);
    if (s) return s;
  }
  return null;
}

// ---- the TCP / UDP / L4 chips (parity spec §7(c), AC21) ------------------------------------------

export type L4Chip = 'tcp' | 'udp' | 'l4';

/** Whether a chip id is one of the L4 chips; the HTTP chips never show an L4 row. */
export function isL4Chip(chip: string): chip is L4Chip {
  return chip === 'tcp' || chip === 'udp' || chip === 'l4';
}

/** `l4` matches every L4 row; `tcp` / `udp` match by the row's sub-label; any other chip never. */
export function l4ChipMatches(chip: string, row: Pick<UnionRow, 'subLabel'>): boolean {
  switch (chip) {
    case 'l4':
      return true;
    case 'tcp':
      return row.subLabel === 'TCP';
    case 'udp':
      return row.subLabel === 'UDP';
    default:
      return false;
  }
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

// ---- availability seam (parity spec §1) ---------------------------------------------------------
//
// `l4.capture.status` / `l4.intercept.status` always answer with `{available, code, reason,
// captures|sessions}` on a parity core. An older core answers a bare array (⇒ available) or refuses
// the gated verbs with an error whose text carries `L4 unavailable: <reason>`. Both shapes map here,
// so the UI never caches availability and never crashes on either core.

export interface L4Availability {
  available: boolean;
  code: string | null;
  reason: string | null;
}

/** Until the first status reply lands: not available, with the literal every UI shows. */
export const PENDING_AVAILABILITY: L4Availability = Object.freeze({
  available: false,
  code: null,
  reason: 'Reading L4 availability…',
});

/** True while `avail` is the pending placeholder (the frozen constant or an equal copy): no status reply yet. */
export function isPendingAvailability(avail: L4Availability): boolean {
  return avail === PENDING_AVAILABILITY || (avail.available === false && avail.code === null && avail.reason === PENDING_AVAILABILITY.reason);
}

const L4_UNAVAILABLE_MARKER = 'L4 unavailable: ';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Map a status reply (new object or older bare array) to availability. */
export function availabilityFromReply(reply: unknown): L4Availability {
  if (Array.isArray(reply)) return { available: true, code: null, reason: null };
  if (isRecord(reply) && typeof reply.available === 'boolean') {
    return {
      available: reply.available,
      code: typeof reply.code === 'string' ? reply.code : null,
      reason: typeof reply.reason === 'string' ? reply.reason : null,
    };
  }
  // Neither shape: say so rather than guess; the control stays off with a visible reason.
  return { available: false, code: null, reason: 'unrecognised L4 status reply' };
}

/**
 * An older core's refusal, `…L4 unavailable: <reason>`, as availability; `null` when the message
 * is some other error (a transport failure is not "L4 unavailable").
 */
export function availabilityFromError(message: string): L4Availability | null {
  const at = message.indexOf(L4_UNAVAILABLE_MARKER);
  if (at < 0) return null;
  return { available: false, code: null, reason: message.slice(at + L4_UNAVAILABLE_MARKER.length) };
}

/**
 * The ids carried by a status reply: `captures` are flow-id strings, `sessions` are objects keyed
 * by `flow`. A bare array (older core) is read the same way.
 */
export function statusIds(reply: unknown, key: 'captures' | 'sessions'): string[] {
  const items: unknown = Array.isArray(reply) ? reply : isRecord(reply) ? reply[key] : undefined;
  if (!Array.isArray(items)) return [];
  const out: string[] = [];
  for (const item of items) {
    if (typeof item === 'string') out.push(item);
    else if (isRecord(item)) {
      const id = typeof item.id === 'string' ? item.id : typeof item.flow === 'string' ? item.flow : null;
      if (id) out.push(id);
    }
  }
  return out;
}

// ---- argument builders (AC18–AC20, AC22) --------------------------------------------------------
//
// Every L4 action builds its arguments here, and `L4_ARG_BUILDERS` lists each key per verb so the
// live schema check (args.test.ts) can prove each one is in the core's inputSchema.

export type L4Direction = 'inbound' | 'outbound';

/** `l4.capture.start`: interface + direction only; the core derives the BPF filter from scope. */
export function captureStartArgs(iface: string, direction: L4Direction): { interface: string; direction: L4Direction } {
  return { interface: iface, direction };
}

/** `l4.capture.stop {id}` for one running capture. */
export function captureStopArgs(id: string): { id: string } {
  return { id };
}

/** One `l4.capture.stop` argument object per running capture id. */
export function stopAllArgs(ids: readonly string[]): { id: string }[] {
  return ids.map((id) => captureStopArgs(id));
}

/** `l4.intercept.forward` / `l4.intercept.drop`: the parked packet id (spec §4), never the flow id. */
export function verdictArgs(parkedId: string): { id: string } {
  return { id: parkedId };
}

/** `l4.intercept.mutate {id, spec}`. */
export function mutateArgs(parkedId: string, spec: PacketSpec): { id: string; spec: PacketSpec } {
  return { id: parkedId, spec };
}

/** `l4.intercept.revert {id}`. */
export function revertArgs(parkedId: string): { id: string } {
  return { id: parkedId };
}

/** The scope add form's draft, one field per `l4.scope.add` argument. */
export interface L4ScopeDraft {
  cidr: string;
  ports: string;
  interface: string;
  direction: L4Direction;
  capability: 'capture' | 'inject' | 'intercept';
}

/** `l4.scope.add` arguments, in the form's field order. */
export function scopeAddArgs(d: L4ScopeDraft): L4ScopeDraft {
  return { cidr: d.cidr, ports: d.ports, interface: d.interface, direction: d.direction, capability: d.capability };
}

/** The inspector's packet window size (spec §2 default). */
export const L4_INSPECT_LIMIT = 256;

/**
 * `l4.flow.get` arguments. With the window (parity core): list rows ask `limit: 0` (flow fields
 * only), the inspector asks a window starting at `offset` (0 for the first read; the reply's
 * `next_offset` for "load more" after a `truncated` reply, spec §2 byte budget). Without the window
 * (older core) only `{id}`, which the older schema accepts.
 */
export function flowGetArgs(
  id: string,
  mode: 'list' | 'inspect',
  window: boolean,
  offset = 0,
): { id: string; offset?: number; limit?: number } {
  if (!window) return { id };
  return mode === 'list' ? { id, limit: 0 } : { id, offset, limit: L4_INSPECT_LIMIT };
}

// ---- packet display (spec §2 fields, §2.3 inert text; AC40) --------------------------------------------
//
// Pure renderers for the inspector. Every string here is built from the packet's decoded fields or
// from its bytes mapped through `asciiColumn`, so the components can drop them into text nodes with
// nothing else to sanitise: no byte outside 0x20–0x7e ever reaches the DOM as itself.

/**
 * One line for a packet row: `127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B` when the core decoded
 * the addresses (ports only when it has them); otherwise the layer stack (`IPv4 · UDP · 36 B`, with
 * `proto` appended only when it is not already the innermost layer), `raw` for an undecoded packet.
 */
export function packetHeadline(p: L4PacketWire): string {
  const size = `${p.length} B`;
  const parts: string[] = [];
  if (p.src != null && p.dst != null) {
    parts.push(`${endpoint(p.src, p.src_port)} → ${endpoint(p.dst, p.dst_port)}`);
    if (p.proto) parts.push(p.proto);
  } else {
    parts.push(...(p.layers.length ? p.layers : ['raw']));
    if (p.proto && p.layers[p.layers.length - 1] !== p.proto) parts.push(p.proto);
  }
  parts.push(size);
  return parts.join(' · ');
}

function endpoint(addr: string, port: number | null | undefined): string {
  return port != null ? `${addr}:${port}` : addr;
}

/**
 * A packet `timestamp` (epoch ms) as a wall clock, `HH:MM:SS.mmm`, 24-hour. `timeZone` is an IANA
 * zone name; omitted, the local zone (what the packet list shows the operator).
 */
export function formatPacketTime(ms: number, timeZone?: string): string {
  const parts = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone }).formatToParts(
    new Date(ms),
  );
  const part = (type: 'hour' | 'minute' | 'second') => (parts.find((p) => p.type === type)?.value ?? '00').padStart(2, '0');
  const millis = String(((ms % 1000) + 1000) % 1000).padStart(3, '0');
  return `${part('hour')}:${part('minute')}:${part('second')}.${millis}`;
}

/** The printable-ASCII column of a hex dump: 0x20–0x7e as themselves, every other byte as `.` (spec §2.3). */
export function asciiColumn(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
  return out;
}

/** Bytes per `hexRows` line. */
const HEX_ROW_BYTES = 16;
/** Width of a full row's hex region: 16 × 2 digits + 15 separators + the extra gap after the 8th byte. */
const HEX_REGION_WIDTH = HEX_ROW_BYTES * 2 + (HEX_ROW_BYTES - 1) + 1;

/**
 * A classic hex dump, one string per 16 bytes: an 8-digit hex offset, two spaces, the bytes as
 * two-digit lowercase hex separated by spaces (an extra space after the 8th, padded so the ASCII
 * column lines up), two spaces, then `|` + `asciiColumn` + `|`. No character of any row is below
 * 0x20 (AC40); the caller adds its own line breaks.
 */
export function hexRows(bytes: Uint8Array): string[] {
  const rows: string[] = [];
  for (let start = 0; start < bytes.length; start += HEX_ROW_BYTES) {
    const chunk = bytes.subarray(start, start + HEX_ROW_BYTES);
    let hex = '';
    for (let i = 0; i < chunk.length; i++) {
      if (i > 0) hex += i === HEX_ROW_BYTES / 2 ? '  ' : ' ';
      hex += chunk[i]!.toString(16).padStart(2, '0');
    }
    rows.push(`${start.toString(16).padStart(8, '0')}  ${hex.padEnd(HEX_REGION_WIDTH)}  |${asciiColumn(chunk)}|`);
  }
  return rows;
}

/** The flow's first-listed (oldest) parked packet, or `null` when none is parked for it. */
export function parkedFor(parked: readonly L4ParkedWire[], flowId: string): L4ParkedWire | null {
  return parked.find((p) => p.flow === flowId) ?? null;
}

// ---- intercept bar model (spec §4, AC20) ------------------------------------------------------------
//
// What the intercept bar renders for the selected flow. Before the first `l4.intercept.status`
// reply it is pending: exactly the shared `Reading L4 availability…` literal (spec §1), not a
// conclusion the core has not given. Intercept unavailable is one documented-limited line with the
// core's reason and no live buttons; available with a packet parked for the flow carries that
// parked id (the verdicts' argument, never the flow id) and its `state`, because Revert on a packet
// that was never mutated is a no-op on the core (`l4.intercept.revert` answers `false`) and so must
// not be a live control; available with nothing parked is a quiet idle line.

export type InterceptBarModel =
  | { kind: 'pending' }
  | { kind: 'limited'; reason: string }
  | { kind: 'idle' }
  | { kind: 'parked'; id: string; state: L4ParkedWire['state'] };

export function interceptBarModel(avail: L4Availability, parked: readonly L4ParkedWire[], flowId: string): InterceptBarModel {
  if (isPendingAvailability(avail)) return { kind: 'pending' };
  if (!avail.available) return { kind: 'limited', reason: avail.reason ?? '' };
  const p = parkedFor(parked, flowId);
  return p ? { kind: 'parked', id: p.id, state: p.state } : { kind: 'idle' };
}

// ---- tools/list feature detects -------------------------------------------------------------------

/** True iff `l4.flow.get` declares `limit` (the parity core's bounded window, spec §2). */
export function supportsFlowWindow(
  tools: readonly { name: string; inputSchema?: { properties?: Record<string, unknown> } }[],
): boolean {
  const t = tools.find((x) => x.name === 'l4.flow.get');
  return !!t && !!t.inputSchema?.properties && 'limit' in t.inputSchema.properties;
}

/** True iff `l4.scope.add` is offered with `confirmable: true` (spec §3; AC39): the add form only then. */
export function supportsOperatorScopeAdd(tools: readonly { name: string; confirmable?: unknown }[]): boolean {
  return tools.some((t) => t.name === 'l4.scope.add' && t.confirmable === true);
}

/** Every verb the builders above emit, with its argument keys, for the live schema check (AC18). */
export const L4_ARG_BUILDERS: readonly { tool: string; keys: readonly string[] }[] = [
  { tool: 'l4.capture.start', keys: ['interface', 'direction'] },
  { tool: 'l4.capture.stop', keys: ['id'] },
  { tool: 'l4.intercept.forward', keys: ['id'] },
  { tool: 'l4.intercept.drop', keys: ['id'] },
  { tool: 'l4.intercept.mutate', keys: ['id', 'spec'] },
  { tool: 'l4.intercept.revert', keys: ['id'] },
  { tool: 'l4.scope.add', keys: ['cidr', 'ports', 'interface', 'direction', 'capability'] },
  { tool: 'l4.flow.get', keys: ['id', 'offset', 'limit'] },
];

// ---- operator-only gate (parity spec §7(c) D12, AC24) ---------------------------------------------
//
// Every Sensitive L4 action (capture start/stop, inject, scope add, the parked-packet verdicts, the
// agent gate toggles) is operator-only on the core. On a connection that did not resolve to the
// operator role — an agent token, or no role echo yet — each such control renders disabled with this
// one reason and its handler returns before anything reaches the bus, so no enabled control can only
// fail (AC33). The connection role comes from the bus client's `initialize` echo (`bus.role()`).

/** The one operator-only reason, verbatim: shown as each gated control's `title` and reason line. */
export const OPERATOR_ONLY_REASON = 'Operator only: reconnect with the Operator URL the core printed';

/** `null` on an operator connection (nothing is gated); the reason for an agent or an unknown role. */
export function operatorOnlyReason(role: 'operator' | 'agent' | null): string | null {
  return role === 'operator' ? null : OPERATOR_ONLY_REASON;
}

// ---- no HTTP verbs on L4 ids (parity spec §7(c) D9 UI, AC33) -----------------------------------
//
// L4 sessions are rows in the one flow list, but `flow.replay`, `flow.mark`, `flow.comment`,
// `poc.build`, `flow.resume`/`flow.kill`/`flow.mutate` are HTTP verbs: the core resolves their id
// in the HTTP `FlowStore` and an L4 id can only fail. The flow list, the context menu and the
// keyboard ask this before acting, and return with `L4_NO_HTTP_VERBS` instead of a bus call.

/** The notice the UI shows when an HTTP verb is asked of an L4 row. */
export const L4_NO_HTTP_VERBS = 'Not available for L4 flows';

/** False iff `id` is an L4 session id (registered by the L4 store in `app.l4Ids()`). */
export function httpVerbAllowed(id: string, l4Ids: ReadonlySet<string>): boolean {
  return !l4Ids.has(id);
}

// ---- poll plan (parity spec §7(c) "Polling", AC23) ------------------------------------------------
//
// The app's 1.5 s timer calls `store.refresh()`; the store asks this plan what is due and returns
// early when nothing is. While the lane is idle (capture unavailable and `l4.flow.list` empty) a
// `tick` (`l4.flow.list`, `l4.capture.status`, `l4.intercept.status`) is due every 10 s and a
// `slow` (`l4.scope.list`, `l4.agent.status`) every 60 s: 6 × 3 + 1 × 2 = 20 `l4.*` calls a
// minute, under AC23's 30. Not idle ⇒ both on every timer call. The plan is pure; the caller
// records `now` into the clock for each part that fired.

/** The timer interval `state/context.tsx` drives the store with. */
export const L4_ACTIVE_MS = 1500;
/** Idle: the fast group's interval. */
export const L4_IDLE_TICK_MS = 10_000;
/** Idle: the slow group's interval (availability is re-read here, never cached for the session). */
export const L4_IDLE_SLOW_MS = 60_000;

export interface L4PollClock {
  /** When the last `tick` fired (epoch or monotonic ms, the caller's choice); `null` before the first. */
  lastTickAt: number | null;
  /** When the last `slow` fired; `null` before the first. */
  lastSlowAt: number | null;
}

export interface L4PollPlan {
  tick: boolean;
  slow: boolean;
}

function due(now: number, last: number | null, interval: number): boolean {
  return last === null || now - last >= interval;
}

/** What `refresh()` should read on this timer call; never mutates `clock`. */
export function l4PollPlan(now: number, clock: Readonly<L4PollClock>, idle: boolean): L4PollPlan {
  if (!idle) return { tick: true, slow: true };
  return {
    tick: due(now, clock.lastTickAt, L4_IDLE_TICK_MS),
    slow: due(now, clock.lastSlowAt, L4_IDLE_SLOW_MS),
  };
}

// ---- once-per-message logging ---------------------------------------------------------------------

export interface OnceLog {
  /** Pass `msg` to the sink unless the same text was already logged and not since forgotten. */
  log(msg: string): void;
  /** Forget one message (the read it came from succeeded), so its recurrence logs again; unknown messages are a no-op. */
  forget(msg: string): void;
  /** Forget every message seen so far. */
  clear(): void;
}

/**
 * A read failure repeats on every poll; the activity log should carry each distinct message once
 * (spec §7(c)), so the store routes every read failure through one of these. Recovery is per
 * message (`forget`): a pass that ran only the slow group must not un-suppress a fast-group verb
 * that is still failing.
 */
export function createOnceLog(sink: (msg: string) => void): OnceLog {
  const seen = new Set<string>();
  return {
    log(msg) {
      if (seen.has(msg)) return;
      seen.add(msg);
      sink(msg);
    },
    forget(msg) {
      seen.delete(msg);
    },
    clear() {
      seen.clear();
    },
  };
}
