// Pure model behind JsonTree: JSONPath generation, lazy flattening of expanded nodes into rows,
// and the filter walk. No DOM; unit-tested directly.

export type NodeKind = 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null';

export interface Row {
  path: string;
  key: string | number | null;
  value: unknown;
  depth: number;
  kind: NodeKind;
  expandable: boolean;
  expanded: boolean;
  /** Child count for containers. */
  count: number;
  /** Trailing comma: not the last sibling. */
  comma: boolean;
}

const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

export function jsonPath(parent: string, key: string | number): string {
  if (typeof key === 'number') return `${parent}[${key}]`;
  if (IDENT.test(key)) return `${parent}.${key}`;
  return `${parent}['${key.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}']`;
}

export function kindOf(v: unknown): NodeKind {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  switch (typeof v) {
    case 'object':
      return 'object';
    case 'string':
      return 'string';
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    default:
      return 'null';
  }
}

export function childEntries(v: unknown, sortKeys: boolean): [string | number, unknown][] {
  if (Array.isArray(v)) return v.map((x, i) => [i, x]);
  if (v && typeof v === 'object') {
    const keys = Object.keys(v as Record<string, unknown>);
    if (sortKeys) keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return keys.map((k) => [k, (v as Record<string, unknown>)[k]]);
  }
  return [];
}

export function countOf(v: unknown): number {
  if (Array.isArray(v)) return v.length;
  if (v && typeof v === 'object') return Object.keys(v as object).length;
  return 0;
}

/** Collapsed-container summary: `3 keys`, `12 items`, `empty`. */
export function preview(v: unknown): string {
  const n = countOf(v);
  if (n === 0) return 'empty';
  if (Array.isArray(v)) return `${n} ${n === 1 ? 'item' : 'items'}`;
  return `${n} ${n === 1 ? 'key' : 'keys'}`;
}

export interface FilterResult {
  query: string;
  /** Paths of nodes that match. */
  matches: Set<string>;
  /** Paths of containers that must be open to reveal a match (ancestors). */
  reveal: Set<string>;
  truncated: boolean;
}

export const FILTER_VISIT_CAP = 400_000;
export const FILTER_MATCH_CAP = 5_000;

export function filterTree(root: unknown, query: string): FilterResult | null {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  const matches = new Set<string>();
  const reveal = new Set<string>();
  let visited = 0;
  let truncated = false;
  type Frame = { value: unknown; path: string; key: string | number | null; ancestors: string[] };
  const stack: Frame[] = [{ value: root, path: '$', key: null, ancestors: [] }];
  while (stack.length) {
    const f = stack.pop()!;
    if (++visited > FILTER_VISIT_CAP || matches.size >= FILTER_MATCH_CAP) {
      truncated = true;
      break;
    }
    const k = kindOf(f.value);
    const keyHit = f.key != null && String(f.key).toLowerCase().includes(q);
    const valHit = k !== 'object' && k !== 'array' && String(f.value).toLowerCase().includes(q);
    if (keyHit || valHit) {
      matches.add(f.path);
      for (const a of f.ancestors) reveal.add(a);
    }
    if (k === 'object' || k === 'array') {
      const anc = [...f.ancestors, f.path];
      const entries = childEntries(f.value, false);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [ck, cv] = entries[i]!;
        stack.push({ value: cv, path: jsonPath(f.path, ck), key: ck, ancestors: anc });
      }
    }
  }
  return { query: q, matches, reveal, truncated };
}

export interface FlattenOptions {
  sortKeys: boolean;
  filter?: FilterResult | null;
  /** Hard cap on rows produced; the status line says when it bites. */
  limit?: number;
}

/** Rows for the currently expanded nodes, depth-first, in display order. */
export function flatten(root: unknown, expanded: ReadonlySet<string>, o: FlattenOptions): { rows: Row[]; truncated: boolean } {
  const limit = o.limit ?? 200_000;
  const rows: Row[] = [];
  const f = o.filter ?? null;
  type Frame = { value: unknown; path: string; key: string | number | null; depth: number; comma: boolean };
  const stack: Frame[] = [{ value: root, path: '$', key: null, depth: 0, comma: false }];
  let truncated = false;
  while (stack.length) {
    const fr = stack.pop()!;
    if (rows.length >= limit) {
      truncated = true;
      break;
    }
    const kind = kindOf(fr.value);
    const expandable = (kind === 'object' || kind === 'array') && countOf(fr.value) > 0;
    const visible = !f || f.matches.has(fr.path) || f.reveal.has(fr.path);
    if (!visible) continue;
    const isOpen = expandable && (f ? f.reveal.has(fr.path) || expanded.has(fr.path) : expanded.has(fr.path));
    rows.push({
      path: fr.path,
      key: fr.key,
      value: fr.value,
      depth: fr.depth,
      kind,
      expandable,
      expanded: isOpen,
      count: countOf(fr.value),
      comma: fr.comma,
    });
    if (isOpen) {
      const entries = childEntries(fr.value, o.sortKeys);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [k, v] = entries[i]!;
        stack.push({ value: v, path: jsonPath(fr.path, k), key: k, depth: fr.depth + 1, comma: i < entries.length - 1 });
      }
    }
  }
  return { rows, truncated };
}

/** Every container path under `root`, up to `cap` of them (for "expand all"). */
export function allContainerPaths(root: unknown, cap = 50_000): { paths: Set<string>; truncated: boolean } {
  const paths = new Set<string>();
  const stack: { value: unknown; path: string }[] = [{ value: root, path: '$' }];
  while (stack.length) {
    const f = stack.pop()!;
    const k = kindOf(f.value);
    if (k !== 'object' && k !== 'array' || countOf(f.value) === 0) continue;
    if (paths.size >= cap) return { paths, truncated: true };
    paths.add(f.path);
    for (const [ck, cv] of childEntries(f.value, false)) stack.push({ value: cv, path: jsonPath(f.path, ck) });
  }
  return { paths, truncated: false };
}

export function parentPath(path: string): string | null {
  if (path === '$') return null;
  const i = Math.max(path.lastIndexOf('.'), path.lastIndexOf('['));
  return i <= 0 ? '$' : path.slice(0, i);
}

/** One-line description for the status line: `string · 24 chars`, `array · 12 items`. */
export function describe(v: unknown): string {
  const k = kindOf(v);
  switch (k) {
    case 'string':
      return `string · ${(v as string).length} chars`;
    case 'number':
      return `number`;
    case 'boolean':
      return `boolean`;
    case 'null':
      return `null`;
    default:
      return `${k} · ${preview(v)}`;
  }
}
