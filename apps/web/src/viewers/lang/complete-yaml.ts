// PoC-YAML schema-aware completion (UI scripting-highlight spec §1.1, plan Task 4). It reconstructs
// the schema path at the caret from the document's indentation and sequence dashes, then offers the
// enclosing map's keys (key position) or that key's enum values (after the colon). Every key and enum
// comes from the generated PoC schema tree, so completion cannot drift from the language.
import { pocSchema } from './defs.gen';

export interface PocCandidate {
  label: string;
  /** One-line description from the schema, shown in the info panel. */
  info?: string;
  /** CodeMirror completion `type` (icon). */
  type?: string;
}

export interface PocContext {
  kind: 'key' | 'enum';
  /** Schema path to the enclosing node, `[]` for list items (e.g. `steps[].http.matchers[]`). */
  path: string;
  /** The partial key or value already typed before the caret. */
  prefix: string;
}

// The schema is a tree of nodes; this is the shape complete-yaml walks (see poc-yaml.schema.json).
interface SchemaNode {
  type?: string;
  keys?: Record<string, SchemaNode>;
  items?: SchemaNode;
  enum?: string[];
  description?: string;
  $ref?: string;
}

const ROOT = pocSchema as unknown as SchemaNode & { $defs?: Record<string, SchemaNode> };

function deref(node: SchemaNode | undefined): SchemaNode | undefined {
  let n = node;
  while (n && n.$ref) n = ROOT.$defs?.[n.$ref.split('/').pop()!];
  return n;
}

/** Resolve a schema path like `steps[].http.matchers[].type` to its node, or null if it doesn't exist. */
function nodeAt(path: string): SchemaNode | null {
  let node: SchemaNode | undefined = ROOT;
  if (path === '') return node;
  for (const seg of path.split('.')) {
    const isList = seg.endsWith('[]');
    const key = isList ? seg.slice(0, -2) : seg;
    node = deref(node);
    if (!node || node.type !== 'map' || !node.keys || !(key in node.keys)) return null;
    node = deref(node.keys[key]);
    if (isList) {
      if (!node || node.type !== 'list' || !node.items) return null;
      node = deref(node.items);
    }
  }
  return node ?? null;
}

interface Parsed {
  contentCol: number;
  dashes: number;
  key: string | null;
  hasColon: boolean;
  value: string;
}

function parseLine(line: string): Parsed {
  const indent = /^\s*/.exec(line)![0].length;
  let rest = line.slice(indent);
  let dashes = 0;
  let m: RegExpExecArray | null;
  while ((m = /^-(\s+|$)/.exec(rest))) {
    dashes++;
    rest = rest.slice(m[0].length);
  }
  const contentCol = line.length - rest.length;
  const kv = /^([\w-]+)\s*:(?:\s+(.*))?$/.exec(rest);
  if (kv) return { contentCol, dashes, key: kv[1]!, hasColon: true, value: kv[2] ?? '' };
  const kp = /^([\w-]*)/.exec(rest)![1]!;
  return { contentCol, dashes, key: kp || null, hasColon: false, value: '' };
}

interface Frame {
  col: number;
  seg: string;
  isList: boolean;
}

export function pocYamlContext(text: string, caret: number): PocContext {
  const before = text.slice(0, caret);
  const lines = before.split('\n');
  const curRaw = lines[lines.length - 1]!;

  // Build the ancestor stack from every completed line before the caret.
  const stack: Frame[] = [];
  for (let i = 0; i < lines.length - 1; i++) {
    const raw = lines[i]!;
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const p = parseLine(raw);
    while (stack.length && stack[stack.length - 1]!.col >= p.contentCol) stack.pop();
    if (p.dashes > 0 && stack.length) stack[stack.length - 1]!.isList = true;
    if (p.key !== null) stack.push({ col: p.contentCol, seg: p.key, isList: false });
  }

  // Fold the current line into the structure: pop siblings, mark the parent a list if it's a `- ` item.
  const cur = parseLine(curRaw);
  while (stack.length && stack[stack.length - 1]!.col >= cur.contentCol) stack.pop();
  if (cur.dashes > 0 && stack.length) stack[stack.length - 1]!.isList = true;

  const containerPath = stack.map((f) => f.seg + (f.isList ? '[]' : '')).join('.');

  // After `key:` we complete that key's value (enum); otherwise we complete a key in the container.
  if (cur.hasColon && cur.key) {
    const path = containerPath ? `${containerPath}.${cur.key}` : cur.key;
    return { kind: 'enum', path, prefix: cur.value.trim() };
  }
  return { kind: 'key', path: containerPath, prefix: cur.key ?? '' };
}

export function pocYamlCompletions(text: string, caret: number): PocCandidate[] {
  const { kind, path, prefix } = pocYamlContext(text, caret);
  const node = nodeAt(path);
  if (!node) return [];

  if (kind === 'enum') {
    const values = node.enum ?? (node.type === 'boolean' ? ['true', 'false'] : []);
    return values.filter((v) => !prefix || v.startsWith(prefix)).map((v) => ({ label: v, type: 'enum' }));
  }

  const keys = node.keys ?? {};
  return Object.keys(keys)
    .filter((k) => !prefix || k.startsWith(prefix))
    .map((k) => {
      const child = deref(keys[k]);
      return { label: k, type: 'property', ...(child?.description ? { info: child.description } : {}) };
    });
}
