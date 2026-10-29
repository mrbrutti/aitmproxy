// Rhai completion, driven entirely by the generated API catalog (UI scripting-highlight spec §1.1,
// plan Task 4). Three contexts: at file top level it offers the hook names (to scaffold a `fn on_…`);
// inside a hook body it offers the globals, receivers and DSL helpers; after a receiver chain
// (`flow.request.`) it offers that object's members. No hook, host-function or receiver name is
// written here — all of it comes from `rhaiApi`, so it cannot drift from the engine.
import { rhaiApi } from './defs.gen';

/** A completion candidate, shaped for a CodeMirror `Completion` but usable without importing CM. */
export interface RhaiCandidate {
  label: string;
  /** Signature, shown dimmed beside the label. */
  detail?: string;
  /** One-line description, shown in the info panel. */
  info?: string;
  /** CodeMirror completion `type` (icon): object | property | method | function | keyword. */
  type?: string;
}

interface Entry {
  name: string;
  kind?: string;
  signature?: string;
  description?: string;
}

const ALL: Entry[] = [...rhaiApi.flow, ...rhaiApi.msg, ...rhaiApi.globals, ...rhaiApi.dsl];
const BY_NAME = new Map<string, Entry>(ALL.map((e) => [e.name, e]));

// parent path -> its direct child segments, in catalog order (e.g. "flow" -> [id, kind, …, request]).
const CHILDREN = new Map<string, string[]>();
for (const e of ALL) {
  const dot = e.name.lastIndexOf('.');
  if (dot < 0) continue;
  const parent = e.name.slice(0, dot);
  const child = e.name.slice(dot + 1);
  const list = CHILDREN.get(parent) ?? [];
  if (!list.includes(child)) list.push(child);
  CHILDREN.set(parent, list);
}

const HOOKS: readonly Entry[] = rhaiApi.hooks;

// Top-level-of-body vocabulary: single-segment receivers (flow, msg, log, http, store, scope, …),
// bare global functions (option, halt, log) and the DSL helpers.
const BODY: Entry[] = (() => {
  const names = new Set<string>();
  for (const parent of CHILDREN.keys()) if (!parent.includes('.')) names.add(parent);
  for (const g of rhaiApi.globals) if (!g.name.includes('.')) names.add(g.name);
  for (const d of rhaiApi.dsl) names.add(d.name);
  return [...names].map((n) => BY_NAME.get(n) ?? { name: n, kind: 'variable' });
})();

const IDENT_TAIL = /[A-Za-z0-9_]*$/;
const RECEIVER_TAIL = /(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;

/** Open-brace depth before the caret — a cheap "are we inside a function body?" test. */
function braceDepth(src: string): number {
  let depth = 0;
  for (const ch of src) {
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
  }
  return depth;
}

const cand = (label: string, e: Entry | undefined, fallbackType: string): RhaiCandidate => ({
  label,
  ...(e?.signature ? { detail: e.signature } : {}),
  ...(e?.description ? { info: e.description } : {}),
  type: e?.kind ?? fallbackType,
});

const byPrefix = (names: string[], prefix: string) =>
  prefix ? names.filter((n) => n.startsWith(prefix)) : names;

export function rhaiCompletions(text: string, caret: number): RhaiCandidate[] {
  const before = text.slice(0, caret);
  const word = IDENT_TAIL.exec(before)?.[0] ?? '';
  const beforeWord = before.slice(0, before.length - word.length);

  // Member access: a receiver chain ending in a dot.
  if (beforeWord.endsWith('.')) {
    const path = RECEIVER_TAIL.exec(beforeWord.slice(0, -1))?.[0] ?? '';
    const children = CHILDREN.get(path) ?? [];
    return byPrefix(children, word).map((seg) => cand(seg, BY_NAME.get(`${path}.${seg}`), 'property'));
  }

  // File top level offers hooks; a hook body offers globals/receivers/DSL.
  if (braceDepth(beforeWord) > 0) {
    return byPrefix(
      BODY.map((e) => e.name),
      word,
    ).map((n) => cand(n, BY_NAME.get(n), 'function'));
  }
  return byPrefix(
    HOOKS.map((h) => h.name),
    word,
  ).map((n) => cand(n, HOOKS.find((h) => h.name === n), 'function'));
}
