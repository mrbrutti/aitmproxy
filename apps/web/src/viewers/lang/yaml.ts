// A tolerant PoC-YAML colorizer as a CodeMirror StreamLanguage parser (UI scripting-highlight spec
// §1.1). It colours what an operator scans — keys, strings, numbers, booleans, structure, comments —
// using the foundation syntax faces. It is a colorizer, not a parser: unusual or half-written
// documents still render, just with fewer colours, and it never throws. The line logic is the
// surface's own YAML lexer (ported from the Findings `<pre>` highlighter it replaces); block scalars
// are the one cross-line construct it tracks. YAML has no key/word catalog, so nothing is generated
// here — schema-aware *completion* is where the PoC key tree is consumed (see complete-yaml.ts).
//
// Only a type-only import of @codemirror/* so this module adds no CodeMirror weight to the lazy chunk.
import type { StreamParser, StringStream } from '@codemirror/language';
import type { SynTag } from './rhai';

interface Tok {
  tag: SynTag | null;
  text: string;
}

const RE_INDENT = /^\s+/;
const RE_KEY = /^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"[\]{},][^:#]*?)\s*:(?=\s|$)/;
/** Inside `[...]` / `{...}` a key cannot run across a delimiter. */
const RE_FLOW_KEY = /^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"[\]{},][^:#,[\]{}]*?)\s*:(?=\s|$)/;
const RE_BOOL = /^(?:true|false|yes|no|on|off|null|~)(?=[\s,\]}]|$)/i;
const RE_NUMBER = /^[-+]?(?:0x[0-9a-fA-F]+|\d[\d_]*(?:\.\d+)?(?:[eE][-+]?\d+)?|\.inf|\.nan)(?=[\s,\]}]|$)/i;
const RE_BLOCK = /^[>|][-+]?\d*(?=\s|$)/;
const RE_ANCHOR = /^[&*!][^\s,\]}]+/;
const RE_DQ = /^"(?:[^"\\]|\\.)*(?:"|$)/;
const RE_SQ = /^'(?:[^']|'')*(?:'|$)/;

interface YamlState {
  // The remaining tokens of the line currently being scanned, shifted off one per token() call.
  queue: Tok[];
  // Indentation of the key that opened an active block scalar (| or >); -1 when not in one. Lines
  // indented deeper than this (and blank lines) are block-scalar body, coloured wholly as string.
  scalarIndent: number;
}

function tokenizeLine(line: string, state: YamlState): Tok[] {
  const out: Tok[] = [];
  const push = (tag: SynTag | null, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.tag === tag && tag === null) last.text += text;
    else out.push({ tag, text });
  };
  let rest = line;
  const take = (n: number, tag: SynTag | null) => {
    push(tag, rest.slice(0, n));
    rest = rest.slice(n);
  };

  const lineIndent = (RE_INDENT.exec(line)?.[0].length ?? 0) * (line.trim() === '' ? 0 : 1);

  // Block-scalar continuation: a blank line, or one indented past the opening key, is body text.
  if (state.scalarIndent >= 0) {
    if (line.trim() === '' || lineIndent > state.scalarIndent) {
      const ind = RE_INDENT.exec(rest);
      if (ind) take(ind[0].length, null);
      take(rest.length, 'string');
      return out;
    }
    state.scalarIndent = -1; // dedented out of the scalar
  }

  const indent = RE_INDENT.exec(rest);
  if (indent) take(indent[0].length, null);
  if (!rest) return out;

  if (rest.startsWith('#')) {
    take(rest.length, 'comment');
    return out;
  }
  if (/^(?:---|\.\.\.)(?=\s|$)/.test(rest)) take(3, 'punct');

  // Sequence entries: "- " (possibly nested "- - key: v").
  while (/^-(?:\s|$)/.test(rest)) {
    take(1, 'punct');
    const ws = RE_INDENT.exec(rest);
    if (ws) take(ws[0].length, null);
  }

  // The indent at which a block scalar on this line would open is the column of its key.
  const keyColumn = line.length - rest.length;

  const key = RE_KEY.exec(rest);
  if (key) {
    const colon = key[0].lastIndexOf(':');
    const name = key[0].slice(0, colon).replace(/\s+$/, '');
    take(name.length, 'key');
    const ws = RE_INDENT.exec(rest);
    if (ws) take(ws[0].length, null);
    take(1, 'punct');
  }

  // Value(s), including flow collections on the same line.
  let depth = 0;
  while (rest) {
    const ws = RE_INDENT.exec(rest);
    if (ws) {
      take(ws[0].length, null);
      continue;
    }
    const c = rest[0]!;
    if (c === '#') {
      take(rest.length, 'comment');
      break;
    }
    if (c === '[' || c === '{') {
      depth++;
      take(1, 'punct');
      continue;
    }
    if (c === ']' || c === '}') {
      depth = Math.max(0, depth - 1);
      take(1, 'punct');
      continue;
    }
    if (c === ',' && depth > 0) {
      take(1, 'punct');
      continue;
    }
    if (depth > 0) {
      const k = RE_FLOW_KEY.exec(rest);
      if (k) {
        const colon = k[0].lastIndexOf(':');
        const name = k[0].slice(0, colon).replace(/\s+$/, '');
        take(name.length, 'key');
        const w = RE_INDENT.exec(rest);
        if (w) take(w[0].length, null);
        take(1, 'punct');
        continue;
      }
    }
    let m: RegExpExecArray | null;
    if ((m = RE_DQ.exec(rest)) || (m = RE_SQ.exec(rest))) {
      take(m[0].length, 'string');
      continue;
    }
    if ((m = RE_BLOCK.exec(rest))) {
      take(m[0].length, 'punct');
      state.scalarIndent = keyColumn; // body lines are indented past the key
      continue;
    }
    if ((m = RE_ANCHOR.exec(rest))) {
      take(m[0].length, 'punct');
      continue;
    }
    if ((m = RE_BOOL.exec(rest))) {
      take(m[0].length, 'boolean');
      continue;
    }
    if ((m = RE_NUMBER.exec(rest))) {
      take(m[0].length, 'number');
      continue;
    }
    // Plain scalar: up to a comment (" #") or, inside a flow collection, the next delimiter.
    const stop = depth > 0 ? /\s#|[,\]}]/ : /\s#/;
    const idx = rest.search(stop);
    const len = idx < 0 ? rest.length : Math.max(1, idx);
    take(len, 'string');
  }
  return out;
}

export const yamlStreamParser: StreamParser<YamlState> = {
  startState: () => ({ queue: [], scalarIndent: -1 }),
  token(stream, state): SynTag | null {
    if (stream.sol()) state.queue = tokenizeLine(stream.string, state);
    const t = state.queue.shift();
    if (!t) {
      stream.skipToEnd();
      return null;
    }
    stream.pos = Math.min(stream.start + t.text.length, stream.string.length);
    if (stream.pos <= stream.start) stream.pos = stream.start + 1; // guarantee progress
    return t.tag;
  },
  // A blank line inside a block scalar is part of it; leaving scalarIndent untouched continues it.
  blankLine: () => undefined,
  languageData: { commentTokens: { line: '#' } },
};
