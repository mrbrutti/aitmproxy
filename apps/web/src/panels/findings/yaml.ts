// A tiny line-based YAML highlighter for the PoC source (§2.7 "the YAML, syntax-highlighted").
// It colours what an operator scans for — keys, strings, numbers, booleans, comments, structure —
// using the five syntax tokens of §2.2. It is not a parser: unusual documents still render, just
// with fewer colours. CodeMirror takes over once the viewers' `Lang` grows a `yaml`.

export type YamlTokenType = 'key' | 'string' | 'number' | 'bool' | 'punct' | 'comment' | 'text';

export interface YamlToken {
  type: YamlTokenType;
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

function tokenizeLine(line: string): YamlToken[] {
  const out: YamlToken[] = [];
  const push = (type: YamlTokenType, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.type === type && type === 'text') last.text += text;
    else out.push({ type, text });
  };

  let rest = line;
  const take = (n: number, type: YamlTokenType) => {
    push(type, rest.slice(0, n));
    rest = rest.slice(n);
  };

  const indent = RE_INDENT.exec(rest);
  if (indent) take(indent[0].length, 'text');
  if (!rest) return out;

  if (rest.startsWith('#')) {
    take(rest.length, 'comment');
    return out;
  }
  if (/^(?:---|\.\.\.)(?=\s|$)/.test(rest)) {
    take(3, 'punct');
  }

  // Sequence entries: "- " (possibly nested "- - key: v").
  while (/^-(?:\s|$)/.test(rest)) {
    take(1, 'punct');
    const ws = RE_INDENT.exec(rest);
    if (ws) take(ws[0].length, 'text');
  }

  const key = RE_KEY.exec(rest);
  if (key) {
    const colon = key[0].lastIndexOf(':');
    const name = key[0].slice(0, colon).replace(/\s+$/, '');
    take(name.length, 'key');
    const ws = RE_INDENT.exec(rest);
    if (ws) take(ws[0].length, 'text');
    take(1, 'punct');
  }

  // Value(s), including flow collections on the same line.
  let depth = 0;
  while (rest) {
    const ws = RE_INDENT.exec(rest);
    if (ws) {
      take(ws[0].length, 'text');
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
        if (w) take(w[0].length, 'text');
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
      continue;
    }
    if ((m = RE_ANCHOR.exec(rest))) {
      take(m[0].length, 'punct');
      continue;
    }
    if ((m = RE_BOOL.exec(rest))) {
      take(m[0].length, 'bool');
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

/** Tokens per line; `text.split('\n')` order, so a `<pre>` can number them with CSS counters. */
export function tokenizeYaml(text: string): YamlToken[][] {
  return text.replace(/\r\n?/g, '\n').split('\n').map(tokenizeLine);
}
