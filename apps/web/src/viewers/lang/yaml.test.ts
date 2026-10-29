import { describe, expect, it } from 'vitest';
import { StringStream } from '@codemirror/language';
import { yamlStreamParser as P } from './yaml';
import type { SynTag } from './rhai';

function collect(text: string): { tag: SynTag | null; text: string }[] {
  const out: { tag: SynTag | null; text: string }[] = [];
  const state = P.startState!(2);
  for (const line of text.split('\n')) {
    const s = new StringStream(line, 2, 2);
    if (s.eol()) {
      // A blank line still advances parser state (block-scalar continuation).
      P.blankLine?.(state, 2);
      continue;
    }
    while (!s.eol()) {
      s.start = s.pos;
      const tag = P.token(s, state) as SynTag | null;
      if (s.pos === s.start) s.pos++;
      out.push({ tag, text: s.current() });
    }
  }
  return out;
}

const tagOf = (toks: ReturnType<typeof collect>, text: string) => toks.find((t) => t.text === text)?.tag;

describe('poc-yaml stream tokenizer', () => {
  it('colours keys, strings, numbers, booleans and comments (AC1/AC2)', () => {
    const toks = collect('id: demo\ninfo:\n  severity: high\n  count: 200\n  active: true # note');
    expect(tagOf(toks, 'id')).toBe('key');
    expect(tagOf(toks, 'severity')).toBe('key');
    expect(tagOf(toks, 'high')).toBe('string');
    expect(tagOf(toks, '200')).toBe('number');
    expect(tagOf(toks, 'true')).toBe('boolean');
    expect(toks.find((t) => t.text.startsWith('#'))?.tag).toBe('comment');
    // The key/value colon is punctuation.
    expect(toks.some((t) => t.text === ':' && t.tag === 'punct')).toBe(true);
  });

  it('colours sequence dashes and step keys', () => {
    const toks = collect('steps:\n  - http:\n      method: GET');
    expect(tagOf(toks, 'steps')).toBe('key');
    expect(tagOf(toks, '-')).toBe('punct');
    expect(tagOf(toks, 'http')).toBe('key');
    expect(tagOf(toks, 'method')).toBe('key');
    expect(tagOf(toks, 'GET')).toBe('string');
  });

  it('colours a flow collection', () => {
    const toks = collect('tags: [sqli, rce]');
    expect(tagOf(toks, 'tags')).toBe('key');
    expect(toks.some((t) => t.text === '[' && t.tag === 'punct')).toBe(true);
    expect(tagOf(toks, 'sqli')).toBe('string');
  });

  it('a block scalar colours its indented body as string', () => {
    const toks = collect('steps:\n  - http:\n      raw: |\n        GET / HTTP/1.1\n        Host: {{Host}}');
    expect(tagOf(toks, 'raw')).toBe('key');
    expect(toks.some((t) => t.text.includes('GET / HTTP/1.1') && t.tag === 'string')).toBe(true);
    expect(toks.some((t) => t.text.includes('Host: {{Host}}') && t.tag === 'string')).toBe(true);
  });

  it('every tag is one of the foundation syntax faces', () => {
    const allowed = new Set<SynTag | null>(['key', 'string', 'number', 'boolean', 'punct', 'comment', 'text', null]);
    for (const t of collect('id: demo\ninfo:\n  severity: high\nsteps:\n  - http:\n      url: {{BaseURL}}/a')) {
      expect(allowed.has(t.tag)).toBe(true);
    }
  });

  it('tolerates odd / malformed lines without throwing (Review Focus)', () => {
    expect(() => collect(':::\n  - - - weird: : :\n"unterminated\n\t\tmixed')).not.toThrow();
  });
});
