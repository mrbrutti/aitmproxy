import { describe, expect, it } from 'vitest';
import { StringStream } from '@codemirror/language';
import { rhaiStreamParser as P, type SynTag } from './rhai';

// Run the StreamParser over a buffer the way CodeMirror's highlighter does: one StringStream per
// line, carrying parser state across newlines, and collect (tag, text) for every token.
function collect(text: string): { tag: SynTag | null; text: string }[] {
  const out: { tag: SynTag | null; text: string }[] = [];
  const state = P.startState!(2);
  for (const line of text.split('\n')) {
    const s = new StringStream(line, 2, 2);
    if (s.eol()) continue;
    while (!s.eol()) {
      s.start = s.pos;
      const tag = P.token(s, state) as SynTag | null;
      if (s.pos === s.start) s.pos++; // never let a buggy branch spin
      out.push({ tag, text: s.current() });
    }
  }
  return out;
}

const tagOf = (toks: ReturnType<typeof collect>, text: string) => toks.find((t) => t.text === text)?.tag;

describe('rhai stream tokenizer', () => {
  it('colours keywords, identifiers, strings and comments (AC1/AC2)', () => {
    const toks = collect('fn on_request(flow){ let x="a"; // c }');
    expect(tagOf(toks, 'fn')).toBe('keyword');
    expect(tagOf(toks, 'let')).toBe('keyword');
    expect(tagOf(toks, 'on_request')).toBe('text'); // identifier, not a keyword
    expect(tagOf(toks, 'flow')).toBe('text');
    expect(tagOf(toks, '"a"')).toBe('string');
    expect(toks.find((t) => t.text.startsWith('//'))?.tag).toBe('comment');
    // Punctuation (dots, parens, braces, semicolons) all colour as punct.
    expect(tagOf(toks, '(')).toBe('punct');
    expect(tagOf(toks, ';')).toBe('punct');
  });

  it('colours literals, numbers and member access', () => {
    const toks = collect('let ok = true; let n = 0xFF; let f = 3.14; flow.request.body');
    expect(tagOf(toks, 'true')).toBe('boolean');
    expect(tagOf(toks, '0xFF')).toBe('number');
    expect(tagOf(toks, '3.14')).toBe('number');
    expect(tagOf(toks, 'flow')).toBe('text');
    expect(tagOf(toks, '.')).toBe('punct');
    expect(tagOf(toks, 'request')).toBe('text');
  });

  it('every tag is one of the foundation syntax faces', () => {
    const allowed = new Set<SynTag | null>(['keyword', 'boolean', 'string', 'number', 'comment', 'punct', 'text', null]);
    for (const t of collect('fn f(){ let s="x"; return 1 + 2; } // done')) expect(allowed.has(t.tag)).toBe(true);
  });

  it('a nested block comment spanning lines stays a comment', () => {
    const toks = collect('/* a /* b */ c */ let x = 1');
    // Everything up to the matching close is comment; the trailing `let` resumes code.
    expect(toks.filter((t) => t.tag === 'comment').length).toBeGreaterThan(0);
    expect(tagOf(toks, 'let')).toBe('keyword');
    expect(tagOf(toks, '1')).toBe('number');
  });

  it('tolerates an unterminated string without throwing (Review Focus: malformed source)', () => {
    expect(() => collect('let x = "oops\nlet y = 2')).not.toThrow();
    const toks = collect('let x = "oops\nlet y = 2');
    // The unterminated double string colours to end of line; the next line resumes as code.
    expect(toks.find((t) => t.text.includes('oops'))?.tag).toBe('string');
    expect(tagOf(toks, 'y')).toBe('text');
    expect(tagOf(toks, '2')).toBe('number');
  });

  it('tolerates an unterminated block comment (colours to buffer end)', () => {
    const toks = collect('let x = 1 /* unterminated\nstill comment\nand here too');
    expect(tagOf(toks, 'x')).toBe('text');
    // After the opener everything is comment; no code tokens leak on later lines.
    expect(toks.some((t) => t.text.includes('still') && t.tag === 'comment')).toBe(true);
    expect(toks.every((t) => t.text !== 'still' || t.tag === 'comment')).toBe(true);
  });
});
