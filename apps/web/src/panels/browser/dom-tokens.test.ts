import { describe, expect, it } from 'vitest';
import { filterLines, tokenizeHtml } from './dom-tokens';

const kinds = (src: string) => tokenizeHtml(src).map((t) => `${t.kind}:${t.text}`);

describe('tokenizeHtml', () => {
  it('tints tag names, attribute names and quoted values; text stays text', () => {
    expect(kinds('<a href="/x" class=\'c\'>Go</a>')).toEqual([
      'punct:<',
      'tag:a',
      'text: ',
      'attr:href',
      'punct:=',
      'string:"/x"',
      'text: ',
      'attr:class',
      'punct:=',
      "string:'c'",
      'punct:>',
      'text:Go',
      'punct:</',
      'tag:a',
      'punct:>',
    ]);
  });
  it('handles boolean attributes, unquoted values and self-closing tags', () => {
    expect(kinds('<input disabled type=text/>')).toEqual([
      'punct:<',
      'tag:input',
      'text: ',
      'attr:disabled',
      'text: ',
      'attr:type',
      'punct:=',
      'string:text',
      'punct:/>',
    ]);
  });
  it('keeps comments and doctype as one token and never loses characters', () => {
    const src = '<!DOCTYPE html>\n<!-- hi -->\n<p>1 < 2 &amp; 3</p>';
    const toks = tokenizeHtml(src);
    expect(toks.map((t) => t.text).join('')).toBe(src);
    expect(toks[0]).toEqual({ kind: 'comment', text: '<!DOCTYPE html>' });
    expect(toks.find((t) => t.text === '<!-- hi -->')?.kind).toBe('comment');
    // a lone `<` in text is text
    expect(toks.filter((t) => t.kind === 'tag').map((t) => t.text)).toEqual(['p', 'p']);
  });
  it('round-trips the fixture DOM and broken markup', () => {
    const fixture = `<html lang="en">\n  <head><title>Shop</title></head>\n  <body>\n    <main id="app"><h1>Hi</h1></main>\n  </body>\n</html>`;
    expect(tokenizeHtml(fixture).map((t) => t.text).join('')).toBe(fixture);
    const broken = '<div class="x <span>y</span';
    expect(tokenizeHtml(broken).map((t) => t.text).join('')).toBe(broken);
    expect(tokenizeHtml('')).toEqual([]);
  });
});

describe('filterLines', () => {
  it('keeps matching lines case-insensitively and reports the total', () => {
    const src = 'a\n<LI class="card">\nb\n<li>';
    expect(filterLines(src, 'li')).toEqual({ lines: ['<LI class="card">', '<li>'], total: 4 });
    expect(filterLines(src, '')).toEqual({ lines: ['a', '<LI class="card">', 'b', '<li>'], total: 4 });
  });
});
