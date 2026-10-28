import { describe, expect, it } from 'vitest';
import { formatForm, formatMultipart, parseForm, parseMultipart, prettyJson } from './pretty';
import { unifiedDiff } from './udiff';

describe('prettyJson', () => {
  it('re-indents with two spaces', () => {
    expect(prettyJson('{"a":1,"b":[true,null]}')).toBe('{\n  "a": 1,\n  "b": [\n    true,\n    null\n  ]\n}');
  });
  it('returns null for invalid JSON', () => {
    expect(prettyJson('{oops')).toBeNull();
  });
});

describe('form', () => {
  it('decodes plus and percent escapes', () => {
    expect(parseForm('q=lamp+shade&page=2&empty=&flag')).toEqual([
      { name: 'q', value: 'lamp shade', raw: 'q=lamp+shade' },
      { name: 'page', value: '2', raw: 'page=2' },
      { name: 'empty', value: '', raw: 'empty=' },
      { name: 'flag', value: '', raw: 'flag' },
    ]);
    expect(formatForm('a=%22x%22&b=1')).toBe('a = "x"\nb = 1');
  });
  it('keeps malformed escapes as-is', () => {
    expect(parseForm('a=%E0%A4%A')[0]!.value).toBe('%E0%A4%A');
  });
});

describe('multipart', () => {
  const text =
    '--B\r\nContent-Disposition: form-data; name="title"\r\n\r\nAurora Lamp\r\n' +
    '--B\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n';
  it('splits parts with their headers', () => {
    const parts = parseMultipart(text, 'B');
    expect(parts).toHaveLength(2);
    expect(parts[0]).toMatchObject({ name: 'title', filename: null, body: 'Aurora Lamp' });
    expect(parts[1]).toMatchObject({ name: 'file', filename: 'a.txt', contentType: 'text/plain', body: 'hello' });
  });
  it('formats one block per part', () => {
    const out = formatMultipart(text, 'B');
    expect(out).toContain('── part 1 · name=title\nAurora Lamp');
    expect(out).toContain('── part 2 · name=file · filename=a.txt · text/plain\nhello');
  });
});

describe('unifiedDiff', () => {
  it('emits hunks with context', () => {
    const a = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].join('\n');
    const b = ['a', 'b', 'c', 'D', 'e', 'f', 'g'].join('\n');
    const patch = unifiedDiff(a, b, 'x', 'y', 1);
    expect(patch).toBe('--- x\n+++ y\n@@ -3,3 +3,3 @@\n c\n-d\n+D\n e\n');
  });
  it('is empty when equal', () => {
    expect(unifiedDiff('same', 'same')).toBe('');
  });
});
