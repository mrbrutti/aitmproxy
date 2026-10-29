import { describe, expect, it } from 'vitest';
import { tokenizeYaml, type YamlToken } from './yaml';

const ofType = (toks: YamlToken[], type: YamlToken['type']) => toks.filter((t) => t.type === type).map((t) => t.text);
const joined = (toks: YamlToken[]) => toks.map((t) => t.text).join('');

describe('tokenizeYaml', () => {
  it('colours keys, strings, numbers, booleans and comments', () => {
    const src = ['# the PoC', 'name: reflected-xss', 'severity: high', 'steps:', "  - request:", '      status: 200 # expected', '      enabled: true', "      q: '\"><img src=x>'"].join('\n');
    const lines = tokenizeYaml(src);
    expect(lines).toHaveLength(8);
    expect(ofType(lines[0]!, 'comment')).toEqual(['# the PoC']);
    expect(ofType(lines[1]!, 'key')).toEqual(['name']);
    expect(ofType(lines[1]!, 'string')).toEqual(['reflected-xss']);
    expect(ofType(lines[3]!, 'key')).toEqual(['steps']);
    expect(ofType(lines[4]!, 'punct')).toEqual(['-', ':']);
    expect(ofType(lines[4]!, 'key')).toEqual(['request']);
    expect(ofType(lines[5]!, 'number')).toEqual(['200']);
    expect(ofType(lines[5]!, 'comment')).toEqual(['# expected']);
    expect(ofType(lines[6]!, 'bool')).toEqual(['true']);
    expect(ofType(lines[7]!, 'string')).toEqual(["'\"><img src=x>'"]);
  });

  it('round-trips every character so the gutter numbers stay aligned', () => {
    const src = 'a: 1\n\n  b: [x, y, {c: 2}]\nd: >\n  folded text # not a comment\n';
    const lines = tokenizeYaml(src);
    expect(lines.map(joined)).toEqual(src.split('\n'));
    expect(ofType(lines[2]!, 'punct')).toEqual([':', '[', ',', ',', '{', ':', '}', ']']);
    expect(ofType(lines[2]!, 'string')).toEqual(['x', 'y']);
    expect(ofType(lines[2]!, 'number')).toEqual(['2']);
    expect(ofType(lines[2]!, 'key')).toEqual(['b', 'c']);
  });

  it('does not treat a URL value as a key', () => {
    const [line] = tokenizeYaml('target: https://api.shop-staging.test');
    expect(ofType(line!, 'key')).toEqual(['target']);
    expect(ofType(line!, 'string')).toEqual(['https://api.shop-staging.test']);
  });
});
