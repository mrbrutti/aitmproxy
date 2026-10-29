import { describe, expect, it } from 'vitest';
import { parseCurl, tokenize, CurlParseError } from './curl-parse';
import { toCurl } from './curl';
import type { FlowDetail } from '~/model/flow';

describe('tokenize', () => {
  it('splits on whitespace and honours single and double quotes', () => {
    expect(tokenize(`curl -H 'a: b c' "d \\"e\\" f" g`)).toEqual(['curl', '-H', 'a: b c', 'd "e" f', 'g']);
  });
  it('drops backslash-newline continuations', () => {
    expect(tokenize('curl \\\n  -X POST \\\r\n  https://x.test')).toEqual(['curl', '-X', 'POST', 'https://x.test']);
  });
  it("decodes $'…' ANSI-C quoting", () => {
    expect(tokenize(`curl -d $'{"a":"b\\n"}' $'it\\'s'`)).toEqual(['curl', '-d', '{"a":"b\n"}', "it's"]);
    expect(tokenize(`$'\\x41\\101\\t'`)).toEqual(['AA\t']);
  });
  it("handles POSIX '\\'' concatenation", () => {
    expect(tokenize(`'it'\\''s'`)).toEqual(["it's"]);
  });
  it('throws on unterminated quotes', () => {
    expect(() => tokenize(`curl 'oops`)).toThrow(CurlParseError);
  });
});

describe('parseCurl', () => {
  it('parses method, headers, raw data and a URL with a query', () => {
    const r = parseCurl(
      `curl -X PUT 'https://api.example.test/v1/items?limit=5&q=a%20b' \\\n  -H 'Content-Type: application/json' -H "X-Token: abc" --data-raw '{"a":1}'`,
    );
    expect(r.method).toBe('PUT');
    expect(r.url).toBe('https://api.example.test/v1/items?limit=5&q=a%20b');
    expect(r.headers).toEqual([
      { name: 'Content-Type', value: 'application/json' },
      { name: 'X-Token', value: 'abc' },
    ]);
    expect(r.body).toBe('{"a":1}');
  });

  it('implies POST and a form content-type for -d / --data', () => {
    const r = parseCurl(`curl https://x.test/login -d 'user=a' --data 'pass=b'`);
    expect(r.method).toBe('POST');
    expect(r.body).toBe('user=a&pass=b');
    expect(r.headers).toEqual([{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }]);
  });

  it('percent-encodes --data-urlencode values and joins them', () => {
    const r = parseCurl(`curl https://x.test/s --data-urlencode 'q=a b&c' --data-urlencode '=raw value' --data-urlencoded 'plain'`);
    expect(r.body).toBe('q=a%20b%26c&raw%20value&plain');
  });

  it('accepts bundled short options and --flag=value forms', () => {
    const r = parseCurl(`curl -XDELETE --url=https://x.test/a -H'X-A: 1' -d'{"k":1}'`);
    expect(r.method).toBe('DELETE');
    expect(r.url).toBe('https://x.test/a');
    expect(r.headers[0]).toEqual({ name: 'X-A', value: '1' });
    expect(r.body).toBe('{"k":1}');
  });

  it('turns -G data into the query string and -I into HEAD', () => {
    expect(parseCurl(`curl -G https://x.test/q?a=1 -d b=2`)).toMatchObject({ method: 'GET', url: 'https://x.test/q?a=1&b=2', body: null });
    expect(parseCurl(`curl -I https://x.test/`).method).toBe('HEAD');
  });

  it('maps -u, -A, -b and --json onto headers', () => {
    const r = parseCurl(`curl -u 'me:pw' -A ua/1 -b 'sid=1' --json '{"x":1}' https://x.test/`);
    expect(r.method).toBe('POST');
    expect(r.headers).toEqual([
      { name: 'User-Agent', value: 'ua/1' },
      { name: 'Cookie', value: 'sid=1' },
      { name: 'Content-Type', value: 'application/json' },
      { name: 'Accept', value: 'application/json' },
      { name: 'Authorization', value: `Basic ${btoa('me:pw')}` },
    ]);
  });

  it('adds https:// to a bare host and records flags it cannot express', () => {
    const r = parseCurl(`curl --compressed -o out.bin -s example.test/path`);
    expect(r.url).toBe('https://example.test/path');
    expect(r.ignored).toEqual(['--compressed', '-o out.bin', '-s']);
  });

  it('tolerates a leading prompt and rejects non-curl input', () => {
    expect(parseCurl(`$ curl https://x.test`).url).toBe('https://x.test');
    expect(() => parseCurl(`wget https://x.test`)).toThrow(/Not a curl/);
    expect(() => parseCurl(`curl -s`)).toThrow(/No URL/);
  });

  it('round-trips the output of lib/curl.ts', () => {
    const detail: FlowDetail = {
      id: 'f1',
      seq: 1,
      kind: 'http',
      method: 'POST',
      scheme: 'https',
      authority: 'auth.shop-staging.test',
      path: '/api/auth/login',
      query: 'remember=1',
      status: 200,
      statusText: 'OK',
      startedAt: 0,
      durationMs: 12,
      reqSize: 186,
      resSize: 518,
      client: { id: 'curl', name: 'curl' },
      tls: 'mitm',
      httpVersion: 'HTTP/2',
      intercept: 'none',
      edited: false,
      isReplay: false,
      origin: 'client',
      inScope: true,
      contentType: 'application/json',
      mark: null,
      comment: null,
      request: {
        headers: [
          { name: 'content-type', value: 'application/json' },
          { name: 'user-agent', value: "curl/8.7.1 (it's quoted)" },
        ],
        body: { text: '{"email":"ops@shop-staging.test","remember":true}', contentType: 'application/json', size: 48, truncated: false },
      },
      response: null,
      conn: {},
      timing: null,
    };
    const r = parseCurl(toCurl(detail));
    expect(r.method).toBe('POST');
    expect(r.url).toBe('https://auth.shop-staging.test/api/auth/login?remember=1');
    expect(r.headers).toEqual(detail.request.headers);
    expect(r.body).toBe(detail.request.body.text);
    expect(r.ignored).toEqual(['--http2']);

    const del = parseCurl(toCurl({ ...detail, method: 'DELETE', request: { headers: [], body: { text: null, contentType: null, size: 0, truncated: false } } }));
    expect(del.method).toBe('DELETE');
    expect(del.body).toBeNull();
  });
});
