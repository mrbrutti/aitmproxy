import { describe, expect, it } from 'vitest';
import {
  applyQuery,
  autoContentType,
  buildMultipart,
  curlToDraft,
  detailToDraft,
  effectiveHeaders,
  emptyDraft,
  encodeForm,
  formatHeaderLines,
  jsonProblem,
  parseHeaderLines,
  parseQuery,
  pushHistory,
  readHistory,
  scopeCheck,
  templateDraft,
} from './model';
import type { FlowDetail } from '~/model/flow';

describe('scope pre-check', () => {
  const scope = [{ host: 'api.shop-staging.test' }, { host: 'localhost:8443' }, { host: '*.corp.test' }];

  it('matches an exact host regardless of port and case', () => {
    expect(scopeCheck('https://API.shop-staging.test/v1', scope)).toEqual({ host: 'api.shop-staging.test', inScope: true });
    expect(scopeCheck('http://api.shop-staging.test:9000/', scope).inScope).toBe(true);
  });
  it('matches host:port only on that port (default ports included)', () => {
    expect(scopeCheck('https://localhost:8443/x', scope).inScope).toBe(true);
    expect(scopeCheck('https://localhost/x', scope).inScope).toBe(false);
    expect(scopeCheck('https://a.test/', [{ host: 'a.test:443' }]).inScope).toBe(true);
    expect(scopeCheck('http://a.test/', [{ host: 'a.test:443' }]).inScope).toBe(false);
  });
  it('matches *.wildcard against subdomains, not the bare domain', () => {
    expect(scopeCheck('https://auth.corp.test/', scope).inScope).toBe(true);
    expect(scopeCheck('https://a.b.corp.test/', scope).inScope).toBe(true);
    expect(scopeCheck('https://corp.test/', scope).inScope).toBe(false);
    expect(scopeCheck('https://evilcorp.test/', scope).inScope).toBe(false);
  });
  it('reports no host for an unparseable or scheme-less URL', () => {
    expect(scopeCheck('api.shop-staging.test/v1', scope)).toEqual({ host: null, inScope: false });
    expect(scopeCheck('https://', scope)).toEqual({ host: null, inScope: false });
    expect(scopeCheck('', scope)).toEqual({ host: null, inScope: false });
  });
});

describe('headers bulk edit', () => {
  it('round-trips rows through the textarea format', () => {
    const rows = [
      { name: 'Accept', value: '*/*' },
      { name: 'X-Empty', value: '' },
      { name: '', value: '' },
    ];
    const text = formatHeaderLines(rows);
    expect(text).toBe('Accept: */*\nX-Empty:');
    expect(parseHeaderLines(text)).toEqual([
      { name: 'Accept', value: '*/*' },
      { name: 'X-Empty', value: '' },
    ]);
    expect(parseHeaderLines('Authorization: Bearer a:b:c\n\nNoColon')).toEqual([
      { name: 'Authorization', value: 'Bearer a:b:c' },
      { name: 'NoColon', value: '' },
    ]);
  });
});

describe('query ↔ url', () => {
  it('parses and rebuilds, keeping the fragment and decoding values', () => {
    const url = 'https://x.test/p?a=1&b=hello%20world&flag#frag';
    expect(parseQuery(url)).toEqual([
      { name: 'a', value: '1' },
      { name: 'b', value: 'hello world' },
      { name: 'flag', value: '' },
    ]);
    expect(applyQuery(url, parseQuery(url))).toBe('https://x.test/p?a=1&b=hello%20world&flag#frag');
    expect(applyQuery(url, [])).toBe('https://x.test/p#frag');
    expect(applyQuery('https://x.test/p', [{ name: 'q', value: 'a/b:c' }, { name: '', value: 'ignored' }])).toBe('https://x.test/p?q=a/b:c');
  });
});

describe('body encoders', () => {
  it('urlencodes form rows and skips blank ones', () => {
    expect(encodeForm([{ name: 'a b', value: 'c&d' }, { name: '', value: '' }])).toBe('a%20b=c%26d');
  });
  it('builds multipart with text and base64 file parts', () => {
    const body = buildMultipart(
      [
        { name: 'title', value: 'hi', file: null },
        { name: 'doc', value: '', file: { name: 'a.txt', type: 'text/plain', size: 3, base64: 'YWJj' } },
      ],
      'B',
    );
    expect(body).toBe(
      '--B\r\nContent-Disposition: form-data; name="title"\r\n\r\nhi\r\n' +
        '--B\r\nContent-Disposition: form-data; name="doc"; filename="a.txt"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n' +
        '--B--\r\n',
    );
  });
  it('flags JSON problems in plain words', () => {
    expect(jsonProblem('')).toBeNull();
    expect(jsonProblem('{"a":1}')).toBeNull();
    expect(jsonProblem('{"a":')).toMatch(/^Invalid JSON/);
  });
});

describe('content-type', () => {
  it('is added automatically from the body mode unless the user set one', () => {
    const d = templateDraft('post-json');
    d.raw = '{"a":1}';
    expect(autoContentType(d, 'B')).toBe('application/json');
    expect(effectiveHeaders(d, 'B')).toEqual({ Accept: 'application/json', 'Content-Type': 'application/json' });
    d.headers.push({ name: 'content-type', value: 'application/vnd.api+json' });
    expect(autoContentType(d, 'B')).toBeNull();
    expect(effectiveHeaders(d, 'B')['content-type']).toBe('application/vnd.api+json');
  });
  it('is absent for an empty body', () => {
    expect(autoContentType(templateDraft('post-form'), 'B')).toBeNull();
    const m = templateDraft('multipart');
    m.multipart = [{ name: 'f', value: 'v', file: null }];
    expect(autoContentType(m, 'B')).toBe('multipart/form-data; boundary=B');
  });
});

describe('prefill', () => {
  const detail: FlowDetail = {
    id: 'f1',
    seq: 1,
    kind: 'http',
    method: 'POST',
    scheme: 'https',
    authority: 'auth.shop-staging.test',
    path: '/login',
    query: 'r=1',
    status: 200,
    statusText: 'OK',
    startedAt: 0,
    durationMs: 1,
    reqSize: 1,
    resSize: 1,
    client: { id: 'c', name: 'c' },
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
        { name: ':authority', value: 'x' },
        { name: 'host', value: 'x' },
        { name: 'content-length', value: '9' },
        { name: 'content-type', value: 'application/x-www-form-urlencoded' },
      ],
      body: { text: 'user=a&pass=b%20c', contentType: 'application/x-www-form-urlencoded', size: 17, truncated: false },
    },
    response: null,
    conn: {},
    timing: null,
  };

  it('fills method, URL, headers (minus hop-by-hop) and decodes a form body into rows', () => {
    const d = detailToDraft(detail);
    expect(d.method).toBe('POST');
    expect(d.url).toBe('https://auth.shop-staging.test/login?r=1');
    expect(d.headers).toEqual([{ name: 'content-type', value: 'application/x-www-form-urlencoded' }]);
    expect(d.bodyMode).toBe('form');
    expect(d.form).toEqual([
      { name: 'user', value: 'a' },
      { name: 'pass', value: 'b c' },
    ]);
  });
  it('maps a parsed cURL to a draft and picks JSON mode from the content-type', () => {
    const d = curlToDraft({ method: 'POST', url: 'https://x.test/a', headers: [{ name: 'Content-Type', value: 'application/json' }], body: '{"k":1}', ignored: [] });
    expect(d.bodyMode).toBe('json');
    expect(d.raw).toBe('{"k":1}');
  });
});

describe('history', () => {
  const mem = () => {
    const m = new Map<string, string>();
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
  };
  it('keeps the last 20 sends newest first, deduped on method+URL, without files', () => {
    const s = mem();
    for (let i = 0; i < 25; i++) {
      const d = emptyDraft();
      d.url = `https://x.test/${i}`;
      pushHistory(d, s, i);
    }
    let h = readHistory(s);
    expect(h).toHaveLength(20);
    expect(h[0]!.draft.url).toBe('https://x.test/24');
    const again = emptyDraft();
    again.url = 'https://x.test/24';
    again.bodyMode = 'multipart';
    again.multipart = [{ name: 'f', value: '', file: { name: 'a', type: 't', size: 1, base64: 'QQ==' } }];
    h = pushHistory(again, s, 99);
    expect(h).toHaveLength(20);
    expect(h[0]!.at).toBe(99);
    expect(h[0]!.draft.multipart[0]!.file).toBeNull();
  });
  it('tolerates garbage in storage', () => {
    const s = mem();
    s.setItem('aitm.compose.history', '{nope');
    expect(readHistory(s)).toEqual([]);
  });
});
