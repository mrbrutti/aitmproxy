import { describe, expect, it } from 'vitest';
import { shQuote, toCurl } from './curl';
import type { FlowDetail, FlowSummary } from '~/model/flow';

const summary: FlowSummary = {
  id: 'f1',
  seq: 50,
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
};

const detail: FlowDetail = {
  ...summary,
  request: {
    headers: [
      { name: ':authority', value: 'auth.shop-staging.test' },
      { name: 'host', value: 'auth.shop-staging.test' },
      { name: 'content-type', value: 'application/json' },
      { name: 'content-length', value: '48' },
      { name: 'user-agent', value: "curl/8.7.1 (it's quoted)" },
    ],
    body: { text: '{"email":"ops@shop-staging.test","remember":true}', contentType: 'application/json', size: 48, truncated: false },
  },
  response: null,
  conn: {},
  timing: null,
};

describe('toCurl', () => {
  it('renders a POST with headers and a JSON body, skipping hop-by-hop and pseudo headers', () => {
    expect(toCurl(detail)).toBe(
      [
        'curl',
        '--http2',
        "'https://auth.shop-staging.test/api/auth/login?remember=1'",
        "-H 'content-type: application/json'",
        "-H 'user-agent: curl/8.7.1 (it'\\''s quoted)'",
        `--data-raw '{"email":"ops@shop-staging.test","remember":true}'`,
      ].join(' \\\n  '),
    );
  });

  it('falls back to method + URL when only the summary is known', () => {
    expect(toCurl({ ...summary, httpVersion: 'HTTP/1.1' })).toBe("curl \\\n  -X POST \\\n  'https://auth.shop-staging.test/api/auth/login?remember=1'");
    expect(toCurl({ ...summary, method: 'GET', query: null, httpVersion: null })).toBe("curl \\\n  'https://auth.shop-staging.test/api/auth/login'");
  });

  it('uses -I for HEAD and upgrade headers for WebSocket flows', () => {
    expect(toCurl({ ...summary, method: 'HEAD', httpVersion: null })).toBe("curl \\\n  -I \\\n  'https://auth.shop-staging.test/api/auth/login?remember=1'");
    const ws = toCurl({ ...summary, kind: 'websocket', scheme: 'wss', method: 'GET', query: null, httpVersion: null });
    expect(ws).toContain("'wss://auth.shop-staging.test/api/auth/login'");
    expect(ws).toContain("-H 'Upgrade: websocket'");
  });

  it('shell-quotes single quotes', () => {
    expect(shQuote("a'b")).toBe(`'a'\\''b'`);
  });
});
