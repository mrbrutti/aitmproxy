// Fixture generator for UI development and perf measurement without a live proxy. Produces
// flows shaped like the mockup's (shop-staging.test, the same clients) with real headers and
// bodies, including one 5 MB JSON response for the body-viewer bar (§2.10(b)).

import type { Body, Client, FlowDetail, Header, Origin } from '~/model/flow';

// Deterministic PRNG so screenshots and perf runs are reproducible.
export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const CLIENTS: Client[] = [
  { id: 'obscura', name: 'obscura', addr: '127.0.0.1:52001' },
  { id: 'curl', name: 'curl', addr: '127.0.0.1:52114' },
  { id: 'safari', name: 'Safari', addr: '127.0.0.1:52230' },
  { id: 'python3', name: 'python3', addr: '127.0.0.1:52301' },
];
export const AGENT_CLIENT: Client = { id: 'aitm', name: 'aitm', addr: '127.0.0.1:9090' };

export const SCOPE_HOSTS = ['api.shop-staging.test', 'auth.shop-staging.test', 'cdn.shop-staging.test'];

interface Endpoint {
  weight: number;
  method: string;
  host: string;
  path: string;
  query?: string[];
  status: number[];
  reqBody?: () => Body;
  resBody: (rng: () => number) => Body;
  client?: string;
  http1?: boolean;
}

const json = (v: unknown, pretty = true): Body => {
  const text = pretty ? JSON.stringify(v, null, 2) : JSON.stringify(v);
  return { text, contentType: 'application/json; charset=utf-8', size: text.length, truncated: false };
};
const empty = (): Body => ({ text: '', contentType: null, size: 0, truncated: false });
const textBody = (text: string, ct: string): Body => ({ text, contentType: ct, size: text.length, truncated: false });

const PRODUCT_NAMES = ['Aurora Lamp', 'Kestrel Desk', 'Vela Chair', 'Orion Speaker', 'Tidal Mug', 'Fennel Rug', 'Nimbus Pillow'];
const product = (rng: () => number, i: number) => ({
  id: 1000 + i,
  sku: `SKU-${(1000 + i).toString(36).toUpperCase()}`,
  name: PRODUCT_NAMES[i % PRODUCT_NAMES.length],
  price: Math.round(rng() * 40000) / 100,
  currency: 'EUR',
  in_stock: rng() > 0.2,
  tags: ['electronics', 'home', 'sale'].filter(() => rng() > 0.5),
  updated_at: new Date(1761556800000 - Math.floor(rng() * 1e8)).toISOString(),
});

const ENDPOINTS: Endpoint[] = [
  {
    weight: 18,
    method: 'GET',
    host: 'api.shop-staging.test',
    path: '/api/products',
    query: ['category=electronics&limit=20', 'category=home&limit=20&page=2', 'sort=price&limit=50'],
    status: [200, 200, 200, 304],
    resBody: (rng) => json({ items: Array.from({ length: 20 }, (_, i) => product(rng, i)), total: 412, page: 1 }),
  },
  {
    weight: 8,
    method: 'GET',
    host: 'api.shop-staging.test',
    path: '/api/me',
    status: [200, 200, 401],
    resBody: () =>
      json({ id: 1042, email: 'ops@shop-staging.test', role: 'admin', mfa_enrolled: false, plan: { tier: 'pro', seats: 5 } }),
  },
  {
    weight: 6,
    method: 'PUT',
    host: 'api.shop-staging.test',
    path: '/api/cart/items/42',
    status: [200, 200, 409],
    reqBody: () => json({ quantity: 3, gift_wrap: false }),
    resBody: () => json({ item_id: 42, quantity: 3, subtotal: 89.7 }),
  },
  {
    weight: 5,
    method: 'POST',
    host: 'auth.shop-staging.test',
    path: '/api/auth/login',
    status: [200, 200, 401, 429],
    reqBody: () => json({ email: 'ops@shop-staging.test', password: 'correct-horse-battery', remember: true }),
    resBody: () =>
      json({
        token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMiLCJyb2xlIjoiYWRtaW4ifQ.3kZ0',
        expires_in: 3600,
        user: { id: 1042, email: 'ops@shop-staging.test', role: 'admin', mfa_enrolled: false },
      }),
  },
  {
    weight: 10,
    method: 'GET',
    host: 'cdn.shop-staging.test',
    path: '/assets/app.3f1c.js',
    status: [200, 304, 304],
    resBody: () =>
      textBody(
        `/*! shop v3.1.0 */\n(()=>{"use strict";const e=document.querySelector("#app");fetch("/api/me").then(r=>r.json()).then(u=>{e.textContent=u.email});})();\n`,
        'application/javascript',
      ),
  },
  {
    weight: 5,
    method: 'GET',
    host: 'cdn.shop-staging.test',
    path: '/assets/app.css',
    status: [200, 304],
    resBody: () => textBody(`:root{--brand:#2563eb}body{font:14px/1.5 system-ui;margin:0}.btn{padding:8px 12px}\n`, 'text/css'),
  },
  {
    weight: 6,
    method: 'GET',
    host: 'cdn.shop-staging.test',
    path: '/assets/hero.webp',
    status: [200],
    resBody: () => ({ text: null, base64: '', contentType: 'image/webp', size: 184_320, truncated: false }),
  },
  {
    weight: 4,
    method: 'POST',
    host: 'telemetry.vendor-analytics.example',
    path: '/v2/batch',
    status: [204, 204, 200],
    client: 'safari',
    reqBody: () => json({ events: [{ t: 'page_view', path: '/' }, { t: 'click', id: 'cta' }] }, false),
    resBody: () => empty(),
  },
  {
    weight: 5,
    method: 'GET',
    host: 'api.shop-staging.test',
    path: '/api/orders',
    query: ['page=1', 'page=3', 'status=open'],
    status: [200, 200, 502],
    client: 'curl',
    resBody: (rng) =>
      json({
        orders: Array.from({ length: 8 }, (_, i) => ({
          id: `ord_${(7000 + i).toString(36)}`,
          total: Math.round(rng() * 50000) / 100,
          status: ['open', 'paid', 'shipped'][Math.floor(rng() * 3)],
        })),
      }),
  },
  {
    weight: 3,
    method: 'PATCH',
    host: 'api.shop-staging.test',
    path: '/api/cart',
    status: [422, 200],
    client: 'python3',
    reqBody: () => json({ coupon: 'WELCOME10' }),
    resBody: () => json({ error: 'coupon_expired', message: 'Coupon WELCOME10 expired on 2026-09-30' }),
  },
  {
    weight: 3,
    method: 'HEAD',
    host: 'api.shop-staging.test',
    path: '/api/health',
    status: [200],
    client: 'python3',
    http1: true,
    resBody: () => empty(),
  },
  {
    weight: 2,
    method: 'DELETE',
    host: 'api.shop-staging.test',
    path: '/api/account/sessions/7',
    status: [204, 403],
    client: 'curl',
    resBody: () => empty(),
  },
  {
    weight: 3,
    method: 'POST',
    host: 'api.shop-staging.test',
    path: '/graphql',
    status: [200],
    reqBody: () => json({ query: '{ viewer { id email orders(first: 5) { edges { node { id total } } } } }' }, false),
    resBody: () => json({ data: { viewer: { id: '1042', email: 'ops@shop-staging.test', orders: { edges: [] } } } }),
  },
  {
    weight: 2,
    method: 'GET',
    host: 'shop-staging.test',
    path: '/',
    status: [200],
    resBody: () =>
      textBody(
        `<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8"><title>Shop</title><link rel="stylesheet" href="https://cdn.shop-staging.test/assets/app.css"></head>\n<body><div id="app"></div><script src="https://cdn.shop-staging.test/assets/app.3f1c.js"></script></body>\n</html>\n`,
        'text/html; charset=utf-8',
      ),
  },
  {
    weight: 2,
    method: 'GET',
    host: 'api.shop-staging.test',
    path: '/api/search',
    query: ['q=lamp', 'q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E'],
    status: [200],
    resBody: (rng) => json({ q: 'lamp', hits: Array.from({ length: 3 }, (_, i) => product(rng, i)) }),
  },
];

const TOTAL_WEIGHT = ENDPOINTS.reduce((a, e) => a + e.weight, 0);

const STATUS_TEXT: Record<number, string> = {
  101: 'Switching Protocols',
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  304: 'Not Modified',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  409: 'Conflict',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
};
export const statusText = (s: number) => STATUS_TEXT[s] ?? '';

const UA: Record<string, string> = {
  obscura: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) obscura/0.3 Chrome/131.0 Safari/537.36',
  curl: 'curl/8.7.1',
  safari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
  python3: 'python-requests/2.32.3',
  aitm: 'aitmproxy/0.3.0 (+agent)',
};

export interface GenOptions {
  rng: () => number;
  seq: number;
  now: number;
  /** When armed, new http requests start paused. */
  armed: boolean;
  scope: readonly string[];
}

/** A freshly started flow: request known, response pending. */
export function generateRequest(o: GenOptions): FlowDetail {
  const { rng } = o;
  let pick = rng() * TOTAL_WEIGHT;
  let ep = ENDPOINTS[0]!;
  for (const e of ENDPOINTS) {
    pick -= e.weight;
    if (pick <= 0) {
      ep = e;
      break;
    }
  }
  const client = ep.client ? CLIENTS.find((c) => c.id === ep.client)! : CLIENTS[Math.floor(rng() * CLIENTS.length)]!;
  const query = ep.query ? ep.query[Math.floor(rng() * ep.query.length)]! : null;
  const reqBody = ep.reqBody ? ep.reqBody() : empty();
  const headers: Header[] = [
    { name: 'host', value: ep.host },
    { name: 'user-agent', value: UA[client.id] ?? 'unknown' },
    { name: 'accept', value: ep.path.startsWith('/assets') ? '*/*' : 'application/json, */*;q=0.8' },
    { name: 'accept-encoding', value: 'gzip, deflate, br' },
  ];
  if (reqBody.size) headers.push({ name: 'content-type', value: reqBody.contentType ?? 'application/octet-stream' });
  if (reqBody.size) headers.push({ name: 'content-length', value: String(reqBody.size) });
  if (ep.host !== 'cdn.shop-staging.test' && rng() > 0.3)
    headers.push({ name: 'authorization', value: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMifQ.sig' });
  if (client.id !== 'curl') headers.push({ name: 'cookie', value: 'session=s%3A9f1c3b; _ga=GA1.2.1' });
  const inScope = o.scope.some((h) => h === ep.host || (h.startsWith('*.') && ep.host.endsWith(h.slice(1))));
  const paused = o.armed && inScope;
  return {
    id: `f_${o.seq.toString(36)}`,
    seq: o.seq,
    kind: 'http',
    method: ep.method,
    scheme: 'https',
    authority: ep.host,
    path: ep.path,
    query,
    status: null,
    statusText: null,
    startedAt: o.now,
    durationMs: null,
    reqSize: reqBody.size + headers.reduce((a, h) => a + h.name.length + h.value.length + 4, 0) + 20,
    resSize: null,
    client,
    tls: inScope ? 'mitm' : ep.host === 'telemetry.vendor-analytics.example' ? 'tunnel' : ep.path === '/api/health' ? 'pinned' : 'mitm',
    httpVersion: ep.http1 ? 'HTTP/1.1' : 'HTTP/2',
    intercept: paused ? 'paused' : 'none',
    edited: false,
    isReplay: false,
    origin: 'client',
    inScope,
    contentType: null,
    mark: null,
    comment: null,
    error: null,
    request: { headers, body: reqBody },
    response: null,
    conn: {
      peer: client.addr ?? '127.0.0.1:0',
      sni: ep.host,
      alpn: ep.http1 ? 'http/1.1' : 'h2',
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      upstream: `${ep.host}:443`,
    },
    timing: null,
  };
}

/** Completes a pending flow with its response. */
export function generateResponse(flow: FlowDetail, rng: () => number, now: number): FlowDetail {
  const ep = ENDPOINTS.find((e) => e.host === flow.authority && e.path === flow.path && e.method === flow.method) ?? ENDPOINTS[0]!;
  const status = ep.status[Math.floor(rng() * ep.status.length)]!;
  const body = status === 304 || status === 204 ? empty() : ep.resBody(rng);
  const headers: Header[] = [
    { name: 'date', value: new Date(now).toUTCString() },
    { name: 'server', value: ep.host.startsWith('cdn') ? 'cloudfront' : 'envoy' },
  ];
  if (body.size) {
    headers.push({ name: 'content-type', value: body.contentType ?? 'application/octet-stream' });
    headers.push({ name: 'content-length', value: String(body.size) });
  }
  if (ep.host.startsWith('cdn')) headers.push({ name: 'cache-control', value: 'public, max-age=31536000, immutable' });
  else headers.push({ name: 'cache-control', value: 'no-store' });
  if (ep.path === '/api/auth/login' && status === 200)
    headers.push({ name: 'set-cookie', value: 'session=s%3A9f1c3b; Path=/; HttpOnly; Secure; SameSite=Lax' });
  if (status === 429) headers.push({ name: 'retry-after', value: '30' });
  const dns = Math.round(rng() * 8);
  const connect = Math.round(rng() * 20);
  const tls = Math.round(rng() * 30);
  const wait = Math.round(status >= 500 ? 800 + rng() * 600 : 10 + rng() * (ep.path === '/api/products' ? 120 : 60));
  const download = Math.round((body.size / 200_000) * 1000 + rng() * 5);
  const durationMs = Math.max(1, now - flow.startedAt, dns + connect + tls + wait + download);
  return {
    ...flow,
    status,
    statusText: statusText(status),
    durationMs,
    resSize: body.size + headers.reduce((a, h) => a + h.name.length + h.value.length + 4, 0),
    contentType: body.contentType,
    response: { headers, body },
    timing: { dnsMs: dns, connectMs: connect, tlsMs: tls, waitMs: wait, downloadMs: download },
  };
}

/** A WebSocket flow with a few frames, for the WS row and frame list. */
export function generateWebSocket(o: GenOptions): FlowDetail {
  const req = generateRequest(o);
  const frames = Array.from({ length: 6 }, (_, i) => {
    const up = i % 3 === 0;
    const text = up
      ? JSON.stringify({ type: 'subscribe', channel: 'orders' })
      : JSON.stringify({ type: 'order.updated', id: `ord_${(7000 + i).toString(36)}`, status: 'shipped' });
    return { dir: up ? 'up' : 'down', opcode: 'text', at: o.now + i * 350, text, size: text.length, injected: false } as const;
  });
  return {
    ...req,
    kind: 'websocket',
    method: 'GET',
    scheme: 'wss',
    authority: 'api.shop-staging.test',
    path: '/ws/notifications',
    query: null,
    status: 101,
    statusText: 'Switching Protocols',
    client: CLIENTS[0]!,
    tls: 'mitm',
    intercept: 'none',
    inScope: true,
    contentType: null,
    ws: { up: frames.filter((f) => f.dir === 'up').length, down: frames.filter((f) => f.dir === 'down').length },
    request: {
      headers: [
        { name: 'host', value: 'api.shop-staging.test' },
        { name: 'upgrade', value: 'websocket' },
        { name: 'connection', value: 'Upgrade' },
        { name: 'sec-websocket-key', value: 'dGhlIHNhbXBsZSBub25jZQ==' },
        { name: 'sec-websocket-version', value: '13' },
      ],
      body: empty(),
    },
    response: {
      headers: [
        { name: 'upgrade', value: 'websocket' },
        { name: 'connection', value: 'Upgrade' },
        { name: 'sec-websocket-accept', value: 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=' },
      ],
      body: empty(),
    },
    wsMessages: [...frames],
  };
}

/** The 5 MB JSON body: a product catalog export. Built once on demand. */
let bigBody: Body | null = null;
export function bigJsonBody(): Body {
  if (bigBody) return bigBody;
  const rng = mulberry32(7);
  const items: unknown[] = [];
  let size = 0;
  const target = 5 * 1024 * 1024;
  let i = 0;
  while (size < target) {
    const p = {
      ...product(rng, i),
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.',
      variants: [
        { color: 'graphite', stock: Math.floor(rng() * 50) },
        { color: 'sand', stock: Math.floor(rng() * 50) },
      ],
      dimensions_mm: { w: 120 + i % 40, h: 300 + i % 90, d: 80 },
    };
    items.push(p);
    size += 420;
    i++;
  }
  const text = JSON.stringify({ exported_at: '2026-10-27T11:05:00Z', count: items.length, items }, null, 2);
  bigBody = { text, contentType: 'application/json; charset=utf-8', size: text.length, truncated: false };
  return bigBody;
}

export function generateBigJsonFlow(o: GenOptions): FlowDetail {
  const req = generateRequest(o);
  const body = bigJsonBody();
  return {
    ...req,
    method: 'GET',
    authority: 'api.shop-staging.test',
    path: '/api/export/catalog.json',
    query: null,
    client: CLIENTS[1]!,
    tls: 'mitm',
    intercept: 'none',
    inScope: true,
    status: 200,
    statusText: 'OK',
    durationMs: 1840,
    reqSize: 402,
    resSize: body.size,
    contentType: body.contentType,
    request: {
      headers: [
        { name: 'host', value: 'api.shop-staging.test' },
        { name: 'user-agent', value: UA.curl! },
        { name: 'accept', value: 'application/json' },
      ],
      body: empty(),
    },
    response: {
      headers: [
        { name: 'content-type', value: body.contentType! },
        { name: 'content-length', value: String(body.size) },
        { name: 'cache-control', value: 'no-store' },
      ],
      body,
    },
    timing: { dnsMs: 2, connectMs: 11, tlsMs: 24, waitMs: 310, downloadMs: 1493 },
  };
}

export function asAgentReplay(flow: FlowDetail, seq: number, now: number, origin: Origin = 'agent'): FlowDetail {
  return {
    ...flow,
    id: `f_${seq.toString(36)}`,
    seq,
    startedAt: now,
    status: null,
    statusText: null,
    durationMs: null,
    resSize: null,
    response: null,
    timing: null,
    intercept: 'none',
    isReplay: true,
    origin,
    client: origin === 'agent' ? AGENT_CLIENT : { id: 'aitm-web', name: 'aitm-web' },
    edited: false,
    mark: null,
    comment: null,
  };
}
