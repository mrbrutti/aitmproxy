import { describe, expect, it } from 'vitest';
import { createStore } from 'solid-js/store';
import type { ToolDef } from '~/bus/types';
import type { FlowEntry } from '~/state/app';
import type { FlowSummary } from '~/model/flow';
import { buildGroups, compactJson, flatten, flowIdsIn, parseQuery, pushRecent, togglePinned, type SetupAction } from './groups';

const tool = (name: string, description: string, props: Record<string, unknown> = {}, mutates = true): ToolDef => ({
  name,
  description,
  inputSchema: { type: 'object', properties: props as NonNullable<ToolDef['inputSchema']['properties']> },
  mutates,
  confirm: null,
});

const TOOLS: ToolDef[] = [
  tool('flow.list', 'List captured flow ids.', {}, false),
  tool('flow.replay', 'Send a captured request again.', { id: { type: 'string', 'x-aitm': 'FlowId' } }),
  tool('flow.kill', 'Abort a flow.', { id: { type: 'string' } }),
  tool('request.send', 'Send a crafted request through the proxy.', { url: { type: 'string' } }),
  tool('ca.install', 'Install the root CA.', {}),
];

const flow = (seq: number, p: Partial<FlowSummary> = {}): FlowEntry => {
  const raw: FlowSummary = {
    id: `f${seq}`,
    seq,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    authority: 'api.shop-staging.test',
    path: `/api/items/${seq}`,
    query: null,
    status: 200,
    statusText: 'OK',
    startedAt: seq,
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
    contentType: null,
    mark: null,
    comment: null,
    ...p,
  };
  const [store, set] = createStore(raw);
  return { id: raw.id, flow: store, raw, set };
};
const FLOWS = [flow(1), flow(2, { authority: 'auth.shop-staging.test', path: '/login', method: 'POST' }), flow(3)];

const SETUP: SetupAction[] = [
  { id: 'install-ca', label: 'Install CA', icon: 'lock', tool: 'ca.install' },
  { id: 'open-browser', label: 'Open browser', icon: 'globe', run: () => {} },
];

describe('parseQuery', () => {
  it('reads the > and / prefixes', () => {
    expect(parseQuery('> kill')).toEqual({ mode: 'commands', text: 'kill' });
    expect(parseQuery('/login')).toEqual({ mode: 'flows', text: 'login' });
    expect(parseQuery('  ca ')).toEqual({ mode: 'all', text: 'ca' });
  });
});

describe('buildGroups', () => {
  it('with an empty query shows Recent, Pinned, Commands, Flows (newest first) and Setup', () => {
    const groups = buildGroups({ query: '', tools: TOOLS, flows: FLOWS, recent: ['cmd:flow.kill', 'setup:open-browser', 'cmd:gone'], pinned: ['flow.replay'], setup: SETUP });
    expect(groups.map((g) => g.id)).toEqual(['recent', 'pinned', 'commands', 'flows', 'setup']);
    const recent = groups[0]!.items;
    expect(recent.map((i) => i.key)).toEqual(['cmd:flow.kill', 'setup:open-browser']);
    expect(groups[1]!.items.map((i) => i.key)).toEqual(['cmd:flow.replay']);
    // pinned commands leave the Commands group; order follows tools/list
    expect(groups[2]!.items.map((i) => i.key)).toEqual(['cmd:flow.list', 'cmd:flow.kill', 'cmd:request.send', 'cmd:ca.install']);
    expect(groups[3]!.items.map((i) => i.key)).toEqual(['flow:f3', 'flow:f2', 'flow:f1']);
    expect(groups[4]!.items.map((i) => i.key)).toEqual(['setup:install-ca', 'setup:open-browser']);
  });

  it('filters by fuzzy match and drops Recent once there is a query', () => {
    const groups = buildGroups({ query: 'send', tools: TOOLS, flows: FLOWS, recent: ['cmd:flow.kill'], pinned: [], setup: SETUP });
    expect(groups.map((g) => g.id)).toEqual(['commands']);
    const cmds = groups[0]!.items.map((i) => i.key);
    expect(cmds[0]).toBe('cmd:request.send');
    expect(cmds).toContain('cmd:flow.replay');
    expect(cmds).not.toContain('cmd:flow.kill');
    const first = groups[0]!.items[0]!;
    expect(first.kind === 'command' && first.nameHits).toEqual([8, 9, 10, 11]);
  });

  it('`>` restricts to commands and `/` to flows', () => {
    expect(buildGroups({ query: '>', tools: TOOLS, flows: FLOWS, recent: [], pinned: [], setup: SETUP }).map((g) => g.id)).toEqual(['commands']);
    const flows = buildGroups({ query: '/login', tools: TOOLS, flows: FLOWS, recent: [], pinned: [], setup: SETUP });
    expect(flows.map((g) => g.id)).toEqual(['flows']);
    expect(flows[0]!.items.map((i) => i.key)).toEqual(['flow:f2']);
  });

  it('matches flows by method and status too, and caps the list', () => {
    const many = Array.from({ length: 30 }, (_, i) => flow(i + 1));
    const groups = buildGroups({ query: '', tools: [], flows: many, recent: [], pinned: [], setup: [] });
    expect(groups[0]!.items).toHaveLength(6);
    const post = buildGroups({ query: 'post', tools: [], flows: FLOWS, recent: [], pinned: [], setup: [] });
    expect(post[0]!.items.map((i) => i.key)).toEqual(['flow:f2']);
    const both = buildGroups({ query: 'items 200', tools: [], flows: FLOWS, recent: [], pinned: [], setup: [] });
    expect(both[0]!.items.map((i) => i.key)).toEqual(['flow:f3', 'flow:f1']);
    const first = both[0]!.items[0]!;
    const at = 'https://api.shop-staging.test/api/items/3'.indexOf('items');
    expect(first.kind === 'flow' && first.hits).toEqual([at, at + 1, at + 2, at + 3, at + 4]);
  });

  it('flattens groups in order for keyboard navigation', () => {
    const groups = buildGroups({ query: 'ca', tools: TOOLS, flows: FLOWS, recent: [], pinned: [], setup: SETUP });
    const flat = flatten(groups);
    expect(flat[0]!.key).toBe('cmd:ca.install');
    expect(flat.some((i) => i.key === 'setup:install-ca')).toBe(true);
  });
});

describe('recent and pinned persistence', () => {
  const mem = () => {
    const m = new Map<string, string>();
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
  };
  it('keeps at most six recents, newest first and deduped', () => {
    const s = mem();
    for (let i = 0; i < 8; i++) pushRecent(`cmd:t${i}`, s);
    const r = pushRecent('cmd:t3', s);
    expect(r).toEqual(['cmd:t3', 'cmd:t7', 'cmd:t6', 'cmd:t5', 'cmd:t4', 'cmd:t2']);
  });
  it('toggles pins', () => {
    const s = mem();
    expect(togglePinned('a', s)).toEqual(['a']);
    expect(togglePinned('b', s)).toEqual(['a', 'b']);
    expect(togglePinned('a', s)).toEqual(['b']);
  });
});

describe('result helpers', () => {
  it('finds flow ids in a string or object result', () => {
    const has = (id: string) => id.startsWith('f');
    expect(flowIdsIn('f9', has)).toEqual([{ label: null, id: 'f9' }]);
    expect(flowIdsIn({ finding_capture: 'f2', poc_path: '/x.yaml', passed: true }, has)).toEqual([{ label: 'finding_capture', id: 'f2' }]);
    expect(flowIdsIn(['f1'], has)).toEqual([]);
  });
  it('compacts JSON to eight lines', () => {
    const r = compactJson({ a: 1, b: [1, 2, 3, 4, 5, 6, 7, 8, 9] });
    expect(r.truncated).toBe(true);
    expect(r.text.split('\n')).toHaveLength(8);
    expect(compactJson(undefined)).toEqual({ text: 'ok', truncated: false });
  });
});
