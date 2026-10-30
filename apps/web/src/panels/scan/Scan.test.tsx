// Stage-1 scanner web surface (AC3 / AC6 web): the Scan nav is gated on `scan.discover`, the launch
// form is built from the tool's inputSchema with a scope-bound target, and a returned result renders
// one endpoint row per endpoint and one injection-point row per point, each point linking to its flow.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { createStore } from 'solid-js/store';
import { AppProvider } from '~/state/context';
import type { AppStore } from '~/state/app';
import type { ToolDef } from '~/bus/types';
import { Sidebar } from '~/shell/Sidebar';
import { ScanPanel } from '../ScanPanel';
import { parseScanResult } from './model';

const genericTool = (name: string): ToolDef => ({ name, description: '', inputSchema: { type: 'object' } });

/** The real `scan.discover` schema shape (crates/aitm-plugin-scanner/src/commands.rs). */
const scanTool = (): ToolDef => ({
  name: 'scan.discover',
  description: 'Discover reachable in-scope URLs and enumerate injection points.',
  inputSchema: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'The in-scope seed URL, e.g. `https://app.example/`.' },
      max_depth: { type: 'integer', description: 'Link depth to follow (clamped to the configured cap).' },
      max_pages: { type: 'integer', description: 'Pages to visit (clamped to the configured cap).' },
    },
    required: ['target'],
  },
});

const RESULT = {
  endpoints: ['https://app.example/', 'https://app.example/login', 'https://app.example/search'],
  injection_points: [
    { flow: 'flow_1', location: 'query', name: 'q', example: 'shoes' },
    { flow: 'flow_2', location: 'cookie', name: 'session_token', example: '<redacted>' },
  ],
  pages_crawled: 3,
  stopped_reason: null,
};

function stubApp(opts: { tools?: ToolDef[]; scope?: { host: string }[]; result?: unknown } = {}) {
  const [proxy, setProxy] = createStore({
    tools: opts.tools ?? [],
    scope: opts.scope ?? [],
    findings: [] as unknown[],
    agentActionsLastMinute: 0,
    version: '0.3.0',
    address: '127.0.0.1:8080',
  });
  const [ui, setUi] = createStore({ sidebar: { kind: 'all' } as { kind: string }, pinned: [] as string[], quickFilter: '', panel: 'scan' });
  const scanDiscover = vi.fn(async (_args: Record<string, unknown>) => ('result' in opts ? opts.result : null));
  const loadDetail = vi.fn(async (_id: string) => null);
  const addScope = vi.fn(async (h: string) => setProxy('scope', (s) => [...s, { host: h }]));
  const app = {
    proxy,
    ui,
    groups: () => ({ apps: [] as { id: string; name: string; count: number }[], domains: [] as { host: string; count: number }[], inScope: 0 }),
    setSidebar: vi.fn((s: { kind: string }) => setUi('sidebar', s)),
    setQuickFilter: vi.fn(),
    scanDiscover,
    loadDetail,
    addScope,
    notice: vi.fn(),
    call: vi.fn(async () => null),
    setL4Ids: vi.fn(),
  };
  return { app: app as unknown as AppStore, scanDiscover, loadDetail, addScope, setProxy };
}

const tick = () => new Promise((r) => setTimeout(r, 30));

// jsdom has no layout: the virtual list measures the scroll element via clientHeight, so give every
// element a tall box and all rows render (mirrors FlowList.test.tsx).
const proto = HTMLElement.prototype;
const original = { w: Object.getOwnPropertyDescriptor(proto, 'clientWidth'), h: Object.getOwnPropertyDescriptor(proto, 'clientHeight') };
beforeEach(() => {
  Object.defineProperty(proto, 'clientWidth', { configurable: true, get: () => 1000 });
  Object.defineProperty(proto, 'clientHeight', { configurable: true, get: () => 2000 });
});
afterEach(() => {
  if (original.w) Object.defineProperty(proto, 'clientWidth', original.w);
  else delete (proto as unknown as Record<string, unknown>).clientWidth;
  if (original.h) Object.defineProperty(proto, 'clientHeight', original.h);
  else delete (proto as unknown as Record<string, unknown>).clientHeight;
  cleanup();
});

describe('parseScanResult', () => {
  it('reads endpoints, injection points and crawl meta from the raw scan.discover object', () => {
    const r = parseScanResult(RESULT);
    expect(r.endpoints).toEqual(['https://app.example/', 'https://app.example/login', 'https://app.example/search']);
    expect(r.injectionPoints).toHaveLength(2);
    expect(r.injectionPoints[0]).toEqual({ flow: 'flow_1', location: 'query', name: 'q', example: 'shoes' });
    expect(r.pagesCrawled).toBe(3);
    expect(r.stoppedReason).toBeNull();
  });

  it('tolerates a missing/garbage result without throwing', () => {
    expect(parseScanResult(null)).toEqual({ endpoints: [], injectionPoints: [], pagesCrawled: null, stoppedReason: null });
  });
});

describe('Scan nav gating', () => {
  it('hides the Scan nav item when scan.discover is not offered', () => {
    const { app } = stubApp({ tools: [genericTool('flow.list')] });
    const r = render(() => (
      <AppProvider store={app}>
        <Sidebar />
      </AppProvider>
    ));
    expect(r.queryByText('Scan')).toBeNull();
  });

  it('shows the Scan nav item when scan.discover is offered', () => {
    const { app } = stubApp({ tools: [scanTool()] });
    const r = render(() => (
      <AppProvider store={app}>
        <Sidebar />
      </AppProvider>
    ));
    expect(r.getByText('Scan')).toBeTruthy();
  });
});

describe('ScanPanel', () => {
  it('builds the launch form from the scan.discover input schema with a scope-bound target', () => {
    const { app } = stubApp({ tools: [scanTool()], scope: [{ host: 'app.example' }] });
    const r = render(() => (
      <AppProvider store={app}>
        <ScanPanel />
      </AppProvider>
    ));
    // The target is scope-bound: a chooser of in-scope hosts, not a free-text field.
    const target = r.getByLabelText<HTMLSelectElement>('Target');
    expect([...target.options].map((o) => o.value)).toContain('app.example');
    // The remaining schema fields come straight from the tool's inputSchema.
    expect(r.container.textContent).toContain('max depth');
    expect(r.container.textContent).toContain('max pages');
  });

  it('does not call scan.discover just from viewing the panel (deny-by-default, no auto-launch)', async () => {
    const { app, scanDiscover } = stubApp({ tools: [scanTool()], scope: [{ host: 'app.example' }], result: RESULT });
    render(() => (
      <AppProvider store={app}>
        <ScanPanel />
      </AppProvider>
    ));
    await tick();
    expect(scanDiscover).not.toHaveBeenCalled();
  });

  it('launches scan.discover with the scope-bound target on submit and renders endpoints + injection points', async () => {
    const { app, scanDiscover } = stubApp({ tools: [scanTool()], scope: [{ host: 'app.example' }], result: RESULT });
    const r = render(() => (
      <AppProvider store={app}>
        <ScanPanel />
      </AppProvider>
    ));
    const target = r.getByLabelText<HTMLSelectElement>('Target');
    target.value = 'app.example';
    target.dispatchEvent(new Event('change', { bubbles: true }));
    await tick();
    r.getByRole('button', { name: /discover/i }).click();
    await tick();

    expect(scanDiscover).toHaveBeenCalledTimes(1);
    expect(scanDiscover.mock.calls[0]![0]!.target).toBe('https://app.example/');

    const endpoints = r.container.querySelectorAll('[aria-label="Endpoints"] [data-endpoint]');
    expect(endpoints).toHaveLength(3);
    const points = r.container.querySelectorAll('[aria-label="Injection points"] [data-point]');
    expect(points).toHaveLength(2);
    // The redacted example is rendered verbatim — never reconstructed.
    expect(r.container.textContent).toContain('<redacted>');
  });

  it('opens the flow for an injection point via loadDetail with its flow id', async () => {
    const { app, loadDetail } = stubApp({ tools: [scanTool()], scope: [{ host: 'app.example' }], result: RESULT });
    const r = render(() => (
      <AppProvider store={app}>
        <ScanPanel />
      </AppProvider>
    ));
    const target = r.getByLabelText<HTMLSelectElement>('Target');
    target.value = 'app.example';
    target.dispatchEvent(new Event('change', { bubbles: true }));
    await tick();
    r.getByRole('button', { name: /discover/i }).click();
    await tick();

    const points = r.container.querySelectorAll<HTMLElement>('[aria-label="Injection points"] [data-point]');
    points[0]!.click();
    expect(loadDetail).toHaveBeenCalledWith('flow_1');
  });
});
