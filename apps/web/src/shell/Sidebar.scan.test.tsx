// T8 Task 14 (D-T8.1, W-6): the Sidebar's Scan item is gated on what the core offers (the v2
// `scan.start` family or the v1 `scan.discover`), and its count is the live job count the scan
// store holds — read once on bootstrap, before the panel is ever opened, so the operator sees a scan
// is running from the nav. The bridge-like bus mirrors `Sidebar.test.tsx`; the fixtures under
// `crates/aitm-scan-model/fixtures/` are wire shapes only (fixtures/README.md).
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppProvider } from '~/state/context';
import { createAppStore, type AppStore } from '~/state/app';
import { bridgeBus } from '~/state/bridgeBus.testkit';
import type { BusClient, ToolDef } from '~/bus/types';
import { scanStore } from '~/panels/scanner/store';
import { Sidebar } from './Sidebar';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

/** The fifteen v2 verbs; hiding all of them leaves a core without the v2 family. */
const SCAN_V2_VERBS = [
  'scan.start',
  'scan.map',
  'scan.status',
  'scan.list',
  'scan.cancel',
  'scan.issues',
  'scan.issue',
  'scan.issue.update',
  'scan.sitemap',
  'scan.checks',
  'scan.profile.list',
  'scan.profile.get',
  'scan.profile.save',
  'scan.profile.delete',
  'scan.session.preview',
];
const DISCOVER: ToolDef = { name: 'scan.discover', description: 'v1 discover', inputSchema: { type: 'object' } };
const tool = (name: string): ToolDef => ({ name, description: `${name} (scan test)`, inputSchema: { type: 'object' } });

const mounted: { app: AppStore; close: () => void }[] = [];

/**
 * The bridge bus serves no `scan.*` verb of its own (`bridgeBus.testkit.ts` answers the flow-list
 * suites' tools only), so the scan catalogue and its replies are added here: the fifteen v2 verbs
 * minus `hide`, answered from the `crates/aitm-scan-model/fixtures/` shapes, `scan.list` optionally
 * by hand. `scan.discover` is appended on request.
 */
function mount(opts: { hide?: string[]; addDiscover?: boolean; list?: unknown } = {}) {
  const base = bridgeBus();
  const hidden = new Set(opts.hide ?? []);
  const scanTools = SCAN_V2_VERBS.filter((v) => !hidden.has(v)).map(tool);
  const bus: BusClient = {
    ...base,
    async tools() {
      const all = await base.tools();
      return [...all, ...scanTools, ...(opts.addDiscover ? [DISCOVER] : [])];
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      if (tool === 'scan.list' && opts.list !== undefined) return opts.list as T;
      if (SCAN_V2_VERBS.includes(tool)) return fixture(`${tool}.json`) as T;
      return base.call<T>(tool, args);
    },
  };
  const app = createAppStore(bus);
  mounted.push({ app, close: () => base.close() });
  render(() => (
    <AppProvider store={app}>
      <Sidebar />
    </AppProvider>
  ));
  return { app };
}

afterEach(() => {
  cleanup();
  for (const m of mounted.splice(0)) {
    scanStore(m.app).dispose();
    m.close();
  }
});

const item = () => screen.queryByText('Scan')?.closest('button') ?? null;
const count = () => item()?.querySelector('[data-kind]')?.textContent ?? null;

describe('Sidebar Scan gating', () => {
  it('shows the Scan item when the core offers scan.start (v2)', async () => {
    mount();
    await waitFor(() => expect(item()).not.toBeNull());
  });

  it('shows the Scan item when the core offers only scan.discover (v1)', async () => {
    const { app } = mount({ hide: SCAN_V2_VERBS, addDiscover: true });
    await waitFor(() => expect(app.proxy.tools.some((t) => t.name === 'scan.discover')).toBe(true));
    expect(item()).not.toBeNull();
  });

  it('hides the Scan item when the core offers neither', async () => {
    const { app } = mount({ hide: SCAN_V2_VERBS });
    await waitFor(() => expect(app.proxy.tools.length).toBeGreaterThan(0));
    expect(item()).toBeNull();
  });
});

describe('Sidebar Scan live count', () => {
  it('shows the live job count from scan.list', async () => {
    mount({ list: fixture('scan.list.json') });
    await waitFor(() => expect(count()).toBe('1 live'));
  });

  it('shows no count when no job is live', async () => {
    const list = fixture('scan.list.json') as { jobs: { state: string; phase: string }[] };
    for (const j of list.jobs) {
      j.state = 'done';
      j.phase = 'done';
    }
    const { app } = mount({ list });
    await waitFor(() => expect(scanStore(app).liveCount()).toBe(0));
    expect(count()).toBeNull();
  });
});
