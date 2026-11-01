// T8 Task 12 (D-T8.8, D-T8.10, W-10, W-16, W-17): the Site map view. What these tests pin down is
// the view's contract with the store and with the live proof (`scripts/scan-live.mjs`): the
// `Site map` listbox and its `[data-node]` options grouped by host, the `Node detail` region, the
// `Insertion points` list with `kind:name` and the engine's `example` rendered verbatim, `Load
// more` iff `next_cursor`, `Open flow <id>` crossing into the app's own selection, and the four
// states every view has. The fixture under `crates/aitm-scan-model/fixtures/` is a wire *shape*,
// never evidence: a green run here says the view renders the contract, not that any scan ever ran.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import { scanStore, type ScanStore } from './store';
import { SitemapView } from './SitemapView';
import css from './scanner.module.css';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

const JOB = 'scan-1a2b3c4d';
const FLOW = '550e8400-e29b-41d4-a716-446655440000';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

interface SitemapWire {
  nodes: Record<string, unknown>[];
  points: Record<string, unknown>[];
  next_cursor: string | null;
}

/** The `scan.sitemap` fixture, parsed fresh per call so a mutation cannot leak. */
const sitemap = (): SitemapWire => fixture('scan.sitemap.json') as SitemapWire;

/** A second node on the same host: the one `next_cursor: "node-2"` points at. */
const node2 = (): Record<string, unknown> => ({
  ...sitemap().nodes[0]!,
  id: 'node-2',
  method: 'POST',
  path_template: '/account',
  flows: [],
  params: [],
  auth: false,
  points: 0,
  audited: false,
});

const built: ScanStore[] = [];

/** A stub app, its store and the mounted view, with the job list read so `selectedJob` is set. */
async function mount(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <SitemapView />
    </AppProvider>
  ));
  await s.refreshJobs();
  await tick();
  return { ...stub, s, r };
}

const list = () => screen.getByRole('listbox', { name: 'Site map' });
const detail = () => screen.getByRole('region', { name: 'Node detail' });
const options = () => Array.from(list().querySelectorAll<HTMLElement>('[role=option][data-node]'));
const option = (id: string) => list().querySelector<HTMLElement>(`[data-node="${id}"]`);
const pointsList = () => screen.getByRole('list', { name: 'Insertion points' });
const pointRows = () => Array.from(pointsList().querySelectorAll<HTMLElement>('li[data-point]'));
const texts = (root: ParentNode, sel: string) => Array.from(root.querySelectorAll(sel)).map((e) => e.textContent);

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  for (const s of built.splice(0)) s.dispose();
  cleanup();
  vi.useRealTimers();
});

describe('SitemapView', () => {
  it('nodes_render', async () => {
    const h = await mount();
    // The mount effect read the page once, for the selected job, with the contract's limit.
    expect(h.argsOf('scan.sitemap')).toEqual([{ job: JOB, limit: 1024 }]);

    const hosts = list().querySelectorAll(`.${css.treeHost}`);
    expect(hosts.length).toBe(1);
    expect(hosts[0]!.textContent).toBe('127.0.0.1:8080');

    expect(options().length).toBe(1);
    const row = option('node-1')!;
    expect(row).not.toBeNull();
    expect(row.getAttribute('role')).toBe('option');
    expect(row.textContent).toContain('/account/{id}');
    expect(row.textContent).toContain('GET');
    expect(row.querySelector('[data-field=points]')!.textContent).toBe('2');
    expect(within(row).getByTitle('audited')).toBeTruthy();
    expect(within(row).getByTitle('authenticated')).toBeTruthy();
  });

  it('points_render_verbatim', async () => {
    await mount();
    const rows = pointRows();
    expect(rows.length).toBe(2);
    expect(rows.map((r) => r.getAttribute('data-point'))).toEqual(['point-json-1', 'point-cookie-1']);
    expect(texts(pointsList(), '[data-field=kind-name]')).toEqual(['json_value:city', 'cookie:theme']);

    const first = rows[0]!;
    const second = rows[1]!;
    expect(first.querySelector('[data-field=path]')!.textContent).toBe('profile.address.city');
    expect(first.querySelector('[data-field=example]')!.textContent).toBe('Lisbon');
    // W-10: the engine redacted it; the UI prints the marker as is, never a value of its own.
    expect(second.querySelector('[data-field=example]')!.textContent).toBe('<redacted>');
    expect(second.querySelector('[data-field=path]')!.textContent).toBe('—');
    expect(texts(first, `.${css.chip}`)).toEqual(['json']);
    expect(texts(second, `.${css.chip}`)).toEqual(['id']);
    expect(first.querySelector('[data-field=frequency]')!.textContent).toBe('3');
    expect(second.querySelector('[data-field=frequency]')!.textContent).toBe('9');
    expect(first.querySelector('[data-field=request]')!.textContent).toBe('POST http://127.0.0.1:8080/account');
  });

  it('load_more_iff_cursor', async () => {
    const h = await mount();
    h.reply('scan.sitemap', (a) => (a.cursor ? { nodes: [node2()], points: [], next_cursor: null } : sitemap()));
    const more = screen.getByRole('button', { name: 'Load more' });
    fireEvent.click(more);
    await tick();
    expect(h.argsOf('scan.sitemap')[1]).toEqual({ job: JOB, limit: 1024, cursor: 'node-2' });
    expect(options().map((o) => o.getAttribute('data-node'))).toEqual(['node-1', 'node-2']);
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('open_flow', async () => {
    const h = await mount();
    fireEvent.click(option('node-1')!);
    const open = within(detail()).getByRole('button', { name: `Open flow ${FLOW}` });
    fireEvent.click(open);
    await tick();
    expect(h.select).toHaveBeenCalledWith(FLOW);
  });

  it('selection_filters_points', async () => {
    const page = sitemap();
    page.nodes.push(node2());
    page.points[1]!.site_node = 'node-2';
    page.next_cursor = null;
    const h = await mount({ replies: { 'scan.sitemap': page } });
    expect(pointRows().length).toBe(2);

    fireEvent.click(option('node-1')!);
    expect(h.s.selectedNode()).toBe('node-1');
    expect(option('node-1')!.getAttribute('aria-selected')).toBe('true');
    expect(option('node-2')!.getAttribute('aria-selected')).toBe('false');
    expect(pointRows().map((r) => r.getAttribute('data-point'))).toEqual(['point-json-1']);

    // The detail shows the selected node's facts.
    const region = detail();
    expect(region.textContent).toContain('/account/{id}');
    expect(region.textContent).toContain('http://127.0.0.1:8080');
    expect(region.textContent).toContain('query:tab');

    fireEvent.click(option('node-2')!);
    expect(pointRows().map((r) => r.getAttribute('data-point'))).toEqual(['point-cookie-1']);
  });

  it('states', async () => {
    // empty
    const empty = await mount({ replies: { 'scan.sitemap': { nodes: [], points: [], next_cursor: null } } });
    expect(screen.getByText('No site map for this job yet')).toBeTruthy();
    expect(list()).toBeTruthy();
    expect(detail()).toBeTruthy();
    empty.s.dispose();
    cleanup();

    // loading: the layout is there with grey bars until the first read answers
    const pending = await mount({ replies: { 'scan.sitemap': () => new Promise(() => {}) } });
    expect(document.querySelector(`.${css.loading}`)).not.toBeNull();
    expect(list()).toBeTruthy();
    pending.s.dispose();
    cleanup();

    // error: the core's text inside the block, and Retry reads again
    const stub = stubApp();
    stub.fail('scan.sitemap', 'x');
    const s = scanStore(stub.app);
    built.push(s);
    render(() => (
      <AppProvider store={stub.app}>
        <SitemapView />
      </AppProvider>
    ));
    await s.refreshJobs();
    await tick();
    const block = document.querySelector(`.${css.errorBlock}`);
    expect(block).not.toBeNull();
    expect(block!.textContent).toContain('x');
    expect(stub.count('scan.sitemap')).toBe(1);
    stub.reply('scan.sitemap', sitemap());
    fireEvent.click(within(block as HTMLElement).getByRole('button', { name: 'Retry' }));
    await tick();
    expect(stub.count('scan.sitemap')).toBe(2);
    expect(options().length).toBe(1);
    expect(document.querySelector(`.${css.errorBlock}`)).toBeNull();

    // reconnecting: every control disabled, a one-line note, the data kept
    fireEvent.click(option('node-1')!);
    stub.setBusState('reconnecting');
    await tick();
    const buttons = Array.from(document.querySelectorAll('button'));
    expect(buttons.length).toBeGreaterThan(0);
    expect(buttons.every((b) => b.disabled)).toBe(true);
    expect(screen.getByText(/reconnecting/)).toBeTruthy();
    expect(options().length).toBe(1);
  });

  it('keyboard', async () => {
    const page = sitemap();
    page.nodes.push(node2());
    page.next_cursor = null;
    const h = await mount({ replies: { 'scan.sitemap': page } });
    const box = list();
    box.focus();
    expect(h.s.selectedNode()).toBeNull();

    fireEvent.keyDown(box, { key: 'ArrowDown' });
    expect(h.s.selectedNode()).toBe('node-1');
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    expect(h.s.selectedNode()).toBe('node-2');
    expect(option('node-2')!.getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(box, { key: 'ArrowUp' });
    expect(h.s.selectedNode()).toBe('node-1');
    fireEvent.keyDown(box, { key: 'End' });
    expect(h.s.selectedNode()).toBe('node-2');
    fireEvent.keyDown(box, { key: 'Home' });
    expect(h.s.selectedNode()).toBe('node-1');

    fireEvent.keyDown(box, { key: 'Enter' });
    expect(document.activeElement).toBe(detail());
  });
});
