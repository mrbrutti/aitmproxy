import { createSignal } from 'solid-js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import type { PocRun } from '~/bus/mock';
import type { BusClient, BusState, ToolDef } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { FindingsPanel } from '~/panels/FindingsPanel';

/** A bus that serves `poc.list` from a fixed array and nothing else; `address: 'fixtures'` keeps the store from polling. */
function fakeBus(runs: PocRun[]): BusClient {
  const [state] = createSignal<BusState>('open');
  const tools: ToolDef[] = ['poc.list', 'poc.run', 'poc.artifact', 'flow.list'].map((name) => ({ name, description: '', inputSchema: { type: 'object' } }));
  return {
    address: 'fixtures',
    state,
    lastError: () => null,
    connect() {},
    close() {},
    async tools() {
      return tools;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      // Like the bridge: every reply is a fresh decoded value, never a shared reference.
      if (tool === 'poc.list') return [...runs] as T;
      if (tool === 'flow.list') return [] as T;
      if (tool === 'poc.run') {
        const src = runs.find((r) => r.poc_path === args.poc_path);
        if (!src) throw new Error('unknown poc');
        await new Promise((r) => setTimeout(r, 30));
        const next: PocRun = { ...src, id: `${src.id}-again`, at: Date.now(), target: String(args.target ?? src.target) };
        runs.unshift(next);
        return next as T;
      }
      throw new Error(`unexpected ${tool}`);
    },
    onNotification() {
      return () => {};
    },
  };
}

/**
 * A bus shaped like the real core: `poc.list` returns library summaries only ({id, title, severity,
 * poc_path}), `poc.get` serves the YAML, `poc.run` answers with a result and keeps no history.
 */
function coreBus(summaries: { id: string; title: string; severity: PocRun['severity']; poc_path: string }[], sources: Record<string, string>, calls: string[] = []): BusClient {
  const [state] = createSignal<BusState>('open');
  const tools: ToolDef[] = ['poc.list', 'poc.get', 'poc.build', 'poc.run', 'poc.artifact', 'flow.list'].map((name) => ({ name, description: '', inputSchema: { type: 'object' } }));
  return {
    address: 'fixtures',
    state,
    lastError: () => null,
    connect() {},
    close() {},
    async tools() {
      return tools;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      calls.push(tool);
      if (tool === 'poc.list') return summaries.map((s) => ({ ...s })) as T;
      if (tool === 'flow.list') return [] as T;
      if (tool === 'poc.get') {
        await new Promise((r) => setTimeout(r, 20));
        const yaml = sources[String(args.poc_path)];
        if (yaml == null) throw new Error('not found');
        return { yaml } as T;
      }
      // The core returns the YAML text and writes no file.
      if (tool === 'poc.build') return `name: ${String(args.name)}\nvars:\n  ${String(args.param)}: probe\n` as T;
      if (tool === 'poc.run') {
        await new Promise((r) => setTimeout(r, 30));
        return { passed: true, evaluated: [{ assertion: 'status == 200', matched: true }], finding_capture: '', screenshot_path: null } as T;
      }
      throw new Error(`unexpected ${tool}`);
    },
    onNotification() {
      return () => {};
    },
  };
}

const run = (over: Partial<PocRun>): PocRun => ({
  id: 'poc_x',
  title: 'Untitled',
  severity: 'low',
  target: 'https://a.test',
  passed: true,
  at: Date.now(),
  origin: 'human',
  poc_path: '/poc/x.yaml',
  yaml: 'name: x\n',
  finding_capture: '',
  screenshot_path: null,
  evaluated: [],
  ...over,
});

const now = Date.now();
const RUNS: PocRun[] = [
  run({ id: 'old', title: 'Oldest: open redirect', severity: 'low', at: now - 3 * 3_600_000, target: 'https://auth.test', poc_path: '/poc/old.yaml' }),
  run({
    id: 'new',
    poc_path: '/poc/new.yaml',
    title: 'Newest: reflected XSS',
    severity: 'high',
    at: now - 60_000,
    origin: 'agent',
    evaluated: [
      { assertion: 'status == 200', matched: true },
      { assertion: 'body contains payload', matched: true },
      { assertion: 'content-type is text/html', matched: false },
    ],
  }),
  run({ id: 'mid', title: 'Middle: rate limit', severity: 'medium', at: now - 30 * 60_000, passed: false, poc_path: '/poc/mid.yaml' }),
];

function mountWith(bus: BusClient) {
  const store = createAppStore(bus);
  const r = render(() => (
    <AppProvider store={store}>
      <FindingsPanel />
    </AppProvider>
  ));
  return { ...r, store };
}
const mount = (runs: PocRun[]) => mountWith(fakeBus(runs));

afterEach(() => cleanup());

describe('FindingsPanel', () => {
  it('lists every run newest first and filters by severity', async () => {
    mount(RUNS);
    const rows = await screen.findAllByRole('option');
    expect(rows).toHaveLength(3);
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringContaining('Newest: reflected XSS'),
      expect.stringContaining('Middle: rate limit'),
      expect.stringContaining('Oldest: open redirect'),
    ]);
    expect(screen.getByText('Findings').parentElement!.textContent).toContain('· 3');
    expect(rows[0]!.textContent).toContain('agent');

    fireEvent.click(screen.getByRole('button', { name: /medium/ }));
    await waitFor(() => expect(screen.getAllByRole('option')).toHaveLength(1));
    expect(screen.getByRole('option').textContent).toContain('Middle: rate limit');

    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    await waitFor(() => expect(screen.getAllByRole('option')).toHaveLength(3));
  });

  it('shows the selected run with its title and assertion counts', async () => {
    mount(RUNS);
    await screen.findAllByRole('option');
    // Newest is selected by default.
    expect(screen.getByRole('heading', { level: 2 }).textContent).toBe('Newest: reflected XSS');
    expect(screen.getByText('2 of 3 matched')).toBeTruthy();
    expect(screen.getByText('No screenshot for this run.')).toBeTruthy();

    fireEvent.click(screen.getByText('Middle: rate limit'));
    await waitFor(() => expect(screen.getByRole('heading', { level: 2 }).textContent).toBe('Middle: rate limit'));
    expect(screen.getByText('No assertions were evaluated.')).toBeTruthy();
    expect(screen.getByText('Failed')).toBeTruthy();
  });

  it('moves the selection with the arrow keys', async () => {
    mount(RUNS);
    await screen.findAllByRole('option');
    const list = screen.getByRole('listbox');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    await waitFor(() => expect(screen.getByRole('heading', { level: 2 }).textContent).toBe('Middle: rate limit'));
    fireEvent.keyDown(list, { key: 'End' });
    await waitFor(() => expect(screen.getByRole('heading', { level: 2 }).textContent).toBe('Oldest: open redirect'));
  });

  it('keeps the frame and says the trade\'s words when there are no findings', async () => {
    mount([]);
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('No findings — build a PoC from any flow with p.'));
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('runs a PoC again from the popover and selects the new run', async () => {
    mount(RUNS.map((r) => ({ ...r })));
    const before = (await screen.findAllByRole('option')).length;
    fireEvent.click(screen.getByText('Middle: rate limit'));
    fireEvent.click(screen.getByRole('button', { name: /Run again/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Run again' });
    const target = dialog.querySelector('input') as HTMLInputElement;
    expect(target.value).toBe('https://a.test');
    fireEvent.input(target, { target: { value: 'https://b.test' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /^Run/ }));
    expect(await screen.findByText('Running…')).toBeTruthy();
    await waitFor(() => {
      const rows = screen.getAllByRole('option');
      expect(rows).toHaveLength(before + 1);
      expect(rows[0]!.getAttribute('aria-selected')).toBe('true');
    });
    expect(screen.getAllByRole('option')[0]!.textContent).toContain('https://b.test');
    expect(screen.getByRole('heading', { level: 2 }).textContent).toBe('Middle: rate limit');
    expect(screen.queryByText('Running…')).toBeNull();
  });

  it('shows a PoC built in this session honestly: not run, not runnable, YAML there to export', async () => {
    const { store } = mountWith(coreBus([], {}));
    await waitFor(() => expect(screen.getByRole('status').textContent).toContain('No findings'));
    // Build from a flow: the core returns YAML text and writes no file, so the store keeps a local entry.
    await store.buildPoc('flow_1', 'cua-reflected', 'q');
    const row = await screen.findByRole('option');
    expect(row.textContent).toContain('cua-reflected');
    expect(row.textContent).toContain('not run');
    expect(row.querySelector('[title="Passed"], [title="Failed"]')).toBeNull();

    expect(screen.getByText('Built in this session — not saved on the server. Export the YAML into poc.dir to run it.')).toBeTruthy();
    expect(screen.getByText('Not run yet')).toBeTruthy();
    expect(screen.getByText('Run the PoC to evaluate its assertions.')).toBeTruthy();
    const runAgain = screen.getByRole('button', { name: /Run again/ }) as HTMLButtonElement;
    expect(runAgain.disabled).toBe(true);
    expect(runAgain.title).toContain('export the YAML into poc.dir');
    expect(screen.getByLabelText('PoC YAML').textContent).toBe('name: cua-reflectedvars:  q: probe');

    // Export › YAML downloads the text (jsdom has no object URLs or Blob.text(); read it with a FileReader).
    const blobs: Blob[] = [];
    const createObjectURL = vi.fn((b: Blob) => (blobs.push(b), 'blob:x'));
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    fireEvent.click(screen.getByRole('button', { name: /Export/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: 'YAML' }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const text = await new Promise<string>((resolve) => {
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result));
      fr.readAsText(blobs[0]!);
    });
    expect(text).toBe('name: cua-reflected\nvars:\n  q: probe\n');
    click.mockRestore();
  });

  it('loads a library entry\'s YAML through poc.get on selection and shows a verdict only after a run', async () => {
    const calls: string[] = [];
    const path = '/tmp/poc/lib.yaml';
    mountWith(coreBus([{ id: 'lib', title: 'lib: idor', severity: 'medium', poc_path: path }], { [path]: 'name: lib\nvars:\n  q: probe\n' }, calls));
    const row = await screen.findByRole('option');
    expect(row.textContent).toContain('not run');
    expect(row.textContent).toContain('—'); // no time: it never ran
    expect(screen.getByText('Not run yet')).toBeTruthy();
    expect(screen.getByText('Run the PoC to evaluate its assertions.')).toBeTruthy();
    expect(screen.queryByText('No YAML for this run.')).toBeNull();
    expect(screen.getByRole('progressbar', { name: 'Loading PoC YAML' })).toBeTruthy();
    await waitFor(() => expect(screen.getByLabelText('PoC YAML').textContent).toBe('name: libvars:  q: probe'));
    expect(calls.filter((c) => c === 'poc.get')).toHaveLength(1);

    const runAgain = screen.getByRole('button', { name: /Run again/ }) as HTMLButtonElement;
    expect(runAgain.disabled).toBe(false);
    fireEvent.click(runAgain);
    const dialog = await screen.findByRole('dialog', { name: 'Run again' });
    expect((dialog.querySelector('textarea') as HTMLTextAreaElement).value).toBe('q=probe'); // vars prefilled from the fetched YAML
    fireEvent.input(dialog.querySelector('input') as HTMLInputElement, { target: { value: 'https://b.test' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /^Run/ }));
    await waitFor(() => expect(screen.getByText('Passed')).toBeTruthy());
    expect(screen.getByText('1 of 1 matched')).toBeTruthy();
    expect(screen.queryByText('Run the PoC to evaluate its assertions.')).toBeNull();
    expect(screen.getByRole('option').querySelector('[title="Passed"]')).toBeTruthy();
    expect(screen.getByRole('option').textContent).not.toContain('not run');
    // The source was asked for once; the run did not refetch it.
    expect(calls.filter((c) => c === 'poc.get')).toHaveLength(1);
  });

  it('highlights the YAML and edits it locally', async () => {
    mount(RUNS);
    await screen.findAllByRole('option');
    const pre = screen.getByLabelText('PoC YAML');
    expect(pre.textContent).toBe('name: x');
    expect(pre.querySelectorAll('[class]').length).toBeGreaterThanOrEqual(3); // key, punct, string
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    const ta = screen.getByLabelText('Edit PoC YAML') as HTMLTextAreaElement;
    fireEvent.input(ta, { target: { value: 'name: y\n' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.getByLabelText('PoC YAML').textContent).toBe('name: y'));
    expect(screen.getByText(/Edited locally/)).toBeTruthy();
  });
});
