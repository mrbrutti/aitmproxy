import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import { AppProvider } from '~/state/context';
import type { AppStore, FlowEntry } from '~/state/app';
import type { ToolDef } from '~/bus/types';
import type { FlowSummary } from '~/model/flow';
import { CommandPalette } from './CommandPalette';

const tool = (name: string, description: string, props: Record<string, unknown> = {}, required: string[] = [], mutates = true, confirm: string | null = null): ToolDef => ({
  name,
  description,
  inputSchema: { type: 'object', properties: props as NonNullable<ToolDef['inputSchema']['properties']>, required },
  mutates,
  confirm,
});

const TOOLS: ToolDef[] = [
  tool('flow.list', 'List captured flow ids.', {}, [], false),
  tool('flow.replay', 'Send a captured request again.', { id: { type: 'string', 'x-aitm': 'FlowId' } }, ['id']),
  tool('flow.kill', 'Abort a flow.', { id: { type: 'string' }, mode: { type: 'string', enum: ['reset', '429', '503'] } }, ['id']),
  tool('ca.install', 'Install the root CA.', { store: { type: 'string' } }, [], true, 'This changes the system trust store.'),
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

function stubApp() {
  const entries = [flow(1), flow(2, { authority: 'auth.shop-staging.test', path: '/login', method: 'POST' })];
  const [version] = createSignal(0);
  const [ui, setUi] = createStore({ paletteOpen: true, theme: 'light', density: 'dense', layout: 'horizontal' });
  const call = vi.fn(async (name: string, args?: Record<string, unknown>) => {
    if (name === 'flow.replay') return 'f2';
    if (name === 'flow.list') return ['f1', 'f2'];
    return { ok: true, name, args };
  });
  const app = {
    ui,
    proxy: { tools: TOOLS, armed: false, scope: [] },
    version,
    entries,
    byId: new Map(entries.map((e) => [e.id, e])),
    openPalette: vi.fn((open: boolean) => setUi('paletteOpen', open)),
    select: vi.fn(),
    notice: vi.fn(),
    call,
    refreshSide: vi.fn(async () => {}),
    arm: vi.fn(),
    setSidebar: vi.fn(),
    setPanel: vi.fn(),
    setTheme: vi.fn(),
    setDensity: vi.fn(),
    setLayout: vi.fn(),
  };
  return app as unknown as AppStore & typeof app;
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const mount = async (app: AppStore) => {
  render(() => <AppProvider store={app}><CommandPalette /></AppProvider>);
  await tick(); // Portal content lands after the first render
  return screen; // render() binds its queries to the container; portals land in document.body
};

// This jsdom has no localStorage; the palette persists recents and pins through it.
const mem = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k), clear: () => mem.clear() },
});

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe('CommandPalette grouping', () => {
  it('shows Commands, Flows and Setup groups from the stubbed tools and flows', async () => {
    const app = stubApp();
    const { getByRole, getAllByRole, queryByText, getByText } = await mount(app);
    expect(getByRole('combobox')).toHaveProperty('placeholder', 'Type a command, a URL, or a setup action…');
    expect(getByText('Commands')).toBeTruthy();
    expect(getByText('Flows')).toBeTruthy();
    expect(getByText('Setup')).toBeTruthy();
    expect(queryByText('Recent')).toBeNull();
    const options = getAllByRole('option');
    expect(options.map((o) => o.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('flow.replay'), expect.stringContaining('Install CA')]));
    // read-only hint on non-mutating tools
    expect(getByText('flow.list').closest('[role="option"]')!.textContent).toContain('read-only');
    // flows newest first
    const flows = options.filter((o) => o.textContent?.includes('shop-staging'));
    expect(flows[0]!.textContent).toContain('/login');
  });

  it('`>` restricts to commands and filters by fuzzy match', async () => {
    const app = stubApp();
    const { getByRole, getAllByRole, queryByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>kill' } });
    await tick();
    expect(queryByText('Flows')).toBeNull();
    expect(queryByText('Setup')).toBeNull();
    const names = getAllByRole('option').map((o) => o.textContent);
    expect(names).toHaveLength(1);
    expect(names[0]).toContain('flow.kill');
  });

  it('`/` restricts to flows and Enter selects the highlighted flow', async () => {
    const app = stubApp();
    const { getByRole, getAllByRole, queryByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '/login' } });
    await tick();
    expect(queryByText('Commands')).toBeNull();
    expect(getAllByRole('option')).toHaveLength(1);
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    expect(app.select).toHaveBeenCalledWith('f2');
    expect(app.openPalette).toHaveBeenCalledWith(false);
  });

  it('⌘P pins the highlighted command and a Pinned group appears', async () => {
    const app = stubApp();
    const { getByRole, getByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>replay' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'p', metaKey: true });
    await tick();
    expect(getByText('Pinned')).toBeTruthy();
    expect(JSON.parse(localStorage.getItem('aitm.palette.pinned')!)).toEqual(['flow.replay']);
  });

  it('runs a parameterless command immediately and shows the result inline', async () => {
    const app = stubApp();
    const { getByRole, getByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>flow.list' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    await tick();
    await tick();
    expect(app.call).toHaveBeenCalledWith('flow.list', {});
    expect(getByRole('status').textContent).toContain('ok');
    expect(getByText(/"f1"/)).toBeTruthy();
    expect(JSON.parse(localStorage.getItem('aitm.palette.recent')!)).toEqual(['cmd:flow.list']);
  });

  it('opens a schema form for a command with parameters, validates required, then runs', async () => {
    const app = stubApp();
    const { getByRole, getByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>kill' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    await tick();
    // enum → segmented radios, id → plain input (name "id" alone is a flow picker)
    expect(getByRole('radiogroup')).toBeTruthy();
    const run = getByText('Run').closest('button')!;
    fireEvent.click(run);
    await tick();
    expect(app.call).not.toHaveBeenCalled();
    expect(getByText('Required')).toBeTruthy();
    const picker = document.querySelector<HTMLInputElement>('input[role="combobox"][placeholder^="Search flows"]')!;
    fireEvent.input(picker, { target: { value: 'f1' } });
    fireEvent.keyDown(picker, { key: 'Enter' });
    await tick();
    fireEvent.click(getByText('429'));
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    await tick();
    expect(app.call).toHaveBeenCalledWith('flow.kill', { id: 'f1', mode: '429' });
  });

  it('asks for confirmation when the tool carries a confirm prompt', async () => {
    const app = stubApp();
    const { getByRole, getByText, queryByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>ca.install' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    expect(getByText('This changes the system trust store.')).toBeTruthy();
    expect(app.call).not.toHaveBeenCalled();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.call).toHaveBeenCalledWith('ca.install', {});
    expect(queryByText('Confirm')).toBeNull();
  });

  it('Esc closes from the list and returns to the list from a form', async () => {
    const app = stubApp();
    const { getByRole } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>replay' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Escape' });
    await tick();
    expect(app.openPalette).not.toHaveBeenCalled();
    expect(getByRole('listbox', { name: 'Results' })).toBeTruthy();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Escape' });
    expect(app.openPalette).toHaveBeenCalledWith(false);
  });
});
