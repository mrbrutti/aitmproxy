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
  tool('ca.install', 'Install the root CA.', { scope: { type: 'string' } }, [], true, 'This changes the system trust store.'),
  tool('ca.uninstall', 'Remove the root CA.', { scope: { type: 'string' } }, [], true, 'This changes the system trust store.'),
];

/** What `ca.status` parsed to on a Mac whose login keychain does not trust the CA yet. */
const CA_UNTRUSTED = { trusted: false, scope: null, platform: 'macos', fingerprint: 'AB:CD' } as const;

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

function stubApp(ca: AppStore['ca'] = null) {
  const entries = [flow(1), flow(2, { authority: 'auth.shop-staging.test', path: '/login', method: 'POST' })];
  const [version] = createSignal(0);
  const [ui, setUi] = createStore({ paletteOpen: true, theme: 'light', density: 'dense', layout: 'horizontal' });
  const call = vi.fn(async (name: string, args?: Record<string, unknown>): Promise<unknown> => {
    if (name === 'flow.replay') return 'f2';
    if (name === 'flow.list') return ['f1', 'f2'];
    return { ok: true, name, args };
  });
  const app = {
    ui,
    proxy: { tools: TOOLS, armed: false, scope: [] },
    ca,
    caInstalling: false,
    setCAInstalling: vi.fn(),
    refreshCA: vi.fn(async () => true),
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

/**
 * The bus as an operator connection sees a confirm-gated verb (bus spec D4): the first call is
 * answered with a non-error `needs_confirmation` envelope and runs nothing; only the identical
 * call re-sent with `_confirm: <token>` runs. `order` records every call in sequence.
 */
const handshakeBus = (app: ReturnType<typeof stubApp>, order: string[] = []) =>
  app.call.mockImplementation(async (name: string, args?: Record<string, unknown>) => {
    order.push(`call:${name}`);
    if (args && typeof args._confirm === 'string') return { changed: true, confirmed_with: args._confirm };
    return { status: 'needs_confirmation', prompt: `${name} changes the trust store of this machine. Confirm?`, confirm_token: 'tok-7f3a' };
  });
const mount = async (app: AppStore) => {
  render(() => <AppProvider store={app}><CommandPalette /></AppProvider>);
  await tick(); // Portal content lands after the first render
  return screen; // render() binds its queries to the container; portals land in document.body
};

/** Records the CA flag and read-back into `order`, alongside the calls `handshakeBus` already records. */
const traceCA = (app: ReturnType<typeof stubApp>, order: string[]) => {
  app.setCAInstalling.mockImplementation((on: boolean) => order.push(`installing:${on}`));
  app.refreshCA.mockImplementation(async () => {
    order.push('refreshCA');
    return true;
  });
};

/**
 * The Setup action taken as far as the bus's own prompt: Run, the tool's Confirm, the first
 * `ca.install` answered with `needs_confirmation`. The flag is up, nothing has run yet.
 */
const atServerPrompt = async (app: ReturnType<typeof stubApp>, order: string[]) => {
  traceCA(app, order);
  handshakeBus(app, order);
  const s = await mount(app);
  fireEvent.click(s.getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
  await tick();
  fireEvent.click(s.getByText('Run').closest('button')!);
  await tick();
  fireEvent.click(s.getByText('Confirm').closest('button')!);
  await tick();
  await tick();
  expect(s.getByRole('alert').textContent).toBe('ca.install changes the trust store of this machine. Confirm?');
  expect(order).toEqual(['installing:true', 'call:ca.install']);
  return s;
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
    expect(options.map((o) => o.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('flow.replay'), expect.stringContaining('Trust the aitmproxy CA')]));
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

  it('the Setup action prefills scope: user on macOS, holds the in-flight flag around the call, then re-reads ca.status (D17.1, D17.5, D17.12)', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    app.setCAInstalling.mockImplementation((on: boolean) => order.push(`installing:${on}`));
    app.refreshCA.mockImplementation(async () => {
      order.push('refreshCA');
      return true;
    });
    app.call.mockImplementation(async (name: string) => {
      order.push(`call:${name}`);
      return { changed: true };
    });
    const { getByRole, getByText } = await mount(app);
    const option = getByText('Trust the aitmproxy CA').closest('[role="option"]')!;
    expect(option.textContent).toContain('Install the root CA into your user trust store; HTTPS is not captured until then');
    fireEvent.click(option);
    await tick();
    expect(getByRole('dialog').querySelector<HTMLInputElement>('#palette-ca-install-scope')!.value).toBe('user');
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.call).toHaveBeenCalledWith('ca.install', { scope: 'user' });
    expect(order).toEqual(['installing:true', 'call:ca.install', 'refreshCA', 'installing:false']);
    expect(getByRole('status').textContent).toContain('ok');
  });

  it('a cancelled macOS dialog is an info notice, not an error (D17.4)', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const msg = 'ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted';
    app.call.mockImplementation(async () => {
      throw new Error(msg);
    });
    const { getByRole, getByText, queryByRole } = await mount(app);
    fireEvent.click(getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.notice).toHaveBeenCalledWith(msg, 'info');
    expect(queryByRole('status')).toBeNull();
    expect(getByRole('listbox', { name: 'Results' })).toBeTruthy();
    expect(app.refreshCA).toHaveBeenCalledTimes(1);
    expect(app.setCAInstalling).toHaveBeenLastCalledWith(false);
  });

  it('any other ca.install failure stays an error result and still re-reads ca.status', async () => {
    const app = stubApp(CA_UNTRUSTED);
    app.call.mockImplementation(async () => {
      throw new Error('ca.install refused: ca.install is refused from an agent frontend');
    });
    const { getByRole, getByText } = await mount(app);
    fireEvent.click(getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.notice).not.toHaveBeenCalled();
    expect(getByRole('status').textContent).toContain('error');
    expect(app.refreshCA).toHaveBeenCalledTimes(1);
  });

  it('the Setup action passes no scope on Linux (D17.1)', async () => {
    const app = stubApp({ trusted: false, scope: null, platform: 'linux-debian', fingerprint: 'AB:CD' });
    const { getByRole, getByText } = await mount(app);
    fireEvent.click(getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
    await tick();
    expect(getByRole('dialog').querySelector<HTMLInputElement>('#palette-ca-install-scope')!.value).toBe('');
  });

  it('ca.install from an operator connection completes the bus confirm handshake: the server prompt replaces the tool’s, Confirm re-sends the call with _confirm, the flag spans both calls', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    const { getByRole, getByText, queryByText, queryByRole } = await atServerPrompt(app, order);
    expect(app.call.mock.calls).toEqual([['ca.install', { scope: 'user' }]]);
    expect(queryByText('This changes the system trust store.')).toBeNull();
    expect(queryByRole('status')).toBeNull();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([
      ['ca.install', { scope: 'user' }],
      ['ca.install', { scope: 'user', _confirm: 'tok-7f3a' }],
    ]);
    expect(order).toEqual(['installing:true', 'call:ca.install', 'call:ca.install', 'refreshCA', 'installing:false']);
    expect(getByRole('status').textContent).toContain('ok');
    expect(getByText(/"confirmed_with": "tok-7f3a"/)).toBeTruthy();
    expect(app.notice).not.toHaveBeenCalled();
  });

  it('cancelling the server prompt sends nothing more, returns to the list, and still clears the flag after one re-read', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    const { getByRole, getByText, queryByRole } = await atServerPrompt(app, order);
    fireEvent.click(getByText('Cancel').closest('button')!);
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([['ca.install', { scope: 'user' }]]);
    expect(order).toEqual(['installing:true', 'call:ca.install', 'refreshCA', 'installing:false']);
    expect(queryByRole('status')).toBeNull();
    expect(queryByRole('alert')).toBeNull();
    expect(getByRole('listbox', { name: 'Results' })).toBeTruthy();
    expect(app.notice).not.toHaveBeenCalled();
  });

  it('closing the palette while the server prompt is up sends nothing more and still releases the flag', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    await atServerPrompt(app, order);
    cleanup();
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([['ca.install', { scope: 'user' }]]);
    expect(order).toEqual(['installing:true', 'call:ca.install', 'refreshCA', 'installing:false']);
  });

  it('closing the palette while the first call is still in flight: the late needs_confirmation reply opens no prompt and releases the flag', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    traceCA(app, order);
    let reply!: (v: unknown) => void;
    app.call.mockImplementation((name: string) => {
      order.push(`call:${name}`);
      return new Promise<unknown>((r) => {
        reply = r;
      });
    });
    const { getByText, queryByRole } = await mount(app);
    fireEvent.click(getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    expect(getByText('Running…')).toBeTruthy();
    expect(order).toEqual(['installing:true', 'call:ca.install']);
    cleanup();
    reply({ status: 'needs_confirmation', prompt: 'ca.install changes the trust store of this machine. Confirm?', confirm_token: 'tok-7f3a' });
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([['ca.install', { scope: 'user' }]]);
    expect(order).toEqual(['installing:true', 'call:ca.install', 'refreshCA', 'installing:false']);
    expect(queryByRole('alert')).toBeNull();
  });

  it('a second needs_confirmation in reply to the confirming call is a stale token: an error result, no third call, the flag released', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    const { getByRole, getByText, queryByRole } = await atServerPrompt(app, order);
    app.call.mockImplementation(async (name: string) => {
      order.push(`call:${name}`);
      return { status: 'needs_confirmation', prompt: 'ca.install changes the trust store of this machine. Confirm?', confirm_token: 'tok-9c1d' };
    });
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([
      ['ca.install', { scope: 'user' }],
      ['ca.install', { scope: 'user', _confirm: 'tok-7f3a' }],
    ]);
    expect(getByRole('status').textContent).toContain('error');
    expect(getByRole('status').textContent).toContain('confirmation was not accepted (stale or reused token)');
    expect(queryByRole('alert')).toBeNull();
    expect(order).toEqual(['installing:true', 'call:ca.install', 'call:ca.install', 'refreshCA', 'installing:false']);
  });

  it('typing in the search box while the server prompt is up declines it: back to the list, nothing more sent, the flag released', async () => {
    const app = stubApp(CA_UNTRUSTED);
    const order: string[] = [];
    const { getByRole, queryByRole } = await atServerPrompt(app, order);
    fireEvent.input(getByRole('combobox'), { target: { value: '>flow' } });
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([['ca.install', { scope: 'user' }]]);
    expect(order).toEqual(['installing:true', 'call:ca.install', 'refreshCA', 'installing:false']);
    expect(queryByRole('alert')).toBeNull();
    expect(getByRole('listbox', { name: 'Results' })).toBeTruthy();
    expect(app.notice).not.toHaveBeenCalled();
  });

  it('ca.uninstall holds the in-flight flag across the handshake, then re-reads ca.status (D17.12)', async () => {
    const app = stubApp({ trusted: true, scope: 'user', platform: 'macos', fingerprint: 'AB:CD' });
    const order: string[] = [];
    app.setCAInstalling.mockImplementation((on: boolean) => order.push(`installing:${on}`));
    app.refreshCA.mockImplementation(async () => {
      order.push('refreshCA');
      return true;
    });
    handshakeBus(app, order);
    const { getByRole, getByText } = await mount(app);
    fireEvent.input(getByRole('combobox'), { target: { value: '>ca.uninstall' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter' });
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(getByRole('alert').textContent).toBe('ca.uninstall changes the trust store of this machine. Confirm?');
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.call.mock.calls).toEqual([
      ['ca.uninstall', {}],
      ['ca.uninstall', { _confirm: 'tok-7f3a' }],
    ]);
    expect(order).toEqual(['installing:true', 'call:ca.uninstall', 'call:ca.uninstall', 'refreshCA', 'installing:false']);
    expect(getByRole('status').textContent).toContain('ok');
  });

  it('says so when ca.status could not be re-read after the run, so a stale word is never silent', async () => {
    const app = stubApp(CA_UNTRUSTED);
    app.refreshCA.mockImplementation(async () => false);
    app.call.mockImplementation(async () => ({ changed: true }));
    const { getByRole, getByText } = await mount(app);
    fireEvent.click(getByText('Trust the aitmproxy CA').closest('[role="option"]')!);
    await tick();
    fireEvent.click(getByText('Run').closest('button')!);
    await tick();
    fireEvent.click(getByText('Confirm').closest('button')!);
    await tick();
    await tick();
    expect(app.notice).toHaveBeenCalledTimes(1);
    expect(app.notice).toHaveBeenCalledWith('ca.status could not be re-read; the CA word may be stale', 'error');
    expect(getByRole('status').textContent).toContain('ok');
    expect(app.setCAInstalling).toHaveBeenLastCalledWith(false);
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
