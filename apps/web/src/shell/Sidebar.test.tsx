import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor } from '@solidjs/testing-library';
import { BusError, type BusClient, type ToolDef } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { scriptsStore } from '~/panels/scripts/store';
import { memoryBus, SERVED_TOOLS, SUBSCRIBE, TEST_VERSION } from '~/state/bridgeBus.testkit';
import { Sidebar } from './Sidebar';

/** The in-memory bus, optionally without a `version` in `proxy.status` (a core older than the field). */
function mount(opts: { version: boolean }) {
  const mem = memoryBus();
  const bus: BusClient = {
    ...mem,
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      const result = await mem.call<T>(tool, args);
      if (tool === 'proxy.status' && !opts.version) {
        const { version: _dropped, ...rest } = result as Record<string, unknown>;
        return rest as T;
      }
      return result;
    },
  };
  const app = createAppStore(bus);
  const view = render(() => (
    <AppProvider store={app}>
      <Sidebar />
    </AppProvider>
  ));
  return { bus, app, view };
}

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

/** The brand row: the mark, the wordmark and — only when the core reported one — the version. */
const brandText = () => screen.getByRole('heading', { name: 'aitmproxy' }).parentElement!.textContent;

describe('Sidebar version', () => {
  it('shows the core’s version as v<version> once proxy.status answers', async () => {
    ({ bus } = mount({ version: true }));

    expect((await screen.findByText(`v${TEST_VERSION}`)).tagName).toBe('SPAN');
    expect(brandText()).toBe(`aitmproxyv${TEST_VERSION}`);
    expect(screen.queryByText(/0\.3\.0/)).toBeNull(); // the old hard-coded number is gone
  });

  it('renders no version at all (not even a bare "v") when the core reports none', async () => {
    let app;
    ({ bus, app } = mount({ version: false }));
    await waitFor(() => expect(app.proxy.address).toBe('127.0.0.1:8080')); // proxy.status answered

    expect(brandText()).toBe('aitmproxy');
  });
});

/** One `script.list` row as the core sends it (`List::invoke` in crates/aitm-plugin-rhai/src/commands.rs). */
interface ScriptInfo {
  name: string;
  path: string;
  api: string;
  hooks: string[];
  enabled: boolean;
  last_error: string | null;
}

describe('Sidebar Scripts count', () => {
  const buses: BusClient[] = [];
  afterEach(() => {
    while (buses.length) buses.pop()!.close();
  });

  /**
   * Three loaded scripts, two enabled — one of those with a hook error, which `activeCount`
   * (panels/scripts/model.ts) does not subtract, so the count is 2. Fresh copies: a toggle mutates them.
   */
  const loadedScripts = (): ScriptInfo[] => [
    { name: 'redact-auth', path: '/home/operator/.aitm/scripts/redact-auth.rhai', api: '1', hooks: ['on_request', 'on_response'], enabled: true, last_error: null },
    { name: 'tag-admin', path: '/home/operator/.aitm/scripts/tag-admin.rhai', api: '1', hooks: ['on_request'], enabled: false, last_error: null },
    { name: 'flaky-parser', path: '/home/operator/.aitm/scripts/flaky-parser.rhai', api: '1', hooks: ['on_response'], enabled: true, last_error: 'on_response: Property not found: content_type (line 12)' },
  ];

  /**
   * The in-memory bus serving those scripts, with `script.enable` / `script.disable` flipping one and
   * answering `{ name, enabled }` as the core does; the tool list and the `script.list` answer are overridable.
   */
  function mountScripts(opts: { tools?: (all: ToolDef[]) => ToolDef[]; list?: () => Promise<unknown> | undefined } = {}) {
    const scripts = loadedScripts();
    const mem = memoryBus({ scripts, tools: [...SERVED_TOOLS, SUBSCRIBE.name, 'script.enable', 'script.disable'] });
    buses.push(mem);
    const calls: string[] = [];
    const bus: BusClient = {
      ...mem,
      async tools() {
        const all = await mem.tools();
        return opts.tools ? opts.tools(all) : all;
      },
      async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
        calls.push(tool);
        if (tool === 'script.list' && opts.list) {
          const answer = opts.list(); // undefined: answer from the loaded scripts
          if (answer !== undefined) return (await answer) as T;
        }
        if (tool === 'script.enable' || tool === 'script.disable') {
          const s = scripts.find((x) => x.name === args.name);
          if (!s) throw new BusError(`no loaded script is named \`${String(args.name)}\``);
          s.enabled = tool === 'script.enable';
          return { name: s.name, enabled: s.enabled } as T;
        }
        return mem.call<T>(tool, args);
      },
    };
    const app = createAppStore(bus);
    render(() => (
      <AppProvider store={app}>
        <Sidebar />
      </AppProvider>
    ));
    return { app, calls };
  }

  /** Let every already-queued promise continuation run: a call made on mount has been recorded by now. */
  const flush = async () => {
    for (let i = 0; i < 10; i++) await Promise.resolve();
  };
  const item = () => screen.getByText('Scripts').closest('button')!;
  /** The item's count text, or null when it shows none. */
  const count = () => item().querySelector('[data-kind]')?.textContent ?? null;

  it('shows how many scripts are enabled once script.list has answered', async () => {
    mountScripts();
    await waitFor(() => expect(count()).toBe('2 active'));
  });

  it('shows no count (not a fake "0 active") while script.list has not answered', async () => {
    let answer!: (v: unknown) => void;
    mountScripts({ list: () => new Promise((r) => (answer = r)) });
    await waitFor(() => expect(answer).toBeTypeOf('function')); // script.list is in flight
    expect(count()).toBeNull();

    answer([{ name: 'only', path: '/s/only.rhai', api: '1', hooks: [], enabled: true, last_error: null }]);
    await waitFor(() => expect(count()).toBe('1 active'));
  });

  it('shows no count when script.list fails, and when the core does not offer it, and then calls nothing', async () => {
    const failed = mountScripts({ list: () => Promise.reject(new BusError('rhai host is not running')) });
    // Wait on what happened (the call was made and settled), not on a toast: the sidebar raises none.
    await waitFor(() => expect(failed.calls).toContain('script.list'));
    await waitFor(() => expect(scriptsStore(failed.app).loaded()).toBe(true));
    expect(count()).toBeNull();
    // The count is a courtesy nobody asked for: a core with no rhai host must not greet every page load with an error toast.
    expect(failed.app.toast()).toBeNull();
    cleanup();

    const { app, calls } = mountScripts({ tools: (all) => all.filter((t) => !t.name.startsWith('script.')) });
    await waitFor(() => expect(app.proxy.tools.length).toBeGreaterThan(0));
    await flush();
    expect(count()).toBeNull();
    expect(calls.filter((c) => c.startsWith('script.'))).toEqual([]);
  });

  it('shows no count for a script.list answer that is not a list', async () => {
    const { app } = mountScripts({ list: () => Promise.resolve({ error: 'not a list' }) });
    await waitFor(() => expect(scriptsStore(app).loaded()).toBe(true));
    expect(count()).toBeNull();
    expect(app.toast()).toBeNull();
  });

  it('reads script.list once on bootstrap, and not the findings', async () => {
    const { calls } = mountScripts();
    await waitFor(() => expect(count()).toBe('2 active'));
    expect(calls.filter((c) => c.startsWith('script.'))).toEqual(['script.list']);
  });

  it('goes back to no count when a later script.list fails, rather than keeping a stale one', async () => {
    let failing = false;
    const { app } = mountScripts({ list: () => (failing ? Promise.reject(new BusError('rhai host is not running')) : undefined) });
    await waitFor(() => expect(count()).toBe('2 active'));

    failing = true;
    await scriptsStore(app).refreshList();
    expect(count()).toBeNull();

    failing = false;
    await scriptsStore(app).refreshList();
    expect(count()).toBe('2 active');
  });

  it('follows the scripts store: disabling a script updates the count', async () => {
    const { app } = mountScripts();
    await waitFor(() => expect(count()).toBe('2 active'));

    const store = scriptsStore(app);
    await store.toggle(store.rows().find((r) => r.name === 'redact-auth')!);
    await waitFor(() => expect(count()).toBe('1 active'));
  });
});
