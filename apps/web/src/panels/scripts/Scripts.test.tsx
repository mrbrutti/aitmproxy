// The Scripts panel on the testkit's in-memory bus plus the `script.*` host written below in the core's
// reply shapes (crates/aitm-plugin-rhai/src/commands.rs): list, row actions, the new-script editor
// (validate / save), the console, capability gating and the not-offered state. The store is the real
// one, so the panel runs through `app.call`, `app.notice` and `app.proxy.tools` exactly as in the UI.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { BusError, type BusClient, type BusRole, type ToolDef } from '~/bus/types';
import { createAppStore } from '~/state/app';
import { memoryBus, SERVED_TOOLS, SUBSCRIBE } from '~/state/bridgeBus.testkit';
import { AppProvider } from '~/state/context';
import { ScriptsPanel } from '../ScriptsPanel';
import { scriptsStore } from './store';

interface MountOpts {
  /** Replace one tool's reply: return a value to answer with it, an Error to reject, `undefined` to fall through to the script host, then the memory bus. */
  reply?: (tool: string, args: Record<string, unknown>) => unknown;
  /** Narrow the advertised tool list. */
  tools?: (all: ToolDef[]) => ToolDef[];
  role?: BusRole | null;
}

const buses: BusClient[] = [];

/** One `script.list` row as the core sends it (`List::invoke` in crates/aitm-plugin-rhai/src/commands.rs). */
interface ScriptInfo {
  name: string;
  path: string;
  api: string;
  hooks: string[];
  enabled: boolean;
  last_error: string | null;
}

const SCRIPT_DIR = '/home/operator/.aitm/scripts';

/** The scripts a mount starts with: two enabled (one of them with a hook error), one disabled. Fresh copies: the test's host mutates them. */
const loadedScripts = (): ScriptInfo[] => [
  { name: 'redact-auth', path: `${SCRIPT_DIR}/redact-auth.rhai`, api: '1', hooks: ['on_request', 'on_response'], enabled: true, last_error: null },
  { name: 'tag-admin', path: `${SCRIPT_DIR}/tag-admin.rhai`, api: '1', hooks: ['on_request'], enabled: false, last_error: null },
  { name: 'flaky-parser', path: `${SCRIPT_DIR}/flaky-parser.rhai`, api: '1', hooks: ['on_response'], enabled: true, last_error: 'on_response: Property not found: content_type (line 12)' },
];

/** The `script.*` tools this core advertises beyond the memory bus's own `script.list` and `script.findings`. */
const SCRIPT_TOOLS = ['script.enable', 'script.disable', 'script.reload', 'script.validate', 'script.save'];

function mount(opts: MountOpts = {}) {
  const scripts = loadedScripts();
  const host = scriptHost(scripts, findingsOldestFirst());
  const mem = memoryBus({ scripts, tools: [...SERVED_TOOLS, SUBSCRIBE.name, ...SCRIPT_TOOLS] });
  const calls: { tool: string; args: Record<string, unknown> }[] = [];
  const bus: BusClient = {
    ...mem,
    role: () => (opts.role === undefined ? 'operator' : opts.role),
    async tools() {
      const all = await mem.tools();
      return opts.tools ? opts.tools(all) : all;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      calls.push({ tool, args });
      const r = opts.reply?.(tool, args);
      if (r instanceof Error) throw r;
      if (r !== undefined) return r as T;
      const hosted = host(tool, args);
      if (hosted) return (await hosted) as T;
      return mem.call<T>(tool, args);
    },
  };
  buses.push(mem);
  const app = createAppStore(bus);
  const view = () =>
    render(() => (
      <AppProvider store={app}>
        <ScriptsPanel />
      </AppProvider>
    ));
  let shown = view();
  return {
    app,
    bus,
    calls,
    /** The lower region swapped to the inspector and back: unmount the panel, mount it again over the same store. */
    remount: () => {
      shown.unmount();
      shown = view();
    },
  };
}

afterEach(() => {
  cleanup();
  while (buses.length) buses.pop()!.close();
});

const GOOD_SRC = `const NAME = "probe";
const API = "1";

fn on_request(flow) {
  flow.tag("probe");
}
`;
const REG_SRC = `const NAME = "probe";
const API = "1";

fn load(reg) {
  reg.command("probe.run", |ctx| ctx);
  reg.option("probe.depth", 3);
}

fn on_request(flow) {
  flow.tag("probe");
}
`;
const BAD_SRC = 'fn on_request(flow) {\n  flow.tag("x");\n';

/** What the core answers `script.validate` and `script.save` for the two sources the editor tests type, keyed by the exact text. */
const REPORTS: Record<string, { name: string; api: string; hooks: string[]; registers: { commands: string[]; options: string[] } }> = {
  [GOOD_SRC]: { name: 'probe', api: '1', hooks: ['on_request'], registers: { commands: [], options: [] } },
  [REG_SRC]: { name: 'probe', api: '1', hooks: ['on_request'], registers: { commands: ['probe.run'], options: ['probe.depth'] } },
};
/** The core's pinned compile-error text (`ScriptError::Compile`, crates/aitm-plugin-rhai/src/error.rs) for BAD_SRC, whose `{` at 1:21 is never closed. */
const BAD_SRC_ERROR = "error: <source>:3:1 — expecting '}' to end the block opened at 1:21\n  help: the file ends mid-statement; look for an unclosed brace, bracket, or string";

/** Script findings as the core's in-memory sink lists them: oldest first, `at` in Unix milliseconds. */
const findingsOldestFirst = () => [
  { name: 'Bearer token sent over cleartext HTTP', severity: 'high', flow_id: 'flow_0007', detail: 'Authorization header on http://api.shop-staging.test/v1/cart', tags: ['auth', 'cleartext'], source: 'redact-auth', at: 1_700_000_000_000 },
  { name: 'Admin path probed', severity: 'info', flow_id: null, detail: null, tags: ['admin'], source: 'tag-admin', at: 1_700_000_180_000 },
  { name: 'Verbose error body', severity: 'medium', flow_id: 'flow_0031', detail: 'Stack trace in a 500 response', tags: [], source: 'flaky-parser', at: 1_700_000_270_000 },
];

const HOST_TOOLS = new Set(['script.enable', 'script.disable', 'script.reload', 'script.validate', 'script.save', 'script.findings']);

/**
 * The rhai host's side of the `script.*` commands the panel drives, over the mount's own `scripts`, in
 * the reply shapes of crates/aitm-plugin-rhai/src/commands.rs: enable / disable flip the flag and
 * answer `{ name, enabled }`; reload clears `last_error` and answers the metadata; validate answers
 * the report (no `path`, no `restart_required`); save adds or replaces the script and answers the
 * report with both; findings answers the newest `limit`, oldest first. A loopback round trip of a few
 * ms, like the memory bus, so in-flight states are real. `undefined` for any other tool.
 */
function scriptHost(scripts: ScriptInfo[], findings: ReturnType<typeof findingsOldestFirst>) {
  const named = (name: unknown): ScriptInfo => {
    const s = scripts.find((x) => x.name === name);
    if (!s) throw new BusError(`no loaded script is named \`${String(name)}\`; loaded: ${scripts.map((x) => x.name).join(', ')}`);
    return s;
  };
  const compiled = (source: unknown) => {
    if (source === BAD_SRC) throw new BusError(BAD_SRC_ERROR);
    const report = typeof source === 'string' ? REPORTS[source] : undefined;
    if (!report) throw new Error('scriptHost: no reply is written for this source');
    return report;
  };
  const answer = (tool: string, args: Record<string, unknown>): unknown => {
    switch (tool) {
      case 'script.enable':
      case 'script.disable': {
        const s = named(args.name);
        s.enabled = tool === 'script.enable';
        return { name: s.name, enabled: s.enabled };
      }
      case 'script.reload': {
        const s = named(args.name);
        s.last_error = null;
        return { name: s.name, path: s.path, api: s.api, hooks: [...s.hooks] };
      }
      case 'script.validate':
        return { ...compiled(args.source) };
      case 'script.save': {
        const name = String(args.name);
        const { api, hooks, registers } = compiled(args.source);
        const enable = typeof args.enable === 'boolean' ? args.enable : true;
        const path = `${SCRIPT_DIR}/${name}.rhai`;
        const loaded = scripts.find((x) => x.name === name);
        if (loaded) Object.assign(loaded, { api, hooks: [...hooks], enabled: enable, last_error: null });
        else scripts.push({ name, path, api, hooks: [...hooks], enabled: enable, last_error: null });
        return { name, path, api, hooks, registers, restart_required: registers.commands.length > 0 || registers.options.length > 0 };
      }
      case 'script.findings': {
        const keep = typeof args.limit === 'number' ? Math.min(Math.max(0, args.limit), findings.length) : findings.length;
        return { findings: findings.slice(findings.length - keep), dropped: 0 };
      }
      default:
        throw new Error(`scriptHost: ${tool} is not a script command`);
    }
  };
  return (tool: string, args: Record<string, unknown>): Promise<unknown> | undefined =>
    HOST_TOOLS.has(tool) ? new Promise((r) => setTimeout(r, 5)).then(() => answer(tool, args)) : undefined;
}

const row = (name: string) => document.querySelector<HTMLElement>(`[data-script="${name}"]`)!;
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
const type = (label: string, value: string) => fireEvent.input(screen.getByLabelText(label), { target: { value } });
/** The first `script.list` has landed and the rows are on screen (the console's findings load alongside and may land first). */
const ready = () => waitFor(() => expect(row('redact-auth')).not.toBeNull());
/** Let every already-queued promise continuation run: a call a handler made has been recorded, a toast it set is set. */
const flush = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};
/** The list column's heading line: "Loaded", plus its row count only while that count is a fact. */
const loadedHeading = () => screen.getByRole('heading', { name: 'Loaded' }).parentElement!.textContent;

describe('ScriptsPanel — list', () => {
  it('renders one row per loaded script with hooks, api and enabled state, and counts the active ones', async () => {
    mount();
    await ready();

    expect(screen.getByText('2 active')).toBeTruthy();
    expect([...document.querySelectorAll('[data-script]')].map((r) => r.getAttribute('data-script'))).toEqual(['redact-auth', 'tag-admin', 'flaky-parser']);

    const redact = row('redact-auth');
    expect([...redact.querySelectorAll('[data-hook]')].map((h) => h.textContent)).toEqual(['on_request', 'on_response']);
    expect(within(redact).getByText('api 1')).toBeTruthy();
    expect(within(redact).getByRole('switch', { name: 'redact-auth enabled' }).getAttribute('aria-checked')).toBe('true');
    expect(within(row('tag-admin')).getByRole('switch', { name: 'tag-admin enabled' }).getAttribute('aria-checked')).toBe('false');
  });

  it('badges only the script whose last hook run failed', async () => {
    mount();
    await ready();
    expect(row('redact-auth').querySelector('[data-last-error]')).toBeNull();
    expect(row('tag-admin').querySelector('[data-last-error]')).toBeNull();
    expect(row('flaky-parser').querySelector('[data-last-error]')?.textContent).toBe('error');
  });

  it('shows a plain empty state, still with the editor, when no script is loaded', async () => {
    mount({ reply: (tool) => (tool === 'script.list' ? [] : undefined) });
    expect(await screen.findByText('No scripts loaded.')).toBeTruthy();
    expect(screen.getByText('0 active')).toBeTruthy();
    expect(screen.getByLabelText('Script source')).toBeTruthy();
  });

  it('says so in place, and calls nothing, when the core does not offer script.list', async () => {
    const { app, calls } = mount({ tools: (all) => all.filter((t) => !t.name.startsWith('script.')) });
    // The panel says so from the first paint; what matters is that nothing is asked once the tool list is known.
    await waitFor(() => expect(app.proxy.tools.length).toBeGreaterThan(0));
    await flush();
    expect(screen.getByText(/Scripts are not enabled on this core/)).toBeTruthy();
    expect(screen.queryByLabelText('Script source')).toBeNull();
    expect(screen.queryByRole('switch')).toBeNull();
    expect(calls.filter((c) => c.tool.startsWith('script.'))).toEqual([]);
  });
});

describe('ScriptsPanel — list errors', () => {
  const MSG = 'rhai host is not running';

  it("shows a failing script.list as a failure, with the core's text and a Retry, never as an empty list", async () => {
    let failing = true;
    const { app } = mount({ reply: (tool) => (tool === 'script.list' && failing ? new BusError(MSG) : undefined) });
    const err = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-list-error]');
      expect(found).not.toBeNull();
      return found!;
    });
    expect(text(err)).toContain(MSG);
    // Opening the panel is not a request to be interrupted: the error block is the signal, there is no toast.
    expect(app.toast()).toBeNull();
    // The body never states what it does not know: not "no scripts", not "no script has failed", not a count.
    expect(screen.queryByText('No scripts loaded.')).toBeNull();
    expect(screen.queryByText('No script has failed.')).toBeNull();
    expect(screen.getByText('Unknown — the scripts could not be read.')).toBeTruthy();
    expect(screen.queryByText(/ active$/)).toBeNull();
    expect(loadedHeading()).toBe('Loaded');
    expect(document.querySelector('[data-script]')).toBeNull();

    // A Retry is the user asking, so a failure of that does toast.
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(app.toast()).toEqual({ text: `script.list: ${MSG}`, kind: 'error' }));

    failing = false;
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await ready();
    expect(document.querySelector('[data-list-error]')).toBeNull();
    expect(screen.getByText('2 active')).toBeTruthy();
  });

  it('keeps the last good rows, with the error beside them, when a later refresh fails', async () => {
    let failing = false;
    mount({ reply: (tool) => (tool === 'script.list' && failing ? new BusError(MSG) : undefined) });
    await ready();

    expect(loadedHeading()).toBe('Loaded3');
    failing = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(document.querySelector('[data-list-error]')).not.toBeNull());
    expect(row('redact-auth')).not.toBeNull(); // still the last good list, still actionable
    expect(screen.queryByText(/ active$/)).toBeNull(); // but no count claimed from a list that could not be re-read
    expect(loadedHeading()).toBe('Loaded'); // nor a row count
  });

  it('does not say "No script has failed." about a good list it has since failed to re-read', async () => {
    const quiet = [{ name: 'quiet', path: '/p/quiet.rhai', api: '1', hooks: [], enabled: true, last_error: null }];
    let failing = false;
    mount({ reply: (tool) => (tool === 'script.list' ? (failing ? new BusError(MSG) : quiet) : undefined) });
    expect(await screen.findByText('No script has failed.')).toBeTruthy(); // a good read of rows with no last_error

    failing = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(document.querySelector('[data-list-error]')).not.toBeNull());
    expect(screen.queryByText('No script has failed.')).toBeNull();
    expect(screen.getByText('Unknown — the scripts could not be read.')).toBeTruthy();
  });

  it.each([
    ['an object', {}],
    ['null', null],
    ['a string', 'nope'],
  ])('treats %s in place of the list as a failure, not as "No scripts loaded."', async (_label, reply) => {
    const { app } = mount({ reply: (tool) => (tool === 'script.list' ? reply : undefined) });
    const err = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-list-error]');
      expect(found).not.toBeNull();
      return found!;
    });
    expect(text(err)).toContain('script.list answered with something that is not a list');
    expect(screen.queryByText('No scripts loaded.')).toBeNull();
    expect(screen.queryByText('No script has failed.')).toBeNull();
    expect(screen.queryByText(/ active$/)).toBeNull();
    expect(app.toast()).toBeNull(); // opening the panel: the block is the signal
  });

  it('claims nothing about scripts or their errors before the first script.list answers', async () => {
    let answer!: (v: unknown) => void;
    mount({ reply: (tool) => (tool === 'script.list' ? new Promise((r) => (answer = r)) : undefined) });
    await waitFor(() => expect(answer).toBeTypeOf('function')); // script.list is in flight
    expect(screen.queryByText('No script has failed.')).toBeNull();
    expect(screen.queryByText('No scripts loaded.')).toBeNull();

    answer([{ name: 'quiet', path: '/p/quiet.rhai', api: '1', hooks: [], enabled: true, last_error: null }]);
    expect(await screen.findByText('No script has failed.')).toBeTruthy();
  });
});

describe('ScriptsPanel — row actions', () => {
  it('disables then re-enables a script and refreshes the list after each action', async () => {
    const { bus, calls } = mount();
    await ready();
    const toggle = () => within(row('redact-auth')).getByRole('switch', { name: 'redact-auth enabled' });
    const before = toggle();

    fireEvent.click(before);
    await waitFor(() => expect(toggle().getAttribute('aria-checked')).toBe('false'));
    expect(screen.getByText('1 active')).toBeTruthy();
    // The refresh updates the row in place, so the control you just used keeps its node (and its keyboard focus).
    expect(toggle()).toBe(before);
    expect(calls.filter((c) => c.tool === 'script.disable')).toEqual([{ tool: 'script.disable', args: { name: 'redact-auth' } }]);
    const afterDisable = (await bus.call<{ name: string; enabled: boolean }[]>('script.list')).find((s) => s.name === 'redact-auth');
    expect(afterDisable?.enabled).toBe(false);

    fireEvent.click(toggle());
    await waitFor(() => expect(toggle().getAttribute('aria-checked')).toBe('true'));
    expect(screen.getByText('2 active')).toBeTruthy();
    expect(calls.filter((c) => c.tool === 'script.enable')).toEqual([{ tool: 'script.enable', args: { name: 'redact-auth' } }]);
  });

  it('reloads a script, which clears its error badge', async () => {
    const { app, calls } = mount();
    await ready();
    expect(row('flaky-parser').querySelector('[data-last-error]')).not.toBeNull();

    fireEvent.click(within(row('flaky-parser')).getByRole('button', { name: 'Reload flaky-parser' }));
    await waitFor(() => expect(row('flaky-parser').querySelector('[data-last-error]')).toBeNull());
    expect(calls.filter((c) => c.tool === 'script.reload')).toEqual([{ tool: 'script.reload', args: { name: 'flaky-parser' } }]);
    expect(app.toast()).toEqual({ text: 'Reloaded flaky-parser', kind: 'info' });
  });

  it('keeps the error toast, re-reads nothing and shows no success when a reload fails', async () => {
    const msg = "error: flaky-parser:12:5 — expecting ')' to end the call";
    const { app, calls } = mount({ reply: (tool) => (tool === 'script.reload' ? new BusError(msg) : undefined) });
    await ready();
    const lists = () => calls.filter((c) => c.tool === 'script.list').length;
    const before = lists();

    fireEvent.click(within(row('flaky-parser')).getByRole('button', { name: 'Reload flaky-parser' }));
    await waitFor(() => expect(app.toast()?.kind).toBe('error'));
    await flush();
    expect(app.toast()).toEqual({ text: `script.reload: ${msg}`, kind: 'error' }); // not replaced by "Reloaded flaky-parser"
    expect(lists()).toBe(before);
    expect(row('flaky-parser').querySelector('[data-last-error]')).not.toBeNull();
  });

  it('keeps the row controls focusable while an action is in flight: aria-disabled, not disabled, and a second click is ignored', async () => {
    let finish!: (v: unknown) => void;
    const { calls } = mount({ reply: (tool) => (tool === 'script.disable' ? new Promise((r) => (finish = r)) : undefined) });
    await ready();
    const toggle = within(row('redact-auth')).getByRole('switch', { name: 'redact-auth enabled' });
    const reload = within(row('redact-auth')).getByRole('button', { name: 'Reload redact-auth' });
    toggle.focus();

    fireEvent.click(toggle);
    await waitFor(() => expect(toggle.getAttribute('aria-disabled')).toBe('true'));
    expect(reload.getAttribute('aria-disabled')).toBe('true');
    // A `disabled` button drops keyboard focus in a real browser; aria-disabled keeps it.
    expect(toggle.hasAttribute('disabled')).toBe(false);
    expect(reload.hasAttribute('disabled')).toBe(false);
    expect(document.activeElement).toBe(toggle);
    fireEvent.click(toggle);
    fireEvent.click(reload);
    expect(calls.filter((c) => c.tool === 'script.disable')).toHaveLength(1);
    expect(calls.some((c) => c.tool === 'script.reload')).toBe(false);

    finish({ name: 'redact-auth', enabled: false });
    await waitFor(() => expect(toggle.hasAttribute('aria-disabled')).toBe(false));
  });

  it("surfaces the core's refusal verbatim and leaves the state unchanged", async () => {
    const refusal =
      'script authoring refused: an agent frontend may not author scripts. Set rhai.allow_agent_authoring = true in the aitmproxy config to allow it, or author from the human CLI / operator UI.';
    const { app } = mount({ reply: (tool) => (tool === 'script.enable' ? new BusError(refusal) : undefined) });
    await ready();

    const toggle = within(row('tag-admin')).getByRole('switch', { name: 'tag-admin enabled' });
    fireEvent.click(toggle);
    await waitFor(() => expect(app.toast()?.kind).toBe('error'));
    expect(app.toast()?.text).toBe(`script.enable: ${refusal}`);
    expect(toggle.getAttribute('aria-checked')).toBe('false');
    expect(screen.getByText('2 active')).toBeTruthy();
  });
});

describe('ScriptsPanel — new-script editor', () => {
  it('validates source and reports name, api, hooks and registered commands/options', async () => {
    const { calls } = mount();
    await ready();

    type('Script source', REG_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    const result = await screen.findByLabelText('Result');
    await waitFor(() => expect(text(result)).toContain('Valid'));
    expect(calls.filter((c) => c.tool === 'script.validate')).toEqual([{ tool: 'script.validate', args: { source: REG_SRC } }]);
    expect(text(result.querySelector('[data-field="name"]'))).toBe('probe');
    expect(text(result.querySelector('[data-field="api"]'))).toBe('1');
    expect(text(result.querySelector('[data-field="hooks"]'))).toBe('on_request');
    expect(text(result.querySelector('[data-field="commands"]'))).toBe('probe.run');
    expect(text(result.querySelector('[data-field="options"]'))).toBe('probe.depth');
  });

  it('shows the core compile error text verbatim, positioned, and writes nothing', async () => {
    const { calls } = mount();
    await ready();

    type('Script source', BAD_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    const alert = await within(await screen.findByLabelText('Result')).findByRole('alert');
    expect(alert.textContent).toBe(BAD_SRC_ERROR);
    expect(alert.textContent).toMatch(/^error: <source>:3:1 — /); // the position is shown, not stripped
    expect(calls.some((c) => c.tool === 'script.save')).toBe(false);
  });

  it('saves with enable: true, shows the result, and lists the new script', async () => {
    const { calls } = mount();
    await ready();

    type('Script name', 'probe');
    type('Script source', GOOD_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const result = await screen.findByLabelText('Result');
    await waitFor(() => expect(text(result)).toContain('Saved probe'));
    expect(calls.filter((c) => c.tool === 'script.save')).toEqual([{ tool: 'script.save', args: { name: 'probe', source: GOOD_SRC, enable: true } }]);
    expect(text(result.querySelector('[data-field="path"]'))).toBe('/home/operator/.aitm/scripts/probe.rhai');
    expect(text(result)).toContain('No restart needed');
    expect(text(result)).not.toContain('Restart required');

    await waitFor(() => expect(row('probe')).not.toBeNull());
    expect([...row('probe').querySelectorAll('[data-hook]')].map((h) => h.textContent)).toEqual(['on_request']);
    expect(screen.getByText('3 active')).toBeTruthy();
  });

  it('says a restart is required when the saved script registers commands or options', async () => {
    mount();
    await ready();

    type('Script name', 'probe');
    type('Script source', REG_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const result = await screen.findByLabelText('Result');
    await waitFor(() => expect(text(result)).toContain('Restart required'));
    expect(text(result)).not.toContain('No restart needed');
    expect(text(result.querySelector('[data-field="commands"]'))).toBe('probe.run');
  });

  it('refuses a bad name client-side: shows why, disables Save, calls nothing', async () => {
    const { calls } = mount();
    await ready();

    type('Script name', 'bad name!');
    type('Script source', GOOD_SRC);

    expect(screen.getByText('A name may contain only letters, digits, "_" and "-".')).toBeTruthy();
    expect(screen.getByLabelText('Script name').getAttribute('aria-invalid')).toBe('true');
    const save = screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(save);
    await flush();
    expect(calls.some((c) => c.tool === 'script.save')).toBe(false);

    type('Script name', 'good-name_1');
    expect(screen.queryByText('A name may contain only letters, digits, "_" and "-".')).toBeNull();
    expect(save.disabled).toBe(false);
  });

  it('keeps Save and Validate off until there is something to send', async () => {
    mount();
    await ready();
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Validate' }) as HTMLButtonElement).disabled).toBe(true);
    type('Script source', GOOD_SRC);
    expect((screen.getByRole('button', { name: 'Validate' }) as HTMLButtonElement).disabled).toBe(false);
    // A source alone is not savable: the file needs a name.
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('ScriptsPanel — stale results', () => {
  it('drops a validate or save result as soon as the source or the name is edited', async () => {
    mount();
    await ready();
    type('Script source', BAD_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
    const result = await screen.findByLabelText('Result');
    await within(result).findByRole('alert');

    type('Script source', GOOD_SRC);
    expect(within(result).queryByRole('alert')).toBeNull();
    expect(text(result)).toBe('');

    type('Script name', 'probe');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(text(result)).toContain('Saved probe'));
    type('Script name', 'probe-2');
    expect(text(result)).toBe('');
  });

  it('does not show a validate answer that arrives after the source was edited', async () => {
    let finish!: (v: unknown) => void;
    mount({ reply: (tool) => (tool === 'script.validate' ? new Promise((r) => (finish = r)) : undefined) });
    await ready();
    type('Script source', GOOD_SRC);
    const validate = screen.getByRole('button', { name: 'Validate' });
    fireEvent.click(validate);
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    expect(validate.getAttribute('aria-disabled')).toBe('true'); // in flight

    type('Script source', `${GOOD_SRC}// edited\n`);
    finish({ name: 'probe', api: '1', hooks: ['on_request'], registers: { commands: [], options: [] } });
    await waitFor(() => expect(validate.hasAttribute('aria-disabled')).toBe(false)); // the call settled
    expect(text(screen.getByLabelText('Result'))).toBe('');
  });

  it('keeps Validate, Save and Refresh focusable while a call is in flight: aria-disabled, not disabled, and a second click is ignored', async () => {
    let finish!: (v: unknown) => void;
    const { calls } = mount({ reply: (tool) => (tool === 'script.validate' ? new Promise((r) => (finish = r)) : undefined) });
    await ready();
    type('Script name', 'probe');
    type('Script source', GOOD_SRC);
    const validate = screen.getByRole('button', { name: 'Validate' });
    const save = screen.getByRole('button', { name: 'Save' });
    const refresh = screen.getByRole('button', { name: 'Refresh' });
    const lists = () => calls.filter((c) => c.tool === 'script.list').length;
    validate.focus();
    const listsBefore = lists();

    fireEvent.click(validate);
    await waitFor(() => expect(validate.getAttribute('aria-disabled')).toBe('true'));
    for (const button of [validate, save, refresh]) {
      expect(button.getAttribute('aria-disabled')).toBe('true');
      // A `disabled` button drops keyboard focus in a real browser; aria-disabled keeps it.
      expect(button.hasAttribute('disabled')).toBe(false);
    }
    expect(document.activeElement).toBe(validate);

    fireEvent.click(validate);
    fireEvent.click(save);
    fireEvent.click(refresh);
    expect(calls.filter((c) => c.tool === 'script.validate')).toHaveLength(1);
    expect(calls.some((c) => c.tool === 'script.save')).toBe(false);
    expect(lists()).toBe(listsBefore);

    finish({ name: 'probe', api: '1', hooks: ['on_request'], registers: { commands: [], options: [] } });
    await waitFor(() => expect(validate.hasAttribute('aria-disabled')).toBe(false));
    expect(save.hasAttribute('aria-disabled')).toBe(false);
    expect(refresh.hasAttribute('aria-disabled')).toBe(false);
  });
});

describe('ScriptsPanel — draft', () => {
  it('keeps the name, the source and the last result when the panel unmounts and comes back', async () => {
    const { remount } = mount();
    await ready();
    type('Script name', 'probe');
    type('Script source', BAD_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));
    await within(await screen.findByLabelText('Result')).findByRole('alert');

    remount();
    await ready();

    expect((screen.getByLabelText('Script name') as HTMLInputElement).value).toBe('probe');
    expect((screen.getByLabelText('Script source') as HTMLTextAreaElement).value).toBe(BAD_SRC);
    expect(within(screen.getByLabelText('Result')).getByRole('alert').textContent).toMatch(/^error: <source>:3:1 — /);
  });
});

describe('ScriptsPanel — console', () => {
  it('lists script findings newest first, with the dropped count', async () => {
    const at = 1_700_000_000_000;
    const f = (name: string, n: number, extra: Record<string, unknown> = {}) => ({ name, severity: 'low', flow_id: null, detail: null, tags: [], source: 'redact-auth', at: at + n, ...extra });
    mount({ reply: (tool) => (tool === 'script.findings' ? { findings: [f('first', 1), f('second', 2, { severity: 'high', flow_id: 'flow_9', tags: ['auth'] }), f('third', 3)], dropped: 7 } : undefined) });
    await ready();

    const items = await waitFor(() => {
      const found = [...document.querySelectorAll('[data-finding]')];
      expect(found).toHaveLength(3);
      return found;
    });
    expect(items.map((i) => i.querySelector('[data-finding-name]')?.textContent)).toEqual(['third', 'second', 'first']);
    expect(text(items[1])).toContain('high');
    expect(text(items[1])).toContain('flow_9');
    expect(text(items[1])).toContain('auth');
    expect(screen.getByText('7 dropped')).toBeTruthy();
  });

  it("shows the core's findings newest first and each failing script's latest error", async () => {
    mount();
    await ready();
    await waitFor(() => expect(document.querySelectorAll('[data-finding]')).toHaveLength(3));
    expect([...document.querySelectorAll('[data-finding-name]')].map((n) => n.textContent)).toEqual([
      'Verbose error body',
      'Admin path probed',
      'Bearer token sent over cleartext HTTP',
    ]);
    const err = document.querySelector('[data-console-error="flaky-parser"]')!;
    expect(text(err)).toContain('on_response: Property not found: content_type (line 12)');
    expect(document.querySelectorAll('[data-console-error]')).toHaveLength(1);
  });

  it('asks the core for only the newest 50 findings', async () => {
    const { calls } = mount();
    await ready();
    await waitFor(() => expect(calls.some((c) => c.tool === 'script.findings')).toBe(true));
    expect(calls.find((c) => c.tool === 'script.findings')?.args).toEqual({ limit: 50 });
  });

  it('Refresh re-reads the scripts and the findings', async () => {
    const { bus } = mount();
    await ready();
    await bus.call('script.save', { name: 'late-arrival', source: GOOD_SRC });
    expect(row('late-arrival')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(row('late-arrival')).not.toBeNull());
  });
});

describe('ScriptsPanel — capability gating', () => {
  it('turns authoring controls off for an agent session but leaves read-only Validate on', async () => {
    mount({ role: 'agent' });
    await ready();

    expect((within(row('redact-auth')).getByRole('switch', { name: 'redact-auth enabled' }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(row('redact-auth')).getByRole('button', { name: 'Reload redact-auth' }) as HTMLButtonElement).disabled).toBe(true);
    type('Script name', 'probe');
    type('Script source', GOOD_SRC);
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Validate' }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText(/Agent session/)).toBeTruthy();
  });

  it('leaves authoring on when the role is unknown, so the core decides and its message shows', async () => {
    mount({ role: null });
    await ready();
    expect((within(row('redact-auth')).getByRole('switch', { name: 'redact-auth enabled' }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByText(/Agent session/)).toBeNull();
  });

  it('disables a control whose command the core does not offer', async () => {
    mount({ tools: (all) => all.filter((t) => t.name !== 'script.reload' && t.name !== 'script.save') });
    await ready();
    expect((within(row('redact-auth')).getByRole('button', { name: 'Reload redact-auth' }) as HTMLButtonElement).disabled).toBe(true);
    type('Script name', 'probe');
    type('Script source', GOOD_SRC);
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(row('redact-auth')).getByRole('switch', { name: 'redact-auth enabled' }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe('scripts store — guards', () => {
  it('save() sends nothing without a valid name and a source, and sends the exact request once it has both', async () => {
    const { app, calls } = mount();
    await ready();
    const store = scriptsStore(app);
    const saves = () => calls.filter((c) => c.tool === 'script.save');

    await store.save(); // nothing typed
    store.setName('bad name!');
    store.setSource(GOOD_SRC);
    await store.save(); // a name the core would refuse
    store.setName('probe');
    store.setSource(' \n\t');
    await store.save(); // a blank source
    expect(saves()).toEqual([]);

    store.setSource(GOOD_SRC);
    await store.save();
    expect(saves()).toEqual([{ tool: 'script.save', args: { name: 'probe', source: GOOD_SRC, enable: true } }]);
  });

  it('validate() sends nothing for a blank source, and only the source otherwise', async () => {
    const { app, calls } = mount();
    await ready();
    const store = scriptsStore(app);
    const validates = () => calls.filter((c) => c.tool === 'script.validate');

    store.setSource('  \n');
    await store.validate();
    expect(validates()).toEqual([]);

    store.setSource(GOOD_SRC);
    await store.validate();
    expect(validates()).toEqual([{ tool: 'script.validate', args: { source: GOOD_SRC } }]);
  });

  it('save() is refused for an agent session, validate() is not', async () => {
    const { app, calls } = mount({ role: 'agent' });
    await ready();
    const store = scriptsStore(app);
    store.setName('probe');
    store.setSource(GOOD_SRC);

    await store.save();
    expect(calls.some((c) => c.tool === 'script.save')).toBe(false);
    await store.validate();
    expect(calls.filter((c) => c.tool === 'script.validate')).toHaveLength(1);
  });
});
