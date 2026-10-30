// The Scripts panel against the fixture bus (src/bus/mock.ts `script.*`, which mirrors the core's
// crates/aitm-plugin-rhai/src/commands.rs shapes): list, row actions, the new-script editor
// (validate / save), the console, capability gating and the not-offered state. The store is the real
// one, so the panel runs through `app.call`, `app.notice` and `app.proxy.tools` exactly as in the UI.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { createMockBus, type MockControls } from '~/bus/mock';
import { BusError, type BusClient, type BusRole, type ToolDef } from '~/bus/types';
import { createAppStore } from '~/state/app';
import { AppProvider } from '~/state/context';
import { ScriptsPanel } from '../ScriptsPanel';

interface MountOpts {
  /** Replace one tool's reply: return a value to answer with it, an Error to reject, `undefined` to fall through to the fixture. */
  reply?: (tool: string, args: Record<string, unknown>) => unknown;
  /** Narrow the advertised tool list. */
  tools?: (all: ToolDef[]) => ToolDef[];
  role?: BusRole | null;
}

const buses: BusClient[] = [];

function mount(opts: MountOpts = {}) {
  const mock = createMockBus({ initial: 0, rate: 0, agentActive: false });
  const calls: { tool: string; args: Record<string, unknown> }[] = [];
  const bus: BusClient & MockControls = {
    ...mock,
    role: () => (opts.role === undefined ? 'operator' : opts.role),
    async tools() {
      const all = await mock.tools();
      return opts.tools ? opts.tools(all) : all;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      calls.push({ tool, args });
      const r = opts.reply?.(tool, args);
      if (r instanceof Error) throw r;
      if (r !== undefined) return r as T;
      return mock.call<T>(tool, args);
    },
  };
  buses.push(mock);
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

const row = (name: string) => document.querySelector<HTMLElement>(`[data-script="${name}"]`)!;
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
const type = (label: string, value: string) => fireEvent.input(screen.getByLabelText(label), { target: { value } });
/** The first `script.list` has landed and the rows are on screen (the console's findings load alongside and may land first). */
const ready = () => waitFor(() => expect(row('redact-auth')).not.toBeNull());

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
    const { calls } = mount({ tools: (all) => all.filter((t) => !t.name.startsWith('script.')) });
    expect(await screen.findByText(/Scripts are not enabled on this core/)).toBeTruthy();
    expect(screen.queryByLabelText('Script source')).toBeNull();
    expect(screen.queryByRole('switch')).toBeNull();
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.filter((c) => c.tool.startsWith('script.'))).toEqual([]);
  });
});

describe('ScriptsPanel — list errors', () => {
  it("surfaces a failing script.list with the core's text instead of showing an empty list as fact", async () => {
    const { app } = mount({ reply: (tool) => (tool === 'script.list' ? new BusError('rhai host is not running') : undefined) });
    await waitFor(() => expect(app.toast()).toEqual({ text: 'script.list: rhai host is not running', kind: 'error' }));
    // A failed list is not "0 active": the header stays silent about a count it does not know.
    expect(screen.queryByText(/ active$/)).toBeNull();
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
    // The refresh updates the row in place: the control you just used keeps its node, so it keeps keyboard focus.
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
    const { bus, calls } = mount();
    await ready();
    const expected = await bus.call('script.validate', { source: BAD_SRC }).then(
      () => '',
      (e: Error) => e.message,
    );
    expect(expected).toMatch(/^error: <source>:3:1 — /);

    type('Script source', BAD_SRC);
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    const alert = await within(await screen.findByLabelText('Result')).findByRole('alert');
    expect(alert.textContent).toBe(expected);
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
    expect(text(result.querySelector('[data-field="path"]'))).toBe('/Users/matt/aitm/scripts/probe.rhai');
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
    await new Promise((r) => setTimeout(r, 50));
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

  it('shows the fixture findings and each failing script latest error', async () => {
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
