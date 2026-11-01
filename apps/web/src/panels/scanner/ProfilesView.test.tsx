// T8 Task 11 (D-T8.5, D-T8.6, D-T8.10): the Profiles list, the profile editor and the check tree.
//
// What these tests pin down is what leaves this UI and what the operator is told before it does: a
// launch carries `{ profile }` and nothing else, the pre-flight reason and note are the spec's
// sentences, the core's confirmation prompt is shown verbatim and `_confirm` is only sent after the
// operator says so, the check tree writes the `id | class | lane:*` grammar, and a session preview
// prints names only.
//
// The replies come from `crates/aitm-scan-model/fixtures/` through `stubApp`: wire *shapes*, never
// evidence. A green run here says the editor holds the contract, not that any scan ever ran
// (fixtures/README.md). The acceptance for this track is `scripts/scan-live.mjs` against a real core.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import { scanStore, type ScanStore } from './store';
import { AGENT_NOTE, CONFIRM_NOTE, PROFILE_NAME_HINT } from './helpers';
import { parseScanProfile, type ScanProfile } from './model';
import { ProfilesView } from './ProfilesView';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

/** The `standard` built-in as the editor loads it, parsed fresh so a mutation cannot leak. */
const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;

/** An L4 scope entry that authorises injecting anywhere on loopback (the W-9 "allowed" case). */
const WILDCARD_INJECT = {
  id: 'l4s-1',
  cidr: '127.0.0.1/32',
  ports: '0-65535',
  interface: '*',
  direction: 'outbound',
  capability: 'inject',
  inject_rate: { pps: 100, burst: 10 },
};

const built: ScanStore[] = [];

/** Mounts the view over a stub app and waits for the default `standard` draft to be bound. */
async function mount(opts: Parameters<typeof stubApp>[0] = {}, awaitDraft = true) {
  const stub = stubApp({ scope: [{ host: '127.0.0.1' }], ...opts });
  const s = scanStore(stub.app);
  built.push(s);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <ProfilesView />
    </AppProvider>
  ));
  if (awaitDraft) await screen.findByLabelText('Profile name');
  return { ...stub, ...r, s };
}

const start = (): HTMLButtonElement => screen.getByRole('button', { name: 'Start' }) as HTMLButtonElement;
const reasonOf = (c: HTMLElement): string | null => c.querySelector('[data-reason]')?.textContent ?? null;
const noteOf = (c: HTMLElement): string | null => c.querySelector('[data-note]')?.textContent ?? null;

/** The scheme radio (`https` | `http`) inside the `Origin scheme` segmented control. */
const schemeRadio = (scheme: string): HTMLButtonElement =>
  within(screen.getByRole('radiogroup', { name: 'Origin scheme' })).getByRole('radio', {
    name: scheme,
  }) as HTMLButtonElement;

/** The Add-origin picker, the way an operator drives it (a disabled port input is left alone). */
function addOrigin(scheme: string, host: string, port?: string): void {
  fireEvent.click(schemeRadio(scheme));
  fireEvent.change(screen.getByLabelText('Origin host'), { target: { value: host } });
  const portInput = screen.getByLabelText('Origin port') as HTMLInputElement;
  if (port !== undefined && !portInput.disabled) fireEvent.input(portInput, { target: { value: port } });
  fireEvent.click(screen.getByRole('button', { name: 'Add origin' }));
}

function addL4Target(ip: string, port: string, proto: string): void {
  fireEvent.input(screen.getByLabelText('L4 target IP'), { target: { value: ip } });
  fireEvent.input(screen.getByLabelText('L4 target port'), { target: { value: port } });
  fireEvent.change(screen.getByLabelText('L4 target proto'), { target: { value: proto } });
  fireEvent.click(screen.getByRole('button', { name: 'Add L4 target' }));
}

/** Turns a lane checkbox on in the Lanes group (the tree has same-named lane rows). */
function toggleLane(lane: string): void {
  const group = screen.getByRole('group', { name: 'Lanes' });
  fireEvent.click(within(group).getByRole('checkbox', { name: new RegExp(`^${lane}`) }));
}

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
});

describe('ProfilesView: the list (D-T8.5, D-T8.10)', () => {
  it('lists_builtins_first: seven built-ins, tagged, with `standard` selected by default', async () => {
    const { container } = await mount();
    const options = [...container.querySelectorAll<HTMLElement>('[role=option][data-profile]')];
    expect(options).toHaveLength(7);
    expect(options[0]!.dataset.profile).toBe('passive-only');
    expect(options.map((o) => o.dataset.profile)).toEqual([
      'passive-only',
      'map-only',
      'light-http',
      'standard',
      'thorough',
      'l4-stream-safe',
      'l4-full',
    ]);
    for (const o of options) expect(o.textContent).toContain('builtin');
    expect(container.querySelector('[data-profile="standard"]')!.getAttribute('aria-selected')).toBe('true');
  });

  it('keyboard: the Profiles listbox moves the selection with Arrow/Home/End (W-17)', async () => {
    const { container } = await mount();
    const list = screen.getByRole('listbox', { name: 'Profiles' });
    const selected = (): string | null =>
      container.querySelector('[role=option][aria-selected="true"]')?.getAttribute('data-profile') ?? null;
    expect(selected()).toBe('standard');

    fireEvent.keyDown(list, { key: 'ArrowDown' });
    await waitFor(() => expect(selected()).toBe('thorough'));
    fireEvent.keyDown(list, { key: 'ArrowUp' });
    await waitFor(() => expect(selected()).toBe('standard'));
    fireEvent.keyDown(list, { key: 'Home' });
    await waitFor(() => expect(selected()).toBe('passive-only'));
    fireEvent.keyDown(list, { key: 'End' });
    await waitFor(() => expect(selected()).toBe('l4-full'));
  });

  it('weird_name_keyboard (B3): a profile name with quote and bracket renders and a keyboard move scrolls it by id', async () => {
    const WEIRD = 'we"ird]';
    const list = fixture('scan.profile.list.json') as { profiles: unknown[] };
    const scroll = vi.fn();
    const proto = Element.prototype as unknown as { scrollIntoView?: (arg?: unknown) => void };
    const had = proto.scrollIntoView;
    proto.scrollIntoView = scroll;
    try {
      const h = await mount({
        replies: {
          'scan.profile.list': {
            profiles: [...list.profiles, { name: WEIRD, builtin: false, summary: { lanes: ['http'], intensity: 'medium', speed: 'normal' } }],
          },
        },
      });
      // The row is found by id, not by a selector: a name with `"` and `]` is still just a string here.
      const row = document.getElementById(`profile-${WEIRD}`);
      expect(row).not.toBeNull();
      expect(row!.getAttribute('data-profile')).toBe(WEIRD);

      const listbox = screen.getByRole('listbox', { name: 'Profiles' });
      fireEvent.keyDown(listbox, { key: 'End' });
      await waitFor(() => expect(h.s.selectedProfile()).toBe(WEIRD));
      expect(scroll).toHaveBeenCalledTimes(1);
      expect(scroll.mock.instances[0]).toBe(row);
    } finally {
      if (had) proto.scrollIntoView = had;
      else delete proto.scrollIntoView;
    }
  });

  it('profiles_error_last_good (B8): a failed reload keeps the rows and shows the last good time', async () => {
    const h = await mount();
    expect(h.container.querySelectorAll('[role=option][data-profile]')).toHaveLength(7);
    h.fail('scan.profile.list', 'bus closed');
    await h.s.loadProfiles();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('bus closed');
    expect(alert.textContent).toMatch(/last good: \d/);
    expect(alert.textContent).not.toContain('last good: —');
    // Data kept: the list read before the failure is still on screen, and Retry reads again.
    expect(h.container.querySelectorAll('[role=option][data-profile]')).toHaveLength(7);
    const before = h.count('scan.profile.list');
    h.reply('scan.profile.list', fixture('scan.profile.list.json'));
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(h.count('scan.profile.list')).toBe(before + 1));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });

  it('No profiles keeps the frame when the core has none', async () => {
    await mount({ replies: { 'scan.profile.list': { profiles: [] } } }, false);
    await waitFor(() => expect(screen.getByRole('status', { name: 'Profiles' }).textContent).toBe('No profiles'));
  });
});

describe('ProfileEditor: binding and targets (D-T8.5)', () => {
  it('editor_binds_profile: name, intensity, lanes and the unavailable-lane tag', async () => {
    await mount();
    const name = screen.getByLabelText('Profile name') as HTMLInputElement;
    expect(name.value).toBe('standard');
    expect(name.readOnly).toBe(true);

    const intensity = screen.getByRole('radiogroup', { name: 'Intensity' });
    expect(within(intensity).getByRole('radio', { name: 'medium' }).getAttribute('aria-checked')).toBe('true');
    expect(within(intensity).getByRole('radio', { name: 'light' }).getAttribute('aria-checked')).toBe('false');

    const lanes = screen.getByRole('group', { name: 'Lanes' });
    expect((within(lanes).getByRole('checkbox', { name: /^http/ }) as HTMLInputElement).checked).toBe(true);
    const ws = within(lanes).getByRole('checkbox', { name: /^ws/ }) as HTMLInputElement;
    expect(ws.checked).toBe(true);
    // The `scan.checks` fixture lists only `http` checks, so every other lane is unavailable here.
    expect(ws.closest('label')!.textContent).toContain('not available on this build');
    expect(
      (within(lanes).getByRole('checkbox', { name: /^http/ }) as HTMLInputElement).closest('label')!.textContent,
    ).not.toContain('not available on this build');
  });

  it('add_origin_and_start: the picker composes the origin and the launch carries the draft whole (W-12)', async () => {
    const { container, argsOf } = await mount();
    // The scheme is a segmented control (a native <select> cannot be driven by real key events in
    // headless Chrome); it defaults to https.
    expect(schemeRadio('https').getAttribute('aria-checked')).toBe('true');
    expect(schemeRadio('http').getAttribute('aria-checked')).toBe('false');
    addOrigin('http', '127.0.0.1', '8080');
    expect(schemeRadio('http').getAttribute('aria-checked')).toBe('true');
    expect(schemeRadio('https').getAttribute('aria-checked')).toBe('false');

    const origins = screen.getByRole('list', { name: 'Origins' });
    await waitFor(() => expect(origins.textContent).toContain('http://127.0.0.1:8080'));
    await waitFor(() => expect(start().disabled).toBe(false));
    expect(reasonOf(container)).toBeNull();

    fireEvent.click(start());
    await waitFor(() => expect(argsOf('scan.start')).toHaveLength(1));
    expect(argsOf('scan.start')[0]).toEqual({
      profile: { ...standard(), target: { origins: ['http://127.0.0.1:8080'], l4: [] } },
    });
    expect(Object.keys(argsOf('scan.start')[0]!)).toEqual(['profile']);
  });

  it('origin_host_carries_a_port: the port input is ignored and never doubled', async () => {
    // The scope entry an operator adds for a test target is `host:port`; the picker must compose
    // `http://127.0.0.1:8080`, never `http://127.0.0.1:8080:8080`.
    await mount({ scope: [{ host: '127.0.0.1:8080' }, { host: '*.example.com' }, { host: 'app.example' }] });
    const host = screen.getByLabelText('Origin host') as HTMLSelectElement;
    expect([...host.options].map((o) => o.value)).toEqual(['127.0.0.1:8080', 'app.example']);

    fireEvent.click(schemeRadio('http'));
    fireEvent.change(host, { target: { value: '127.0.0.1:8080' } });
    const port = screen.getByLabelText('Origin port') as HTMLInputElement;
    await waitFor(() => expect(port.disabled).toBe(true));
    fireEvent.click(screen.getByRole('button', { name: 'Add origin' }));

    const origins = screen.getByRole('list', { name: 'Origins' });
    await waitFor(() => expect(origins.textContent).toContain('http://127.0.0.1:8080'));
    expect(origins.textContent).not.toContain('8080:8080');

    // A host with no port still takes the typed one.
    fireEvent.change(host, { target: { value: 'app.example' } });
    await waitFor(() => expect((screen.getByLabelText('Origin port') as HTMLInputElement).disabled).toBe(false));
    fireEvent.input(screen.getByLabelText('Origin port'), { target: { value: '9443' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add origin' }));
    await waitFor(() => expect(origins.textContent).toContain('http://app.example:9443'));
  });

  it('out_of_scope_disables: the reason names the host to add', async () => {
    const { container, setScope } = await mount();
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));

    setScope([]);
    await waitFor(() => expect(start().disabled).toBe(true));
    expect(reasonOf(container)).toBe('out of scope: add 127.0.0.1 to Scope');
    expect(screen.getByRole('button', { name: 'Add 127.0.0.1 to Scope' })).toBeTruthy();
  });

  it('l4_hint_disables: no covering L4 scope entry dims Start with the D11 hint (W-9)', async () => {
    const blocked = await mount();
    toggleLane('l4_stream');
    addL4Target('127.0.0.1', '9', 'udp');
    await waitFor(() => expect(screen.getByRole('list', { name: 'L4 targets' }).textContent).toContain('127.0.0.1:9'));
    await waitFor(() => expect(start().disabled).toBe(true));
    expect(reasonOf(blocked.container)).toContain('no L4 scope entry with Inject covers 127.0.0.1:9');
    expect(reasonOf(blocked.container)).toContain('interface: "*"');
    cleanup();

    const allowed = await mount({ replies: { 'l4.scope.list': [WILDCARD_INJECT] } });
    toggleLane('l4_stream');
    addL4Target('127.0.0.1', '9', 'udp');
    await waitFor(() => expect(start().disabled).toBe(false));
    expect(reasonOf(allowed.container)).toBeNull();
    expect(noteOf(allowed.container)).toBe('The core will ask for confirmation.');
    expect(noteOf(allowed.container)).toBe(CONFIRM_NOTE);
  });
});

describe('ProfileEditor: the launch handshake (D-T8.6)', () => {
  const PROMPT =
    'scan.start will fuzz 127.0.0.1:9/udp from profile l4-stream-safe: up to 500 cases, 65536 B/s, matched L4 scope entry l4s-1.';
  const needsConfirm = { status: 'needs_confirmation', confirm_token: 'tok-1', prompt: PROMPT };

  it('dialog_verbatim_and_cancel: the prompt is the core’s, Cancel sends nothing', async () => {
    const h = await mount({ replies: { 'scan.start': needsConfirm } });
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));
    fireEvent.click(start());

    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain(PROMPT);
    expect(within(dialog).getByRole('heading', { name: 'Confirm scan' })).toBeTruthy();
    expect(within(dialog).getByRole('button', { name: 'Start scan' })).toBeTruthy();

    // Cancelling the core's confirmation is never gated on anything: the button is live at once.
    const cancel = within(dialog).getByRole('button', { name: 'Cancel' }) as HTMLButtonElement;
    expect(cancel.disabled).toBe(false);
    fireEvent.click(cancel);
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(h.count('scan.start')).toBe(1);
    expect(h.argsOf('scan.start').some((a) => '_confirm' in a)).toBe(false);
    cleanup();

    // A fresh mount for the confirming half, so the confirmed launch is `scan.start` call index 1.
    const c = await mount({ replies: { 'scan.start': needsConfirm } });
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));
    fireEvent.click(start());
    await screen.findByRole('alertdialog');
    c.reply('scan.start', fixture('scan.start.json'));
    fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));

    await waitFor(() => expect(c.count('scan.start')).toBe(2));
    expect(c.argsOf('scan.start')[1]!._confirm).toBe('tok-1');
    expect(c.argsOf('scan.start')[1]!.profile).toBeDefined();
  });

  it('error_texts: a refusal prints the D-T8.6 sentence and keeps the draft', async () => {
    const { fail } = await mount();
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));

    fail('scan.start', 'scan: invalid_profile: budget.probes must be > 0');
    fireEvent.click(start());
    const result = await screen.findByRole('status', { name: 'Launch result' });
    await waitFor(() => expect(result.textContent).toContain('Invalid profile: budget.probes must be > 0'));
    // The draft survives a refusal: the origin is still there and the name is unchanged.
    expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080');
    expect((screen.getByLabelText('Profile name') as HTMLInputElement).value).toBe('standard');
  });

  it('agent_note: an agent session is explained, never pre-refused (W-15)', async () => {
    const { container, fail } = await mount({ role: 'agent' });
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));
    expect(container.querySelector('[data-note]')!.textContent).toContain('scanner.allow_agent_active');
    expect(noteOf(container)).toBe(AGENT_NOTE);

    fail('scan.start', 'scan: refused_agent: x');
    fireEvent.click(start());
    const result = await screen.findByRole('status', { name: 'Launch result' });
    await waitFor(() => expect(result.textContent).toContain('Agent session'));
  });
});

describe('ProfileEditor: errors it does not own (PA5)', () => {
  it('profile_error_block_is_separate: an issue-update failure never shows in the editor', async () => {
    const h = await mount();
    h.fail('scan.issue.update', 'scan: not_found: x');
    expect(await h.s.updateIssue('issue-x', 'confirmed')).toBeNull();
    expect(h.s.lastError()).toEqual({ source: 'issue', code: 'not_found', text: 'Not found: x' });
    // The toast went out; the editor shows no error text of any kind.
    expect(h.notice).toHaveBeenCalledWith('Not found: x', 'error');
    expect(screen.queryByRole('status', { name: 'Launch result' })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('form', { name: 'Profile editor' }).textContent).not.toContain('Not found');
    // The editor is still bound and usable.
    expect((screen.getByLabelText('Profile name') as HTMLInputElement).value).toBe('standard');
  });
});

describe('ProfileEditor: per-profile local state (PA9)', () => {
  it('per_profile_reset: a preview, a half-typed L4 target and a typed port never follow the operator to another profile', async () => {
    const h = await mount({
      replies: { 'scan.profile.get': (args: Record<string, unknown>) => ({ ...(fixture('scan.profile.get.json') as object), name: args.name }) },
    });
    const nameInput = () => screen.getByLabelText('Profile name') as HTMLInputElement;
    const pick = async (name: string) => {
      fireEvent.click(h.container.querySelector<HTMLElement>(`[data-profile="${name}"]`)!);
      await waitFor(() => expect(nameInput().value).toBe(name));
    };
    // Both drafts are loaded first, so a later switch between them has no loading gap that would
    // unmount the editor by accident: the reset must come from keying the editor on the profile.
    await pick('thorough');
    await pick('standard');
    expect(h.s.draft('thorough')).not.toBeNull();

    // A preview on `standard` ...
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080'));
    fireEvent.click(screen.getByRole('button', { name: 'Preview session for http://127.0.0.1:8080' }));
    await waitFor(() => expect(h.container.querySelector('[data-preview]')).not.toBeNull());
    // ... is gone on `thorough`.
    await pick('thorough');
    expect(h.container.querySelector('[data-preview]')).toBeNull();

    // A half-typed L4 target and a typed port on `thorough` do not land in `standard`'s pickers.
    fireEvent.input(screen.getByLabelText('L4 target IP'), { target: { value: '10.0.0' } });
    fireEvent.input(screen.getByLabelText('Origin port'), { target: { value: '9' } });
    expect((screen.getByLabelText('L4 target IP') as HTMLInputElement).value).toBe('10.0.0');
    expect((screen.getByLabelText('Origin port') as HTMLInputElement).value).toBe('9');
    await pick('standard');
    expect((screen.getByLabelText('L4 target IP') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Origin port') as HTMLInputElement).value).toBe('');
    // The draft itself is kept: the origin added on `standard` is still there.
    expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080');
  });

  it('picker_rejects_unknown: a select value outside the options is ignored, never cast into the draft', async () => {
    await mount();
    toggleLane('l4_stream');
    fireEvent.input(screen.getByLabelText('L4 target IP'), { target: { value: '127.0.0.1' } });
    fireEvent.input(screen.getByLabelText('L4 target port'), { target: { value: '9' } });
    fireEvent.change(screen.getByLabelText('L4 target proto'), { target: { value: 'bogus' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add L4 target' }));
    const row = await waitFor(() => {
      const el = screen.getByRole('list', { name: 'L4 targets' }).querySelector('[data-l4="127.0.0.1:9"]');
      expect(el).not.toBeNull();
      return el!;
    });
    expect(row.textContent).toContain('tcp');
  });
});

describe('ProfileEditor: a closed bus (D-T8.10)', () => {
  it('reconnecting_disables_editor: every control is off and a note says so; open re-enables Start', async () => {
    const h = await mount();
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(start().disabled).toBe(false));
    const NOTE = 'reconnecting: controls are disabled until the bus is back';
    expect(screen.queryByText(NOTE)).toBeNull();

    h.setBusState('reconnecting');
    await waitFor(() => expect(start().disabled).toBe(true));
    const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;
    expect(button('Save').disabled).toBe(true);
    expect(button('Map only').disabled).toBe(true);
    expect(button('Save as').disabled).toBe(true);
    // The body is one disabled fieldset: its controls are disabled through the ancestor, which
    // `:disabled` sees and the `disabled` property (the attribute) does not.
    expect(button('Add origin').matches(':disabled')).toBe(true);
    expect(button('Preview session for http://127.0.0.1:8080').matches(':disabled')).toBe(true);
    expect((screen.getByLabelText('Profile name') as HTMLInputElement).matches(':disabled')).toBe(true);
    expect(screen.getByText(NOTE)).toBeTruthy();
    // Data kept: the draft is still on screen.
    expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080');

    h.setBusState('open');
    await waitFor(() => expect(start().disabled).toBe(false));
    expect(button('Save as').disabled).toBe(false);
    expect((screen.getByLabelText('Profile name') as HTMLInputElement).matches(':disabled')).toBe(false);
    expect(screen.queryByText(NOTE)).toBeNull();
  });
});

describe('CheckTree and the selector grammar (W-11)', () => {
  it('check_tree_writes_grammar: a toggle writes the selector, an unknown one is flagged', async () => {
    await mount();
    const tree = await screen.findByRole('tree', { name: 'Checks' });
    const exclude = screen.getByLabelText('Exclude selectors') as HTMLTextAreaElement;

    fireEvent.click(within(tree).getByRole('checkbox', { name: 'Error-based SQL injection' }));
    await waitFor(() => expect(exclude.value).toBe('http.sqli-error'));

    // Checking it again withdraws the selector rather than leaving a stale one behind, so the
    // class row below is a real "uncheck" of a class that is fully on.
    fireEvent.click(within(tree).getByRole('checkbox', { name: 'Error-based SQL injection' }));
    await waitFor(() => expect(exclude.value).toBe(''));

    // Unchecking the whole class replaces the single id it covers.
    fireEvent.click(within(tree).getByRole('checkbox', { name: 'sqli-error' }));
    await waitFor(() => expect(exclude.value).toBe('sqli-error'));

    const include = screen.getByLabelText('Include selectors') as HTMLTextAreaElement;
    fireEvent.input(include, { target: { value: 'nope' } });
    await waitFor(() => {
      const unknown = tree.querySelector('[data-unknown="true"]');
      expect(unknown).not.toBeNull();
      expect(unknown!.textContent).toBe('nope');
    });
  });
});

describe('ProfileEditor: save, delete and session preview (D-T8.5, W-12, W-13)', () => {
  it('save_as_and_delete: a builtin cannot be overwritten, a saved profile can be deleted', async () => {
    const h = await mount();
    const save = () => screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;
    expect(save().disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull();

    // The builtin's name is read-only until `Save as` turns the field into the new-name field.
    fireEvent.click(screen.getByRole('button', { name: 'Save as' }));
    const name = screen.getByLabelText('Profile name') as HTMLInputElement;
    await waitFor(() => expect(name.readOnly).toBe(false));
    fireEvent.input(name, { target: { value: 'my-api' } });
    await waitFor(() => expect(save().disabled).toBe(false));

    const list = fixture('scan.profile.list.json') as { profiles: unknown[] };
    h.reply('scan.profile.list', {
      profiles: [...list.profiles, { name: 'my-api', builtin: false, summary: { lanes: ['http'], intensity: 'medium', speed: 'normal' } }],
    });
    h.reply('scan.profile.get', { ...(fixture('scan.profile.get.json') as object), name: 'my-api' });
    fireEvent.click(save());
    await waitFor(() => expect(h.argsOf('scan.profile.save')).toHaveLength(1));
    expect((h.argsOf('scan.profile.save')[0]!.profile as ScanProfile).name).toBe('my-api');
    // The save re-reads the list before it settles; `Confirm delete` below is disabled while any
    // guarded call is in flight, so wait for the save to finish rather than racing its microtasks.
    await waitFor(() => expect(h.s.busy()).toBe(false));

    const saved = await waitFor(() => {
      const row = h.container.querySelector<HTMLElement>('[data-profile="my-api"]');
      expect(row).not.toBeNull();
      return row!;
    });
    fireEvent.click(saved);
    const del = await screen.findByRole('button', { name: 'Delete' });

    fireEvent.click(del);
    expect(screen.getByText('Delete my-api?')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));
    await waitFor(() => expect(h.argsOf('scan.profile.delete')).toEqual([{ name: 'my-api' }]));

    // A built-in offers no Delete at all.
    fireEvent.click(h.container.querySelector<HTMLElement>('[data-profile="standard"]')!);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull());
  });

  it('save_name_rule: a name the engine would refuse keeps Save off and shows the hint; a builtin name too', async () => {
    const h = await mount();
    const save = () => screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;
    // The pre-flight reason is a `note` too, so the hint is found by its own marker.
    const hint = () => h.container.querySelector<HTMLElement>('[data-name-hint]');

    fireEvent.click(screen.getByRole('button', { name: 'Save as' }));
    const name = screen.getByLabelText('Profile name') as HTMLInputElement;
    await waitFor(() => expect(name.readOnly).toBe(false));

    fireEvent.input(name, { target: { value: 'My-API' } });
    await waitFor(() => expect(save().disabled).toBe(true));
    expect(hint()).not.toBeNull();
    expect(hint()!.getAttribute('role')).toBe('note');
    expect(hint()!.textContent).toBe(PROFILE_NAME_HINT);

    fireEvent.input(name, { target: { value: 'my-api' } });
    await waitFor(() => expect(save().disabled).toBe(false));
    expect(hint()).toBeNull();

    // A built-in's name is never a save target, even typed by hand after `Save as`.
    fireEvent.input(name, { target: { value: 'standard' } });
    await waitFor(() => expect(save().disabled).toBe(true));
    expect(hint()).not.toBeNull();
  });

  it('preview_names_only: the preview prints names and the canary, never a value (W-13)', async () => {
    const { container, argsOf } = await mount();
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080'));

    fireEvent.click(screen.getByRole('button', { name: 'Preview session for http://127.0.0.1:8080' }));
    const preview = await waitFor(() => {
      const el = container.querySelector('[data-preview]');
      expect(el).not.toBeNull();
      return el!;
    });
    expect([...preview.querySelectorAll('p')].map((p) => p.textContent)).toEqual([
      'cookies: sid · headers: authorization',
      'Canary: GET /account (expects 200)',
    ]);
    expect(argsOf('scan.session.preview')).toEqual([{ target: 'http://127.0.0.1:8080' }]);
  });

  it('preview_names_only: no canary says detection is off', async () => {
    const { container } = await mount({
      replies: {
        'scan.session.preview': {
          origin: 'http://127.0.0.1:8080',
          cookies: [],
          headers: [],
          source_flow: null,
          observed_at: 1761900000000,
          canary: { kind: 'none' },
        },
      },
    });
    addOrigin('http', '127.0.0.1', '8080');
    await waitFor(() => expect(screen.getByRole('list', { name: 'Origins' }).textContent).toContain('http://127.0.0.1:8080'));
    fireEvent.click(screen.getByRole('button', { name: 'Preview session for http://127.0.0.1:8080' }));
    await waitFor(() => {
      const preview = container.querySelector('[data-preview]');
      expect([...(preview?.querySelectorAll('p') ?? [])].map((p) => p.textContent)).toEqual([
        'cookies: — · headers: —',
        'Canary: none; auth-lost detection off',
      ]);
    });
  });
});
