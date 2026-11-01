// The toolbar's half of the system-proxy pill (spec D12 pill word, D15 web; plan Task 22, F-web): the
// listening pill is a menu button that appends the pill word after the address, and its menu
// carries the "Set as system proxy" checkbox, the `detail` line and — with `guidance` — "Copy env
// line". The polled `proxy.status.system_proxy` is the SEVEN-field compact object (no guidance, no
// remedy); the full object comes from `proxy.system.status`, which the menu asks for when it opens
// (D15, amended 2026-11-01). A component unit test over the in-memory bus: never frontend evidence
// (the live proof is plan Task 23).

import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@solidjs/testing-library';
import type { BusClient } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { Toolbar } from './Toolbar';

/** The compact D6 sub-object `proxy.status` carries when another proxy owns the system setting. */
const OTHER = { state: 'other', host: '127.0.0.1', port: 9090, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS → 127.0.0.1:9090 (not this core)' };
/** A points-at-us status, as the set verb replies. */
const POINTS_AT_US = { state: 'points_at_us', host: null, port: null, managed_by_us: true, setting: false, supported: true, detail: 'HTTP and HTTPS → 127.0.0.1:8080 (this core)' };
/** No mechanism on this host: the compact object says so; the env line is only on the full one. */
const UNSUPPORTED = { state: 'unsupported', host: null, port: null, managed_by_us: false, setting: false, supported: false, detail: 'no system proxy mechanism on this host' };
const ENV_LINE = 'export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080';
/** The full `proxy.system.status` object for that host (D6: `guidance` is the env line when unsupported). */
const UNSUPPORTED_FULL = { ...UNSUPPORTED, mechanism: 'none', services: [], guidance: ENV_LINE, remedy: null };
const OFF = { state: 'off', host: null, port: null, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS off' };
const NEEDS_ADMIN = { state: 'needs_privilege', host: null, port: null, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS off' };
const REMEDY = 'The system proxy needs an administrator.';
const NEEDS_ADMIN_FULL = { ...NEEDS_ADMIN, mechanism: 'gsettings', services: [], guidance: null, remedy: REMEDY };

/** The three `proxy.system.*` verbs the store may call, offered by the test bus on top of its own catalogue. */
const SYS_TOOLS = ['proxy.system.status', 'proxy.system.set', 'proxy.system.unset'];

interface MountOpts {
  /** What `proxy.status` reports as `system_proxy` (the compact object); `undefined` leaves it out. */
  status: unknown;
  /** What `proxy.system.status` replies (the full object). Default: the compact one with null guidance/remedy. */
  full?: unknown;
  /** The bus role; default operator. */
  role?: 'operator' | 'agent' | null;
  /** `proxy.status.intercept_armed`. */
  armed?: boolean;
  /** A held set/unset reply. */
  hold?: Promise<unknown>;
  /** Leave `proxy.system.status` out of the catalogue (a core without the read). */
  noStatusTool?: boolean;
}

/**
 * The memory bus with the compact `system_proxy` on `proxy.status`, the full object on
 * `proxy.system.status`, and set/unset answered with POINTS_AT_US; every `proxy.system.*` call is recorded.
 */
function mountWith(opts: MountOpts) {
  const mem = memoryBus({ extraTools: opts.noStatusTool ? SYS_TOOLS.filter((t) => t !== 'proxy.system.status') : SYS_TOOLS });
  const calls: string[] = [];
  const ctl = { status: opts.status as unknown, full: (opts.full ?? (opts.status ? { ...(opts.status as object), guidance: null, remedy: null } : null)) as unknown, polls: 0 };
  const bus: BusClient = {
    ...mem,
    role: () => (opts.role === undefined ? 'operator' : opts.role),
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      if (tool === 'proxy.system.status') {
        calls.push(tool);
        return ctl.full as T;
      }
      if (tool === 'proxy.system.set' || tool === 'proxy.system.unset') {
        calls.push(tool);
        if (opts.hold) return (await opts.hold) as T;
        return POINTS_AT_US as T;
      }
      const result = await mem.call<T>(tool, args);
      if (tool === 'proxy.status') {
        ctl.polls += 1;
        const r = result as Record<string, unknown>;
        return { ...r, system_proxy: ctl.status, ...(opts.armed ? { intercept_armed: true } : {}) } as T;
      }
      return result;
    },
  };
  const app = createAppStore(bus);
  render(() => (
    <AppProvider store={app}>
      <Toolbar />
    </AppProvider>
  ));
  return { bus, app, calls, ctl };
}

const mount = (status: unknown, full?: unknown) => mountWith({ status, full });

let bus: BusClient | null = null;
/** jsdom has no `navigator.clipboard`; a test that stubs one gets it removed again here. */
const hadClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
  if (hadClipboard) Object.defineProperty(navigator, 'clipboard', hadClipboard);
  else delete (navigator as { clipboard?: unknown }).clipboard;
});

const pill = () => screen.getByRole('button', { name: /^aitmproxy · / });
const copyEnv = () => screen.queryByRole('menuitem', { name: 'Copy env line' }) as HTMLButtonElement | null;

describe('Toolbar system-proxy pill', () => {
  it('is a menu button whose text carries the D12 word after the address for an `other` status', async () => {
    let app;
    ({ bus, app } = mount(OTHER));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('other'));

    const b = pill();
    expect(b.tagName).toBe('BUTTON');
    expect(b.getAttribute('aria-haspopup')).toBe('menu');
    expect(b.getAttribute('aria-expanded')).toBe('false');
    expect(b.textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy → 127.0.0.1:9090');
  });

  it('opens a menu with the unchecked "Set as system proxy" item and the disabled detail line; selecting calls proxy.system.set', async () => {
    let app, calls: string[];
    ({ bus, app, calls } = mount(OTHER));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('other'));

    fireEvent.click(pill());
    expect(pill().getAttribute('aria-expanded')).toBe('true');
    const menu = screen.getByRole('menu', { name: 'System proxy' });
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.getAttribute('aria-checked')).toBe('false');
    expect(item.disabled).toBe(false);
    const detail = screen.getByRole('menuitem', { name: OTHER.detail }) as HTMLButtonElement;
    expect(detail.disabled).toBe(true);
    expect(copyEnv()).toBeNull();
    expect(menu.querySelectorAll('[role^="menuitem"]').length).toBe(2);
    // Opening asked the core for the full status (D15 amendment); nothing else was sent.
    await waitFor(() => expect(calls).toEqual(['proxy.system.status']));
    expect(copyEnv()).toBeNull(); // the full status of an `other` host has no guidance

    fireEvent.click(item);
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.set']));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('points_at_us'));
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy → us');
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('checked when the system proxy points at us; selecting calls proxy.system.unset', async () => {
    let app, calls: string[];
    ({ bus, app, calls } = mount(POINTS_AT_US));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('points_at_us'));

    fireEvent.click(pill());
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' });
    expect(item.getAttribute('aria-checked')).toBe('true');
    fireEvent.click(item);
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.unset']));
  });

  it('unsupported: no pill word, the item is disabled with its title, and "Copy env line" appears only once the menu-open read brings `guidance`, then copies it', async () => {
    let app, calls: string[];
    ({ bus, app, calls } = mount(UNSUPPORTED, UNSUPPORTED_FULL));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('unsupported'));
    expect(app.proxy.systemProxy?.guidance).toBeNull(); // the compact poll carries none
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080');

    const written: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t: string) => void written.push(t) }, configurable: true });

    fireEvent.click(pill());
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(item.title).toBe('system proxy not available here');
    expect(copyEnv()).toBeNull(); // rendered from the compact status first…
    await waitFor(() => expect(copyEnv()).not.toBeNull()); // …and the item lands with the full one
    expect(calls).toEqual(['proxy.system.status']);
    expect(app.proxy.systemProxy?.guidance).toBe(ENV_LINE);
    expect(copyEnv()!.title).toBe(ENV_LINE); // the operator sees the line before copying it

    fireEvent.click(copyEnv()!);
    await waitFor(() => expect(written).toEqual([ENV_LINE]));
    await waitFor(() => expect(app.toast()).toEqual({ text: 'Copied env line', kind: 'info' }));
  });

  it('a failed copy goes to the notice toast as an error (D15), not to the console', async () => {
    let app;
    ({ bus, app } = mount(UNSUPPORTED, UNSUPPORTED_FULL));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('unsupported'));
    // No clipboard stub: jsdom has neither `navigator.clipboard` nor `execCommand`, so `copyText` fails.

    fireEvent.click(pill());
    await waitFor(() => expect(copyEnv()).not.toBeNull());
    fireEvent.click(copyEnv()!);

    await waitFor(() => expect(app.toast()).toEqual({ text: 'copy env line failed', kind: 'error' }));
  });

  it('the kept guidance survives the next 2 s poll: a reopened menu offers "Copy env line" at once', async () => {
    let app, calls: string[], ctl: { polls: number };
    ({ bus, app, calls, ctl } = mount(UNSUPPORTED, UNSUPPORTED_FULL));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('unsupported'));
    fireEvent.click(pill());
    await waitFor(() => expect(copyEnv()).not.toBeNull());
    fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());

    // A real poll of the store's own reader (the compact object, no guidance) runs within ~2 s; it keeps the line.
    const before = ctl.polls;
    await waitFor(() => expect(ctl.polls).toBeGreaterThan(before), { timeout: 4000 });
    expect(app.proxy.systemProxy?.guidance).toBe(ENV_LINE);

    fireEvent.click(pill());
    expect(copyEnv()).not.toBeNull(); // synchronously, from the kept field
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.status']));
  }, 8000);

  it('a core without proxy.system.status: the menu opens on the compact status and sends nothing', async () => {
    let app, calls: string[];
    ({ bus, app, calls } = mountWith({ status: UNSUPPORTED, full: UNSUPPORTED_FULL, noStatusTool: true }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('unsupported'));

    fireEvent.click(pill());
    expect(screen.getByRole('menu', { name: 'System proxy' })).toBeTruthy();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toEqual([]);
    expect(copyEnv()).toBeNull();
  });
});

// ---- tester additions (stage 5): the in-flight word and title, the operator gate, word order, the empty detail row ----

describe('Toolbar system-proxy pill (tester)', () => {
  it('shows · sys-proxy setting… and the disabled in-flight item until the reply, then the new word', async () => {
    let release!: (v: unknown) => void;
    const hold = new Promise<unknown>((r) => (release = r));
    let app, calls: string[], ctl: { status: unknown };
    ({ bus, app, calls, ctl } = mountWith({ status: OFF, hold }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('off'));
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy off');

    fireEvent.click(pill());
    fireEvent.click(screen.getByRole('menuitemradio', { name: 'Set as system proxy' }));
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.set']));

    // In flight: the pill word is the D12 working row, and the reopened menu's item is disabled with its title.
    await waitFor(() => expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy setting…'));
    expect(app.proxy.systemProxySetting).toBe(true);
    fireEvent.click(pill());
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(item.title).toBe('setting system proxy…');
    fireEvent.click(item); // a disabled item sends nothing
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.set', 'proxy.system.status']));

    ctl.status = POINTS_AT_US; // the core's next poll agrees with the reply
    release(POINTS_AT_US);
    await waitFor(() => expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy → us'));
    expect(app.proxy.systemProxySetting).toBe(false);
  });

  it('on a non-operator connection the item is disabled with the operator-token title and sends no change', async () => {
    let app, calls: string[];
    ({ bus, app, calls } = mountWith({ status: OFF, role: 'agent' }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('off'));

    fireEvent.click(pill());
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(item.title).toBe('connect with the operator token to change the system proxy');
    expect(item.getAttribute('aria-checked')).toBe('false');
    fireEvent.click(item);
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toEqual(['proxy.system.status']); // the read on open, never a set
    // The word itself does not depend on the role.
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy off');
  });

  it('puts the pill word after the address and before · intercept armed (D14/D15 order)', async () => {
    let app;
    ({ bus, app } = mountWith({ status: OTHER, armed: true }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('other'));
    await waitFor(() => expect(app.proxy.armed).toBe(true));

    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy → 127.0.0.1:9090 · intercept armed');
  });

  it('needs_privilege: the pill says needs admin; the item is disabled, and its title is the remedy the menu-open read fetched', async () => {
    let app;
    ({ bus, app } = mount(NEEDS_ADMIN, NEEDS_ADMIN_FULL));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('needs_privilege'));
    expect(app.proxy.systemProxy?.remedy).toBeNull(); // not on the compact object
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy needs admin');

    fireEvent.click(pill());
    const item = () => screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item().disabled).toBe(true);
    expect(item().title).toBe(''); // nothing to say until the full status lands…
    await waitFor(() => expect(item().title).toBe(REMEDY)); // …then the D3 sentence
    expect(copyEnv()).toBeNull();
  });

  it('an empty detail suppresses the detail row: the menu is the checkbox alone', async () => {
    let app;
    ({ bus, app } = mountWith({ status: { ...OFF, detail: '' } }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('off'));

    fireEvent.click(pill());
    const menu = screen.getByRole('menu', { name: 'System proxy' });
    expect(menu.querySelectorAll('[role^="menuitem"]').length).toBe(1);
    expect(screen.getByRole('menuitemradio', { name: 'Set as system proxy' })).toBeTruthy();
  });

  it('a core older than the field: no word, the menu still opens, its only item is disabled without a title', async () => {
    let app;
    ({ bus, app } = mountWith({ status: undefined, full: null, noStatusTool: true }));
    // The bootstrap read has landed once the address is on the store; system_proxy is absent from it.
    await waitFor(() => expect(app.proxy.address).toBe('127.0.0.1:8080'));
    expect(app.proxy.systemProxy).toBeNull();
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080');

    fireEvent.click(pill());
    const menu = screen.getByRole('menu', { name: 'System proxy' });
    expect(menu.querySelectorAll('[role^="menuitem"]').length).toBe(1);
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(item.title).toBe('');
  });

  it('a refused set does not leave the pill stuck on setting…: the word returns and the error is on the toast', async () => {
    let app, calls: string[];
    const hold = Promise.reject(new Error('a system-proxy change is already in flight'));
    hold.catch(() => {}); // the store consumes it; keep node quiet about the early rejection
    ({ bus, app, calls } = mountWith({ status: OFF, hold }));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('off'));

    fireEvent.click(pill());
    fireEvent.click(screen.getByRole('menuitemradio', { name: 'Set as system proxy' }));
    await waitFor(() => expect(calls).toEqual(['proxy.system.status', 'proxy.system.set']));

    await waitFor(() => expect(app.toast()).toEqual({ text: 'system proxy: a system-proxy change is already in flight', kind: 'error' }));
    expect(app.proxy.systemProxySetting).toBe(false);
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080 · sys-proxy off');
  });
});
