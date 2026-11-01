// The toolbar's half of the system-proxy pill (spec D12 pill word, D15 web; plan Task 22): the
// listening pill is a menu button that appends the pill word after the address, and its menu
// carries the "Set as system proxy" checkbox, the `detail` line and — with `guidance` — "Copy env
// line". A component unit test over the in-memory bus: never frontend evidence (the live proof is
// plan Task 23).

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
/** No mechanism on this host: the D6 `guidance` env line is the only thing to offer. */
const UNSUPPORTED = { state: 'unsupported', host: null, port: null, managed_by_us: false, setting: false, supported: false, detail: 'no system proxy mechanism on this host', guidance: 'export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080' };

/** The memory bus with `system_proxy` on `proxy.status` and the two verbs answered; every `proxy.system.*` call is recorded. */
function mount(status: unknown) {
  const mem = memoryBus();
  const calls: string[] = [];
  const bus: BusClient = {
    ...mem,
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      if (tool === 'proxy.system.set' || tool === 'proxy.system.unset') {
        calls.push(tool);
        return POINTS_AT_US as T;
      }
      const result = await mem.call<T>(tool, args);
      if (tool === 'proxy.status') return { ...(result as Record<string, unknown>), system_proxy: status } as T;
      return result;
    },
  };
  const app = createAppStore(bus);
  render(() => (
    <AppProvider store={app}>
      <Toolbar />
    </AppProvider>
  ));
  return { bus, app, calls };
}

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

const pill = () => screen.getByRole('button', { name: /^aitmproxy · / });

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
    expect(screen.queryByRole('menuitem', { name: 'Copy env line' })).toBeNull();
    expect(menu.querySelectorAll('[role^="menuitem"]').length).toBe(2);

    fireEvent.click(item);
    await waitFor(() => expect(calls).toEqual(['proxy.system.set']));
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
    await waitFor(() => expect(calls).toEqual(['proxy.system.unset']));
  });

  it('unsupported: no pill word, the item is disabled with its title, and "Copy env line" copies `guidance`', async () => {
    let app;
    ({ bus, app } = mount(UNSUPPORTED));
    await waitFor(() => expect(app.proxy.systemProxy?.state).toBe('unsupported'));
    expect(pill().textContent).toBe('aitmproxy · listening 127.0.0.1:8080');

    const written: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t: string) => void written.push(t) }, configurable: true });

    fireEvent.click(pill());
    const item = screen.getByRole('menuitemradio', { name: 'Set as system proxy' }) as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(item.title).toBe('system proxy not available here');
    fireEvent.click(screen.getByRole('menuitem', { name: 'Copy env line' }));
    await waitFor(() => expect(written).toEqual([UNSUPPORTED.guidance]));
  });
});
