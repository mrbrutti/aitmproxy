// The store's half of the system-proxy pill (spec D6 `proxy.status.system_proxy`, D15 web; plan
// Task 21): both `proxy.status` readers parse `system_proxy` into `app.proxy.systemProxy`, and the
// two actions call `proxy.system.set {}` / `proxy.system.unset`, hold `systemProxySetting` while the
// call is in flight, store the reply's status, and route a refusal through the `guarded` notice.
//
// The bus is `bridgeBus.testkit.ts`'s request/reply double of the live bridge frames, wrapped here so
// its `proxy.status` reply carries a `system_proxy` sub-object and it answers the two verbs. It is a
// unit harness for the store's parsing and nothing more: never frontend evidence (plan rule 3).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BusError } from '~/bus/types';
import { createAppStore } from './app';
import { bridgeBus, gate, tick, type TestBus } from './bridgeBus.testkit';

/** The compact D6 sub-object `proxy.status` carries, as the core sends it for each state. */
const POINTS_AT_US = { state: 'points_at_us', host: null, port: null, managed_by_us: true, setting: false, supported: true, detail: 'HTTP and HTTPS → 127.0.0.1:8080 (this core)' };
const OTHER = { state: 'other', host: '127.0.0.1', port: 9090, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS → 127.0.0.1:9090 (not this core)' };
const OFF = { state: 'off', host: null, port: null, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS off' };

interface SysCtl {
  /** What `proxy.status` reports as `system_proxy`; `undefined` leaves the field out (a core older than it). */
  status: unknown;
  /** The reply to `proxy.system.set` / `proxy.system.unset` (the full D6 status object plus `changed`/`commands`). */
  reply: unknown;
  /** The reply to `proxy.system.status` (the full D6 object, `guidance`/`remedy` included). */
  full: unknown;
  /** Held until released: the verb's reply is delayed, so the in-flight flag can be observed. */
  hold: Promise<void> | null;
  /** When set, the verb rejects with this `BusError` message (the core's refusal). */
  fail: string | null;
  /** Every `proxy.system.*` call, in order, with its arguments. */
  calls: { tool: string; args: Record<string, unknown> }[];
}

type SysBus = TestBus & { sys: SysCtl };

/**
 * The bridge-shaped bus with `system_proxy` on `proxy.status` and the two mutating verbs answered.
 * `{ absent: true }` is a core older than the field: `proxy.status` carries no `system_proxy` at all.
 */
function sysproxyBus(opts: { status?: unknown; absent?: boolean; statusTool?: boolean } = {}): SysBus {
  const bus = bridgeBus() as SysBus;
  const status = opts.absent ? undefined : (opts.status ?? POINTS_AT_US);
  const sys: SysCtl = { status, reply: { ...POINTS_AT_US, changed: true, commands: [] }, full: { ...POINTS_AT_US, guidance: null, remedy: null }, hold: null, fail: null, calls: [] };
  const inner = bus.call.bind(bus);
  bus.call = async <T,>(tool: string, args: Record<string, unknown> = {}): Promise<T> => {
    if (tool === 'proxy.status') {
      const s = (await inner<Record<string, unknown>>(tool, args)) ?? {};
      return (sys.status === undefined ? s : { ...s, system_proxy: sys.status }) as T;
    }
    if (tool === 'proxy.system.set' || tool === 'proxy.system.unset' || tool === 'proxy.system.status') {
      sys.calls.push({ tool, args });
      await new Promise((r) => setTimeout(r, 5)); // the loopback round trip, like the testkit's
      if (sys.hold) await sys.hold;
      if (sys.fail) throw new BusError(sys.fail);
      return (tool === 'proxy.system.status' ? sys.full : sys.reply) as T;
    }
    return inner<T>(tool, args);
  };
  // The three verbs are in the catalogue (a core with the feature); `statusTool: false` is a core without the read.
  const innerTools = bus.tools.bind(bus);
  bus.tools = async () => [
    ...(await innerTools()),
    ...['proxy.system.set', 'proxy.system.unset', ...(opts.statusTool === false ? [] : ['proxy.system.status'])].map((name) => ({ name, description: `${name} (test bus)`, inputSchema: { type: 'object' as const, properties: {} } })),
  ];
  bus.sys = sys;
  return bus;
}

let open: TestBus[] = [];
const start = (bus: SysBus = sysproxyBus()) => {
  open.push(bus);
  return { bus, app: createAppStore(bus) };
};

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — system proxy status from proxy.status', () => {
  it('starts with no status and no change in flight', () => {
    const { app } = start();

    expect(app.proxy.systemProxy).toBeNull();
    expect(app.proxy.systemProxySetting).toBe(false);
  });

  it('the connect-time read parses system_proxy points_at_us into app.proxy.systemProxy', async () => {
    const { app } = start();

    await tick(200); // bootstrap: tools/list, side data (one proxy.status), first flow.list

    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    expect(app.proxy.systemProxy).toEqual({
      state: 'points_at_us',
      host: null,
      port: null,
      managed_by_us: true,
      setting: false,
      supported: true,
      detail: 'HTTP and HTTPS → 127.0.0.1:8080 (this core)',
      guidance: null,
      remedy: null,
    });
  });

  it('the 2 s status poll follows the core: another tool takes the system proxy over', async () => {
    const { bus, app } = start();
    await tick(200);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    const statuses = bus.count('proxy.status');

    bus.sys.status = OTHER;
    await tick(2500); // one status poll interval (~2 s) plus a call's latency

    expect(bus.count('proxy.status')).toBeGreaterThan(statuses);
    expect(app.proxy.systemProxy?.state).toBe('other');
    expect(app.proxy.systemProxy?.host).toBe('127.0.0.1');
    expect(app.proxy.systemProxy?.port).toBe(9090);
    expect(app.proxy.systemProxy?.managed_by_us).toBe(false);
  });

  it('a core older than the field leaves systemProxy null, and the key stays on the store', async () => {
    const { app } = start(sysproxyBus({ absent: true }));

    await tick(2500); // bootstrap read and at least one poll, neither carrying system_proxy

    expect(app.proxy.systemProxy).toBeNull();
    expect('systemProxy' in app.proxy).toBe(true);
  });
});

describe('app store — setSystemProxy / unsetSystemProxy', () => {
  it('setSystemProxy calls proxy.system.set {} and holds systemProxySetting until the reply, then stores it', async () => {
    const { bus, app } = start(sysproxyBus({ status: OFF }));
    await tick(200);
    expect(app.proxy.systemProxy?.state).toBe('off');
    const held = gate();
    bus.sys.hold = held.promise;
    bus.sys.reply = { ...POINTS_AT_US, changed: true, commands: ['networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080'] };

    const done = app.setSystemProxy();
    await tick(50); // past the call's latency: it is in flight, waiting on the core

    expect(app.proxy.systemProxySetting).toBe(true);
    expect(bus.sys.calls).toEqual([{ tool: 'proxy.system.set', args: {} }]);
    expect(app.proxy.systemProxy?.state).toBe('off'); // nothing is stored before the reply

    held.release();
    await tick(10); // the released reply settles on the fake clock
    await done;

    expect(app.proxy.systemProxySetting).toBe(false);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    expect(app.proxy.systemProxy?.managed_by_us).toBe(true);
    expect(app.proxy.systemProxy?.detail).toBe('HTTP and HTTPS → 127.0.0.1:8080 (this core)');
    expect(app.toast()).toBeNull();
  });

  it('unsetSystemProxy calls proxy.system.unset and stores the restored status', async () => {
    const { bus, app } = start();
    await tick(200);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    bus.sys.reply = { ...OTHER, changed: true, commands: [], restored: ['Wi-Fi'], left_alone: [] };

    const done = app.unsetSystemProxy();
    await tick(50); // the call's few ms of fake-clock latency
    await done;

    expect(bus.sys.calls).toEqual([{ tool: 'proxy.system.unset', args: {} }]);
    expect(app.proxy.systemProxySetting).toBe(false);
    expect(app.proxy.systemProxy?.state).toBe('other');
    expect(app.proxy.systemProxy?.host).toBe('127.0.0.1');
    expect(app.proxy.systemProxy?.port).toBe(9090);
    expect(app.toast()).toBeNull();
  });

  it('a refused set clears systemProxySetting, keeps the last status and reaches the toast as an error', async () => {
    const { bus, app } = start(sysproxyBus({ status: OFF }));
    await tick(200);
    bus.sys.fail = 'a system-proxy change is already in flight';

    const pending = app.setSystemProxy();
    await tick(2); // inside the call's latency: the refusal has not arrived yet
    expect(app.proxy.systemProxySetting).toBe(true); // flagged before the reply
    await tick(50);
    const result = await pending;

    expect(result).toBeNull(); // `guarded` swallows the error into the notice
    expect(app.proxy.systemProxySetting).toBe(false);
    expect(app.proxy.systemProxy?.state).toBe('off');
    expect(app.toast()).toEqual({ text: 'system proxy: a system-proxy change is already in flight', kind: 'error' });
  });

  it('a refused unset also clears the flag and reports through the same notice', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.sys.fail = 'proxy.system.unset: not serving';

    const done = app.unsetSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxySetting).toBe(false);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    expect(app.toast()?.kind).toBe('error');
    expect(app.toast()?.text).toBe('system proxy: proxy.system.unset: not serving');
  });
});

// ---- tester additions (stage 5): the two flags are distinct, a failed poll keeps the last status, malformed replies ----

describe('app store — system proxy edge cases (tester)', () => {
  it('another client’s in-flight set arrives as systemProxy.setting, and our own flag stays false', async () => {
    const { bus, app } = start(sysproxyBus({ status: { ...OFF, setting: true } }));

    await tick(200);

    expect(app.proxy.systemProxy?.setting).toBe(true);
    expect(app.proxy.systemProxy?.state).toBe('off');
    expect(app.proxy.systemProxySetting).toBe(false);
    expect(bus.sys.calls).toEqual([]); // nothing of ours was sent
  });

  it('a failed proxy.status poll keeps the last system-proxy status (the catch path does not wipe it)', async () => {
    const { bus, app } = start(sysproxyBus({ status: OTHER }));
    await tick(200);
    expect(app.proxy.systemProxy?.state).toBe('other');
    const statuses = bus.count('proxy.status');

    bus.ctl.failStatus = 1;
    await tick(2500);

    expect(bus.count('proxy.status')).toBeGreaterThan(statuses); // the poll ran and threw
    expect(app.proxy.systemProxy?.state).toBe('other');
    expect(app.proxy.systemProxy?.port).toBe(9090);
  });

  it('a system_proxy that is not an object (a string, an array) leaves the store at null', async () => {
    const { bus, app } = start(sysproxyBus({ status: 'points_at_us' }));
    await tick(200);
    expect(app.proxy.systemProxy).toBeNull();

    bus.sys.status = [POINTS_AT_US];
    await tick(2500);
    expect(app.proxy.systemProxy).toBeNull();

    bus.sys.status = POINTS_AT_US; // and recovers on the next well-formed poll
    await tick(2500);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
  });

  it('a state string the client does not know is stored as unknown (no word, no crash), detail kept', async () => {
    const { app } = start(sysproxyBus({ status: { ...OFF, state: 'teleported', detail: 'from a newer core' } }));

    await tick(200);

    expect(app.proxy.systemProxy?.state).toBe('unknown');
    expect(app.proxy.systemProxy?.detail).toBe('from a newer core');
  });

  it('a set whose reply is not a status object clears the flag, stores null, raises no error, and the next poll refills', async () => {
    const { bus, app } = start(sysproxyBus({ status: OFF }));
    await tick(200);
    bus.sys.reply = 'ok';
    bus.sys.status = POINTS_AT_US; // what the core will say on the next poll

    const done = app.setSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxySetting).toBe(false);
    expect(app.proxy.systemProxy).toBeNull();
    expect(app.toast()).toBeNull();

    await tick(2500);
    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
  });

  it('a set reply with a newer state string is stored as unknown rather than dropped', async () => {
    const { bus, app } = start(sysproxyBus({ status: OFF }));
    await tick(200);
    bus.sys.reply = { ...POINTS_AT_US, state: 'half_set', changed: true, commands: [] };

    const done = app.setSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxy?.state).toBe('unknown');
    expect(app.proxy.systemProxy?.detail).toBe(POINTS_AT_US.detail);
    expect(app.proxy.systemProxySetting).toBe(false);
  });

  it('the refusal toast carries the core’s message verbatim after the "system proxy: " prefix (an agent-token refusal)', async () => {
    const { bus, app } = start(sysproxyBus({ status: OFF }));
    await tick(200);
    bus.sys.fail = 'proxy.system.set: operator only';

    const done = app.setSystemProxy();
    await tick(50);
    await done;

    expect(app.toast()).toEqual({ text: 'system proxy: proxy.system.set: operator only', kind: 'error' });
    // An error toast lives 6 s, then clears; the flag was already down.
    await tick(6100);
    expect(app.toast()).toBeNull();
    expect(app.proxy.systemProxySetting).toBe(false);
  });
});

// ---- F-web (spec D15 amendment, 2026-11-01): the menu-open full read and what the poll keeps ----

const UNSUPPORTED = { state: 'unsupported', host: null, port: null, managed_by_us: false, setting: false, supported: false, detail: 'no system proxy mechanism on this host' };
const ENV_LINE = 'export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080';
const NEEDS_ADMIN = { state: 'needs_privilege', host: null, port: null, managed_by_us: false, setting: false, supported: true, detail: 'HTTP and HTTPS off' };
const REMEDY = 'The system proxy needs an administrator; run the core as one.';

describe('app store — refreshSystemProxy (the full read on menu open)', () => {
  it('calls proxy.system.status and stores the full object, guidance included', async () => {
    const { bus, app } = start(sysproxyBus({ status: UNSUPPORTED }));
    await tick(200);
    expect(app.proxy.systemProxy?.state).toBe('unsupported');
    expect(app.proxy.systemProxy?.guidance).toBeNull(); // the compact poll has none
    bus.sys.full = { ...UNSUPPORTED, guidance: ENV_LINE, remedy: null, mechanism: 'none', services: [] };

    const done = app.refreshSystemProxy();
    await tick(50);
    await done;

    expect(bus.sys.calls).toEqual([{ tool: 'proxy.system.status', args: {} }]);
    expect(app.proxy.systemProxy?.guidance).toBe(ENV_LINE);
    expect(app.proxy.systemProxy?.state).toBe('unsupported');
    expect(app.proxy.systemProxySetting).toBe(false); // a read is not a change
    expect(app.toast()).toBeNull();
  });

  it('the 2 s poll after it keeps guidance and remedy, and still follows the compact fields', async () => {
    const { bus, app } = start(sysproxyBus({ status: NEEDS_ADMIN }));
    await tick(200);
    bus.sys.full = { ...NEEDS_ADMIN, guidance: null, remedy: REMEDY };
    const done = app.refreshSystemProxy();
    await tick(50);
    await done;
    expect(app.proxy.systemProxy?.remedy).toBe(REMEDY);
    const statuses = bus.count('proxy.status');

    bus.sys.status = { ...NEEDS_ADMIN, detail: 'HTTP off, HTTPS off' };
    await tick(2500);

    expect(bus.count('proxy.status')).toBeGreaterThan(statuses);
    expect(app.proxy.systemProxy?.remedy).toBe(REMEDY);
    expect(app.proxy.systemProxy?.detail).toBe('HTTP off, HTTPS off');
    expect(app.proxy.systemProxy?.guidance).toBeNull();
  });

  it('a set/unset reply replaces the kept guidance/remedy (the full object is authoritative)', async () => {
    const { bus, app } = start(sysproxyBus({ status: NEEDS_ADMIN }));
    await tick(200);
    bus.sys.full = { ...NEEDS_ADMIN, remedy: REMEDY };
    let done = app.refreshSystemProxy();
    await tick(50);
    await done;
    expect(app.proxy.systemProxy?.remedy).toBe(REMEDY);
    bus.sys.reply = { ...POINTS_AT_US, guidance: null, remedy: null, changed: true, commands: [] };

    done = app.setSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxy?.state).toBe('points_at_us');
    expect(app.proxy.systemProxy?.remedy).toBeNull();
  });

  it('does nothing on a core that does not offer proxy.system.status', async () => {
    const { bus, app } = start(sysproxyBus({ status: UNSUPPORTED, statusTool: false }));
    await tick(200);

    const done = app.refreshSystemProxy();
    await tick(50);
    await done;

    expect(bus.sys.calls).toEqual([]);
    expect(app.proxy.systemProxy?.state).toBe('unsupported');
    expect(app.proxy.systemProxy?.guidance).toBeNull();
    expect(app.toast()).toBeNull();
  });

  it('a refused read keeps the compact status and reaches the toast as an error', async () => {
    const { bus, app } = start(sysproxyBus({ status: UNSUPPORTED }));
    await tick(200);
    bus.sys.fail = 'proxy.system.status: bus closed (1006)';

    const done = app.refreshSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxy?.state).toBe('unsupported');
    expect(app.toast()).toEqual({ text: 'system proxy: proxy.system.status: bus closed (1006)', kind: 'error' });
  });

  it('a reply that is not a status object keeps the compact status rather than wiping it', async () => {
    const { bus, app } = start(sysproxyBus({ status: UNSUPPORTED }));
    await tick(200);
    bus.sys.full = 'ok';

    const done = app.refreshSystemProxy();
    await tick(50);
    await done;

    expect(app.proxy.systemProxy?.state).toBe('unsupported');
    expect(app.toast()).toBeNull();
  });
});
