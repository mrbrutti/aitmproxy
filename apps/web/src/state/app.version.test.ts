// The sidebar's version comes from the core's `proxy.status`, never from a number baked into the UI
// (it used to say 0.3.0 while the binary was 0.5.0).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { BusClient } from '~/bus/types';
import { createAppStore } from './app';
import { memoryBus, TEST_VERSION } from './bridgeBus.testkit';

/**
 * The in-memory bus with `proxy.status` rewritten, standing in for cores that report another version
 * or none. It pushes nothing (like the /bus bridge), so the poll loop is the live source.
 */
function withStatus(rewrite: (status: Record<string, unknown>) => Record<string, unknown>, address = '127.0.0.1:8082'): BusClient {
  const mem = memoryBus({ address });
  return {
    ...mem,
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      const result = await mem.call<T>(tool, args);
      return (tool === 'proxy.status' ? rewrite(result as Record<string, unknown>) : result) as T;
    },
  };
}

let open: BusClient[] = [];
const start = (bus: BusClient) => {
  open.push(bus);
  return createAppStore(bus);
};
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — core version', () => {
  it('has no version until the core reports one, then shows the core’s', async () => {
    const app = start(withStatus((s) => s));
    expect(app.proxy.version).toBe(''); // nothing, not a stale number

    await tick(200); // bootstrap: tools/list, then proxy.status

    expect(app.proxy.version).toBe(TEST_VERSION);
  });

  it('follows a changed version on the status poll (a core restarted on a new binary)', async () => {
    let reported = '1.2.3';
    const app = start(withStatus((s) => ({ ...s, version: reported })));
    await tick(200);
    expect(app.proxy.version).toBe('1.2.3');

    reported = '1.2.4';
    await tick(3000); // proxy.status is re-read about every 2 s while polling

    expect(app.proxy.version).toBe('1.2.4');
  });

  it('ignores a non-string or missing version on the status poll too, keeping the last good one', async () => {
    let reported: unknown = '1.2.3';
    let reads = 0;
    const app = start(
      withStatus((s) => {
        reads++;
        return { ...s, version: reported };
      }),
    );
    await tick(200);
    expect(app.proxy.version).toBe('1.2.3');
    expect(reads).toBe(1); // bootstrap's refreshSide

    reported = 5;
    await tick(2500); // one poll at ~2 s
    expect(reads).toBe(2); // the poll did read it…
    expect(app.proxy.version).toBe('1.2.3'); // …and ignored the number

    reported = null;
    await tick(2500);
    expect(reads).toBe(3);
    expect(app.proxy.version).toBe('1.2.3');
  });

  it.each([
    ['omits version (a core older than the field)', (s: Record<string, unknown>) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== 'version'))],
    ['sends a non-string version', (s: Record<string, unknown>) => ({ ...s, version: 5 })],
  ])('stays empty when the core %s', async (_name, rewrite) => {
    const app = start(withStatus(rewrite));

    await tick(200);

    expect(app.proxy.address).toBe('127.0.0.1:8080'); // proxy.status was read…
    expect(app.proxy.version).toBe(''); // …and no version was invented
  });
});
