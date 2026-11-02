// T8 Task 14 (W-1, D-T8.1): the ScanPanel three-way switch on what the core offers. A core with the
// v2 `scan.start` family shows the v2 Scanner; a core with only the v1 `scan.discover` shows the
// shipped v1 panel unchanged; a core with neither says so plainly. The v1 panel's own suite
// (`panels/scan/Scan.test.tsx`) runs unchanged alongside this one.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { AppProvider } from '~/state/context';
import { stubApp } from './scanner/testkit';
import { scanStore, type ScanStore } from './scanner/store';
import { ScanPanel } from './ScanPanel';

const built: ScanStore[] = [];

function mount(tools: string[]) {
  const stub = stubApp({ tools });
  built.push(scanStore(stub.app));
  const r = render(() => (
    <AppProvider store={stub.app}>
      <ScanPanel />
    </AppProvider>
  ));
  return { ...stub, r };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('ScanPanel offered switch', () => {
  it('shows the v2 Scanner when the core offers scan.start', async () => {
    const h = mount(['scan.start', 'scan.discover']);
    await vi.advanceTimersByTimeAsync(0);
    expect(h.r.container.querySelector('section[aria-label="Scanner"]')).not.toBeNull();
    expect(h.r.container.querySelector('section[aria-label="Scan"]')).toBeNull();
  });

  it('shows the v1 Scan panel when the core offers only scan.discover', async () => {
    const h = mount(['scan.discover']);
    await vi.advanceTimersByTimeAsync(0);
    expect(h.r.container.querySelector('section[aria-label="Scan"]')).not.toBeNull();
    expect(h.r.container.querySelector('section[aria-label="Scanner"]')).toBeNull();
  });

  it('says the scanner is not offered when the core offers neither', async () => {
    const h = mount([]);
    await vi.advanceTimersByTimeAsync(0);
    expect(h.r.getByText('The scanner is not offered by this core.')).toBeTruthy();
    expect(h.r.container.querySelector('section[aria-label="Scan"]')).toBeNull();
  });
});
