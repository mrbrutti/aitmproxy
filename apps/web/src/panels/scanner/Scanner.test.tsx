// T8 Task 14 (D-T8.1, D-T8.2, D-T8.10): the Scanner shell — header, the four-tab strip with its
// live counts, the persistent job strip and the keyboard contract, plus the two umbrella states
// (reconnecting disables every control; the surface outlives the panel so polling continues while
// it is unmounted). The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never
// evidence (fixtures/README.md): a green run here says the shell wires the views and the store, not
// that any scan ran.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import { scanStore, type ScanStore } from './store';
import { Scanner } from './Scanner';
import css from './scanner.module.css';

const JOB = 'scan-1a2b3c4d';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

const built: ScanStore[] = [];

function mount(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <Scanner />
    </AppProvider>
  ));
  const tab = (name: string): HTMLButtonElement => {
    const el = r.container.querySelector(`button[role=tab][data-tab="${name}"]`);
    if (!(el instanceof HTMLButtonElement)) throw new Error(`no tab ${name}`);
    return el;
  };
  const tabCount = (name: string): string => tab(name).querySelector(`.${css.tabCount}`)?.textContent ?? '';
  const tablist = (): HTMLElement => r.getByRole('tablist', { name: 'Scan views' });
  const panel = (): HTMLElement => r.getByRole('tabpanel');
  return { ...stub, s, r, tab, tabCount, tablist, panel };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('Scanner shell', () => {
  it('renders four tabs, Profiles selected by default', async () => {
    const h = mount();
    await tick();
    const tabs = h.r.getAllByRole('tab');
    expect(tabs).toHaveLength(4);
    expect(tabs.map((t) => t.getAttribute('data-tab'))).toEqual(['profiles', 'jobs', 'sitemap', 'issues']);
    expect(tabs.map((t) => t.textContent?.replace(/\d.*/, '').trim())).toEqual(['Profiles', 'Jobs', 'Site map', 'Issues']);
    expect(h.tab('profiles').getAttribute('aria-selected')).toBe('true');
    expect(h.tab('jobs').getAttribute('aria-selected')).toBe('false');
  });

  it('ArrowRight on the tablist selects Jobs and shows the Jobs listbox', async () => {
    const h = mount();
    await tick();
    fireEvent.keyDown(h.tablist(), { key: 'ArrowRight' });
    await tick();
    expect(h.tab('jobs').getAttribute('aria-selected')).toBe('true');
    expect(h.panel().querySelector('[role=listbox][aria-label="Jobs"]')).not.toBeNull();
  });

  it('ArrowLeft from Profiles wraps to Issues', async () => {
    const h = mount();
    await tick();
    fireEvent.keyDown(h.tablist(), { key: 'ArrowLeft' });
    await tick();
    expect(h.tab('issues').getAttribute('aria-selected')).toBe('true');
    expect(h.tab('profiles').getAttribute('aria-selected')).toBe('false');
  });

  it('tab counts read the loaded fixtures', async () => {
    const h = mount();
    await tick();
    await h.s.refreshSitemap(JOB);
    await h.s.refreshIssues(JOB);
    await tick();
    expect(h.tabCount('profiles')).toBe('7');
    expect(h.tabCount('jobs')).toBe('1 live / 2');
    expect(h.tabCount('sitemap')).toBe('1');
    expect(h.tabCount('issues')).toBe('2');
  });

  it('no_duplicate_bootstrap_reads (PA11): the shell and the views join the store’s reads instead of repeating them', async () => {
    const h = mount();
    await tick();
    // Profiles is the default tab: the shell’s mount effect and the Profiles view both want the list
    // and the catalogue, and the store’s own bootstrap already asked. One verb each.
    expect(h.count('scan.profile.list')).toBe(1);
    expect(h.count('scan.checks')).toBe(1);
    expect(h.count('scan.list')).toBe(1);
    expect(h.count('l4.scope.list')).toBe(1);

    for (let i = 0; i < 2; i++) {
      fireEvent.click(h.tab('jobs'));
      await tick();
      fireEvent.click(h.tab('profiles'));
      await tick();
    }
    expect(h.count('scan.profile.list')).toBe(1);
    expect(h.count('scan.checks')).toBe(1);
    expect(h.count('l4.scope.list')).toBe(1);
  });

  it('state_survives_unmount: tab, selection and polling outlive the panel', async () => {
    const h = mount();
    await tick();
    // Open Issues and select an issue, the way an operator does.
    fireEvent.click(h.tab('issues'));
    await tick();
    const option = h.r.container.querySelector('[role=option][data-issue="issue-4c3b2a19"]');
    expect(option).not.toBeNull();
    fireEvent.click(option!);
    await tick();
    expect(option!.getAttribute('aria-selected')).toBe('true');

    // Unmount the panel; the store (and its polling) stays. A live job is polled while unmounted.
    const before = h.count('scan.status');
    cleanup();
    await tick(2100);
    expect(h.count('scan.status') - before).toBeGreaterThanOrEqual(2);

    // Re-open on the same app: the tab and the selected issue are exactly where they were left.
    const r2 = render(() => (
      <AppProvider store={h.app}>
        <Scanner />
      </AppProvider>
    ));
    await tick();
    expect(r2.container.querySelector('button[role=tab][data-tab="issues"]')!.getAttribute('aria-selected')).toBe('true');
    const option2 = r2.container.querySelector('[role=option][data-issue="issue-4c3b2a19"]');
    expect(option2).not.toBeNull();
    expect(option2!.getAttribute('aria-selected')).toBe('true');
  });

  it('reconnecting_note: a note appears and every button in the section is disabled', async () => {
    const h = mount();
    await tick();
    fireEvent.click(h.tab('jobs'));
    await tick();
    h.setBusState('reconnecting');
    await tick();
    const section = h.r.getByRole('region', { name: 'Scanner' });
    expect(section.querySelector(`.${css.reconnectNote}`)).not.toBeNull();
    const buttons = Array.from(section.querySelectorAll('button')) as HTMLButtonElement[];
    expect(buttons.length).toBeGreaterThan(0);
    expect(buttons.every((b) => b.disabled)).toBe(true);
  });
});
