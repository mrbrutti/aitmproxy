// Stage-5 Tester additions (whole-branch T8): view-level edges. An issue with no evidence block, a
// site-map point with no `site_node`, keyboard handlers over an empty list, the W-16 states the
// view suites left out (Profiles loading/error, Issues loading), the W-17 Enter on Profiles, and
// the ConfirmInject wiring the scanner relies on (confirm fires onConfirm, the backdrop cancels,
// `busy` freezes both buttons).
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence
// (fixtures/README.md): nothing here says a scan ran. Acceptance for T8 is `scripts/scan-live.mjs`.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { JSX } from 'solid-js';

import { AppProvider } from '~/state/context';
import { ConfirmInject } from '~/panels/l4/ConfirmInject';

import { IssuesView } from './IssuesView';
import { JobsView } from './JobsView';
import { ProfilesView } from './ProfilesView';
import { SitemapView } from './SitemapView';
import { scanStore, type ScanStore } from './store';
import { stubApp } from './testkit';
import css from './scanner.module.css';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, '../../../../../crates/aitm-scan-model/fixtures');
type Raw = Record<string, unknown>;
const fixture = (name: string): unknown => JSON.parse(readFileSync(resolve(FIXTURES, name), 'utf8'));
const raw = (name: string): Raw => fixture(name) as Raw;

const JOB = 'scan-1a2b3c4d';
const XSS = 'issue-9f8e7d6c';

const built: ScanStore[] = [];

/** A stub app and its store; the view is rendered under the real provider. */
function mount(view: () => JSX.Element, opts: Parameters<typeof stubApp>[0] = {}, pre?: (stub: ReturnType<typeof stubApp>) => void) {
  const stub = stubApp(opts);
  pre?.(stub);
  const s = scanStore(stub.app);
  built.push(s);
  const r = render(() => <AppProvider store={stub.app}>{view()}</AppProvider>);
  return { ...stub, s, r };
}

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
});

/* ------------------------------------------------------------------ IssueDetail */

describe('tester: IssueDetail with the evidence block absent', () => {
  it('prints dashes for payload and matched, no flow buttons and no tables, and the issue still renders', async () => {
    const issue = raw('scan.issue.json');
    delete issue.evidence;
    const h = mount(() => <IssuesView />, { replies: { 'scan.issue': issue } });
    await h.s.refreshJobs();
    await screen.findByRole('listbox', { name: 'Issues' });
    await waitFor(() => expect(document.querySelector(`[data-issue="${XSS}"]`)).not.toBeNull());

    fireEvent.click(document.querySelector(`[data-issue="${XSS}"]`)!);
    const region = await screen.findByRole('region', { name: 'Issue detail' });
    const evidence = await waitFor(() => {
      const el = region.querySelector<HTMLElement>('section[aria-label="Evidence"]');
      expect(el).not.toBeNull();
      return el!;
    });

    expect(within(region).getByRole('heading', { level: 2 }).textContent).toBe('Reflected cross-site scripting');
    expect(evidence.querySelector('[data-field="payload"]')).toBeNull();
    expect(evidence.querySelector('[data-field="matched"]')).toBeNull();
    expect(evidence.querySelectorAll(`.${css.dash}`).length).toBe(2);
    expect(within(evidence).queryAllByRole('button', { name: /^Open flow / })).toHaveLength(0);
    expect(within(evidence).queryByRole('table', { name: 'Timing' })).toBeNull();
    expect(within(evidence).queryByRole('table', { name: 'Diff' })).toBeNull();
    expect(evidence.querySelector('[aria-label="L4 evidence"]')).toBeNull();
    // The cross-links outside the evidence block are untouched by its absence.
    expect(within(region).getByRole('button', { name: 'Open PoC poc-3b1c' })).toBeTruthy();
  });
});

/* ------------------------------------------------------------------ SitemapView */

describe('tester: SitemapView with a point that has no site_node', () => {
  it('lists the orphan point under "all points" and hides it once a node is selected', async () => {
    const page = raw('scan.sitemap.json');
    const points = page.points as Raw[];
    page.points = [...points, { ...points[0]!, id: 'point-orphan', site_node: null, example: 'orphan-example' }];
    page.next_cursor = null;
    const h = mount(() => <SitemapView />, { replies: { 'scan.sitemap': page } });
    await h.s.refreshJobs();

    const rows = () => Array.from(screen.getByRole('list', { name: 'Insertion points' }).querySelectorAll<HTMLElement>('li[data-point]'));
    await waitFor(() => expect(rows().map((r) => r.getAttribute('data-point'))).toEqual(['point-json-1', 'point-cookie-1', 'point-orphan']));
    expect(rows()[2]!.querySelector('[data-field=example]')!.textContent).toBe('orphan-example');

    fireEvent.click(screen.getByRole('listbox', { name: 'Site map' }).querySelector('[data-node="node-1"]')!);
    await waitFor(() => expect(rows().map((r) => r.getAttribute('data-point'))).toEqual(['point-json-1', 'point-cookie-1']));
  });
});

/* ------------------------------------------------------------------ keyboard over empty lists */

describe('tester: keyboard handlers over an empty list (W-17)', () => {
  const KEYS = ['ArrowDown', 'ArrowUp', 'Home', 'End'] as const;

  it('Issues: nothing is selected, nothing throws, Enter is a no-op without a detail', async () => {
    const h = mount(() => <IssuesView />, {
      replies: { 'scan.issues': { issues: [], next_cursor: null, by_severity: {} } },
    });
    await h.s.refreshJobs();
    const list = await screen.findByRole('listbox', { name: 'Issues' });
    await screen.findByText('No issues for this job');
    list.focus();
    for (const key of KEYS) {
      fireEvent.keyDown(list, { key });
      expect(h.s.selectedIssue()).toBeNull();
    }
    expect(list.getAttribute('aria-activedescendant')).toBeNull();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(screen.queryByRole('region', { name: 'Issue detail' })).toBeNull();
    expect(document.activeElement).toBe(list);
  });

  it('Jobs: nothing is selected; the empty layout has no detail pane, so Enter is a no-op', async () => {
    const h = mount(() => <JobsView />, { replies: { 'scan.list': { jobs: [] } } });
    const list = await screen.findByRole('listbox', { name: 'Jobs' });
    await screen.findByText('No jobs yet: start one from Profiles');
    list.focus();
    for (const key of KEYS) {
      fireEvent.keyDown(list, { key });
      expect(h.s.selectedJob()).toBeNull();
    }
    expect(list.getAttribute('aria-activedescendant')).toBeNull();
    expect(list.closest(`.${css.layout}`)!.getAttribute('data-empty')).toBe('true');
    expect(screen.queryByRole('region', { name: 'Job detail' })).toBeNull();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(list);
  });

  it('Site map: nothing is selected and Enter moves focus to the (empty) detail', async () => {
    const h = mount(() => <SitemapView />, {
      replies: { 'scan.sitemap': { nodes: [], points: [], next_cursor: null } },
    });
    await h.s.refreshJobs();
    const list = await screen.findByRole('listbox', { name: 'Site map' });
    await screen.findByText('No site map for this job yet');
    list.focus();
    for (const key of KEYS) {
      fireEvent.keyDown(list, { key });
      expect(h.s.selectedNode()).toBeNull();
    }
    expect(list.getAttribute('aria-activedescendant')).toBeNull();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(screen.getByRole('region', { name: 'Node detail' }));
  });
});

/* ------------------------------------------------------------------ ProfilesView gaps */

describe('tester: ProfilesView states and Enter (W-16, W-17)', () => {
  it('loading: grey bars until scan.profile.list answers', async () => {
    mount(() => <ProfilesView />, { replies: { 'scan.profile.list': () => new Promise(() => {}) } });
    expect(screen.getByLabelText('Loading profiles')).toBeTruthy();
    expect(screen.queryByRole('listbox', { name: 'Profiles' })).toBeNull();
  });

  it('error: the core text in an alert with Retry that reads the list again', async () => {
    const h = mount(() => <ProfilesView />, {}, (stub) => stub.fail('scan.profile.list', 'bus closed'));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('bus closed');
    const before = h.count('scan.profile.list');
    expect(before).toBeGreaterThanOrEqual(1);

    h.reply('scan.profile.list', fixture('scan.profile.list.json'));
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(h.count('scan.profile.list')).toBe(before + 1));
    await screen.findByRole('listbox', { name: 'Profiles' });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('Enter on the Profiles listbox focuses the editor pane', async () => {
    mount(() => <ProfilesView />, { scope: [{ host: '127.0.0.1' }] });
    await screen.findByLabelText('Profile name');
    const list = screen.getByRole('listbox', { name: 'Profiles' });
    list.focus();
    fireEvent.keyDown(list, { key: 'Enter' });
    const active = document.activeElement as HTMLElement | null;
    expect(active).not.toBe(list);
    expect(active?.classList.contains(css.detail!)).toBe(true);
    expect(active?.contains(screen.getByLabelText('Profile name'))).toBe(true);
  });
});

/* ------------------------------------------------------------------ IssuesView loading */

describe('tester: IssuesView loading state (W-16)', () => {
  it('shows grey bars until the first scan.issues answers', async () => {
    const h = mount(() => <IssuesView />, { replies: { 'scan.issues': () => new Promise(() => {}) } });
    await h.s.refreshJobs();
    await screen.findByRole('listbox', { name: 'Issues' });
    await waitFor(() => expect(screen.getByLabelText('Loading issues')).toBeTruthy());
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    expect(screen.queryByText('No issues for this job')).toBeNull();
  });
});

/* ------------------------------------------------------------------ ConfirmInject */

describe('tester: ConfirmInject wiring the scanner relies on', () => {
  it('the custom-labelled primary calls onConfirm once and never onCancel', () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(() => <ConfirmInject prompt="p" confirmLabel="Start scan" onConfirm={onConfirm} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('a click on the backdrop cancels; a click inside the card does not', () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(() => <ConfirmInject prompt="p" confirmLabel="Start scan" onConfirm={onConfirm} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole('alertdialog'));
    expect(onCancel).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('presentation'));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('busy disables both buttons so a double confirm cannot send _confirm twice', () => {
    const onConfirm = vi.fn();
    render(() => <ConfirmInject prompt="p" confirmLabel="Start scan" busy onConfirm={onConfirm} onCancel={() => {}} />);
    const confirm = screen.getByRole('button', { name: 'Start scan' }) as HTMLButtonElement;
    const cancel = screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    expect(cancel.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
