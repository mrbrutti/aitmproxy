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
import { JobStrip } from './JobStrip';
import { parseScanProfile, type ScanProfile } from './model';
import { ProfilesView } from './ProfilesView';
import { SitemapView } from './SitemapView';
import { scanStore, type ScanStore } from './store';
import { stubApp } from './testkit';
import css from './scanner.module.css';
import jobsCss from './jobs.module.css';

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

  it('Jobs: nothing is selected; the empty state is the Kit sentence and Open Profiles, with no listbox, card or wells to key over', async () => {
    const h = mount(() => <JobsView />, { replies: { 'scan.list': { jobs: [] } } });
    h.s.setTab('jobs');
    await screen.findByText('No jobs yet — pick a profile and Start Scan.');
    expect(h.s.selectedJob()).toBeNull();
    expect(screen.queryByRole('listbox', { name: 'Jobs' })).toBeNull();
    expect(screen.queryByRole('region', { name: 'Selected job' })).toBeNull();
    expect(document.querySelector(`.${jobsCss.wells}`)).toBeNull();
    // The one control: Open Profiles switches the tab; the keys have nothing to move.
    fireEvent.click(screen.getByRole('button', { name: 'Open Profiles' }));
    expect(h.s.tab()).toBe('profiles');
    expect(h.s.selectedJob()).toBeNull();
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

/* ------------------------------------------------------------------ fix round: A3 and A8 in the views */

const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;
const SCOPE = { scope: [{ host: '127.0.0.1' }] };
const jobsRow = (id: string) => document.querySelector<HTMLElement>(`[role=option][data-job="${id}"]`);

describe('tester: Cancel placement (A3) and error ownership (A8) in the Jobs view', () => {
  it('rows_have_no_cancel: no row carries a `Cancel scan <job>` control; exactly two exist, the strip’s (another tab) and the card’s', async () => {
    // This harness mounts the strip and the view together on the Profiles tab (the shell never
    // does): the strip and the card are both present, so both Cancels are.
    mount(() => (
      <>
        <JobStrip />
        <JobsView />
      </>
    ));
    await waitFor(() => expect(jobsRow(JOB)).not.toBeNull());
    const rows = Array.from(document.querySelectorAll<HTMLElement>('[role=option][data-job]'));
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.querySelectorAll('button[aria-label^="Cancel scan"]')).toHaveLength(0);
      // The Kit cells: the state word and the severity words are there, Cancel is not.
      expect(row.querySelector('[data-field=state]')).not.toBeNull();
      expect(row.querySelector('[data-field=issues]')).not.toBeNull();
      expect(row.querySelector('[role=img]')).toBeNull();
    }
    const cancels = screen.getAllByRole('button', { name: `Cancel scan ${JOB}` });
    expect(cancels).toHaveLength(2);
    const strip = document.querySelector(`.${css.strip}`)!;
    const card = document.querySelector(`.${jobsCss.card}`)!;
    expect(strip.getAttribute('aria-label')).toBe('Selected job');
    expect(card.getAttribute('aria-label')).toBe('Selected job');
    expect(cancels.filter((b) => strip.contains(b))).toHaveLength(1);
    expect(cancels.filter((b) => card.contains(b))).toHaveLength(1);
  });

  it('a launch refusal never shows in the Jobs view; a refused cancel does, and a later error of another source replaces it', async () => {
    const h = mount(
      () => (
        <>
          <JobStrip />
          <JobsView />
        </>
      ),
      SCOPE,
    );
    await waitFor(() => expect(jobsRow(JOB)).not.toBeNull());

    h.fail('scan.start', 'scan: out_of_scope: host 10.0.0.9');
    await h.s.launch(standard(), 'start');
    expect(h.s.lastError()).toEqual({ source: 'launch', code: 'out_of_scope', text: 'Out of scope: host 10.0.0.9' });
    expect(document.querySelector('[data-error]')).toBeNull();
    expect(screen.queryByText('Out of scope: host 10.0.0.9')).toBeNull();

    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    await h.s.cancel(JOB);
    const line = await screen.findByText('Not found: scan-1a2b3c4d');
    expect(line.getAttribute('data-error')).toBe('cancel');
    expect(line.getAttribute('role')).toBe('alert');
    expect(document.querySelector(`.${jobsCss.card}`)!.contains(line)).toBe(true);

    // One error slot (A8): the next launch refusal belongs to the editor, so the cancel line goes.
    await h.s.launch(standard(), 'start');
    await waitFor(() => expect(document.querySelector('[data-error="cancel"]')).toBeNull());
    expect(h.s.lastError()!.source).toBe('launch');
  });
});

describe('tester: error ownership (A8) and a code-less error (W-3) in the editor', () => {
  async function mountEditor() {
    const h = mount(() => <ProfilesView />, SCOPE);
    await screen.findByLabelText('Profile name');
    return h;
  }

  it('a refused cancel reaches the toast, never the editor', async () => {
    const h = await mountEditor();
    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    const result = await h.s.cancel(JOB);
    expect(result.ok).toBe(false);
    expect(h.notice).toHaveBeenCalledWith('Not found: scan-1a2b3c4d', 'error');
    expect(h.s.lastError()).toEqual({ source: 'cancel', code: 'not_found', text: 'Not found: scan-1a2b3c4d' });
    expect(screen.queryByRole('status', { name: 'Launch result' })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('form', { name: 'Profile editor' }).textContent).not.toContain('Not found');
  });

  it('a launch rejection with no scan: code renders its text verbatim, with no Add-to-Scope affordance', async () => {
    const h = await mountEditor();
    h.fail('scan.start', 'bus closed');
    await h.s.launch(standard(), 'start');
    expect(h.s.lastError()).toEqual({ source: 'launch', code: null, text: 'bus closed' });
    const result = await screen.findByRole('status', { name: 'Launch result' });
    expect(result.textContent).toBe('bus closed');
    expect(result.querySelectorAll('button')).toHaveLength(0);
    expect(h.notice).toHaveBeenCalledWith('bus closed', 'error');
  });

  it('a failed scan.profile.get shows the profile error block with Retry; Retry reads again and binds the editor', async () => {
    const h = mount(() => <ProfilesView />, SCOPE, (stub) => stub.fail('scan.profile.get', 'scan: not_found: standard'));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Not found: standard');
    expect(screen.queryByLabelText('Profile name')).toBeNull();
    expect(h.s.lastError()).toEqual({ source: 'profile', code: 'not_found', text: 'Not found: standard' });
    // Not the launch-result block: that one renders launch/save/delete/preview only.
    expect(screen.queryByRole('status', { name: 'Launch result' })).toBeNull();

    const before = h.count('scan.profile.get');
    h.reply('scan.profile.get', fixture('scan.profile.get.json'));
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(h.count('scan.profile.get')).toBe(before + 1));
    const name = (await screen.findByLabelText('Profile name')) as HTMLInputElement;
    expect(name.value).toBe('standard');
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
