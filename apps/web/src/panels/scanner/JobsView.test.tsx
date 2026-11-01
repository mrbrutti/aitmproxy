// T8 Task 10 (D-T8.2 job strip, D-T8.6 "After a start", D-T8.7, D-T8.10): the Jobs view and the
// persistent job strip. These tests pin the rendered *values* (every counter as the fixture
// states it), the texts of D-T8.7, the monotonic rule on the screen (W-5), what a Cancel click
// sends (W-7's wire half), the listbox keyboard contract (W-17) and the four states (W-16).
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence: a green
// run here says the views render the contract, not that any scan ever ran (fixtures/README.md).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, within } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import { parseScanProfile, type ScanProfile } from './model';
import { scanStore, type ScanStore } from './store';
import { JobStrip } from './JobStrip';
import { JobsView } from './JobsView';
import css from './scanner.module.css';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

const JOB = 'scan-1a2b3c4d';
const DONE = 'scan-55667788';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/** The `scan.status` fixture as a mutable record, parsed fresh per call. */
const statusFixture = (): Record<string, unknown> => fixture('scan.status.json') as Record<string, unknown>;
const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;

const built: ScanStore[] = [];

/** A stub app, its store, and the strip + view mounted under the real provider. */
function mount(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <JobStrip />
      <JobsView />
    </AppProvider>
  ));
  const options = () => r.getAllByRole('option');
  const row = (id: string): HTMLElement => {
    const el = r.container.querySelector(`[role=option][data-job="${id}"]`);
    if (!(el instanceof HTMLElement)) throw new Error(`no row for ${id}`);
    return el;
  };
  const strip = () => r.getByRole('region', { name: 'Selected job' });
  const detail = () => r.getByRole('region', { name: 'Job detail' });
  const field = (scope: HTMLElement, name: string): string => {
    const el = scope.querySelector(`[data-field=${name}]`);
    if (!el) throw new Error(`no [data-field=${name}]`);
    return el.textContent ?? '';
  };
  return { ...stub, s, r, options, row, strip, detail, field };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('JobsView: rows and strip', () => {
  it('rows_render_from_list: one option per job with the list counters', async () => {
    const h = mount();
    await tick();
    const rows = h.options();
    expect(rows).toHaveLength(2);
    const first = rows[0]!;
    expect(first.getAttribute('data-job')).toBe(JOB);
    expect(first.getAttribute('data-state')).toBe('running');
    expect(h.field(first, 'state')).toBe('running · auditing');
    expect(h.field(first, 'probes')).toBe('418/2000');
    expect(h.field(first, 'points')).toBe('80/120');
    expect(h.field(first, 'elapsed')).toBe('0:42');
    // The row carries no control: the selected job's Cancel lives in the strip and the detail.
    expect(first.querySelector('button')).toBeNull();
    expect(rows[1]!.getAttribute('data-job')).toBe(DONE);
    expect(h.field(rows[1]!, 'state')).toBe('done');
  });

  it('strip_mirrors_selected: the strip shows the selected job and Cancel follows its state', async () => {
    const h = mount();
    await tick();
    const strip = h.strip();
    expect(strip.getAttribute('data-job')).toBe(JOB);
    expect(strip.getAttribute('data-state')).toBe('running');
    expect(h.field(strip, 'probes')).toBe('418/2000');
    expect(h.field(strip, 'points')).toBe('80/120');
    expect(h.field(strip, 'elapsed')).toBe('0:42');
    const cancel = within(strip).getByRole('button', { name: `Cancel scan ${JOB}` }) as HTMLButtonElement;
    expect(cancel.disabled).toBe(false);

    fireEvent.click(h.row(DONE));
    await tick();
    expect(h.s.selectedJob()).toBe(DONE);
    const after = h.strip();
    expect(after.getAttribute('data-job')).toBe(DONE);
    expect(h.field(after, 'state')).toBe('done');
    const doneCancel = within(after).getByRole('button', { name: `Cancel scan ${DONE}` }) as HTMLButtonElement;
    expect(doneCancel.disabled).toBe(true);
  });

  it('severity_bar_segments: one segment per non-zero level, worst first, named for a reader', async () => {
    const h = mount();
    await tick();
    const bar = h.row(JOB).querySelector('[role=img]');
    expect(bar).not.toBeNull();
    expect(bar!.getAttribute('aria-label')).toBe('issues: high 1, medium 1, low 1');
    const segs = Array.from(bar!.querySelectorAll(`.${css.barSeg}`));
    expect(segs.map((e) => e.getAttribute('data-severity'))).toEqual(['high', 'medium', 'low']);
    // The finished job has no issues: no segment, and the bar says so.
    const empty = h.row(DONE).querySelector('[role=img]');
    expect(empty!.getAttribute('data-empty')).toBe('true');
    expect(empty!.querySelectorAll(`.${css.barSeg}`)).toHaveLength(0);
  });
});

describe('JobsView: detail texts (W-14)', () => {
  it('detail_texts: stopped_reason, error, lanes and started_by render with the D-T8.7 texts', async () => {
    const h = mount();
    await tick();
    const detail = h.detail();
    expect(detail.textContent).toContain('operator · web-ui');
    expect(detail.textContent).toContain('ws: lane not available on this build');
    expect(detail.textContent).toContain('standard');
    expect(detail.textContent).toContain('http://127.0.0.1:8080');

    h.reply('scan.status', { ...statusFixture(), stopped_reason: 'budget' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.detail(), 'stopped')).toBe('stopped: probe budget reached');

    h.reply('scan.status', { ...statusFixture(), stopped_reason: 'cancelled' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.detail(), 'stopped')).toBe('cancelled by operator');

    h.reply('scan.status', { ...statusFixture(), state: 'failed', stopped_reason: 'failed', error: 'boom' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.detail(), 'stopped')).toBe('failed');
    const error = h.detail().querySelector('[data-field=error]');
    expect(error).not.toBeNull();
    expect(error!.textContent).toBe('boom');
    expect(error!.classList.contains(css.mono!)).toBe(true);
    expect(h.field(h.row(JOB), 'state')).toBe('failed');
  });

  it('crawl_facts (PA6): the Crawl section prints crawl.errors and crawl.forms_skipped, 0 as `0` rather than a dash', async () => {
    const h = mount();
    await tick();
    // The fixture carries neither field: both default to 0 and print as `0`.
    expect(h.field(h.detail(), 'crawl-errors')).toBe('0');
    expect(h.field(h.detail(), 'crawl-forms-skipped')).toBe('0');

    const raw = statusFixture();
    const crawl = raw.crawl as Record<string, unknown>;
    h.reply('scan.status', { ...raw, crawl: { ...crawl, errors: 2, forms_skipped: 1 } });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.detail(), 'crawl-errors')).toBe('2');
    expect(h.field(h.detail(), 'crawl-forms-skipped')).toBe('1');
  });

  it('start_notice: the after-start notice lists clamped, skipped lanes, and can be dismissed', async () => {
    const h = mount();
    await tick();
    expect(h.r.container.querySelector('[data-notice=start]')).toBeNull();
    const outcome = await h.s.launch(standard(), 'start');
    expect(outcome.kind).toBe('started');
    await tick();
    const notice = h.r.container.querySelector('[data-notice=start]');
    expect(notice).not.toBeNull();
    expect(notice!.getAttribute('role')).toBe('status');
    expect(notice!.textContent).toContain('budget.probes: 50000 -> 20000');
    expect(notice!.textContent).toContain('ws: lane not available on this build');
    // The fixture has no `dry_run` key: the line is absent, not `dry_run: false`.
    expect(notice!.textContent).not.toContain('dry_run');
    fireEvent.click(within(notice as HTMLElement).getByRole('button', { name: 'Dismiss start notice' }));
    await tick();
    expect(h.r.container.querySelector('[data-notice=start]')).toBeNull();
    expect(h.s.startNotice()).toBeNull();
  });

  it('start_notice_dry_run: a start result carrying dry_run prints it', async () => {
    const start = fixture('scan.start.json') as Record<string, unknown>;
    const h = mount({ replies: { 'scan.start': { ...start, dry_run: true } } });
    await tick();
    await h.s.launch(standard(), 'start');
    await tick();
    expect(h.r.container.querySelector('[data-notice=start]')!.textContent).toContain('dry_run: true');
  });
});

describe('JobsView: live values', () => {
  it('never_decreases (W-5): an older running reply is not drawn', async () => {
    const h = mount();
    await tick();
    const withSent = (sent: number, elapsed_ms: number) => {
      const st = statusFixture();
      return { ...st, elapsed_ms, probes: { ...(st.probes as Record<string, unknown>), sent } };
    };
    const seen: string[] = [];
    for (const [sent, elapsed] of [
      [418, 42000],
      [300, 41000],
      [450, 43000],
    ] as const) {
      h.reply('scan.status', withSent(sent, elapsed));
      await h.s.refreshStatus(JOB);
      seen.push(h.field(h.row(JOB), 'probes'));
      expect(h.field(h.strip(), 'probes')).toBe(seen[seen.length - 1]);
    }
    expect(seen).toEqual(['418/2000', '418/2000', '450/2000']);
  });

  it('cancel_calls_verb: the detail Cancel sends scan.cancel { job } and the row shows the reply', async () => {
    const h = mount();
    await tick();
    expect(h.count('scan.cancel')).toBe(0);
    // Scoped to the detail: the strip carries a same-named Cancel of its own.
    fireEvent.click(within(h.detail()).getByRole('button', { name: `Cancel scan ${JOB}` }));
    await tick();
    expect(h.argsOf('scan.cancel')[0]).toEqual({ job: JOB });
    expect(h.field(h.row(JOB), 'state')).toBe('cancelling · auditing');
    expect(h.row(JOB).getAttribute('data-state')).toBe('cancelling');
    expect(h.field(h.strip(), 'state')).toBe('cancelling · auditing');
  });
});

describe('JobsView: per-job errors (PA4, PA5)', () => {
  it('status_error_block: a failed scan.status read shows its text in the detail with a Retry that reads again', async () => {
    const h = mount();
    await tick();
    expect(h.detail().querySelector(`.${css.errorBlock}`)).toBeNull();

    h.fail('scan.status', 'scan: not_found: scan-1a2b3c4d');
    await h.s.refreshStatus(JOB);
    const block = h.detail().querySelector(`.${css.errorBlock}`);
    expect(block).not.toBeNull();
    expect(block!.textContent).toContain('scan: not_found');
    // The block sits above the facts: the operator reads why the counters stopped before the counters.
    const detailText = h.detail().textContent ?? '';
    expect(detailText.indexOf('scan: not_found')).toBeLessThan(detailText.indexOf('Overview'));
    // Data kept: the held status still renders behind the block.
    expect(h.detail().textContent).toContain('operator · web-ui');

    const before = h.count('scan.status');
    h.reply('scan.status', statusFixture());
    fireEvent.click(within(block as HTMLElement).getByRole('button', { name: 'Retry' }));
    await tick();
    expect(h.count('scan.status')).toBe(before + 1);
    expect(h.detail().querySelector(`.${css.errorBlock}`)).toBeNull();
  });

  it('cancel_failure_renders: a refused scan.cancel shows the core’s text in the Jobs view', async () => {
    const h = mount();
    await tick();
    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    fireEvent.click(within(h.detail()).getByRole('button', { name: `Cancel scan ${JOB}` }));
    await tick();
    expect(h.argsOf('scan.cancel')[0]).toEqual({ job: JOB });
    const line = h.detail().querySelector('[data-error="cancel"]');
    expect(line).not.toBeNull();
    expect(line!.textContent).toBe('Not found: scan-1a2b3c4d');
    expect(h.notice).toHaveBeenCalledWith('Not found: scan-1a2b3c4d', 'error');
    // The row keeps what the list said: a refused cancel changes no counter.
    expect(h.field(h.row(JOB), 'state')).toBe('running · auditing');
  });
});

describe('JobsView: keyboard (W-17)', () => {
  it('keyboard: ArrowDown / Home / End move the selection, Enter focuses the detail', async () => {
    const h = mount();
    await tick();
    const list = h.r.getByRole('listbox', { name: 'Jobs' });
    list.focus();
    expect(document.activeElement).toBe(list);
    expect(h.s.selectedJob()).toBe(JOB);

    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(h.s.selectedJob()).toBe(DONE);
    expect(h.row(DONE).getAttribute('aria-selected')).toBe('true');
    expect(h.row(JOB).getAttribute('aria-selected')).toBe('false');

    fireEvent.keyDown(list, { key: 'Home' });
    expect(h.s.selectedJob()).toBe(JOB);

    fireEvent.keyDown(list, { key: 'End' });
    expect(h.s.selectedJob()).toBe(DONE);

    fireEvent.keyDown(list, { key: 'ArrowUp' });
    expect(h.s.selectedJob()).toBe(JOB);

    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(h.detail());
  });
});

describe('JobsView: states (W-16)', () => {
  it('loading: grey bars until the first scan.list answers', () => {
    // A reply that never settles keeps `jobsLoaded()` false for the whole test.
    const h = mount({ replies: { 'scan.list': () => new Promise(() => {}) } });
    expect(h.s.jobsLoaded()).toBe(false);
    expect(h.r.container.querySelector(`.${css.loading}`)).not.toBeNull();
    expect(h.r.container.querySelector('[role=option]')).toBeNull();
    expect(h.r.queryByRole('region', { name: 'Selected job' })).toBeNull();
  });

  it('empty: an empty list keeps the frame and says where to start', async () => {
    const h = mount({ replies: { 'scan.list': { jobs: [] } } });
    await tick();
    expect(h.s.jobsLoaded()).toBe(true);
    expect(h.r.container.querySelector(`.${css.loading}`)).toBeNull();
    expect(h.r.getByText('No jobs yet: start one from Profiles')).toBeTruthy();
    expect(h.r.getByRole('listbox', { name: 'Jobs' })).toBeTruthy();
    expect(h.r.queryByRole('region', { name: 'Selected job' })).toBeNull();
  });

  it('error: the core text in a block with Retry that reads scan.list again', async () => {
    const h = mount();
    await tick();
    const before = h.count('scan.list');
    h.fail('scan.list', 'bus closed');
    await h.s.refreshJobs();
    const block = h.r.container.querySelector(`.${css.errorBlock}`);
    expect(block).not.toBeNull();
    expect(block!.textContent).toContain('bus closed');
    // Data kept: the rows read before the failure are still on screen.
    expect(h.options()).toHaveLength(2);

    h.reply('scan.list', fixture('scan.list.json'));
    fireEvent.click(within(block as HTMLElement).getByRole('button', { name: 'Retry' }));
    await tick();
    expect(h.count('scan.list')).toBe(before + 2);
    expect(h.r.container.querySelector(`.${css.errorBlock}`)).toBeNull();
  });

  it('reconnecting: every button is disabled and a note says so; data is kept', async () => {
    const h = mount();
    await tick();
    h.setBusState('reconnecting');
    await tick();
    const buttons = Array.from(h.r.container.querySelectorAll('button')) as HTMLButtonElement[];
    expect(buttons.length).toBeGreaterThan(0);
    expect(buttons.every((b) => b.disabled)).toBe(true);
    const note = h.r.container.querySelector(`.${css.listHead} .${css.note}`);
    expect(note).not.toBeNull();
    expect(note!.textContent).toContain('reconnecting');
    expect(h.options()).toHaveLength(2);
    expect(h.field(h.row(JOB), 'probes')).toBe('418/2000');

    h.setBusState('open');
    await tick();
    expect(h.r.container.querySelector(`.${css.listHead} .${css.note}`)).toBeNull();
    const strip = h.strip();
    const cancel = within(strip).getByRole('button', { name: `Cancel scan ${JOB}` }) as HTMLButtonElement;
    expect(cancel.disabled).toBe(false);
  });
});
