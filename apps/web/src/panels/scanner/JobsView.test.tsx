// The Jobs view (spec D18 W1 + W2, plan Tasks 3.4 and 3.8): the one column of the locked comp —
// the bus banner, the selected job's card, the jobs table and the two wells — over the store's
// held truth, plus the job strip on the other tabs. These tests pin the rendered *values* (every
// counter as the fixture states it, in the Kit's words), the D4 sentences and the raw token
// (AC35), what a Cancel click sends, the listbox keyboard contract, the entrance rule (D12: the
// pointer and a start play it, the keyboard never does) and the four states (W-16, D15).
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
import { NO_JOBS_TEXT } from './helpers';
import { parseScanProfile, type ScanProfile } from './model';
import { scanStore, type ScanStore, type Tab } from './store';
import { JobStrip } from './JobStrip';
import { JobsView } from './JobsView';
import { fmtLastGood } from './primitives';
import css from './scanner.module.css';
import jobsCss from './jobs.module.css';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

const JOB = 'scan-1a2b3c4d';
const DONE = 'scan-55667788';
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/** The `scan.status` fixture as a mutable record, parsed fresh per call. */
const statusFixture = (): Record<string, unknown> => fixture('scan.status.json') as Record<string, unknown>;
const standard = (): ScanProfile => parseScanProfile(fixture('scan.profile.get.json'))!;
/** A finished status for the second list row (the fixture's reply is the first job's; the model keys by the reply's `job`). */
const doneStatus = (): Record<string, unknown> => ({
  ...statusFixture(),
  job: DONE,
  state: 'done',
  phase: 'done',
  finished_at: 1761900069000,
  probes: { ...(statusFixture().probes as Record<string, unknown>), sent: 0, budget: 0 },
});

const built: ScanStore[] = [];

/**
 * A stub app, its store on `tab` (the Jobs tab by default: the card is the selected job's region
 * there and the strip renders nothing), and the strip + view mounted under the real provider.
 */
function mount(opts: Parameters<typeof stubApp>[0] = {}, tab: Tab = 'jobs') {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  s.setTab(tab);
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
  /** The one `Selected job` region: the card on the Jobs tab, the strip elsewhere. */
  const region = () => r.getByRole('region', { name: 'Selected job' });
  const field = (scope: HTMLElement, name: string): string => {
    const el = scope.querySelector(`[data-field="${name}"]`);
    if (!el) throw new Error(`no [data-field=${name}]`);
    return el.textContent ?? '';
  };
  const cancelButton = (scope: HTMLElement, job: string) => within(scope).getByRole('button', { name: `Cancel scan ${job}` }) as HTMLButtonElement;
  return { ...stub, s, r, options, row, region, field, cancelButton };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('JobsView: the table rows', () => {
  it('rows_render_from_list: one option per job, the Kit cells from the list counters and the held status', async () => {
    const h = mount();
    await tick();
    const rows = h.options();
    expect(rows).toHaveLength(2);
    const first = rows[0]!;
    expect(first.id).toBe(`job-${JOB}`);
    expect(first.getAttribute('data-job')).toBe(JOB);
    expect(first.getAttribute('data-state')).toBe('running');
    expect(first.getAttribute('aria-selected')).toBe('true');
    expect(h.field(first, 'state')).toBe('Auditing');
    expect(h.field(first, 'profile')).toBe('standard');
    expect(h.field(first, 'target')).toBe('127.0.0.1:8080');
    // The held status: 180 of 240 checks.
    expect(h.field(first, 'progress')).toBe('75 % · 180 of 240');
    expect(h.field(first, 'probes')).toBe('418 of 2,000');
    expect(h.field(first, 'points')).toBe('80 of 120');
    expect(h.field(first, 'issues')).toBe('1 high, 1 medium, 1 low');
    expect(Array.from(first.querySelectorAll('[data-field=issues] [data-severity]')).map((e) => e.getAttribute('data-severity'))).toEqual([
      'high',
      'medium',
      'low',
    ]);
    expect(h.field(first, 'elapsed')).toBe('0:42');
    expect(first.getAttribute('aria-label')).toBe(
      'Auditing, standard, 127.0.0.1:8080, 75 percent, 180 of 240 checks, 3 issues: 1 high, 1 medium, 1 low, 42 seconds.',
    );
    // The keyboard and reader Cancel is the card's: no row carries a `Cancel scan <job>` control.
    expect(first.querySelector('button[aria-label^="Cancel scan"]')).toBeNull();
    const done = rows[1]!;
    expect(done.getAttribute('data-job')).toBe(DONE);
    expect(h.field(done, 'state')).toBe('Done');
    // A zero budget reads the Kit's `0 probes`, never `0 of 0`.
    expect(h.field(done, 'probes')).toBe('0 probes');
    expect(h.field(done, 'issues')).toBe('no issues');
    expect(done.querySelector('[data-field=issues] [data-ink=muted]')).not.toBeNull();
    expect(done.querySelector('[data-field=issues] [data-severity]')).toBeNull();
    // No element of the Jobs tab carries `data-count` (the live script's severity count reads it elsewhere).
    expect(h.r.container.querySelector('[data-count]')).toBeNull();
  });

  it('table_header_and_listbox: the hidden header reads the Kit labels; the listbox is `Jobs`', async () => {
    const h = mount();
    await tick();
    const head = h.r.container.querySelector(`.${jobsCss.head}`)!;
    expect(head.getAttribute('aria-hidden')).toBe('true');
    expect(head.textContent).toBe('StateProfileTargetProgressProbesPointsIssuesElapsed');
    const list = h.r.getByRole('listbox', { name: 'Jobs' });
    expect(list.getAttribute('aria-activedescendant')).toBe(`job-${JOB}`);
  });
});

describe('JobsView: the card', () => {
  it('card_mirrors_selected: the card is the selected job’s region; its chip, heading, finding line and verb follow the state', async () => {
    const h = mount();
    await tick();
    const card = h.region();
    expect(card.tagName).toBe('SECTION');
    expect(card.classList.contains(jobsCss.card!)).toBe(true);
    expect(card.getAttribute('data-job')).toBe(JOB);
    expect(card.getAttribute('data-state')).toBe('running');
    expect(card.getAttribute('data-tone')).toBe('progress');
    const chip = card.querySelector('[data-field=state]')!;
    expect(chip.classList.contains(jobsCss.chip!)).toBe(true);
    expect(chip.getAttribute('data-tone')).toBe('progress');
    expect(chip.textContent).toBe('Auditing');
    expect(card.querySelector('h2')!.textContent).toBe('127.0.0.1:8080');
    const finding = h.field(card, 'finding');
    expect(finding.startsWith('3 issues so far: 1 high, 1 medium, 1 low · http.reflected-xss and 1 more check running now · standard · started ')).toBe(true);
    expect(finding.endsWith(' by web-ui')).toBe(true);
    const cancel = h.cancelButton(card, JOB);
    expect(cancel.disabled).toBe(false);
    expect(cancel.textContent).toBe('Cancel Scan');
    expect(cancel.getAttribute('title')).toBe('Stop this job; the issues and site map it found stay (⌥⌘.)');
    expect(within(card).queryByRole('button', { name: `Scan again ${JOB}` })).toBeNull();

    h.reply('scan.status', (args) => (args.job === DONE ? doneStatus() : statusFixture()));
    fireEvent.click(h.row(DONE));
    await tick();
    expect(h.s.selectedJob()).toBe(DONE);
    const after = h.region();
    expect(after.getAttribute('data-job')).toBe(DONE);
    expect(after.getAttribute('data-state')).toBe('done');
    expect(after.getAttribute('data-tone')).toBe('success');
    expect(h.field(after, 'state')).toBe('Done');
    expect(within(after).queryByRole('button', { name: `Cancel scan ${DONE}` })).toBeNull();
    const again = within(after).getByRole('button', { name: `Scan again ${DONE}` }) as HTMLButtonElement;
    expect(again.disabled).toBe(false);
    expect(again.getAttribute('title')).toBe('Start a new job with profile standard against 127.0.0.1:8080');
    fireEvent.click(again);
    await tick();
    expect(h.argsOf('scan.start')[0]).toEqual({ profile_name: 'standard', overrides: { target: { origins: ['http://127.0.0.1:8080'] } } });
  });

  it('card_texts: the started-by words, the notices, the D4 sentences and the raw token on the card', async () => {
    const h = mount();
    await tick();
    const card = h.region();
    expect(h.field(card, 'notices')).toContain('Skipped ws: lane not available on this build');
    expect(card.querySelector('[data-field=stopped]')).toBeNull();

    // The D4 sentences (Jobs view W1): the budget figure is the job's own, grouped; a reason reads
    // once the merged state is terminal (the terminal status wins over the running list row).
    h.reply('scan.status', { ...statusFixture(), state: 'done', phase: 'done', finished_at: 1761900069000, stopped_reason: 'budget' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.region(), 'stopped')).toBe(
      'Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further.',
    );
    expect(h.field(h.region(), 'stopped-raw')).toBe('stopped_reason: budget');

    // `cancelled` on a job that is not in the cancelled state still gets its sentence.
    h.reply('scan.status', { ...statusFixture(), state: 'done', phase: 'done', finished_at: 1761900069000, stopped_reason: 'cancelled' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.region(), 'stopped')).toBe('Stopped early: the job was cancelled.');

    // `failed` with an error: the error line says it, there is no sentence, the raw line stays.
    h.reply('scan.status', { ...statusFixture(), state: 'failed', phase: 'done', stopped_reason: 'failed', error: 'boom' });
    await h.s.refreshStatus(JOB);
    expect(h.region().querySelector('[data-field=stopped]')).toBeNull();
    expect(h.field(h.region(), 'stopped-raw')).toBe('stopped_reason: failed');
    expect(h.field(h.region(), 'error')).toBe('boom');
    expect(h.region().getAttribute('data-tone')).toBe('danger');
    expect(h.field(h.row(JOB), 'state')).toBe('Failed');
    expect(h.field(h.row(JOB), 'sub')).toBe('boom');
  });

  it('stopped_sentence_and_raw_line (AC35): the reason line is the D4 sentence and the raw token sits in the attention block in the data face', async () => {
    const h = mount();
    await tick();
    // No reason yet: no reason line, and no raw line at all (the token appears nowhere else).
    expect(h.region().querySelector('[data-field=stopped]')).toBeNull();
    expect(h.region().querySelector('[data-field="stopped-raw"]')).toBeNull();

    h.reply('scan.status', { ...statusFixture(), state: 'done', phase: 'done', finished_at: 1761900069000, stopped_reason: 'errors' });
    await h.s.refreshStatus(JOB);
    const card = h.region();
    expect(h.field(card, 'stopped')).toBe('Stopped early: too many errors from the target.');
    const raw = card.querySelector('[data-field="stopped-raw"]')!;
    expect(raw.textContent).toBe('stopped_reason: errors');
    expect(raw.classList.contains(jobsCss.rawLine!)).toBe(true);
    expect(raw.closest('[data-field=attention]')).not.toBeNull();
    // The sentence is above the raw line.
    expect(card.querySelector('[data-field=stopped]')!.compareDocumentPosition(raw) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(h.field(h.row(JOB), 'sub')).toBe('Stopped early: too many errors from the target.');
  });

  it('crawl_trouble_line: a crawl with errors adds the D4 line to the attention block, the last_error words only when the engine sends them', async () => {
    const h = mount();
    await tick();
    expect(h.field(h.region(), 'attention')).not.toContain('The crawl fetched');

    const raw = statusFixture();
    const crawl = raw.crawl as Record<string, unknown>;
    h.reply('scan.status', { ...raw, crawl: { ...crawl, pages: 1, errors: 1 } });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.region(), 'attention')).toContain('The crawl fetched 1 page and hit 1 error');

    h.reply('scan.status', { ...raw, crawl: { ...crawl, pages: 0, errors: 1, last_error: 'connect_refused' } });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.region(), 'attention')).toContain('The crawl fetched 0 pages and hit 1 error — the target refused the connection');
  });

  it('launch_notices: after a start the card’s notices read the launch clamps and skipped lanes in the Kit words, de-duplicated against the status', async () => {
    const h = mount();
    await tick();
    const outcome = await h.s.launch(standard(), 'start');
    expect(outcome.kind).toBe('started');
    await tick();
    const notices = Array.from(h.region().querySelectorAll('[data-field=notices] li')).map((li) => li.textContent);
    expect(notices).toEqual(['Clamped budget.probes 50000 → 20000', 'Skipped ws: lane not available on this build']);
    // The fixture has no `dry_run` key and the Kit has no word for it: the line is absent.
    expect(h.region().textContent).not.toContain('dry_run');
  });
});

describe('JobsView: the wells', () => {
  it('wells_read_the_kit_rows (PA6 migrated): the Crawl well prints the crawl counters, `Crawl errors` only above zero, `Forms not submitted` 0 as `0`', async () => {
    const h = mount();
    await tick();
    const wells = h.r.container.querySelectorAll(`.${jobsCss.well}`);
    expect(wells).toHaveLength(2);
    const crawl = h.r.getByRole('region', { name: 'Crawl and points' });
    const issues = h.r.getByRole('region', { name: 'Issues' });
    const rowText = (well: HTMLElement, key: string): string | null => {
      const el = Array.from(well.querySelectorAll('[data-key]')).find((e) => e.getAttribute('data-key') === key);
      return el ? el.querySelector('[data-field=value]')!.textContent : null;
    };
    expect(rowText(crawl, 'Pages fetched')).toBe('37');
    expect(rowText(crawl, 'Forms not submitted')).toBe('0');
    expect(rowText(crawl, 'Crawl errors')).toBeNull();
    expect(rowText(crawl, 'Lane skipped')).toBe('WebSocket: lane not available on this build');
    expect(rowText(issues, 'Critical · High · Medium')).toBe('0 · 1 · 1');
    expect(rowText(issues, 'Checks scheduled · done · errors · skipped')).toBe('240 · 180 · 0 · 0');

    const raw = statusFixture();
    const crawlRaw = raw.crawl as Record<string, unknown>;
    h.reply('scan.status', { ...raw, crawl: { ...crawlRaw, errors: 2, forms_skipped: 1 } });
    await h.s.refreshStatus(JOB);
    expect(rowText(h.r.getByRole('region', { name: 'Crawl and points' }), 'Crawl errors')).toBe('2');
    expect(rowText(h.r.getByRole('region', { name: 'Crawl and points' }), 'Forms not submitted')).toBe('1');
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
    }
    expect(seen).toEqual(['418 of 2,000', '418 of 2,000', '450 of 2,000']);
  });

  it('cancel_calls_verb: the card’s Cancel sends scan.cancel { job }; the row, the chip and the verb show the reply', async () => {
    const h = mount();
    await tick();
    expect(h.count('scan.cancel')).toBe(0);
    fireEvent.click(h.cancelButton(h.region(), JOB));
    await tick();
    expect(h.argsOf('scan.cancel')[0]).toEqual({ job: JOB });
    expect(h.field(h.row(JOB), 'state')).toBe('Cancelling');
    expect(h.row(JOB).getAttribute('data-state')).toBe('cancelling');
    const card = h.region();
    expect(h.field(card, 'state')).toBe('Cancelling');
    expect(card.getAttribute('data-tone')).toBe('pending');
    // The chip's dot breathes only while cancelling (D12).
    expect(card.querySelector(`[data-field=state] .${jobsCss.chipDot}`)!.classList.contains(jobsCss.breathe!)).toBe(true);
    const cancel = h.cancelButton(card, JOB);
    expect(cancel.disabled).toBe(true);
    expect(cancel.textContent).toBe('Cancelling…');
  });

  it('cancel_disabled_while_cancelling (AC35): a cancelling status disables the card’s Cancel; no second scan.cancel', async () => {
    const h = mount();
    await tick();
    expect(h.cancelButton(h.region(), JOB).disabled).toBe(false);
    expect(h.region().querySelector(`.${jobsCss.chipDot}`)!.classList.contains(jobsCss.breathe!)).toBe(false);

    // The list still says `running`; the held status says `cancelling` at the same elapsed, so the
    // merged state is `cancelling` and the Cancel cannot send a second scan.cancel.
    h.reply('scan.status', { ...statusFixture(), state: 'cancelling' });
    await h.s.refreshStatus(JOB);
    expect(h.field(h.region(), 'state')).toBe('Cancelling');
    expect(h.region().getAttribute('data-state')).toBe('cancelling');
    expect(h.cancelButton(h.region(), JOB).disabled).toBe(true);
    expect(h.count('scan.cancel')).toBe(0);
  });
});

describe('JobsView: per-job errors (PA4, PA5)', () => {
  it('status_error_block: a failed scan.status read shows its text in the card with a Retry that reads again', async () => {
    const h = mount();
    await tick();
    expect(h.region().querySelector(`.${css.errorBlock}`)).toBeNull();

    h.fail('scan.status', 'scan: not_found: scan-1a2b3c4d');
    await h.s.refreshStatus(JOB);
    const block = h.region().querySelector(`.${css.errorBlock}`);
    expect(block).not.toBeNull();
    expect(block!.textContent).toContain('scan: not_found');
    // Data kept: the held status still renders behind the block.
    expect(h.region().querySelector('h2')!.textContent).toBe('127.0.0.1:8080');

    const before = h.count('scan.status');
    h.reply('scan.status', statusFixture());
    fireEvent.click(within(block as HTMLElement).getByRole('button', { name: 'Retry' }));
    await tick();
    expect(h.count('scan.status')).toBe(before + 1);
    expect(h.region().querySelector(`.${css.errorBlock}`)).toBeNull();
  });

  it('cancel_failure_renders: a refused scan.cancel shows the core’s text in the card', async () => {
    const h = mount();
    await tick();
    h.fail('scan.cancel', 'scan: not_found: scan-1a2b3c4d');
    fireEvent.click(h.cancelButton(h.region(), JOB));
    await tick();
    expect(h.argsOf('scan.cancel')[0]).toEqual({ job: JOB });
    const line = h.region().querySelector('[data-error="cancel"]');
    expect(line).not.toBeNull();
    expect(line!.textContent).toBe('Not found: scan-1a2b3c4d');
    expect(line!.getAttribute('role')).toBe('alert');
    expect(h.notice).toHaveBeenCalledWith('Not found: scan-1a2b3c4d', 'error');
    // The row keeps what the list said: a refused cancel changes no counter.
    expect(h.field(h.row(JOB), 'state')).toBe('Auditing');
  });
});

describe('JobsView: keyboard and the entrance (W-17, D12)', () => {
  it('keyboard: ArrowDown / Home / End move the selection, Enter focuses the card', async () => {
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
    // The card's primary verb takes focus (D14 as gap 77 amends it: the primary, else the first enabled):
    // Cancel on a live job, though the comp lists Show Site Map and Show Issues before it.
    expect(h.region().contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toBe(h.cancelButton(h.region(), JOB));

    // A done job: Enter focuses Scan Again, the terminal primary.
    h.reply('scan.status', (args) => (args.job === DONE ? doneStatus() : statusFixture()));
    list.focus();
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    await tick();
    expect(h.region().getAttribute('data-job')).toBe(DONE);
    fireEvent.keyDown(list, { key: 'Enter' });
    const again = within(h.region()).getByRole('button', { name: `Scan again ${DONE}` }) as HTMLButtonElement;
    expect(again.disabled).toBe(false);
    expect(document.activeElement).toBe(again);
  });

  it('entrance_follows_the_pointer_not_the_keyboard: a click bumps the generation and plays, an arrow changes the job without either, a start plays again', async () => {
    const h = mount();
    await tick();
    // The first list selected the first job: generation 1, played.
    const card = h.region();
    expect(card.getAttribute('data-job')).toBe(JOB);
    expect(card.getAttribute('data-generation')).toBe('1');
    expect(card.getAttribute('data-entrance')).toBe('play');
    // The table takes part on the first generation only; the wells follow the card.
    const list = h.r.getByRole('listbox', { name: 'Jobs' });
    expect(list.classList.contains(jobsCss.enter!)).toBe(true);
    expect(list.getAttribute('data-entrance')).toBe('play');
    const wells = () => h.r.container.querySelector(`.${jobsCss.wells}`)!;
    expect(wells().getAttribute('data-entrance')).toBe('play');

    fireEvent.click(h.row(DONE));
    await tick();
    expect(h.region().getAttribute('data-job')).toBe(DONE);
    expect(h.region().getAttribute('data-generation')).toBe('2');
    expect(h.region().getAttribute('data-entrance')).toBe('play');
    expect(h.r.getByRole('listbox', { name: 'Jobs' }).getAttribute('data-entrance')).toBeNull();

    fireEvent.keyDown(h.r.getByRole('listbox', { name: 'Jobs' }), { key: 'ArrowUp' });
    await tick();
    expect(h.region().getAttribute('data-job')).toBe(JOB);
    expect(h.region().getAttribute('data-generation')).toBe('2');
    expect(h.region().getAttribute('data-entrance')).toBe('none');
    expect(wells().getAttribute('data-entrance')).toBe('none');

    // A store-side selection (a start, another client's job): the view did not make it, so it plays.
    h.s.setSelectedJob(DONE);
    await tick();
    expect(h.region().getAttribute('data-job')).toBe(DONE);
    expect(h.region().getAttribute('data-generation')).toBe('3');
    expect(h.region().getAttribute('data-entrance')).toBe('play');
  });

  it('wells_remount_on_the_generation (gap 79): two pointer clicks each give a new `.wells` element, an arrow key keeps it', async () => {
    const h = mount();
    await tick();
    const wells = () => h.r.container.querySelector(`.${jobsCss.wells}`)!;
    const first = wells();
    expect(first).not.toBeNull();
    fireEvent.click(h.row(DONE));
    await tick();
    const second = wells();
    expect(second).not.toBe(first);
    expect(second.getAttribute('data-entrance')).toBe('play');
    fireEvent.click(h.row(JOB));
    await tick();
    const third = wells();
    expect(third).not.toBe(second);
    expect(h.region().getAttribute('data-generation')).toBe('3');
    // The keyboard changes the job and keeps the generation: the same wells element, nothing plays.
    fireEvent.keyDown(h.r.getByRole('listbox', { name: 'Jobs' }), { key: 'ArrowDown' });
    await tick();
    expect(h.region().getAttribute('data-job')).toBe(DONE);
    expect(wells()).toBe(third);
    expect(wells().getAttribute('data-entrance')).toBe('none');
  });
});

describe('JobsView: states (W-16, D15)', () => {
  it('loading: grey bars until the first scan.list answers; no card, table or wells', () => {
    // A reply that never settles keeps `jobsLoaded()` false for the whole test.
    const h = mount({ replies: { 'scan.list': () => new Promise(() => {}) } });
    expect(h.s.jobsLoaded()).toBe(false);
    expect(h.r.container.querySelector(`.${css.loading}`)).not.toBeNull();
    expect(h.r.container.querySelector('[role=option]')).toBeNull();
    expect(h.r.queryByRole('listbox', { name: 'Jobs' })).toBeNull();
    expect(h.r.queryByRole('region', { name: 'Selected job' })).toBeNull();
  });

  it('empty: the Kit sentence and an Open Profiles button; no card, table or wells', async () => {
    const h = mount({ replies: { 'scan.list': { jobs: [] } } });
    await tick();
    expect(h.s.jobsLoaded()).toBe(true);
    expect(h.r.container.querySelector(`.${css.loading}`)).toBeNull();
    expect(NO_JOBS_TEXT).toBe('No jobs yet — pick a profile and Start Scan.');
    expect(h.r.getByText('No jobs yet — pick a profile and Start Scan.')).toBeTruthy();
    expect(h.r.queryByRole('listbox', { name: 'Jobs' })).toBeNull();
    expect(h.r.queryByRole('region', { name: 'Selected job' })).toBeNull();
    expect(h.r.container.querySelector(`.${jobsCss.wells}`)).toBeNull();
    fireEvent.click(h.r.getByRole('button', { name: 'Open Profiles' }));
    expect(h.s.tab()).toBe('profiles');
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

  it('jobs_last_good_is_read_time: a remounted view reports when the list was read, not when it mounted', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    const LATER = T + 30 * 60_000;
    vi.setSystemTime(T);
    const h = mount();
    await tick();
    expect(h.s.jobsLoadedAt()).toBe(T);

    vi.setSystemTime(LATER);
    h.r.unmount();
    const r2 = render(() => (
      <AppProvider store={h.app}>
        <JobStrip />
        <JobsView />
      </AppProvider>
    ));
    await tick();
    h.fail('scan.list', 'bus closed');
    await h.s.refreshJobs();

    const block = r2.container.querySelector(`.${css.errorBlock}`);
    expect(block).not.toBeNull();
    expect(block!.textContent).toContain(`last good: ${fmtLastGood(T)}`);
    expect(block!.textContent).not.toContain(fmtLastGood(LATER));
    expect(h.s.jobsLoadedAt()).toBe(T);
  });

  it('bus_banner (AC38): the D15 banner with the values’ age above the card; every control disabled; the rows keep their values', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = mount();
    await tick();
    expect(h.r.container.querySelector('[data-reconnect]')).toBeNull();

    // The bus goes away; the store's 1 s clock (not the view) reads the wall clock 42 s on.
    h.setBusState('reconnecting');
    vi.setSystemTime(T + 41_000);
    await tick(1_000);
    const banner = h.r.container.querySelector(`.${jobsCss.banner} [data-reconnect]`);
    expect(banner).not.toBeNull();
    expect(banner!.textContent).toBe('Bus disconnected · showing values from 0:42 ago · reconnecting…');
    // The banner sits above the card.
    expect(banner!.compareDocumentPosition(h.region()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const buttons = Array.from(h.r.container.querySelectorAll('button')) as HTMLButtonElement[];
    expect(buttons.length).toBeGreaterThan(0);
    expect(buttons.every((b) => b.disabled)).toBe(true);
    expect(h.options()).toHaveLength(2);
    expect(h.field(h.row(JOB), 'probes')).toBe('418 of 2,000');

    h.setBusState('open');
    await tick();
    expect(h.r.container.querySelector('[data-reconnect]')).toBeNull();
    expect(h.cancelButton(h.region(), JOB).disabled).toBe(false);
  });

  it('bus_banner_counts_up (AC38, gap 76): the age clause advances every second on the store’s clock while the bus is away; the view owns no timer', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = mount();
    await tick();
    expect(h.s.jobsLoadedAt()).toBe(T);

    // The bus goes away with the values 42 s old: the polls stop, the clock does not.
    h.setBusState('reconnecting');
    vi.setSystemTime(T + 41_000);
    await tick(1_000);
    const banner = () => h.r.container.querySelector(`.${jobsCss.banner} [data-reconnect]`);
    expect(banner()!.textContent).toBe('Bus disconnected · showing values from 0:42 ago · reconnecting…');

    await tick(5_000);
    expect(h.s.nowMs()).toBe(T + 47_000);
    expect(banner()!.textContent).toBe('Bus disconnected · showing values from 0:47 ago · reconnecting…');
    // The data was not re-read behind the banner: the rows keep their values.
    expect(h.field(h.row(JOB), 'probes')).toBe('418 of 2,000');
  });
});

describe('JobStrip: the other tabs', () => {
  it('strip_on_other_tabs_only: nothing on the Jobs tab; on Issues the one region reads the state word, the row text, the severity words and the elapsed time, with Cancel', async () => {
    const h = mount();
    await tick();
    // On the Jobs tab the one `Selected job` region is the card.
    expect(h.r.getAllByRole('region', { name: 'Selected job' })).toHaveLength(1);
    expect(h.region().classList.contains(jobsCss.card!)).toBe(true);

    // This harness keeps JobsView mounted; the shell swaps the view per tab (Scanner.test pins one
    // region per tab), so the strip is found by its class here.
    h.s.setTab('issues');
    await tick();
    const stripEl = () => h.r.container.querySelector(`.${css.strip}`);
    expect(stripEl()).not.toBeNull();
    const strip = stripEl() as HTMLElement;
    expect(strip.getAttribute('role')).toBe('region');
    expect(strip.getAttribute('aria-label')).toBe('Selected job');
    expect(strip.getAttribute('data-job')).toBe(JOB);
    expect(strip.getAttribute('data-state')).toBe('running');
    expect(h.field(strip, 'state')).toBe('Auditing');
    expect(h.field(strip, 'progress')).toBe('75 % · 180 of 240');
    expect(h.field(strip, 'issues')).toBe('1 high, 1 medium, 1 low');
    expect(strip.querySelectorAll('[data-field=issues] [data-severity]')).toHaveLength(3);
    expect(h.field(strip, 'elapsed')).toBe('0:42');
    // The severity bar is gone from the strip.
    expect(strip.querySelector('[role=img]')).toBeNull();
    expect(h.cancelButton(strip, JOB).disabled).toBe(false);

    h.s.setSelectedJob(DONE);
    await tick();
    const after = stripEl() as HTMLElement;
    expect(after.getAttribute('data-job')).toBe(DONE);
    expect(h.field(after, 'state')).toBe('Done');
    expect(h.field(after, 'issues')).toBe('no issues');
    expect(h.cancelButton(after, DONE).disabled).toBe(true);

    h.s.setTab('jobs');
    await tick();
    expect(h.r.container.querySelector(`.${css.strip}`)).toBeNull();
  });
});
