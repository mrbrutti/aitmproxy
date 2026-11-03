// The two wells under the table (spec D18 W2, D11, D21; plan Task 3.8c, AC37's wells clause): the
// Kit's `wellRows` drawn as `.kv` rows, one cell per value in its ink. The facts are AC51's running
// auditing job (the mac pins `wellRowsAreTheWellsWordsAndInks`), so every key and text here is the
// literal the mac asserts; the inks are the cells' `data-ink` / `.sev[data-severity]` hooks that
// `jobs.module.css` paints by. Nothing here reads the store.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import {
  WELL_CELL_SEPARATOR,
  WELL_CRAWL_SUBTITLE,
  WELL_CRAWL_TITLE,
  WELL_ISSUES_SUBTITLE,
  WELL_ISSUES_TITLE,
  WELL_KEY,
  jobFacts,
  type JobFacts,
} from './helpers';
import { JobWells } from './JobWells';
import css from './jobs.module.css';
import type { BySeverity, JobStatus, JobSummary } from './model';
import { parseJobStatus } from './model';
import { fixture } from './testkit';

afterEach(() => cleanup());

const status = () => parseJobStatus(fixture('scan.status.json'))!;

const tally = (over: Partial<BySeverity> = {}): BySeverity => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  ...over,
});

/** The `scan.list` row a status implies: the shared counters, nothing else. */
const rowOf = (s: JobStatus): JobSummary => ({
  job: s.job,
  state: s.state,
  phase: s.phase,
  elapsed_ms: s.elapsed_ms,
  probes: s.probes,
  points: s.points,
  issues: s.issues,
});

/** AC51's running auditing job, the facts the mac pins `wellRowsAreTheWellsWordsAndInks` builds. */
const ac51 = (): JobFacts => {
  const st: JobStatus = {
    ...status(),
    state: 'running',
    phase: 'auditing',
    elapsed_ms: 64_000,
    points: { found: 1020, queued: 923, audited: 97, skipped: { frequent: 722, ignored: 6, limit: 0 } },
    probes: { ...status().probes, by_lane: { ws: 47, http: 240 }, errors: 0, timeouts: 3, rate_waits: 1 },
    issues: { total: 5, by_severity: tally({ high: 1, low: 4 }), by_confidence: { certain: 1, firm: 2, tentative: 2 } },
    crawl: { pages: 46, queued: 12, depth: 3, forms_submitted: 5, forms_skipped: 2, errors: 1, last_error: null },
    lanes: {
      requested: ['http', 'ws', 'l4_stream'],
      run: ['http', 'ws'],
      skipped: [{ lane: 'l4_stream', reason: 'no L4 scope entry' }],
    },
    l4: { cases: 1024, crashes: 0, liveness_failures: 2, retired_elements: 7 },
    checks: { ...status().checks, scheduled: 6468, done: 3236, errors: 7, skipped: 3 },
  };
  return jobFacts(rowOf(st), st);
};

const mount = (facts: JobFacts, play = true) => render(() => <JobWells facts={facts} generation={1} play={play} />);

/** Every `.kv` row of a well as `key = text`, the text read from the row's `[data-field=value]`. */
const rowLines = (well: HTMLElement): string[] =>
  Array.from(well.querySelectorAll(`.${css.kv}`)).map(
    (kv) => `${kv.getAttribute('data-key')} = ${kv.querySelector('[data-field=value]')!.textContent}`,
  );

const row = (well: HTMLElement, key: string): HTMLElement => {
  const kv = Array.from(well.querySelectorAll(`.${css.kv}`)).find((e) => e.getAttribute('data-key') === key);
  if (!kv) throw new Error(`no row ${key}`);
  return kv as HTMLElement;
};

/** A row's cells: the spans inside `[data-field=value]` (the separators are bare text between them). */
const cells = (kv: HTMLElement): HTMLElement[] => Array.from(kv.querySelector('[data-field=value]')!.querySelectorAll('span'));

/** How a cell is inked: `muted`, `value`, or `sev:<level>` for a `.sev[data-severity]` span. */
const inkOf = (cell: HTMLElement): string =>
  cell.classList.contains(css.sev!) ? `sev:${cell.getAttribute('data-severity')}` : (cell.getAttribute('data-ink') ?? 'none');

describe('JobWells', () => {
  it('wells_read_the_kit_rows (AC37, AC51): both wells, their titles and subtitles, every row in order, every cell in its ink', () => {
    const r = mount(ac51());

    const wells = r.container.querySelectorAll(`.${css.well}`);
    expect(wells).toHaveLength(2);
    const crawl = r.getByRole('region', { name: WELL_CRAWL_TITLE });
    const issues = r.getByRole('region', { name: WELL_ISSUES_TITLE });
    expect(crawl.tagName).toBe('SECTION');
    expect(issues.tagName).toBe('SECTION');
    expect(crawl.getAttribute('aria-label')).toBe('Crawl and points');
    expect(issues.getAttribute('aria-label')).toBe('Issues');

    // The title with its subtitle at the right.
    const crawlTitle = crawl.querySelector(`h3.${css.wellTitle}`)!;
    expect(crawlTitle.textContent).toBe(`${WELL_CRAWL_TITLE}${WELL_CRAWL_SUBTITLE}`);
    expect(crawlTitle.querySelector(`.${css.wellSub}`)!.textContent).toBe('what the job found to test');
    const issuesTitle = issues.querySelector(`h3.${css.wellTitle}`)!;
    expect(issuesTitle.textContent).toBe(`${WELL_ISSUES_TITLE}${WELL_ISSUES_SUBTITLE}`);
    expect(issuesTitle.querySelector(`.${css.wellSub}`)!.textContent).toBe('by severity and confidence');

    // AC51's crawl rows, in D11's order, the cells joined by the separator.
    expect(WELL_CELL_SEPARATOR).toBe(' · ');
    expect(rowLines(crawl)).toEqual([
      'Pages fetched = 46',
      'Pages waiting = 12',
      'Depth = 3',
      'Forms submitted = 5',
      'Forms not submitted = 2',
      'Crawl errors = 1',
      'Points found = 1,020',
      'Waiting for audit = 923',
      'Audited = 97',
      'skipped as repetitive = 722',
      'skipped by rule = 6',
      'skipped at the per-request cap = 0',
      'Lanes = HTTP, WebSocket',
      'Lane skipped = L4 stream: no L4 scope entry',
      'Probes by lane = HTTP 240 · WebSocket 47',
      'Session = yes · no · ok · no',
      'L4 cases = 1,024',
      'L4 crashes = 0',
      'L4 liveness failures = 2',
      'L4 retired elements = 7',
    ]);
    // Each key is its own span so the row can split key and value.
    expect(row(crawl, WELL_KEY.pagesFetched).firstElementChild!.textContent).toBe('Pages fetched');

    // One cell per value: the lane probes are two spans, the session four, every one in the value ink.
    const probes = cells(row(crawl, WELL_KEY.probesByLane));
    expect(probes.map((c) => c.textContent)).toEqual(['HTTP 240', 'WebSocket 47']);
    expect(probes.map(inkOf)).toEqual(['value', 'value']);
    const session = cells(row(crawl, WELL_KEY.session));
    expect(session.map((c) => c.textContent)).toEqual(['yes', 'no', 'ok', 'no']);
    expect(session.map(inkOf)).toEqual(['value', 'value', 'value', 'value']);
    expect(cells(row(crawl, WELL_KEY.lanes)).map((c) => c.textContent)).toEqual(['HTTP, WebSocket']);
    // The Crawl well has no severity ink.
    expect(crawl.querySelectorAll('[data-severity]')).toHaveLength(0);
    expect(crawl.querySelectorAll('[data-ink=muted]')).toHaveLength(0);

    // AC51's issue rows.
    expect(rowLines(issues)).toEqual([
      'Critical · High · Medium = 0 · 1 · 0',
      'Low = 4',
      'Info = 0',
      'Certain · Firm · Tentative = 1 · 2 · 2',
      'Probe errors · timeouts · rate waits = 0 · 3 · 1',
      'Checks scheduled · done · errors · skipped = 6,468 · 3,236 · 7 · 3',
    ]);
    // The inks: a zero severity count is muted, a count above zero carries its severity, counts are values.
    const chm = cells(row(issues, WELL_KEY.criticalHighMedium));
    expect(chm.map((c) => c.textContent)).toEqual(['0', '1', '0']);
    expect(chm.map(inkOf)).toEqual(['muted', 'sev:high', 'muted']);
    expect(chm[1]!.classList.contains(css.sev!)).toBe(true);
    expect(chm[0]!.hasAttribute('data-severity')).toBe(false);
    expect(cells(row(issues, WELL_KEY.low)).map(inkOf)).toEqual(['sev:low']);
    expect(cells(row(issues, WELL_KEY.low)).map((c) => c.textContent)).toEqual(['4']);
    expect(cells(row(issues, WELL_KEY.info)).map(inkOf)).toEqual(['muted']);
    expect(cells(row(issues, WELL_KEY.certainFirmTentative)).map(inkOf)).toEqual(['value', 'value', 'value']);
    expect(cells(row(issues, WELL_KEY.probeErrors)).map(inkOf)).toEqual(['value', 'value', 'value']);
    const checks = cells(row(issues, WELL_KEY.checks));
    expect(checks.map((c) => c.textContent)).toEqual(['6,468', '3,236', '7', '3']);
    expect(checks.map(inkOf)).toEqual(['value', 'value', 'value', 'value']);
    // The separator is text between the cells, not a cell of its own.
    expect(row(issues, WELL_KEY.checks).querySelector('[data-field=value]')!.childNodes).toHaveLength(7);

    // The ledger's `data-count` never reaches the wells (D11: the word carries the count).
    expect(r.container.querySelectorAll('[data-count]')).toHaveLength(0);

    // The block is the entrance's fourth and follows the card's play.
    const block = r.container.querySelector(`.${css.wells}`) as HTMLElement;
    expect(block.classList.contains(css.enter!)).toBe(true);
    expect(block.style.getPropertyValue('--jobs-i')).toBe('3');
    expect(block.getAttribute('data-entrance')).toBe('play');
  });

  it('wells_before_the_status (AC51): the status-only values read —, the conditional rows are absent, the — is a value cell', () => {
    const r = mount(jobFacts(ac51().summary, null));
    const crawl = r.getByRole('region', { name: WELL_CRAWL_TITLE });
    const issues = r.getByRole('region', { name: WELL_ISSUES_TITLE });

    expect(rowLines(crawl)).toEqual([
      'Pages fetched = —',
      'Pages waiting = —',
      'Depth = —',
      'Forms submitted = —',
      'Forms not submitted = —',
      'Points found = 1,020',
      'Waiting for audit = 923',
      'Audited = 97',
      'skipped as repetitive = 722',
      'skipped by rule = 6',
      'skipped at the per-request cap = 0',
      'Lanes = —',
      'Probes by lane = HTTP 240 · WebSocket 47',
    ]);
    for (const absent of [WELL_KEY.crawlErrors, WELL_KEY.laneSkipped, WELL_KEY.session, WELL_KEY.l4Cases]) {
      expect(crawl.querySelector(`[data-key="${absent}"]`)).toBeNull();
    }
    expect(cells(row(crawl, WELL_KEY.pagesFetched)).map(inkOf)).toEqual(['value']);

    expect(rowLines(issues)).toEqual([
      'Critical · High · Medium = 0 · 1 · 0',
      'Low = 4',
      'Info = 0',
      'Certain · Firm · Tentative = 1 · 2 · 2',
      'Probe errors · timeouts · rate waits = 0 · 3 · 1',
      'Checks scheduled · done · errors · skipped = —',
    ]);
    const checks = cells(row(issues, WELL_KEY.checks));
    expect(checks.map((c) => c.textContent)).toEqual(['—']);
    expect(checks.map(inkOf)).toEqual(['value']);
  });

  it('wells_follow_the_entrance_and_the_facts: play false is `none`; a new status redraws the rows in place', () => {
    const [facts, setFacts] = createSignal<JobFacts>(jobFacts(ac51().summary, null));
    const r = render(() => <JobWells facts={facts()} generation={1} play={false} />);
    const block = r.container.querySelector(`.${css.wells}`) as HTMLElement;
    expect(block.getAttribute('data-entrance')).toBe('none');
    expect(block.style.getPropertyValue('--jobs-i')).toBe('3');

    const crawl = r.getByRole('region', { name: WELL_CRAWL_TITLE });
    expect(rowLines(crawl)).toHaveLength(13);
    expect(row(crawl, WELL_KEY.pagesFetched).querySelector('[data-field=value]')!.textContent).toBe('—');

    setFacts(ac51());
    expect(rowLines(crawl)).toHaveLength(20);
    expect(row(crawl, WELL_KEY.pagesFetched).querySelector('[data-field=value]')!.textContent).toBe('46');
    expect(cells(row(r.getByRole('region', { name: WELL_ISSUES_TITLE }), WELL_KEY.checks)).map((c) => c.textContent)).toEqual([
      '6,468',
      '3,236',
      '7',
      '3',
    ]);
  });
});
