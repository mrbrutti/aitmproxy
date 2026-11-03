// Tester additions for the Jobs view, Part 3 Task 3.9 (spec D18 W1 + W2, D21; plan gaps 74, 76,
// 77). The coder suites pin the comp's happy path block by block; this file walks the hostile
// path end to end — a status a malicious core could send, through `parseJobStatus` (Task 3.1b's
// bounds), `jobFacts`, the helpers and the three components — and pins what reaches the DOM. It
// also pins the finding line as one literal, Enter's fallback when the primary verb is disabled
// (gap 77), the banner clock across a minute and across a reconnect, and a few empty / oversized /
// malformed shapes a proxy must survive. Nothing here is evidence that a scan ran.
//
// Two pins carry a `GAP` tag: they hold today's behaviour so the panel can see it, and flip when
// the coder closes the gap. Each names the finding in its comment.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, within } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { AppProvider } from '~/state/context';
import { fixture, stubApp } from './testkit';
import {
  attention,
  clock,
  findingLine,
  hostsText,
  jobAccessibilityLabel,
  jobFacts,
  jobHeading,
  jobProgress,
  SCAN_AGAIN_HELP_GENERIC,
  scanAgainHelp,
  wellRows,
  type JobFacts,
  type Part,
} from './helpers';
import { MAX_SAMPLES, parseJobStatus, parseJobSummary, STR_MAX } from './model';
import { scanStore, type ScanStore } from './store';
import { JobCard } from './JobCard';
import { JobsTable } from './JobsTable';
import { JobStrip } from './JobStrip';
import { JobsView } from './JobsView';
import { JobWells } from './JobWells';
import css from './jobs.module.css';

const JOB = 'scan-c0ffee01';
const FIXTURE_JOB = 'scan-1a2b3c4d';
/** 11:32 UTC; the card prints it in the test process's own zone, so the expectations go through `clock`. */
const STARTED_AT = Date.UTC(2026, 10, 2, 11, 32, 0);
const zone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);
const UNPRINTABLE = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

/** The comp's running job (AC37), as `JobCard.test.tsx` builds it. */
function compStatus(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    job: JOB,
    state: 'running',
    phase: 'auditing',
    profile_name: 'standard',
    targets: ['http://127.0.0.1:8117'],
    started_by: { frontend: 'operator', client_label: null },
    started_at: STARTED_AT,
    finished_at: null,
    elapsed_ms: 64_000,
    stopped_reason: null,
    probes: { sent: 287, budget: 2000, errors: 0, timeouts: 0, rate_waits: 0, by_lane: { http: 287 } },
    crawl: { pages: 46, queued: 0, depth: 3, forms_submitted: 4 },
    points: { found: 1020, queued: 923, audited: 97, skipped: { ignored: 0, frequent: 0, limit: 0 } },
    checks: { scheduled: 6468, done: 3236, running: ['xss-reflected', 'sqli-error', 'open-redirect', 'path-traversal'] },
    issues: {
      total: 4,
      by_severity: { critical: 0, high: 0, medium: 0, low: 4, info: 0 },
      by_confidence: { certain: 1, firm: 2, tentative: 1 },
    },
    l4: null,
    session: null,
    lanes: { requested: ['http'], run: ['http'], skipped: [] },
    clamped: [],
    error: null,
    ...over,
  };
}

/** The dead-target job of AC37: done, stopped on errors, with the given check-error fields. */
const deadStatus = (checks: Record<string, unknown>, over: Record<string, unknown> = {}): Record<string, unknown> =>
  compStatus({
    state: 'done',
    phase: 'done',
    elapsed_ms: 4_000,
    finished_at: STARTED_AT + 4_000,
    stopped_reason: 'errors',
    checks: { scheduled: 135, done: 49, running: [], ...checks },
    issues: {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      by_confidence: { certain: 0, firm: 0, tentative: 0 },
    },
    ...over,
  });

/** The facts the view builds: the list row's counters are the status's own. */
function factsOf(raw: Record<string, unknown>): JobFacts {
  const status = parseJobStatus(raw);
  if (status === null) throw new Error('status fixture did not parse');
  const summary = parseJobSummary({
    job: raw.job,
    state: raw.state,
    phase: raw.phase,
    elapsed_ms: raw.elapsed_ms,
    probes: raw.probes,
    points: raw.points,
    issues: raw.issues,
  });
  if (summary === null) throw new Error('summary fixture did not parse');
  return jobFacts(summary, status);
}

const built: ScanStore[] = [];

/** The card, the table (one row: the same job) and the wells under the real provider over a stub app. */
function mountParts(initial: JobFacts, opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  s.setTab('jobs');
  const [facts, setFacts] = createSignal(initial);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <div>
        <JobCard facts={facts()} generation={1} play={false} launchNotices={[]} />
        <JobsTable rows={[facts()]} selected={facts().summary.job} onSelect={() => {}} onFocusCard={() => {}} play={false} first={false} generation={1} />
        <JobWells facts={facts()} generation={1} play={false} />
      </div>
    </AppProvider>
  ));
  const card = () => r.getByRole('region', { name: 'Selected job' });
  const row = () => r.getByRole('option');
  const field = (scope: HTMLElement, name: string): HTMLElement => {
    const el = scope.querySelector(`[data-field="${name}"]`);
    if (!(el instanceof HTMLElement)) throw new Error(`no [data-field=${name}]`);
    return el;
  };
  const text = (scope: HTMLElement, name: string): string => field(scope, name).textContent ?? '';
  const kpi = (index: number): HTMLElement => field(card(), 'kpis').querySelectorAll<HTMLElement>(`.${css.kpi}`)[index]!;
  const wellRow = (title: string, key: string): HTMLElement[] =>
    Array.from(r.getByRole('region', { name: title }).querySelectorAll<HTMLElement>(`.${css.kv}`)).filter(
      (kv) => kv.getAttribute('data-key') === key,
    );
  return { ...stub, s, r, card, row, field, text, kpi, wellRow, setFacts };
}

/** The whole Jobs view with the strip, as the shell mounts it, over the fixture pack. */
function mountView(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  s.setTab('jobs');
  const r = render(() => (
    <AppProvider store={stub.app}>
      <JobStrip />
      <JobsView />
    </AppProvider>
  ));
  const region = () => r.getByRole('region', { name: 'Selected job' });
  const list = () => r.getByRole('listbox', { name: 'Jobs' });
  const banner = () => r.container.querySelector(`.${css.banner} [data-reconnect]`);
  return { ...stub, s, r, region, list, banner };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

/* ------------------------------------------------------------------ gap 74 end to end */

describe('tester: a hostile status through the model, the helpers and the components (gap 74, web AC1b)', () => {
  const DETAIL_1000 = `${'a'.repeat(300)}\u0000${'b'.repeat(300)}\t${'c'.repeat(200)}\u2028${'d'.repeat(197)}`;
  const CLEAN_400 = `${'a'.repeat(300)}${'b'.repeat(100)}`;

  it('long_detail_renders_cut_and_clean: a 1,000-char sample detail with a NUL, a tab and U+2028 is one 400-char clean row', () => {
    expect(DETAIL_1000.length).toBe(1000);
    const f = factsOf(
      deadStatus({
        errors: 7,
        error_samples: [{ check: 'xss-reflected', point: 'GET /login', detail: DETAIL_1000 }],
      }),
    );
    // The model cut it; the helper carries it as is; the card draws exactly that.
    expect(f.status!.checks.error_samples[0]!.detail).toBe(CLEAN_400);
    expect(CLEAN_400.length).toBe(STR_MAX);
    const lines = attention(f);
    expect(lines).toHaveLength(1);
    expect(lines[0]!.text).toBe('7 checks could not run');
    expect(lines[0]!.samples[0]!.detail).toBe(CLEAN_400);

    const h = mountParts(f);
    const details = h.field(h.card(), 'attention').querySelector('details')!;
    expect(details.querySelector('summary')!.textContent).toBe('7 checks could not run');
    const items = Array.from(details.querySelectorAll('li')).map((li) => li.textContent);
    expect(items).toEqual([`xss-reflected · ${CLEAN_400}`]);
    expect(items[0]!.length).toBe('xss-reflected · '.length + 400);
    // No control, format or separator scalar reached the region, anywhere.
    expect(UNPRINTABLE.test(h.card().textContent ?? '')).toBe(false);
    expect(UNPRINTABLE.test(h.row().textContent ?? '')).toBe(false);
    // The wells read the counter, not the samples: `errors` is 7 whatever the sample looked like.
    expect(h.wellRow('Issues', 'Checks scheduled · done · errors · skipped')[0]!.querySelector('[data-field=value]')!.textContent).toBe(
      '135 · 49 · 7 · 0',
    );
  });

  it('nine_samples_render_eight_rows: the engine cap of 8 holds for the samples, the running ids and the skipped lanes', () => {
    const nine = <T,>(f: (i: number) => T): T[] => Array.from({ length: 9 }, (_, i) => f(i));
    const f = factsOf(
      deadStatus(
        {
          errors: 9,
          error_samples: nine((i) => ({ check: `check-${i}`, point: `p${i}`, detail: `d${i}` })),
          running: nine((i) => `http.check-${i}`),
        },
        {
          state: 'running',
          phase: 'auditing',
          finished_at: null,
          stopped_reason: null,
          lanes: {
            requested: ['http', 'ws'],
            run: ['http'],
            skipped: nine((i) => ({ lane: 'ws', reason: `reason ${i}` })),
          },
        },
      ),
    );
    expect(MAX_SAMPLES).toBe(8);
    expect(f.status!.checks.error_samples).toHaveLength(8);
    expect(f.status!.checks.running).toHaveLength(8);
    expect(f.status!.lanes.skipped).toHaveLength(8);

    const h = mountParts(f);
    const details = h.field(h.card(), 'attention').querySelector('details')!;
    // The count line is the engine's counter; the rows are the capped samples.
    expect(details.querySelector('summary')!.textContent).toBe('9 checks could not run');
    expect(Array.from(details.querySelectorAll('li')).map((li) => li.textContent)).toEqual(
      nine((i) => `check-${i} · d${i}`).slice(0, 8),
    );
    // Eight ids: the first and 7 more, in the now tag, the finding line and the row's label.
    expect(jobProgress(f).nowTag).toBe('now · http.check-0 and 7 more');
    expect(h.text(h.card(), 'now')).toBe('now · http.check-0 and 7 more');
    expect(findingLine(f, zone()).text).toBe(
      `no issues so far · http.check-0 and 7 more checks running now · standard · started ${clock(STARTED_AT, zone())} by the operator`,
    );
    // Eight `Lane skipped` rows in the Crawl well, one per capped entry, in wire order.
    const skipped = wellRows(f).crawl.filter((r) => r.key === 'Lane skipped');
    expect(skipped.map((r) => r.text)).toEqual(nine((i) => `WebSocket: reason ${i}`).slice(0, 8));
    expect(h.wellRow('Crawl and points', 'Lane skipped')).toHaveLength(8);
    // The Notices list carries the same eight skipped lanes (no launch notices): never nine.
    expect(h.field(h.card(), 'notices').querySelectorAll('li')).toHaveLength(8);
  });

  it('unbounded_target_pins_the_gap (GAP, for the coder): a 10,000-char target with a bidi override reaches every host cell uncut and uncleaned', () => {
    // Task 3.1b bounded every string of a status the Jobs view draws except `targets` (still
    // `strList`: 1,024 entries of any length, no cleaning). The Kit cuts each target to
    // `ScanWire.targetMax` (200 scalars) and the list to `listMax` (8); the TUI bounds them in
    // `bound_status`. Until the web does the same, this is what a hostile core can put on the
    // card's heading, the row's Target cell and its title, the accessibility label and the Scan
    // Again help. The row survives (every other cell is right) because `.cell` clips with
    // `overflow: hidden; white-space: nowrap`; the heading (`.heading`) has no such rule.
    const host = `${'a'.repeat(5000)}\u202E${'b'.repeat(4999)}`;
    expect(host.length).toBe(10_000);
    const f = factsOf(compStatus({ targets: [`http://${host}:8117`] }));
    expect(f.status!.targets[0]).toBe(`http://${host}:8117`); // GAP: not cut to 200, the U+202E kept.
    expect(hostsText(f)).toBe(`${host}:8117`);
    expect(jobHeading(f)).toBe(`${host}:8117`);

    const h = mountParts(f);
    const heading = h.card().querySelector('h2')!;
    expect(heading.textContent).toBe(`${host}:8117`);
    expect(heading.textContent!.length).toBe(10_005);
    expect(UNPRINTABLE.test(heading.textContent!)).toBe(true); // GAP: a format scalar in the DOM.
    const target = h.field(h.row(), 'target');
    expect(target.textContent).toBe(`${host}:8117`);
    expect(target.getAttribute('title')).toBe(`${host}:8117`);
    expect(h.row().getAttribute('aria-label')!.length).toBeGreaterThan(10_000);
    expect(jobAccessibilityLabel(f).startsWith(`Auditing, standard, ${host}:8117, 50 percent, `)).toBe(true);
    // The rest of the row is intact: the host did not break the grid's other cells.
    expect(h.text(h.row(), 'state')).toBe('Auditing');
    expect(h.text(h.row(), 'profile')).toBe('standard');
    expect(h.text(h.row(), 'progress')).toBe('50\u00a0% · 3,236 of 6,468');
    expect(h.text(h.row(), 'probes')).toBe('287 of 2,000');
    expect(h.text(h.row(), 'points')).toBe('97 of 1,020');
    expect(h.text(h.row(), 'issues')).toBe('4 low');
    expect(h.text(h.row(), 'elapsed')).toBe('1:04');
    expect(h.text(h.card(), 'now')).toBe('now · xss-reflected and 3 more');

    // Nine targets: the Kit would hold eight (`a0.test and 7 more`); the web keeps all nine.
    const many = factsOf(compStatus({ targets: Array.from({ length: 9 }, (_, i) => `http://a${i}.test`) }));
    expect(many.status!.targets).toHaveLength(9); // GAP: not cut to 8.
    expect(jobHeading(many)).toBe('a0.test and 8 more');
    // A done job's Scan Again carries the uncut host into its help and its `scan.start` origins.
    const done = factsOf(compStatus({ state: 'done', phase: 'done', targets: [`http://${host}:8117`] }));
    expect(scanAgainHelp(done.status!)).toBe(`Start a new job with profile standard against ${host}:8117`);
  });

  it('hostile_started_at: the clock refuses what no date holds; the card reads `started —` for a rejected stamp and `started 00:00` for an absurd one', () => {
    // `clock` itself (the Kit's `ScanFormat.clock(ms:timeZone:)`): out of `Date`'s range, or not a number, is `00:00`.
    expect(clock(Number.NaN, 'UTC')).toBe('00:00');
    expect(clock(Number.POSITIVE_INFINITY, 'UTC')).toBe('00:00');
    expect(clock(1e300, 'UTC')).toBe('00:00');
    expect(clock(8.64e15 + 1, 'UTC')).toBe('00:00');
    expect(clock(-8.64e15 - 1, 'UTC')).toBe('00:00');
    // Inside `Date`'s range a stamp is a time, a negative one included (the model rejects those before the clock sees them).
    expect(clock(8.64e15 - 60_000, 'UTC')).toBe('23:59');
    expect(clock(-1, 'UTC')).toBe('23:59');
    expect(clock(0, 'UTC')).toBe('00:00');

    // The model: a negative, non-finite or non-numeric stamp reads 0 (`num`), which the card treats as unknown.
    for (const bad of [-5, Number.NaN, Number.POSITIVE_INFINITY, 'yesterday', null, { ms: 1 }]) {
      const st = parseJobStatus(compStatus({ started_at: bad }))!;
      expect(st.started_at, String(bad)).toBe(0);
    }
    const rejected = factsOf(compStatus({ started_at: -5 }));
    expect(findingLine(rejected, zone()).text).toBe(
      '4 low issues so far · xss-reflected and 3 more checks running now · standard · started by the operator',
    );
    const h = mountParts(rejected);
    const scale = () => Array.from(h.field(h.card(), 'lane').querySelector(`.${css.scale}`)!.children).map((c) => c.textContent);
    expect(scale()).toEqual(['started —', 'elapsed 1:04', 'at this pace, about 1:04 to go']);
    expect(h.text(h.card(), 'finding').endsWith(' · standard · started by the operator')).toBe(true);

    // A finite but absurd stamp passes `num` and prints `00:00` (the clock's floor) rather than `—`:
    // pinned so the panel sees it; the honest reading for a stamp no date holds would be `started —`.
    h.setFacts(factsOf(compStatus({ started_at: 1e300 })));
    expect(scale()).toEqual(['started 00:00', 'elapsed 1:04', 'at this pace, about 1:04 to go']);
    expect(h.text(h.card(), 'finding').endsWith(' · standard · started 00:00 by the operator')).toBe(true);
    // The same floor on `finished_at`.
    h.setFacts(factsOf(compStatus({ state: 'done', phase: 'done', finished_at: 1e300, checks: { scheduled: 6468, done: 6468, running: [] } })));
    expect(h.text(h.card(), 'finding')).toBe(`standard · started ${clock(STARTED_AT, zone())} by the operator · finished 00:00`);
  });

  it('empty_status_values: no targets, no profile name, no budget, nothing running, no issues', () => {
    const f = factsOf(
      compStatus({
        targets: [],
        profile_name: '',
        probes: { sent: 287, budget: 0, errors: 0, timeouts: 0, rate_waits: 0, by_lane: {} },
        checks: { scheduled: 6468, done: 3236, running: [] },
        issues: {
          total: 0,
          by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          by_confidence: { certain: 0, firm: 0, tentative: 0 },
        },
      }),
    );
    const h = mountParts(f);
    const card = h.card();
    expect(card.querySelector('h2')!.textContent).toBe('—');
    expect(h.text(card, 'finding')).toBe(`no issues so far · — · started ${clock(STARTED_AT, zone())} by the operator`);
    expect(card.querySelector('[data-field=now]')).toBeNull();
    expect(h.text(card, 'to-go')).toBe('3,232 checks to go');
    // The gauge with no budget: no fill track, the probes counted alone.
    const gauge = h.field(card, 'gauge');
    expect(gauge.getAttribute('aria-label')).toBe('Probe budget, 287 probes');
    expect(gauge.querySelector(`.${css.gaugeFill}`)).toBeNull();
    expect(gauge.textContent).toBe('probe budget287 probes');
    expect(h.kpi(2).textContent).toBe('Probes287');
    expect(h.kpi(2).getAttribute('title')).toBe('287 probes sent (the probe budget, not progress)');
    expect(h.field(card, 'ledger').getAttribute('aria-label')).toBe('no issues');
    expect(h.text(card, 'ledger-word')).toBe('no issues yet');
    expect(h.kpi(4).querySelector('[data-ink=muted]')!.textContent).toBe('no issues yet');
    // The row.
    expect(h.text(h.row(), 'profile')).toBe('—');
    expect(h.text(h.row(), 'target')).toBe('—');
    expect(h.field(h.row(), 'target').getAttribute('title')).toBe('—');
    expect(h.text(h.row(), 'probes')).toBe('287 probes');
    expect(h.text(h.row(), 'issues')).toBe('no issues yet');
    // The label leaves the unknown profile and hosts out rather than reading `—` aloud (the Kit's rule).
    expect(h.row().getAttribute('aria-label')).toBe('Auditing, 50 percent, 3,236 of 6,468 checks, no issues yet, 1 minute 4 seconds.');
    // The wells: no lanes, no probes by lane.
    expect(h.wellRow('Crawl and points', 'Probes by lane')[0]!.querySelector('[data-field=value]')!.textContent).toBe('—');
    // Scan Again on a finished job with no profile name: the generic help.
    h.setFacts(factsOf(compStatus({ state: 'done', phase: 'done', profile_name: '', targets: [] })));
    const again = within(h.card()).getByRole('button', { name: `Scan again ${JOB}` });
    expect(again.getAttribute('title')).toBe(SCAN_AGAIN_HELP_GENERIC);
    expect(SCAN_AGAIN_HELP_GENERIC).toBe("Start a new job with this job's profile and target");
  });

  it('oversized_counters_clamp: done past scheduled is 100 % with nothing to go; a ten-figure count groups', () => {
    const f = factsOf(
      compStatus({
        checks: { scheduled: 6468, done: 7000, running: ['xss-reflected'] },
        points: { found: 1_234_567_890, queued: 0, audited: 1_000_000, skipped: { ignored: 0, frequent: 0, limit: 0 } },
      }),
    );
    const h = mountParts(f);
    const lane = h.field(h.card(), 'lane');
    expect(lane.getAttribute('data-fraction')).toBe('1.0000');
    expect(lane.getAttribute('aria-valuenow')).toBe('100');
    expect(lane.getAttribute('aria-valuetext')).toBe('100 percent');
    expect(h.card().querySelector('[data-field=to-go]')).toBeNull();
    expect(h.text(h.card(), 'estimate')).toBe('');
    expect(h.field(h.card(), 'estimate').getAttribute('title')).toBeNull();
    expect(h.kpi(0).querySelector(`.${css.tick}`)!.textContent).toBe('100\u00a0%');
    expect(h.kpi(1).textContent).toBe('Checks7,000of 6,468');
    expect(h.kpi(3).textContent).toBe('Points audited1,000,000of 1,234,567,890');
    expect(h.text(h.row(), 'progress')).toBe('100\u00a0% · 7,000 of 6,468');
    expect(h.text(h.row(), 'points')).toBe('1,000,000 of 1,234,567,890');
    expect(h.row().querySelector(`svg.${css.ring}`)!.getAttribute('data-fraction')).toBe('1.0000');
    expect(h.wellRow('Crawl and points', 'Points found')[0]!.querySelector('[data-field=value]')!.textContent).toBe('1,234,567,890');
  });

  it('malformed_sub_objects_still_render: strings and arrays where objects belong read as zeros, and the card, row and wells draw', () => {
    const raw = compStatus({
      started_by: 'nobody',
      issues: 'none',
      checks: [],
      crawl: null,
      probes: 5,
      points: 'many',
      lanes: 7,
      clamped: 'x',
      error: 12,
      l4: 'yes',
      session: [],
    });
    const st = parseJobStatus(raw);
    expect(st).not.toBeNull();
    expect(st!.started_by).toEqual({ frontend: '', client_label: null });
    expect(st!.checks).toEqual({ scheduled: 0, done: 0, running: [], errors: 0, error_samples: [], skipped: 0, skipped_samples: [] });
    expect(st!.error).toBeNull();
    const summary = parseJobSummary({ job: JOB, state: 'running', phase: 'auditing', elapsed_ms: 64_000, probes: 5, points: 'many', issues: 'none' })!;
    const f = jobFacts(summary, st);
    const h = mountParts(f);
    const card = h.card();
    expect(h.text(card, 'state')).toBe('Auditing');
    expect(card.querySelector('h2')!.textContent).toBe('127.0.0.1:8117');
    expect(h.text(card, 'finding')).toBe(`no issues so far · standard · started ${clock(STARTED_AT, zone())} by the operator`);
    // Auditing with nothing scheduled: the scheduling variant.
    expect(h.text(card, 'phase')).toBe('Scheduling checks');
    expect(h.field(card, 'lane').getAttribute('aria-valuetext')).toBe('Scheduling checks');
    expect(h.kpi(1).textContent).toBe('Checks0of 0');
    expect(h.kpi(2).textContent).toBe('Probes0');
    expect(h.text(h.row(), 'progress')).toBe('Scheduling checks');
    expect(h.text(h.row(), 'probes')).toBe('0 probes');
    expect(h.text(h.row(), 'points')).toBe('0 of 0');
    expect(h.wellRow('Issues', 'Checks scheduled · done · errors · skipped')[0]!.querySelector('[data-field=value]')!.textContent).toBe('0 · 0 · 0 · 0');
    expect(card.querySelector('[data-field=attention]')).toBeNull();
  });
});

/* ------------------------------------------------------------------ the finding line as one literal */

describe('tester: the comp card’s finding line as one literal (AC37, AC36)', () => {
  it('comp_finding_line_whole: the text and the ten parts with their roles, the clock computed for the process zone', () => {
    const f = factsOf(compStatus());
    const when = clock(STARTED_AT, zone());
    expect(when).toMatch(/^\d\d:\d\d$/);
    const line = findingLine(f, zone());
    expect(line.text).toBe(`4 low issues so far · xss-reflected and 3 more checks running now · standard · started ${when} by the operator`);
    expect(line.parts).toEqual<Part[]>([
      { text: '4', role: 'figure' },
      { text: ' low issues so far', role: 'plain' },
      { text: ' · ', role: 'plain' },
      { text: 'xss-reflected', role: 'checkId' },
      { text: ' and 3 more checks running now', role: 'plain' },
      { text: ' · ', role: 'plain' },
      { text: 'standard', role: 'plain' },
      { text: ' · ', role: 'plain' },
      { text: `started ${when} by `, role: 'plain' },
      { text: 'the operator', role: 'plain' },
    ]);
    const h = mountParts(f);
    const finding = h.field(h.card(), 'finding');
    expect(finding.textContent).toBe(line.text);
    expect(Array.from(finding.querySelectorAll(`.${css.part}`)).map((p) => [p.getAttribute('data-role'), p.textContent])).toEqual(
      line.parts.map((p) => [p.role, p.text]),
    );
  });
});

/* ------------------------------------------------------------------ gap 77: Enter's fallback */

describe('tester: Enter in the listbox when the primary verb is disabled (gap 77)', () => {
  it('enter_falls_back_to_the_first_enabled_verb_then_the_card: cancelling → Show Site Map; bus away → the card itself', async () => {
    const h = mountView();
    await tick();
    const list = h.list();
    list.focus();
    // The baseline: a live job's primary verb.
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(within(h.region()).getByRole('button', { name: `Cancel scan ${FIXTURE_JOB}` }));

    // The merged state is `cancelling`: the primary verb is disabled, so the first enabled verb takes focus.
    h.reply('scan.status', { ...(fixture('scan.status.json') as Record<string, unknown>), state: 'cancelling' });
    await h.s.refreshStatus(FIXTURE_JOB);
    const cancel = within(h.region()).getByRole('button', { name: `Cancel scan ${FIXTURE_JOB}` }) as HTMLButtonElement;
    expect(cancel.disabled).toBe(true);
    expect(cancel.textContent).toBe('Cancelling…');
    list.focus();
    fireEvent.keyDown(list, { key: 'Enter' });
    const siteMap = within(h.region()).getByRole('button', { name: 'Show Site Map' });
    expect(document.activeElement).toBe(siteMap);
    expect(Array.from(h.region().querySelectorAll(`.${css.titleRow} button`)).map((b) => b.textContent)).toEqual([
      'Show Site Map',
      'Show Issues',
      'Cancelling…',
    ]);

    // The bus is away: every verb is disabled, so the card (tabIndex -1) takes focus and nothing is pressed.
    h.setBusState('reconnecting');
    await tick();
    expect(Array.from(h.region().querySelectorAll('button')).every((b) => (b as HTMLButtonElement).disabled)).toBe(true);
    list.focus();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(h.region());
    expect(h.region().tabIndex).toBe(-1);
    expect(h.count('scan.cancel')).toBe(0);

    // Back: Enter returns to the primary verb once it is enabled again (the status is live again).
    h.reply('scan.status', fixture('scan.status.json'));
    h.setBusState('open');
    await tick();
    await h.s.refreshStatus(FIXTURE_JOB);
    list.focus();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(document.activeElement).toBe(within(h.region()).getByRole('button', { name: `Cancel scan ${FIXTURE_JOB}` }));
    expect(h.s.selectedJob()).toBe(FIXTURE_JOB);
  });
});

/* ------------------------------------------------------------------ the banner clock */

describe('tester: the banner age on the store clock (AC38, gap 76)', () => {
  it('banner_age_crosses_the_minute_and_restarts_after_a_reconnect: 0:58 → 1:00 → 2:00; a re-opened bus re-reads the list, so the next outage counts from that read', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = mountView();
    await tick();
    expect(h.s.jobsLoadedAt()).toBe(T);
    expect(h.banner()).toBeNull();

    h.setBusState('reconnecting');
    vi.setSystemTime(T + 57_000);
    await tick(1_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 0:58 ago · reconnecting…');
    await tick(2_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 1:00 ago · reconnecting…');
    await tick(60_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 2:00 ago · reconnecting…');
    expect(h.s.nowMs()).toBe(T + 120_000);
    // The polls were stopped behind the banner: one list, read before the outage.
    expect(h.count('scan.list')).toBe(1);

    // The bus comes back: the banner goes, the live model resyncs and the list's time moves to now.
    h.setBusState('open');
    await tick(100);
    expect(h.banner()).toBeNull();
    expect(h.count('scan.list')).toBe(2);
    expect(h.s.jobsLoadedAt()).toBe(T + 120_000);

    // A second outage five seconds later counts from the second read, not the first.
    h.setBusState('reconnecting');
    await tick(5_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 0:05 ago · reconnecting…');
    // The rows kept their values throughout.
    expect(h.r.getAllByRole('option')).toHaveLength(2);
    expect(h.r.container.querySelector(`[role=option][data-job="${FIXTURE_JOB}"] [data-field=probes]`)!.textContent).toBe('418 of 2,000');
  });

  it('banner_age_never_reads_negative: a list that lands between two clock ticks shows 0:00 ago, not a minus', async () => {
    const T = Date.UTC(2026, 9, 31, 14, 3, 22);
    vi.setSystemTime(T);
    const h = mountView();
    await tick();
    expect(h.s.nowMs()).toBe(T);
    // 400 ms on, between two ticks of the store clock, a list is read: `jobsLoadedAt` is ahead of `nowMs`.
    await tick(400);
    await h.s.refreshJobs();
    expect(h.s.jobsLoadedAt()).toBe(T + 400);
    expect(h.s.nowMs()).toBe(T);
    h.setBusState('reconnecting');
    await tick(0);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 0:00 ago · reconnecting…');
    // The next tick (T + 1,000): 600 ms old, still 0:00; the one after (T + 2,000): 1,600 ms, 0:01.
    await tick(600);
    expect(h.s.nowMs()).toBe(T + 1_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 0:00 ago · reconnecting…');
    await tick(1_000);
    expect(h.s.nowMs()).toBe(T + 2_000);
    expect(h.banner()!.textContent).toBe('Bus disconnected · showing values from 0:01 ago · reconnecting…');
  });
});
