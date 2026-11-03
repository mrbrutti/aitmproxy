// The jobs table (spec D18 W2, D10, D12, D14; plan Task 3.8b; AC37, AC38): the five rows of the
// locked comp (`docs/design/mockup/scan-jobs/committed.html`) built as facts and read back cell by
// cell in the Kit's words; the caption assistive technology reaches through `aria-describedby`;
// the hover Cancel as a pointer-only control (hidden from readers, out of the tab order, one
// `scan.cancel`, the selection untouched, disabled while the bus is away); the keyboard's cause
// against the pointer's; rows keyed by their id so a poll remounts only the counters that changed;
// the entrance attribute on the tab's first generation only. The table reads nothing from the
// store but the cancel verb and its gate: every row arrives as a prop.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import { AGENT_DOT_HELP, jobFacts, type JobFacts } from './helpers';
import type { BySeverity, JobState, JobStatus, JobSummary, Phase, StartedBy, StoppedReason } from './model';
import { scanStore, type ScanStore } from './store';
import { JobsTable } from './JobsTable';
import css from './jobs.module.css';

const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/* ---- the comp's five rows as facts */

const CRAWL = 'scan-c0a1f1e0';
const AUDIT = 'scan-a0d17000';
const DEAD = 'scan-dead0001';
const CANCELLING = 'scan-ca9ce111';
const LIGHT = 'scan-1194700f';

const OPERATOR: StartedBy = { frontend: 'operator', client_label: 'web-ui' };
const AGENT: StartedBy = { frontend: 'mcp', client_label: 'claude' };

interface RowSpec {
  job: string;
  state: JobState;
  phase: Phase;
  profile: string;
  host: string;
  elapsedMs: number;
  /** `[sent, budget]`. */
  probes: [number, number];
  /** `[audited, found]`. */
  points: [number, number];
  /** `[done, scheduled, running]`. */
  checks: [number, number, string[]];
  /** `[pages, queued]`. */
  crawl: [number, number];
  issues?: Partial<BySeverity>;
  startedBy?: StartedBy;
  stoppedReason?: StoppedReason;
  error?: string;
}

const bySeverity = (p: Partial<BySeverity> = {}): BySeverity => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  ...p,
});

/** A list row and its status built from one spec, merged as the view merges them (`jobFacts`). */
function facts(spec: RowSpec): JobFacts {
  const by = bySeverity(spec.issues);
  const total = by.critical + by.high + by.medium + by.low + by.info;
  const shared = {
    job: spec.job,
    state: spec.state,
    phase: spec.phase,
    elapsed_ms: spec.elapsedMs,
    probes: { sent: spec.probes[0], budget: spec.probes[1], errors: 0, timeouts: 0, rate_waits: 0, by_lane: { http: spec.probes[0] } },
    points: { found: spec.points[1], queued: 0, audited: spec.points[0], skipped: { ignored: 0, frequent: 0, limit: 0 } },
    issues: { total, by_severity: by, by_confidence: { certain: total, firm: 0, tentative: 0 } },
  };
  const summary: JobSummary = { ...shared };
  const terminal = spec.state === 'done' || spec.state === 'cancelled' || spec.state === 'failed';
  const status: JobStatus = {
    ...shared,
    profile_name: spec.profile,
    targets: [`http://${spec.host}`],
    started_by: spec.startedBy ?? OPERATOR,
    started_at: 1761900000000,
    finished_at: terminal ? 1761900000000 + spec.elapsedMs : null,
    stopped_reason: spec.stoppedReason ?? null,
    crawl: { pages: spec.crawl[0], queued: spec.crawl[1], depth: 3, forms_submitted: 0, errors: 0, forms_skipped: 0, last_error: null },
    checks: { scheduled: spec.checks[1], done: spec.checks[0], running: spec.checks[2], errors: 0, error_samples: [], skipped: 0, skipped_samples: [] },
    l4: null,
    session: null,
    lanes: { requested: ['http'], run: ['http'], skipped: [] },
    clamped: [],
    error: spec.error ?? null,
  };
  return jobFacts(summary, status);
}

const crawling = (): JobFacts =>
  facts({
    job: CRAWL,
    state: 'running',
    phase: 'crawling',
    profile: 'thorough',
    host: '127.0.0.1:8119',
    elapsedMs: 5_000,
    probes: [11, 2000],
    points: [0, 0],
    checks: [0, 0, []],
    crawl: [46, 12],
  });

const auditing = (elapsedMs = 64_000): JobFacts =>
  facts({
    job: AUDIT,
    state: 'running',
    phase: 'auditing',
    profile: 'standard',
    host: '127.0.0.1:8117',
    elapsedMs,
    probes: [287, 2000],
    points: [97, 1020],
    checks: [3236, 6468, ['xss-reflected', 'sqli-error', 'open-redirect', 'cmdi']],
    crawl: [37, 0],
    issues: { low: 4 },
    startedBy: AGENT,
  });

const deadTarget = (): JobFacts =>
  facts({
    job: DEAD,
    state: 'done',
    phase: 'done',
    profile: 'standard',
    host: '127.0.0.1:8121',
    elapsedMs: 30_000,
    probes: [1, 2000],
    points: [0, 14],
    checks: [49, 135, []],
    crawl: [2, 0],
    stoppedReason: 'errors',
  });

const cancelling = (): JobFacts =>
  facts({
    job: CANCELLING,
    state: 'cancelling',
    phase: 'auditing',
    profile: 'standard',
    host: '127.0.0.1:8117',
    elapsedMs: 21_000,
    probes: [46, 2000],
    points: [0, 0],
    checks: [0, 0, []],
    crawl: [12, 0],
  });

const lightDone = (): JobFacts =>
  facts({
    job: LIGHT,
    state: 'done',
    phase: 'done',
    profile: 'light-http',
    host: '127.0.0.1:8120',
    elapsedMs: 95_000,
    probes: [143, 2000],
    points: [36, 36],
    checks: [171, 171, []],
    crawl: [9, 0],
    issues: { high: 1, low: 2 },
  });

const compRows = (): JobFacts[] => [crawling(), auditing(), deadTarget(), cancelling(), lightDone()];

/* ---- mounting */

const built: ScanStore[] = [];

/** The table under the real provider over a stub app; the selection is a local signal `onSelect` moves. */
function mount(initialRows: JobFacts[], selected: string | null, opts: { first?: boolean; play?: boolean } = {}) {
  const stub = stubApp();
  const s = scanStore(stub.app);
  built.push(s);
  const [rows, setRows] = createSignal(initialRows);
  const [sel, setSel] = createSignal<string | null>(selected);
  const [first, setFirst] = createSignal(opts.first ?? true);
  const [play, setPlay] = createSignal(opts.play ?? true);
  const onSelect = vi.fn((job: string, _cause: 'pointer' | 'keyboard') => setSel(job));
  const onFocusCard = vi.fn();
  const r = render(() => (
    <AppProvider store={stub.app}>
      <JobsTable rows={rows()} selected={sel()} onSelect={onSelect} onFocusCard={onFocusCard} play={play()} first={first()} generation={1} />
    </AppProvider>
  ));
  const list = () => r.getByRole('listbox', { name: 'Jobs' });
  const row = (id: string): HTMLElement => {
    const el = r.container.querySelector(`[role=option][data-job="${id}"]`);
    if (!(el instanceof HTMLElement)) throw new Error(`no row for ${id}`);
    return el;
  };
  const field = (scope: HTMLElement, name: string): string => {
    const el = scope.querySelector(`[data-field="${name}"]`);
    if (!el) throw new Error(`no [data-field=${name}]`);
    return el.textContent ?? '';
  };
  const cancel = (scope: HTMLElement): HTMLButtonElement | null => scope.querySelector<HTMLButtonElement>('[data-action=cancel]');
  return { ...stub, s, r, setRows, setSel, setFirst, setPlay, onSelect, onFocusCard, list, row, field, cancel };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('JobsTable: the comp rows (AC37)', () => {
  it('comp_rows: the five rows of committed.html, cell by cell in the Kit words, ring or dot, the agent dot, the ticks', () => {
    const h = mount(compRows(), AUDIT);
    const options = h.r.getAllByRole('option');
    expect(options.map((o) => o.id)).toEqual([CRAWL, AUDIT, DEAD, CANCELLING, LIGHT].map((id) => `job-${id}`));

    // The header: hidden from readers, the Kit labels, nine cells with the action column last.
    const head = h.r.container.querySelector(`.${css.head}`)!;
    expect(head.getAttribute('aria-hidden')).toBe('true');
    expect(head.textContent).toBe('StateProfileTargetProgressProbesPointsIssuesElapsed');
    expect(head.querySelectorAll(`.${css.cell}`)).toHaveLength(9);

    // Crawling: a determinate ring on the pages, no dot, no sub-line, `no issues yet` muted.
    const crawl = h.row(CRAWL);
    expect(crawl.getAttribute('data-state')).toBe('running');
    expect(crawl.getAttribute('aria-selected')).toBe('false');
    expect(h.field(crawl, 'state')).toBe('Crawling');
    expect(crawl.querySelector('[data-field=sub]')).toBeNull();
    expect(h.field(crawl, 'profile')).toBe('thorough');
    expect(h.field(crawl, 'target')).toBe('127.0.0.1:8119');
    expect(h.field(crawl, 'progress')).toBe('46 pages, 12 queued');
    expect(h.field(crawl, 'probes')).toBe('11 of 2,000');
    expect(h.field(crawl, 'points')).toBe('0 of 0');
    expect(h.field(crawl, 'issues')).toBe('no issues yet');
    expect(crawl.querySelector('[data-field=issues] [data-ink=muted]')).not.toBeNull();
    expect(h.field(crawl, 'elapsed')).toBe('0:05');
    const crawlRing = crawl.querySelector(`svg.${css.ring}`)!;
    expect(crawlRing).not.toBeNull();
    expect(crawlRing.getAttribute('data-fraction')).toBe((46 / 58).toFixed(4));
    expect(crawl.querySelector(`.${css.dot}`)).toBeNull();
    expect(crawl.querySelector(`.${css.agentDot}`)).toBeNull();

    // Auditing, selected, agent-started: the ring at 0.5003, the agent dot, every number a tick.
    const audit = h.row(AUDIT);
    expect(audit.getAttribute('aria-selected')).toBe('true');
    expect(h.list().getAttribute('aria-activedescendant')).toBe(`job-${AUDIT}`);
    expect(h.field(audit, 'state')).toBe('Auditing');
    expect(audit.querySelector('[data-field=sub]')).toBeNull();
    expect(audit.querySelector(`svg.${css.ring}`)!.getAttribute('data-fraction')).toBe('0.5003');
    const who = audit.querySelector(`.${css.agentDot}`)!;
    expect(who).not.toBeNull();
    expect(who.getAttribute('title')).toBe(AGENT_DOT_HELP);
    expect(who.getAttribute('aria-hidden')).toBe('true');
    expect(h.field(audit, 'profile')).toBe('standard');
    const target = audit.querySelector('[data-field=target]')!;
    expect(target.textContent).toBe('127.0.0.1:8117');
    expect(target.getAttribute('title')).toBe('127.0.0.1:8117');
    expect(h.field(audit, 'progress')).toBe('50 % · 3,236 of 6,468');
    expect(audit.querySelector(`[data-field=progress] .${css.tick}`)!.textContent).toBe('50 % · 3,236 of 6,468');
    const probes = audit.querySelector('[data-field=probes]')!;
    expect(probes.textContent).toBe('287 of 2,000');
    expect(probes.querySelector(`.${css.tick}`)!.textContent).toBe('287');
    expect(probes.querySelector('[data-ink=muted]')!.textContent).toBe('of 2,000');
    const points = audit.querySelector('[data-field=points]')!;
    expect(points.textContent).toBe('97 of 1,020');
    expect(points.querySelector(`.${css.tick}`)!.textContent).toBe('97');
    expect(h.field(audit, 'issues')).toBe('4 low');
    const low = audit.querySelector('[data-field=issues] [data-severity="low"]')!;
    expect(low.textContent).toBe('4 low');
    expect(low.classList.contains(css.sev!)).toBe(true);
    expect(audit.querySelector(`[data-field=elapsed] .${css.tick}`)!.textContent).toBe('1:04');
    expect(audit.getAttribute('aria-label')).toBe(
      'Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468 checks, 4 issues: 4 low, 1 minute 4 seconds.',
    );

    // Done, stopped early: the success dot, the D4 sentence as the sub-line with the full text as its title.
    const dead = h.row(DEAD);
    expect(dead.getAttribute('data-state')).toBe('done');
    expect(h.field(dead, 'state')).toBe('Done');
    const sub = dead.querySelector('[data-field=sub]')!;
    expect(sub.textContent).toBe('Stopped early: too many errors from the target.');
    expect(sub.getAttribute('title')).toBe('Stopped early: too many errors from the target.');
    expect(sub.classList.contains(css.sub!)).toBe(true);
    expect(dead.querySelector(`svg.${css.ring}`)).toBeNull();
    const okDot = dead.querySelector(`.${css.dot}`)!;
    expect(okDot.getAttribute('data-tone')).toBe('success');
    expect(okDot.classList.contains(css.breathe!)).toBe(false);
    expect(h.field(dead, 'target')).toBe('127.0.0.1:8121');
    expect(h.field(dead, 'progress')).toBe('49 of 135');
    expect(h.field(dead, 'probes')).toBe('1 of 2,000');
    expect(h.field(dead, 'points')).toBe('0 of 14');
    expect(h.field(dead, 'issues')).toBe('no issues');
    expect(dead.querySelector('[data-field=issues] [data-severity]')).toBeNull();
    expect(h.field(dead, 'elapsed')).toBe('0:30');

    // Cancelling: the pending dot breathing, no ring, the Kit's scheduling words for 0 of 0 scheduled.
    const canc = h.row(CANCELLING);
    expect(h.field(canc, 'state')).toBe('Cancelling');
    expect(canc.querySelector(`svg.${css.ring}`)).toBeNull();
    const pend = canc.querySelector(`.${css.dot}`)!;
    expect(pend.getAttribute('data-tone')).toBe('pending');
    expect(pend.classList.contains(css.breathe!)).toBe(true);
    expect(h.field(canc, 'progress')).toBe('Scheduling checks');
    expect(h.field(canc, 'probes')).toBe('46 of 2,000');
    expect(h.field(canc, 'issues')).toBe('no issues yet');
    expect(h.field(canc, 'elapsed')).toBe('0:21');

    // Done, light-http: two severity words in their inks, `, ` between.
    const light = h.row(LIGHT);
    expect(h.field(light, 'state')).toBe('Done');
    expect(light.querySelector('[data-field=sub]')).toBeNull();
    expect(h.field(light, 'profile')).toBe('light-http');
    expect(h.field(light, 'target')).toBe('127.0.0.1:8120');
    expect(h.field(light, 'progress')).toBe('171 of 171');
    expect(h.field(light, 'probes')).toBe('143 of 2,000');
    expect(h.field(light, 'points')).toBe('36 of 36');
    expect(h.field(light, 'issues')).toBe('1 high, 2 low');
    const sev = Array.from(light.querySelectorAll('[data-field=issues] [data-severity]'));
    expect(sev.map((e) => e.getAttribute('data-severity'))).toEqual(['high', 'low']);
    expect(sev.map((e) => e.textContent)).toEqual(['1 high', '2 low']);
    expect(h.field(light, 'elapsed')).toBe('1:35');

    // No row owns a reader-visible Cancel (the card's is the keyboard path); nothing carries `data-count`.
    for (const o of options) expect(o.querySelector('button[aria-label^="Cancel scan"]')).toBeNull();
    expect(h.r.container.querySelector('[data-count]')).toBeNull();
  });

  it('caption_describes_the_listbox: `4 jobs · 1 running` reaches the listbox through aria-describedby on a hidden span', () => {
    const h = mount([auditing(), deadTarget(), cancelling(), lightDone()], AUDIT);
    const list = h.list();
    const id = list.getAttribute('aria-describedby');
    expect(id).not.toBeNull();
    const caption = document.getElementById(id!)!;
    expect(caption).not.toBeNull();
    expect(caption.textContent).toBe('4 jobs · 1 running');
    expect(caption.classList.contains(css.visuallyHidden!)).toBe(true);
    expect(list.getAttribute('aria-label')).toBe('Jobs');
  });
});

describe('JobsTable: the hover Cancel (D14, AC38)', () => {
  it('hover_cancel_is_pointer_only: hidden from readers and the tab order; a click sends one scan.cancel and moves no selection; disabled while the bus is away', async () => {
    const h = mount(compRows(), AUDIT);
    await tick();
    const button = h.cancel(h.row(AUDIT))!;
    expect(button).not.toBeNull();
    expect(button.tagName).toBe('BUTTON');
    expect(button.textContent).toBe('Cancel');
    expect(button.getAttribute('aria-hidden')).toBe('true');
    expect(button.tabIndex).toBe(-1);
    expect(button.getAttribute('aria-label')).toBeNull();
    expect(button.classList.contains(css.hoverCancel!)).toBe(true);
    expect(button.disabled).toBe(false);
    // The crawling row has one too; terminal and cancelling rows have none (D2: one cancel per job).
    expect(h.cancel(h.row(CRAWL))).not.toBeNull();
    expect(h.cancel(h.row(DEAD))).toBeNull();
    expect(h.cancel(h.row(CANCELLING))).toBeNull();
    expect(h.cancel(h.row(LIGHT))).toBeNull();

    h.setSel(CRAWL);
    fireEvent.click(h.cancel(h.row(AUDIT))!);
    await tick();
    expect(h.argsOf('scan.cancel')).toEqual([{ job: AUDIT }]);
    expect(h.onSelect).not.toHaveBeenCalled();
    expect(h.row(CRAWL).getAttribute('aria-selected')).toBe('true');

    h.setBusState('closed');
    expect(h.cancel(h.row(AUDIT))!.disabled).toBe(true);
    expect(h.cancel(h.row(CRAWL))!.disabled).toBe(true);
    h.setBusState('open');
    expect(h.cancel(h.row(AUDIT))!.disabled).toBe(false);
  });
});

describe('JobsTable: selection and keyboard (D12, D14)', () => {
  it('keys_select_without_pointer_cause: the arrows report `keyboard`, a click `pointer`; Enter and ArrowRight hand focus to the card', () => {
    const h = mount(compRows(), AUDIT);
    const list = h.list();
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(h.onSelect).toHaveBeenLastCalledWith(DEAD, 'keyboard');
    expect(h.row(DEAD).getAttribute('aria-selected')).toBe('true');
    expect(h.row(AUDIT).getAttribute('aria-selected')).toBe('false');
    fireEvent.keyDown(list, { key: 'ArrowUp' });
    expect(h.onSelect).toHaveBeenLastCalledWith(AUDIT, 'keyboard');
    fireEvent.keyDown(list, { key: 'End' });
    expect(h.onSelect).toHaveBeenLastCalledWith(LIGHT, 'keyboard');
    fireEvent.keyDown(list, { key: 'Home' });
    expect(h.onSelect).toHaveBeenLastCalledWith(CRAWL, 'keyboard');

    fireEvent.click(h.row(LIGHT));
    expect(h.onSelect).toHaveBeenLastCalledWith(LIGHT, 'pointer');
    expect(h.onSelect).toHaveBeenCalledTimes(5);

    expect(h.onFocusCard).not.toHaveBeenCalled();
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(h.onFocusCard).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(list, { key: 'ArrowRight' });
    expect(h.onFocusCard).toHaveBeenCalledTimes(2);
    expect(h.onSelect).toHaveBeenCalledTimes(5);
  });

  it('rows_are_keyed_by_job: a poll with fresh objects keeps every row node and remounts only the counter that changed', () => {
    const h = mount(compRows(), AUDIT);
    const auditBefore = h.row(AUDIT);
    const crawlBefore = h.row(CRAWL);
    const progressTick = auditBefore.querySelector(`[data-field=progress] .${css.tick}`)!;
    const elapsedTick = auditBefore.querySelector(`[data-field=elapsed] .${css.tick}`)!;
    expect(elapsedTick.textContent).toBe('1:04');

    // The next poll: new facts objects, only the auditing row's elapsed time moved.
    h.setRows([crawling(), auditing(65_000), deadTarget(), cancelling(), lightDone()]);
    expect(h.row(AUDIT)).toBe(auditBefore);
    expect(h.row(CRAWL)).toBe(crawlBefore);
    expect(auditBefore.querySelector(`[data-field=progress] .${css.tick}`)).toBe(progressTick);
    const elapsedAfter = auditBefore.querySelector(`[data-field=elapsed] .${css.tick}`)!;
    expect(elapsedAfter).not.toBe(elapsedTick);
    expect(elapsedAfter.textContent).toBe('1:05');
    expect(auditBefore.getAttribute('aria-label')).toBe(
      'Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468 checks, 4 issues: 4 low, 1 minute 5 seconds.',
    );

    // A job leaves the list: its row goes, the others stay.
    h.setRows([auditing(65_000), deadTarget(), cancelling(), lightDone()]);
    expect(h.r.container.querySelector(`[role=option][data-job="${CRAWL}"]`)).toBeNull();
    expect(h.row(AUDIT)).toBe(auditBefore);
    expect(h.r.getAllByRole('option')).toHaveLength(4);
  });

  it('entrance_marks_the_first_generation_only: `.enter` at block index 2, `data-entrance` play / none while first, absent after', () => {
    const h = mount(compRows(), AUDIT, { first: true, play: true });
    const list = h.list();
    expect(list.classList.contains(css.enter!)).toBe(true);
    expect(list.style.getPropertyValue('--jobs-i')).toBe('2');
    expect(list.getAttribute('data-entrance')).toBe('play');
    h.setPlay(false);
    expect(list.getAttribute('data-entrance')).toBe('none');
    h.setFirst(false);
    expect(list.getAttribute('data-entrance')).toBeNull();
    h.setPlay(true);
    expect(list.getAttribute('data-entrance')).toBeNull();
  });
});
