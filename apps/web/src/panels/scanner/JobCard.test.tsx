// The selected job's card (spec D18 W2, D11–D14; plan Task 3.8a; AC37, AC38): the comp's running
// job rendered block for block in the Kit's words — the chip, the heading, the finding line's
// parts, the three verbs, the lane with its now mark and tag, the scale row, the ledger, the gauge,
// the KPI strip — then the cancelling, done, dead-target, budget-warning and offline variants, the
// end swap, Scan Again's send and refusal, Escape to the listbox, and the entrance indices.
//
// Facts are built from wire shapes (`parseJobStatus` / `parseJobSummary`) the way the view builds
// them from the store; the store is mounted for what the verbs send. Nothing here is evidence a
// scan ran: it pins that the card renders the contract.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, within } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { AppProvider } from '~/state/context';
import { stubApp } from './testkit';
import {
  CANCEL_SCAN_HELP,
  clock,
  jobFacts,
  KPI_LABELS,
  SHOW_ISSUES_HELP,
  SHOW_SITE_MAP_HELP,
  type JobFacts,
} from './helpers';
import { parseJobStatus, parseJobSummary } from './model';
import { scanStore, type ScanStore } from './store';
import { JobCard } from './JobCard';
import css from './jobs.module.css';

const JOB = 'scan-c0ffee01';
/** A second job the card is handed without a remount (the selection moved). */
const OTHER = 'scan-0ddba11e';
/** 11:32 UTC; the finding line and the scale row print it in the test's own zone. */
const STARTED_AT = Date.UTC(2026, 10, 2, 11, 32, 0);
const zone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;
const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

/** The comp's running job (AC37): `standard` on `127.0.0.1:8117`, 3,236 of 6,468, 287 of 2,000, 97 of 1,020, 4 low, four running ids. */
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

/** A finished comp job: 1:09, done. */
const doneStatus = (over: Record<string, unknown> = {}): Record<string, unknown> =>
  compStatus({
    state: 'done',
    phase: 'done',
    elapsed_ms: 69_000,
    finished_at: STARTED_AT + 69_000,
    checks: { scheduled: 6468, done: 6468, running: [] },
    points: { found: 1020, queued: 0, audited: 1020, skipped: { ignored: 0, frequent: 0, limit: 0 } },
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

interface MountProps {
  generation?: number;
  play?: boolean;
  launchNotices?: string[];
}

/** The card under the real provider, beside a bare listbox (what Escape returns focus to). */
function mount(initial: JobFacts, props: MountProps = {}, opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  s.setTab('jobs');
  const [facts, setFacts] = createSignal(initial);
  const [generation, setGeneration] = createSignal(props.generation ?? 1);
  const [play, setPlay] = createSignal(props.play ?? true);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <div>
        <JobCard facts={facts()} generation={generation()} play={play()} launchNotices={props.launchNotices ?? []} />
        <div role="listbox" aria-label="Jobs" tabIndex={0} />
      </div>
    </AppProvider>
  ));
  const card = () => r.getByRole('region', { name: 'Selected job' });
  const field = (name: string): HTMLElement => {
    const el = card().querySelector(`[data-field="${name}"]`);
    if (!(el instanceof HTMLElement)) throw new Error(`no [data-field=${name}]`);
    return el;
  };
  const text = (name: string): string => field(name).textContent ?? '';
  const button = (name: string) => within(card()).getByRole('button', { name }) as HTMLButtonElement;
  const nowDot = () => card().querySelector(`.${css.nowDot}`);
  return { ...stub, s, r, card, field, text, button, nowDot, setFacts, setGeneration, setPlay };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
  vi.useRealTimers();
});

describe('JobCard: the comp', () => {
  it('comp_running_card (AC37): every block of the locked comp in the Kit words', () => {
    const h = mount(factsOf(compStatus()));
    const card = h.card();
    expect(card.getAttribute('data-job')).toBe(JOB);
    expect(card.getAttribute('data-state')).toBe('running');
    expect(card.getAttribute('data-tone')).toBe('progress');

    // 1. Title row: the chip (static dot), the heading, the finding line in parts, the verbs.
    const chip = h.field('state');
    expect(chip.classList.contains(css.chip!)).toBe(true);
    expect(chip.textContent).toBe('Auditing');
    expect(chip.querySelector(`.${css.chipDot}`)!.classList.contains(css.breathe!)).toBe(false);
    const heading = card.querySelector('h2')!;
    expect(heading.textContent).toBe('127.0.0.1:8117');
    expect(heading.classList.contains(css.heading!)).toBe(true);
    expect(heading.getAttribute('title')).toBeNull();
    expect(card.querySelector('[data-field=stopped]')).toBeNull();
    const finding = h.text('finding');
    expect(finding.startsWith('4 low issues so far · xss-reflected and 3 more checks running now · standard · started ')).toBe(true);
    expect(finding.endsWith(' by the operator')).toBe(true);
    const parts = Array.from(h.field('finding').querySelectorAll(`.${css.part}`));
    expect(parts[0]!.getAttribute('data-role')).toBe('figure');
    expect(parts[0]!.textContent).toBe('4');
    expect(h.field('finding').querySelector('[data-role=checkId]')!.textContent).toBe('xss-reflected');
    expect(h.field('finding').querySelector('[data-role=agent]')).toBeNull();

    const siteMap = h.button('Show Site Map');
    expect(siteMap.getAttribute('title')).toBe(SHOW_SITE_MAP_HELP);
    const issues = h.button('Show Issues');
    expect(issues.getAttribute('title')).toBe(SHOW_ISSUES_HELP);
    const cancel = h.button(`Cancel scan ${JOB}`);
    expect(cancel.disabled).toBe(false);
    expect(cancel.textContent).toBe('Cancel Scan');
    expect(cancel.getAttribute('title')).toBe(CANCEL_SCAN_HELP);
    expect(within(card).queryByRole('button', { name: `Scan again ${JOB}` })).toBeNull();
    expect(card.querySelector('[data-field=scan-again-error]')).toBeNull();
    // The verbs sit in the title row, in the comp's order.
    expect(Array.from(card.querySelectorAll(`.${css.titleRow} button`)).map((b) => b.textContent)).toEqual([
      'Show Site Map',
      'Show Issues',
      'Cancel Scan',
    ]);
    h.s.setAllJobs(true);
    fireEvent.click(issues);
    expect(h.s.tab()).toBe('issues');
    expect(h.s.allJobs()).toBe(false);
    fireEvent.click(siteMap);
    expect(h.s.tab()).toBe('sitemap');

    // 2. The lane: one progressbar, the crawl cap, the audit fill at the fraction, the now mark and tag.
    const lane = h.field('lane');
    expect(lane.getAttribute('role')).toBe('progressbar');
    expect(lane.getAttribute('aria-label')).toBe('Progress');
    expect(lane.getAttribute('aria-valuenow')).toBe('50');
    expect(lane.getAttribute('aria-valuetext')).toBe('50 percent');
    expect(lane.getAttribute('data-fraction')).toBe('0.5003');
    expect(lane.getAttribute('title')).toBe("3,236 of 6,468 checks (derived from the engine's counters)");
    expect(lane.style.getPropertyValue('--jobs-f')).toBe('0.5003092145949288');
    const track = lane.querySelector(`.${css.track}`)!;
    const crawl = track.querySelector(`.${css.crawl}`)!;
    expect(crawl.querySelector(`.${css.segLabel}`)!.textContent).toBe('crawl');
    expect(crawl.querySelector(`.${css.segSub}`)!.textContent).toBe('46 pages');
    const audit = track.querySelector(`.${css.audit}`)!;
    expect(audit.querySelector(`.${css.segLabel}`)!.textContent).toBe('audit');
    expect(audit.querySelector(`.${css.segSub}`)!.textContent).toBe('3,236 checks done');
    expect(h.text('to-go')).toBe('3,232 checks to go');
    expect(h.field('to-go').classList.contains(css.toGo!)).toBe(true);
    // The now mark and the tag are children of the audit fill (they ride its trailing edge).
    const mark = audit.querySelector(`.${css.nowMark}`)!;
    expect(mark).not.toBeNull();
    expect(mark.getAttribute('aria-hidden')).toBe('true');
    expect(h.nowDot()!.classList.contains(css.breathe!)).toBe(true);
    const now = h.field('now');
    expect(now.closest(`.${css.audit}`)).toBe(audit);
    expect(now.classList.contains(css.nowTag!)).toBe(true);
    expect(now.textContent).toBe('now · xss-reflected and 3 more');
    expect(now.querySelector('[data-role=checkId]')!.textContent).toBe('xss-reflected');
    // The end sentence's live region is in place and empty while the job runs.
    const end = h.field('end');
    expect(end.getAttribute('aria-live')).toBe('polite');
    expect(end.textContent).toBe('');
    expect(end.classList.contains(css.endSwap!)).toBe(false);
    const scale = lane.querySelector(`.${css.scale}`)!;
    const scaleParts = Array.from(scale.children).map((c) => c.textContent);
    expect(scaleParts).toEqual([`started ${clock(STARTED_AT, zone())}`, 'elapsed 1:04', 'at this pace, about 1:04 to go']);
    const estimate = h.field('estimate');
    expect(estimate.getAttribute('title')).toBe(
      'Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second, 3,232 to go.',
    );

    // 3. The ledger: four low marks and the word.
    const ledger = h.field('ledger');
    expect(ledger.getAttribute('role')).toBe('img');
    expect(ledger.getAttribute('aria-label')).toBe('4 issues: 4 low');
    const marks = ledger.querySelectorAll(`.${css.mark}[data-severity="low"]`);
    expect(marks).toHaveLength(4);
    expect(ledger.querySelectorAll(`.${css.group}`)).toHaveLength(1);
    expect(ledger.querySelector(`.${css.group}`)!.getAttribute('data-severity')).toBe('low');
    const word = h.field('ledger-word');
    expect(word.textContent).toBe('4 low');
    expect(word.getAttribute('data-severity')).toBe('low');
    expect(word.classList.contains(css.sev!)).toBe(true);
    expect(card.querySelector('[data-count]')).toBeNull();

    // 4. The gauge: label, a 14.35 % fill in the resting ink, the text.
    const gauge = h.field('gauge');
    expect(gauge.getAttribute('role')).toBe('img');
    expect(gauge.getAttribute('aria-label')).toBe('Probe budget, 287 of 2,000');
    expect(gauge.hasAttribute('data-warn')).toBe(false);
    expect(gauge.getAttribute('title')).toBe('287 of 2,000 probes sent (the probe budget, not progress)');
    expect(gauge.textContent).toBe('probe budget287 of 2,000');
    const fill = gauge.querySelector(`.${css.gaugeFill}`) as HTMLElement;
    expect(fill.style.width).toBe('14.35%');

    // 5. The KPI strip: five cells, numerals through the tick, units and the severity word.
    const kpis = h.field('kpis');
    const cells = Array.from(kpis.querySelectorAll(`.${css.kpi}`)) as HTMLElement[];
    expect(cells.map((c) => c.getAttribute('data-kpi'))).toEqual([...KPI_LABELS]);
    expect(cells.map((c) => c.querySelector(`.${css.kpiLabel}`)!.textContent)).toEqual([...KPI_LABELS]);
    const numerals = cells.map((c) => c.querySelector(`.${css.tick}`)!.textContent);
    expect(numerals).toEqual(['50 %', '3,236', '287', '97', '4']);
    expect(cells[0]!.querySelector(`.${css.kpiValue}`)!.getAttribute('data-ink')).toBe('accent');
    expect(cells[0]!.getAttribute('title')).toBe("3,236 of 6,468 checks (derived from the engine's counters)");
    expect(cells.slice(1, 4).map((c) => c.querySelector(`.${css.kpiUnit}`)!.textContent)).toEqual(['of 6,468', 'of 2,000', 'of 1,020']);
    expect(cells[2]!.getAttribute('title')).toBe('287 of 2,000 probes sent (the probe budget, not progress)');
    const issuesCell = cells[4]!;
    expect(issuesCell.getAttribute('title')).toBe('4 issues: 4 low');
    const sev = issuesCell.querySelector(`.${css.sev}`)!;
    expect(sev.getAttribute('data-severity')).toBe('low');
    expect(sev.textContent).toBe('4 low');

    // 6. Nothing to draw attention to: no block at all.
    expect(card.querySelector('[data-field=attention]')).toBeNull();
    expect(card.querySelector('[data-field="stopped-raw"]')).toBeNull();
  });

  it('scheduling_card: the phase line sits in the empty track as .phaseLine, after the cap; a queued job has it alone', () => {
    // Auditing with nothing scheduled yet (D11 §2): the cap, then `Scheduling checks` inside the empty track.
    const h = mount(factsOf(compStatus({ checks: { scheduled: 0, done: 0, running: [] } })));
    const lane = h.field('lane');
    expect(lane.getAttribute('aria-valuenow')).toBeNull();
    expect(lane.getAttribute('aria-valuetext')).toBe('Scheduling checks');
    const track = lane.querySelector(`.${css.track}`)!;
    expect(track.querySelector(`.${css.crawl}`)).not.toBeNull();
    expect(track.querySelector(`.${css.audit}`)).toBeNull();
    const phase = h.field('phase');
    expect(phase.textContent).toBe('Scheduling checks');
    expect(phase.classList.contains(css.phaseLine!)).toBe(true);
    expect(phase.classList.contains(css.toGo!)).toBe(false);
    expect(h.card().querySelector('[data-field=to-go]')).toBeNull();
    // The cap precedes the line in the track, so the sheet's `.crawl ~ .phaseLine` offset applies.
    expect(phase.previousElementSibling?.classList.contains(css.crawl!)).toBe(true);

    // Queued: the empty track with the phase line centred inside, no cap, no mark.
    h.setFacts(factsOf(compStatus({ state: 'queued', phase: 'queued', checks: { scheduled: 0, done: 0, running: [] } })));
    const queued = h.field('phase');
    expect(queued.textContent).toBe('Waiting for the engine to start this job.');
    expect(queued.classList.contains(css.phaseLine!)).toBe(true);
    expect(h.field('lane').querySelector(`.${css.crawl}`)).toBeNull();
    expect(h.field('lane').querySelector(`.${css.nowMark}`)).toBeNull();
  });

  it('cancelling_card: the chip breathes, the primary verb reads Cancelling… and is off, the now dot is still', () => {
    const h = mount(factsOf(compStatus({ state: 'cancelling' })));
    const card = h.card();
    expect(card.getAttribute('data-tone')).toBe('pending');
    const chip = h.field('state');
    expect(chip.textContent).toBe('Cancelling');
    expect(chip.querySelector(`.${css.chipDot}`)!.classList.contains(css.breathe!)).toBe(true);
    const cancel = h.button(`Cancel scan ${JOB}`);
    expect(cancel.disabled).toBe(true);
    expect(cancel.textContent).toBe('Cancelling…');
    // The lane is frozen at its value; the dot stops breathing (D11 §2, D12).
    expect(h.field('lane').getAttribute('data-fraction')).toBe('0.5003');
    expect(h.nowDot()).not.toBeNull();
    expect(h.nowDot()!.classList.contains(css.breathe!)).toBe(false);
    expect(h.text('now')).toBe('now · xss-reflected and 3 more');
    // No estimate while cancelling.
    expect(h.text('estimate')).toBe('');
  });

  it('done_card_scan_again: the end sentence swaps in, Scan Again sends scan.start, a refusal is the verb’s title and a line', async () => {
    const h = mount(factsOf(doneStatus()));
    h.reply('scan.status', doneStatus());
    await h.s.refreshStatus(JOB);
    const card = h.card();
    expect(card.getAttribute('data-tone')).toBe('success');
    expect(h.text('state')).toBe('Done');
    expect(h.text('finding')).toBe(
      `standard · started ${clock(STARTED_AT, zone())} by the operator · finished ${clock(STARTED_AT + 69_000, zone())}`,
    );
    const end = h.field('end');
    expect(end.textContent).toBe('Done in 1:09 · 1,020 points · 6,468 checks.');
    expect(end.getAttribute('aria-live')).toBe('polite');
    expect(end.classList.contains(css.endSentence!)).toBe(true);
    expect(end.classList.contains(css.endSwap!)).toBe(true);
    // The mark, the right label, the now tag and the estimate are gone; the lane is frozen at its final fraction.
    expect(card.querySelector(`.${css.nowMark}`)).toBeNull();
    expect(card.querySelector('[data-field=to-go]')).toBeNull();
    expect(card.querySelector('[data-field=now]')).toBeNull();
    expect(h.text('estimate')).toBe('');
    expect(h.field('lane').getAttribute('data-fraction')).toBe('1.0000');
    expect(h.field('lane').getAttribute('aria-valuetext')).toBe('');
    expect(h.field('lane').hasAttribute('aria-valuenow')).toBe(false);
    expect(Array.from(h.field('lane').querySelector(`.${css.scale}`)!.children).map((c) => c.textContent)).toEqual([
      `started ${clock(STARTED_AT, zone())}`,
      'elapsed 1:09',
      '',
    ]);
    // The KPI strip: no percent once finished (the Kit's `—`), the counters final.
    const cells = Array.from(h.field('kpis').querySelectorAll(`.${css.kpi}`));
    expect(cells.map((c) => c.querySelector(`.${css.tick}`)!.textContent)).toEqual(['—', '6,468', '287', '1,020', '4']);

    expect(within(card).queryByRole('button', { name: `Cancel scan ${JOB}` })).toBeNull();
    const again = h.button(`Scan again ${JOB}`);
    expect(again.textContent).toBe('Scan Again');
    expect(again.disabled).toBe(false);
    expect(again.getAttribute('title')).toBe('Start a new job with profile standard against 127.0.0.1:8117');
    fireEvent.click(again);
    await tick();
    expect(h.argsOf('scan.start')).toEqual([{ profile_name: 'standard', overrides: { target: { origins: ['http://127.0.0.1:8117'] } } }]);
    expect(card.querySelector('[data-field=scan-again-error]')).toBeNull();

    // A core refusal reads under the title row and as the verb's title; Escape clears it and hands focus to the listbox.
    h.fail('scan.start', 'scan: busy: another scan is running');
    fireEvent.click(h.button(`Scan again ${JOB}`));
    await tick();
    const refusal = 'Busy: another scan is running (max_jobs or an origin already being scanned)';
    const line = h.field('scan-again-error');
    expect(line.textContent).toBe(`Unable to scan again: ${refusal}`);
    expect(line.classList.contains(css.scanAgainError!)).toBe(true);
    expect(h.button(`Scan again ${JOB}`).getAttribute('title')).toBe(refusal);
    h.button(`Scan again ${JOB}`).focus();
    fireEvent.keyDown(h.button(`Scan again ${JOB}`), { key: 'Escape' });
    expect(document.activeElement).toBe(h.r.getByRole('listbox', { name: 'Jobs' }));
    expect(card.querySelector('[data-field=scan-again-error]')).toBeNull();
    expect(h.button(`Scan again ${JOB}`).getAttribute('title')).toBe('Start a new job with profile standard against 127.0.0.1:8117');
  });

  it('dead_target_card (AC37): the D4 sentence, the attention disclosure with its sample, the raw token once', () => {
    const raw = doneStatus({
      stopped_reason: 'errors',
      elapsed_ms: 4_000,
      finished_at: STARTED_AT + 4_000,
      checks: {
        scheduled: 135,
        done: 49,
        running: [],
        errors: 7,
        error_samples: [{ check: 'xss-reflected', point: 'GET /login', detail: 'connection refused' }],
      },
      points: { found: 12, queued: 0, audited: 12, skipped: { ignored: 0, frequent: 0, limit: 0 } },
      issues: {
        total: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        by_confidence: { certain: 0, firm: 0, tentative: 0 },
      },
    });
    const h = mount(factsOf(raw));
    const card = h.card();
    expect(h.text('state')).toBe('Done');
    expect(h.text('stopped')).toBe('Stopped early: too many errors from the target.');
    expect(h.field('stopped').classList.contains(css.reason!)).toBe(true);
    expect(h.text('end')).toBe('Done in 0:04 · 12 points · 135 checks.');
    const attention = h.field('attention');
    const details = attention.querySelector('details')!;
    expect(details.querySelector('summary')!.textContent).toBe('7 checks could not run');
    expect(Array.from(details.querySelectorAll('li')).map((li) => li.textContent)).toEqual(['xss-reflected · connection refused']);
    const rawLine = h.field('stopped-raw');
    expect(rawLine.textContent).toBe('stopped_reason: errors');
    expect(rawLine.classList.contains(css.rawLine!)).toBe(true);
    expect(rawLine.closest('[data-field=attention]')).toBe(attention);
    // Apart from the sentence, the raw line is the only `errors` token inside the region.
    const rest = (card.textContent ?? '').replace('Stopped early: too many errors from the target.', '');
    expect(rest.match(/\berrors\b/g)).toEqual(['errors']);
    // The order: sentence above the finding line, the raw line below the disclosure.
    expect(h.field('stopped').compareDocumentPosition(h.field('finding')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(details.compareDocumentPosition(rawLine) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // No issues: the ledger and the Issues cell say so in the muted ink.
    expect(h.field('ledger').getAttribute('aria-label')).toBe('no issues');
    expect(h.text('ledger-word')).toBe('no issues');
    expect(h.field('ledger-word').getAttribute('data-ink')).toBe('muted');
    expect(h.field('ledger').querySelector(`.${css.mark}`)).toBeNull();
    const issuesCell = h.field('kpis').querySelectorAll(`.${css.kpi}`)[4]!;
    expect(issuesCell.querySelector(`.${css.tick}`)!.textContent).toBe('0');
    expect(issuesCell.querySelector('[data-ink=muted]')!.textContent).toBe('no issues');
  });

  it('budget_warning_gauge: 41 of 50 probes on `tiny-budget` turns the gauge amber', () => {
    const h = mount(
      factsOf(
        compStatus({
          profile_name: 'tiny-budget',
          probes: { sent: 41, budget: 50, errors: 0, timeouts: 0, rate_waits: 0, by_lane: { http: 41 } },
        }),
      ),
    );
    const gauge = h.field('gauge');
    expect(gauge.getAttribute('data-warn')).toBe('true');
    expect(gauge.getAttribute('aria-label')).toBe('Probe budget, 41 of 50');
    expect((gauge.querySelector(`.${css.gaugeFill}`) as HTMLElement).style.width).toBe('82%');
    expect(h.field('kpis').querySelectorAll(`.${css.kpi}`)[2]!.textContent).toBe('Probes41of 50');
  });

  it('offline_card (AC38): every verb is disabled while the bus is not open and the now dot does not breathe', async () => {
    const h = mount(factsOf(compStatus()));
    expect(h.nowDot()!.classList.contains(css.breathe!)).toBe(true);
    h.setBusState('reconnecting');
    await tick();
    const buttons = Array.from(h.card().querySelectorAll('button')) as HTMLButtonElement[];
    expect(buttons.map((b) => b.textContent)).toEqual(['Show Site Map', 'Show Issues', 'Cancel Scan']);
    expect(buttons.every((b) => b.disabled)).toBe(true);
    expect(h.nowDot()!.classList.contains(css.breathe!)).toBe(false);
    // The values stay.
    expect(h.text('to-go')).toBe('3,232 checks to go');
    h.setBusState('open');
    await tick();
    expect(h.button(`Cancel scan ${JOB}`).disabled).toBe(false);
    expect(h.nowDot()!.classList.contains(css.breathe!)).toBe(true);
  });

  it('offline_scan_again (AC38, gap 79): Scan again <job> on a done card is off while the bus is reconnecting and on again when it opens', async () => {
    const h = mount(factsOf(doneStatus()));
    expect(h.button(`Scan again ${JOB}`).disabled).toBe(false);
    h.setBusState('reconnecting');
    await tick();
    expect(h.button(`Scan again ${JOB}`).disabled).toBe(true);
    h.setBusState('open');
    await tick();
    expect(h.button(`Scan again ${JOB}`).disabled).toBe(false);
  });

  it('cancel_in_flight_is_per_job (gap 79): a Cancel awaiting its reply reads Cancelling…; a new job on the card gets a fresh, enabled Cancel Scan', async () => {
    const h = mount(factsOf(compStatus()), {}, { replies: { 'scan.cancel': () => new Promise<never>(() => {}) } });
    fireEvent.click(h.button(`Cancel scan ${JOB}`));
    await tick();
    expect(h.count('scan.cancel')).toBe(1);
    expect(h.button(`Cancel scan ${JOB}`).disabled).toBe(true);
    expect(h.button(`Cancel scan ${JOB}`).textContent).toBe('Cancelling…');
    h.setFacts(factsOf(compStatus({ job: OTHER })));
    await tick();
    const cancel = h.button(`Cancel scan ${OTHER}`);
    expect(cancel.disabled).toBe(false);
    expect(cancel.textContent).toBe('Cancel Scan');
  });

  it('cancel_finally_guard_is_per_job (spec round 2): a late reply to the last job’s Cancel does not clear the Cancelling… the next job has in flight', async () => {
    // One deferred per `scan.cancel` call, keyed by the job it names; the test resolves each by hand.
    const pending = new Map<string, (status: Record<string, unknown>) => void>();
    const h = mount(
      factsOf(compStatus()),
      {},
      {
        replies: {
          'scan.cancel': (args: Record<string, unknown>) =>
            new Promise<Record<string, unknown>>((resolveReply) => {
              pending.set(String(args.job), resolveReply);
            }),
        },
      },
    );
    fireEvent.click(h.button(`Cancel scan ${JOB}`));
    await tick();
    expect(h.count('scan.cancel')).toBe(1);
    expect(h.button(`Cancel scan ${JOB}`).textContent).toBe('Cancelling…');
    expect(h.button(`Cancel scan ${JOB}`).disabled).toBe(true);
    // The selection moves: OTHER on the same card, and its own Cancel is sent.
    h.setFacts(factsOf(compStatus({ job: OTHER })));
    await tick();
    fireEvent.click(h.button(`Cancel scan ${OTHER}`));
    await tick();
    expect(h.count('scan.cancel')).toBe(2);
    expect([...pending.keys()]).toEqual([JOB, OTHER]);
    expect(h.button(`Cancel scan ${OTHER}`).textContent).toBe('Cancelling…');
    // JOB's reply lands late. It is not OTHER's: OTHER's Cancel stays in flight.
    pending.get(JOB)!(compStatus({ state: 'cancelling' }));
    await tick();
    expect(h.button(`Cancel scan ${OTHER}`).textContent).toBe('Cancelling…');
    expect(h.button(`Cancel scan ${OTHER}`).disabled).toBe(true);
    // OTHER's own reply clears it.
    pending.get(OTHER)!(compStatus({ job: OTHER, state: 'cancelling' }));
    await tick();
    expect(h.button(`Cancel scan ${OTHER}`).textContent).toBe('Cancel Scan');
    expect(h.button(`Cancel scan ${OTHER}`).disabled).toBe(false);
  });

  it('entrance_indices: the title row, the lane block and the KPI strip enter at indices 0, 1, 2; the card says whether it plays', () => {
    const h = mount(factsOf(compStatus()), { generation: 3, play: true });
    const card = h.card();
    expect(card.getAttribute('data-generation')).toBe('3');
    expect(card.getAttribute('data-entrance')).toBe('play');
    const blocks = Array.from(card.querySelectorAll(`.${css.enter}`)) as HTMLElement[];
    expect(blocks).toHaveLength(3);
    expect(blocks.map((b) => b.style.getPropertyValue('--jobs-i'))).toEqual(['0', '1', '2']);
    expect(blocks[0]!.classList.contains(css.titleRow!)).toBe(true);
    expect(blocks[1]!.classList.contains(css.lane!)).toBe(true);
    expect(blocks[1]!.contains(h.field('ledger'))).toBe(true);
    expect(blocks[1]!.contains(h.field('gauge'))).toBe(true);
    expect(blocks[2]!.classList.contains(css.kpis!)).toBe(true);
    // A keyboard selection: the same generation, nothing plays.
    h.setPlay(false);
    expect(h.card().getAttribute('data-entrance')).toBe('none');
    expect(h.card().getAttribute('data-generation')).toBe('3');
  });
});
