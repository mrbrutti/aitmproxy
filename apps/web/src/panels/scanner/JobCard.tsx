// The selected job's card (spec D18 W2, D11–D14; plan Task 3.8a): the locked comp's blocks, top
// to bottom, every class from `jobs.module.css`, every string from `helpers.ts`, every shared part
// from `jobParts.tsx`. The `role="region" aria-label="Selected job"` section the live script calls
// `STRIP` on the Jobs tab carries `data-job`, `data-state`, `data-tone` and the entrance's
// `data-generation` / `data-entrance`. The blocks are keyed on the generation, so a pointer
// selection, a start or the first list remounts them and `jobsEnter` plays once, staggered by
// `--jobs-i`; a keyboard selection keeps the generation and plays nothing (D12). The now mark and
// the now tag are children of the audit fill, so they ride its trailing edge and its width
// transition (plan gap 54); the end sentence's live region is in place from the start and fills
// (with `.endSwap`) once the terminal status has landed. No timer lives here (AC32).

import { createEffect, createMemo, createSignal, For, on, Show, type Component, type JSX } from 'solid-js';
import { Button } from '~/components';
import { useApp } from '~/state/context';
import {
  attention,
  budgetWarning,
  CANCEL_SCAN_HELP,
  CANCELLING_TITLE,
  clock,
  endSentence,
  findingLine,
  GAUGE_LABEL,
  gaugeAccessibilityLabel,
  grouped,
  isTerminal,
  issuesTileHelp,
  jobHeading,
  jobHeadingHelp,
  jobProgress,
  KPI_LABELS,
  LANE_AUDIT_LABEL,
  LANE_CRAWL_LABEL,
  laneChecksDone,
  lanePages,
  ledgerGroups,
  MISSING_VALUE,
  notices,
  ofText,
  probeBudgetText,
  probesTileHelp,
  progressAccessibilityValue,
  rawCrawlErrorLine,
  rawReasonLine,
  reasonLine,
  SCAN_AGAIN_ERROR_PREFIX,
  SCAN_AGAIN_HELP_GENERIC,
  scaleElapsed,
  scaleStarted,
  scanAgainHelp,
  severityWordParts,
  severityWords,
  SHOW_ISSUES_HELP,
  SHOW_SITE_MAP_HELP,
  stateWords,
  tone,
  type JobFacts,
  type LedgerGroup,
} from './helpers';
import { Parts, SeverityWords, StateChip, Tick } from './jobParts';
import { ErrorBlock } from './primitives';
import { scanStore } from './store';
import css from './jobs.module.css';

export interface JobCardProps {
  facts: JobFacts;
  /** Bumped on every selection change that plays the entrance; the card's blocks key on it. */
  generation: number;
  /** Whether this generation's entrance plays (`data-entrance="play"`) or not (`"none"`). */
  play: boolean;
  /** The launch's notices (`scan.start`'s clamps and skipped lanes, in the Kit's words) for this job. */
  launchNotices: string[];
}

/** The Jobs view's time zone for the finding line's and the scale row's clock (`started 11:32`). */
const zone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;

/** `14.35%`: a fill width from a 0…1 fraction, two decimals at most. */
const widthOf = (fraction: number): string => `${+(Math.min(1, Math.max(0, fraction)) * 100).toFixed(2)}%`;

/** The ledger marks of one group: `marks` of them (capped by `ledgerGroups`), each in the severity's ink. */
const marksOf = (group: LedgerGroup): number[] => Array.from({ length: group.marks }, (_, i) => i);

export const JobCard: Component<JobCardProps> = (props) => {
  const s = scanStore(useApp());
  const f = () => props.facts;
  const j = () => f().summary;
  const job = () => j().job;
  const terminal = () => isTerminal(j().state);
  const cancelling = () => j().state === 'cancelling';
  const offline = () => !s.busOpen();
  /** A `scan.cancel` this card sent and has not heard back from (D2: one per job). */
  const [cancelInFlight, setCancelInFlight] = createSignal(false);
  /** Off once terminal, while the merged state is `cancelling`, while a cancel is in flight, while the store is busy or the bus is away. */
  const canCancel = () => !terminal() && !cancelling() && !cancelInFlight() && !s.busy() && !offline();
  /** Scan Again: a terminal job, no launch in flight or awaiting confirmation, the bus open (D13). */
  const canScanAgain = () => terminal() && !s.busy() && s.pendingConfirm() === null && !offline();

  /* ---- Scan Again's refusal (D13): the store's launch error, shown while this card's Scan Again was the last launch. */
  const [againLaunched, setAgainLaunched] = createSignal(false);
  const launchError = s.errorFor(['launch']);
  const scanAgainError = () => (againLaunched() ? launchError() : null);
  createEffect(on(job, () => setAgainLaunched(false), { defer: true }));
  const scanAgainTitle = () => {
    const refusal = scanAgainError();
    if (refusal !== null) return refusal.text;
    const st = f().status;
    return st === null ? SCAN_AGAIN_HELP_GENERIC : scanAgainHelp(st);
  };
  const cancelError = s.errorFor(['cancel']);

  const onCancel = async (): Promise<void> => {
    setCancelInFlight(true);
    try {
      await s.cancel(job());
    } finally {
      setCancelInFlight(false);
    }
  };
  const onScanAgain = async (): Promise<void> => {
    setAgainLaunched(true);
    const outcome = await s.scanAgain(job());
    if (outcome.kind === 'started') setAgainLaunched(false);
  };

  /* ---- the words */
  const progress = createMemo(() => jobProgress(f()));
  const finding = createMemo(() => findingLine(f(), zone()));
  const attentionLines = createMemo(() => attention(f()));
  const noticeLines = createMemo(() => {
    const st = f().status;
    return st === null ? props.launchNotices : notices(st, props.launchNotices);
  });
  const hasAttention = () => {
    const st = f().status;
    return (
      attentionLines().length > 0 ||
      noticeLines().length > 0 ||
      (st !== null && (st.error !== null || st.stopped_reason !== null || st.crawl.last_error !== null))
    );
  };
  const by = () => j().issues.by_severity;
  const groups = createMemo(() => ledgerGroups(by()));
  const sent = () => j().probes.sent;
  const budget = () => j().probes.budget;
  const warn = () => budgetWarning(sent(), budget());
  /**
   * The end sentence waits for the terminal status (D9): while the list says terminal and the held
   * status is still a live read, its numbers must not be quoted.
   */
  const end = createMemo(() => {
    const st = f().status;
    return endSentence(j(), st !== null && isTerminal(st.state) ? st.checks : null);
  });

  /* ---- the lane's shape (D11 §2's phase variants) */
  const checks = () => f().status?.checks ?? null;
  const crawl = () => f().status?.crawl ?? null;
  const phase = () => j().phase;
  const live = () => !terminal();
  /** The fraction the fill and `data-fraction` read: the determinate value, or a finished job's final one. */
  const laneFraction = (): number | null => {
    const p = progress();
    if (p.fraction !== null) return p.fraction;
    const ring = p.ring;
    return typeof ring === 'object' && 'finished' in ring ? ring.finished : null;
  };
  /** Crawling draws one crawl segment at the crawling fraction; no cap, no mark, no right label. */
  const crawlingLane = () => live() && phase() === 'crawling' && checks() !== null;
  /** The cap and the audit fill: auditing, reporting, or terminal with something scheduled. */
  const auditLane = () => {
    const c = checks();
    if (c === null) return false;
    if (live()) return phase() === 'auditing' || phase() === 'reporting';
    return c.scheduled > 0;
  };
  /** The now mark rides the fill's trailing edge while the job is live. */
  const showMark = () => live() && auditLane() && laneFraction() !== null;
  const breathing = () => showMark() && !cancelling() && !offline();
  /** The phase line inside the empty track: queued, passive, scheduling, or before the status lands. */
  const phaseInTrack = () => !crawlingLane() && !auditLane() && !terminal() && progress().phaseLine !== '';
  const schedulingInTrack = () => auditLane() && live() && laneFraction() === null;
  const valueText = () => progressAccessibilityValue(progress()) ?? (terminal() ? '' : progress().phaseLine);
  const started = () => {
    const st = f().status;
    return st !== null && st.started_at > 0 ? clock(st.started_at, zone()) : MISSING_VALUE;
  };

  /* ---- the KPI strip's five cells */
  interface Kpi {
    label: string;
    numeral: string;
    unit?: string;
    help?: string;
    ink?: 'accent';
    severity?: boolean;
  }
  const kpis = createMemo<Kpi[]>(() => {
    const p = progress();
    const c = checks();
    const points = j().points;
    const total = j().issues.total;
    return [
      { label: KPI_LABELS[0]!, numeral: p.percentText ?? MISSING_VALUE, help: p.helpText, ink: 'accent' },
      c === null
        ? { label: KPI_LABELS[1]!, numeral: MISSING_VALUE }
        : { label: KPI_LABELS[1]!, numeral: grouped(c.done), unit: ofText(c.scheduled) },
      {
        label: KPI_LABELS[2]!,
        numeral: grouped(sent()),
        ...(budget() > 0 ? { unit: ofText(budget()) } : {}),
        help: probesTileHelp(sent(), budget()),
      },
      { label: KPI_LABELS[3]!, numeral: grouped(points.audited), unit: ofText(points.found) },
      { label: KPI_LABELS[4]!, numeral: grouped(total), help: issuesTileHelp(by()), severity: true },
    ];
  });

  /* ---- Escape inside the card: back to the listbox, the refusal cleared (D13, D14). */
  let root: HTMLElement | undefined;
  const onKeyDown: JSX.EventHandler<HTMLElement, KeyboardEvent> = (e) => {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    setAgainLaunched(false);
    const listbox = root?.parentElement?.querySelector<HTMLElement>('[role="listbox"]');
    listbox?.focus({ preventScroll: true });
  };

  return (
    <section
      ref={root}
      class={css.card}
      role="region"
      aria-label="Selected job"
      tabIndex={-1}
      data-job={job()}
      data-state={j().state}
      data-tone={tone(f())}
      data-generation={props.generation}
      data-entrance={props.play ? 'play' : 'none'}
      onKeyDown={onKeyDown}
    >
      {/* Keyed on the generation: a new one remounts the blocks and the entrance plays once more. */}
      <Show keyed when={String(props.generation)}>
        {/* ---- 1. the title row: chip, heading, reason and finding lines, the verbs */}
        <div class={`${css.titleRow} ${css.enter}`} style={{ '--jobs-i': 0 }}>
          <div>
            <StateChip word={stateWords(j())} tone={tone(f())} breathing={cancelling()} />
            <h2 class={css.heading} title={jobHeadingHelp(f()) ?? undefined}>
              {jobHeading(f())}
            </h2>
            <Show when={reasonLine(f())}>
              {(reason) => (
                <p class={css.reason} data-field="stopped">
                  {reason()}
                </p>
              )}
            </Show>
            <p class={css.finding} data-field="finding">
              <Parts parts={finding().parts} />
            </p>
          </div>
          <div class={css.verbs}>
            <Button variant="outline" title={SHOW_SITE_MAP_HELP} disabled={offline()} onClick={() => s.setTab('sitemap')}>
              Show Site Map
            </Button>
            <Button
              variant="outline"
              title={SHOW_ISSUES_HELP}
              disabled={offline()}
              onClick={() => {
                s.setAllJobs(false);
                s.setTab('issues');
              }}
            >
              Show Issues
            </Button>
            <Show
              when={terminal()}
              fallback={
                <Button
                  variant="primary"
                  aria-label={`Cancel scan ${job()}`}
                  title={CANCEL_SCAN_HELP}
                  disabled={!canCancel()}
                  onClick={() => void onCancel()}
                >
                  {cancelling() || cancelInFlight() ? CANCELLING_TITLE : 'Cancel Scan'}
                </Button>
              }
            >
              <Button
                variant="primary"
                aria-label={`Scan again ${job()}`}
                title={scanAgainTitle()}
                disabled={!canScanAgain()}
                onClick={() => void onScanAgain()}
              >
                Scan Again
              </Button>
            </Show>
          </div>
        </div>
        <Show when={scanAgainError()}>
          {(err) => (
            <p class={css.scanAgainError} data-field="scan-again-error">
              {SCAN_AGAIN_ERROR_PREFIX + err().text}
            </p>
          )}
        </Show>

        {/* A failed per-job read (PA4): the core's text with Retry, above the facts. */}
        <Show when={s.statusError(job())}>
          {(err) => <ErrorBlock text={err()} onRetry={() => void s.refreshStatus(job())} disabled={offline()} />}
        </Show>
        {/* The one store error this view owns (PA5): a refused cancel, beside the toast. */}
        <Show when={cancelError()}>
          {(err) => (
            <p class={css.errorText} role="alert" data-error="cancel">
              {err().text}
            </p>
          )}
        </Show>

        {/* ---- 2. the lane block: the track, the scale row, the ledger and the gauge */}
        <div class={`${css.lane} ${css.enter}`} style={{ '--jobs-i': 1 }}>
          {/* The lane is one element (D14): the track and the scale row under `Progress`; `--jobs-f` reaches the fill. */}
          <div
            data-field="lane"
            role="progressbar"
            aria-label="Progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress().fraction === null ? undefined : Math.floor(progress().fraction! * 100)}
            aria-valuetext={valueText()}
            title={progress().helpText}
            data-fraction={laneFraction() === null ? undefined : laneFraction()!.toFixed(4)}
            style={laneFraction() === null ? undefined : { '--jobs-f': String(laneFraction()) }}
          >
            <div class={css.track}>
              {/* Crawling: one crawl segment at the crawling fraction. */}
              <Show when={crawlingLane()}>
                <div class={css.crawl} style={laneFraction() === null ? undefined : { width: widthOf(laneFraction()!) }}>
                  <span class={css.segLabel}>{LANE_CRAWL_LABEL}</span>
                  <span class={`${css.segSub} ${css.unit}`}>{progress().phaseLine}</span>
                </div>
              </Show>
              {/* Auditing, reporting, terminal: the crawl cap, then the audit fill at the fraction. */}
              <Show when={auditLane()}>
                <div class={css.crawl}>
                  <span class={css.segLabel}>{LANE_CRAWL_LABEL}</span>
                  <Show when={crawl()}>{(c) => <span class={`${css.segSub} ${css.unit}`}>{lanePages(c().pages)}</span>}</Show>
                </div>
                <Show when={laneFraction() !== null}>
                  <div class={css.audit}>
                    <span class={css.segLabel}>{LANE_AUDIT_LABEL}</span>
                    <Show when={checks()}>{(c) => <span class={`${css.segSub} ${css.unit}`}>{laneChecksDone(c().done)}</span>}</Show>
                    <Show when={showMark()}>
                      <i class={css.nowMark} aria-hidden="true">
                        <i class={`${css.nowDot}${breathing() ? ` ${css.breathe}` : ''}`} />
                      </i>
                    </Show>
                    {/* The now tag under the mark: the running ids, or `Writing results` while reporting. */}
                    <Show when={live()}>
                      <Show
                        when={phase() === 'reporting'}
                        fallback={
                          <Show when={progress().nowTagParts}>
                            {(parts) => (
                              <span class={css.nowTag} data-field="now">
                                <Parts parts={parts()} />
                              </span>
                            )}
                          </Show>
                        }
                      >
                        <span class={css.nowTag} data-field="now">
                          {progress().phaseLine}
                        </span>
                      </Show>
                    </Show>
                  </div>
                </Show>
                <Show when={schedulingInTrack()}>
                  <span class={css.phaseLine} data-field="phase">
                    {progress().phaseLine}
                  </span>
                </Show>
              </Show>
              {/* Queued, passive, or before the status lands: the phase line inside the empty track. */}
              <Show when={phaseInTrack()}>
                <span class={css.phaseLine} data-field="phase">
                  {progress().phaseLine}
                </span>
              </Show>
              <Show when={progress().checksToGoText}>
                {(toGo) => (
                  <span class={css.toGo} data-field="to-go">
                    {toGo()}
                  </span>
                )}
              </Show>
              {/* The end sentence takes the now tag's place when the job ends: the tab's one live region. */}
              <span class={`${css.endSentence}${end() !== null ? ` ${css.endSwap}` : ''}`} data-field="end" aria-live="polite">
                {end() ?? ''}
              </span>
            </div>
            <div class={css.scale}>
              <span class={css.unit}>{scaleStarted(started())}</span>
              <span class={css.unit}>{scaleElapsed(j().elapsed_ms)}</span>
              <span class={css.unit} data-field="estimate" title={progress().estimateHelp ?? undefined}>
                {progress().estimateText ?? ''}
              </span>
            </div>
          </div>

          {/* ---- 3. the issue ledger */}
          <div class={css.ledger} data-field="ledger" role="img" aria-label={issuesTileHelp(by())}>
            <Show
              when={groups().length > 0}
              fallback={
                <span class={css.ledgerWord} data-field="ledger-word" data-ink="muted">
                  {severityWords(by(), live())}
                </span>
              }
            >
              <For each={groups()}>
                {(group) => (
                  <div class={css.group} data-severity={group.severity}>
                    <For each={marksOf(group)}>{() => <i class={css.mark} data-severity={group.severity} aria-hidden="true" />}</For>
                    <span class={`${css.ledgerWord} ${css.sev}`} data-field="ledger-word" data-severity={group.severity}>
                      {group.word}
                    </span>
                  </div>
                )}
              </For>
            </Show>
          </div>

          {/* ---- 4. the probe gauge */}
          <div
            class={css.gauge}
            data-field="gauge"
            role="img"
            aria-label={gaugeAccessibilityLabel(sent(), budget())}
            data-warn={warn() ? 'true' : undefined}
            title={probesTileHelp(sent(), budget())}
          >
            <span>{GAUGE_LABEL}</span>
            <Show when={budget() > 0}>
              <div class={css.track}>
                <i class={css.gaugeFill} style={{ width: widthOf(sent() / budget()) }} />
              </div>
            </Show>
            <span class={css.unit}>{probeBudgetText(sent(), budget())}</span>
          </div>
        </div>

        {/* ---- 5. the KPI strip */}
        <div class={`${css.kpis} ${css.enter}`} data-field="kpis" style={{ '--jobs-i': 2 }}>
          <For each={kpis()}>
            {(cell) => (
              <div class={css.kpi} data-kpi={cell.label} title={cell.help}>
                <span class={css.kpiLabel}>{cell.label}</span>
                <span class={css.kpiValue} data-ink={cell.ink}>
                  <Tick text={cell.numeral} />
                  <Show when={cell.unit}>{(unit) => <span class={css.kpiUnit}>{unit()}</span>}</Show>
                  <Show when={cell.severity}>
                    <SeverityWords parts={severityWordParts(by())} empty={severityWords(by(), live())} class={css.kpiUnit} />
                  </Show>
                </span>
              </div>
            )}
          </For>
        </div>

        {/* ---- 6. the attention block (D9, D11 §6): the count lines, the error, the raw lines, the notices */}
        <Show when={hasAttention()}>
          <div class={css.attention} data-field="attention">
            <For each={attentionLines()}>
              {(line) => (
                <Show when={line.samples.length > 0} fallback={<p>{line.text}</p>}>
                  <details>
                    <summary>{line.text}</summary>
                    <ul class={css.notices}>
                      <For each={line.samples}>
                        {(sample) => (
                          <li class={css.unit}>
                            {sample.check} · {sample.detail}
                          </li>
                        )}
                      </For>
                    </ul>
                  </details>
                </Show>
              )}
            </For>
            <Show when={f().status}>
              {(st) => (
                <>
                  <Show when={st().error !== null}>
                    <p class={`${css.errorText} ${css.unit}`} data-field="error">
                      {st().error}
                    </p>
                  </Show>
                  <Show when={st().stopped_reason}>
                    {(reason) => (
                      <p class={css.rawLine} data-field="stopped-raw">
                        {rawReasonLine(reason())}
                      </p>
                    )}
                  </Show>
                  <Show when={st().crawl.last_error}>
                    {(kind) => (
                      <p class={css.rawLine} data-field="crawl-raw">
                        {rawCrawlErrorLine(kind())}
                      </p>
                    )}
                  </Show>
                </>
              )}
            </Show>
            <Show when={noticeLines().length > 0}>
              <h3 class={css.kpiLabel}>Notices</h3>
              <ul class={css.notices} data-field="notices">
                <For each={noticeLines()}>{(line) => <li>{line}</li>}</For>
              </ul>
            </Show>
          </div>
        </Show>
      </Show>
    </section>
  );
};
