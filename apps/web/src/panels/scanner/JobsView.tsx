// The Jobs view (D-T8.7): the Findings list+detail grid over the scan jobs. Rows are the
// `scan.list` summaries, each drawn from the full `scan.status` once that is held; the detail is
// the full status, section by section, with the fixed texts of D-T8.7 and the after-start notice
// of D-T8.6. States per D-T8.10: grey bars until the first list answers, an empty frame, the
// core's error text with the last good time and Retry, and a reconnecting note that disables every
// control while keeping the data.
//
// This file renders what the store holds. The one read it asks for is the selected job's full
// status when none is held yet (a finished job is never polled, and its detail needs the fields
// only `scan.status` carries); that read is gated on the bus being open inside `live.ts` (W-16).

import { createEffect, createMemo, For, Match, on, Show, Switch, type Component } from 'solid-js';
import { Button } from '~/components';
import { fmtWhenFull } from '~/panels/findings/model';
import { useApp } from '~/state/context';
import { crawlErrorWords, crawlTroubleText, fmtElapsed, isTerminal, rawReasonLine, stateWords, stoppedReasonText } from './helpers';
import { jobOf, StateDot } from './JobStrip';
import { SEVERITY_ORDER, type CrawlCounters, type JobStatus, type JobSummary, type Lane, type StartResult } from './model';
import { Dash, ErrorBlock, Fact, listboxKeys, LoadingBars, ReconnectNote, Section } from './primitives';
import { SeverityBar } from './SeverityBar';
import { scanStore } from './store';
import css from './scanner.module.css';

const list = (xs: readonly string[]): string | null => (xs.length > 0 ? xs.join(', ') : null);
const byLane = (lanes: Partial<Record<Lane, number>>): string | null =>
  list((Object.keys(lanes) as Lane[]).map((lane) => `${lane} ${lanes[lane] ?? 0}`));

const canaryText = (st: JobStatus): string | null => {
  const session = st.session;
  if (!session) return null;
  if (session.canary.kind === 'none') return 'none';
  const expected = session.canary.expected_status;
  return `${session.canary.method} ${session.canary.path}${expected === null ? '' : ` → ${expected}`}`;
};

/**
 * The D4 crawl line: `The crawl fetched 0 pages and hit 1 error — the target refused the
 * connection`; the ` — ` suffix only when the engine sent `last_error`; `null` when the crawl hit no
 * error. W1 spells the join here because `helpers.ts` has no `crawlTroubleLine` yet; the Kit's
 * helper (Task 3.5) takes it over in the W2 card.
 */
const crawlTroubleLine = (crawl: CrawlCounters): string | null => {
  const text = crawlTroubleText(crawl);
  if (text === null) return null;
  return crawl.last_error === null ? text : `${text} — ${crawlErrorWords(crawl.last_error)}`;
};

/** The after-start notice lines (D-T8.6): clamped, skipped lanes, and `dry_run` only when sent. */
export function startNoticeLines(n: StartResult): string[] {
  const out = n.clamped.map((c) => `${c.field}: ${c.requested} -> ${c.applied}`);
  for (const sk of n.lanes.skipped) out.push(`${sk.lane}: ${sk.reason}`);
  if (n.dry_run !== undefined) out.push(`dry_run: ${n.dry_run}`);
  return out;
}

export const JobsView: Component = () => {
  const s = scanStore(useApp());
  const rows = () => s.jobs();
  const selectedId = () => s.selectedJob();
  const selected = createMemo<JobSummary | null>(() => {
    const id = selectedId();
    return id === null ? null : jobOf(s, id);
  });
  /** The full status, when held; the summary-only facts render without it. */
  const detail = createMemo<JobStatus | null>(() => {
    const id = selectedId();
    return id === null ? null : s.status(id);
  });
  const notice = createMemo<StartResult | null>(() => {
    const n = s.startNotice();
    return n !== null && n.job === selectedId() ? n : null;
  });
  const offline = () => !s.busOpen();
  const cancelError = s.errorFor(['cancel']);

  // A selected job whose full status is not held yet is read once; the live poll takes over for a
  // live job, and a finished job's detail is complete after this one read.
  createEffect(
    on(selectedId, (id) => {
      if (id !== null && s.status(id) === null) void s.refreshStatus(id);
    }),
  );

  let detailEl: HTMLDivElement | undefined;

  const select = (id: string) => s.setSelectedJob(id);
  const onKeyDown = listboxKeys({
    ids: () => rows().map((j) => j.job),
    selectedId,
    select,
    focusDetail: () => detailEl?.focus({ preventScroll: true }),
    domId: (id) => `job-${id}`,
  });

  /** Off once terminal and while the merged state is `cancelling` (D2: one scan.cancel per job). */
  const canCancel = (j: JobSummary): boolean =>
    !isTerminal(j.state) && j.state !== 'cancelling' && !s.busy() && !offline();

  return (
    <div class={css.layout} data-empty={s.jobsLoaded() && rows().length === 0 ? 'true' : undefined}>
      <section class={css.list}>
        <div class={css.listHead}>
          <span class={css.listTitle}>
            Jobs
            <span class={css.n}>· {rows().length}</span>
          </span>
          <Show when={offline()}>
            <ReconnectNote />
          </Show>
        </div>
        {/* The "last good" is when the list was last read without an error (D-T8.10): the store's
            time, so a remount after a long gap does not pass itself off as fresh. */}
        <Show when={s.jobsError()}>
          {(err) => <ErrorBlock text={err()} lastGood={s.jobsLoadedAt()} onRetry={() => void s.refreshJobs()} disabled={offline()} />}
        </Show>
        <div
          class={css.rows}
          role="listbox"
          aria-label="Jobs"
          tabIndex={0}
          aria-activedescendant={selectedId() ? `job-${selectedId()}` : undefined}
          onKeyDown={onKeyDown}
        >
          <Switch>
            <Match when={!s.jobsLoaded()}>
              <LoadingBars label="Loading jobs" />
            </Match>
            <Match when={rows().length === 0}>
              <div class={css.empty}>No jobs yet: start one from Profiles</div>
            </Match>
            <Match when={rows().length > 0}>
              <For each={rows()}>
                {(summary) => {
                  // One memo per row: the held status (or the summary) is resolved once per change,
                  // not once per field the row prints.
                  const j = createMemo(() => jobOf(s, summary.job) ?? summary);
                  return (
                    <div
                      id={`job-${summary.job}`}
                      data-job={summary.job}
                      data-state={j().state}
                      class={`${css.row} ${css.jobRow}`}
                      role="option"
                      aria-selected={selectedId() === summary.job}
                      onClick={() => select(summary.job)}
                    >
                      {/* Two lines, no control: line 1 is the state and elapsed, line 2 the id,
                          counters and the severity bar. Cancel lives in the strip and the detail. */}
                      <div class={css.rowMain}>
                        <StateDot state={j().state} />
                        <span data-field="state">{stateWords(j())}</span>
                      </div>
                      <div class={css.rowSecondary}>
                        <span data-field="elapsed">{fmtElapsed(j().elapsed_ms)}</span>
                      </div>
                      <div class={css.rowMeta}>
                        <span class={css.mono}>{summary.job}</span>
                        <span class={css.sep}>·</span>
                        <span>
                          probes <span data-field="probes">{`${j().probes.sent}/${j().probes.budget}`}</span>
                        </span>
                        <span class={css.sep}>·</span>
                        <span>
                          points <span data-field="points">{`${j().points.audited}/${j().points.found}`}</span>
                        </span>
                      </div>
                      <SeverityBar by={j().issues.by_severity} />
                    </div>
                  );
                }}
              </For>
            </Match>
          </Switch>
        </div>
      </section>

      <Show when={rows().length > 0}>
        <div class={css.detail} role="region" aria-label="Job detail" tabIndex={-1} ref={detailEl}>
          <Show when={selected()} fallback={<div class={css.empty}>No job selected</div>}>
            {(j) => (
              <div class={css.body}>
                <div class={css.detailHead}>
                  <h2>
                    <span class={css.mono}>{j().job}</span>
                  </h2>
                  <Button
                    variant="small"
                    aria-label={`Cancel scan ${j().job}`}
                    disabled={!canCancel(j())}
                    onClick={() => void s.cancel(j().job)}
                  >
                    Cancel
                  </Button>
                </div>

                {/* A failed per-job read (PA4): the core's text with Retry, above the facts, so the
                    operator reads why the counters stopped before reading the counters. */}
                <Show when={s.statusError(j().job)}>
                  {(err) => <ErrorBlock text={err()} onRetry={() => void s.refreshStatus(j().job)} disabled={offline()} />}
                </Show>
                {/* The one store error this view owns (PA5): a refused cancel, beside the toast. */}
                <Show when={cancelError()}>
                  {(err) => (
                    <p class={css.reason} role="alert" data-error="cancel">
                      {err().text}
                    </p>
                  )}
                </Show>

                <Show when={notice()}>
                  {(n) => (
                    <div class={css.notice} role="status" data-notice="start">
                      <div>
                        <b>{n().job}</b> started
                      </div>
                      <For each={startNoticeLines(n())}>{(line) => <div class={css.mono}>{line}</div>}</For>
                      <Button variant="small" aria-label="Dismiss start notice" disabled={offline()} onClick={() => s.dismissStartNotice()}>
                        Dismiss
                      </Button>
                    </div>
                  )}
                </Show>

                <Section title="Overview">
                  <dl class={css.facts}>
                    <Fact label="state" field="state" value={stateWords(j())} />
                    <Fact label="phase" value={j().phase} />
                    <Fact label="elapsed" value={fmtElapsed(j().elapsed_ms)} mono />
                    <Show when={detail()}>
                      {(st) => (
                        <>
                          <Fact label="profile" value={st().profile_name} />
                          <Fact label="targets" value={list(st().targets)} mono />
                          <Fact
                            label="started by"
                            value={st().started_by.client_label === null ? st().started_by.frontend : `${st().started_by.frontend} · ${st().started_by.client_label}`}
                          />
                          <Fact label="started" value={fmtWhenFull(st().started_at)} />
                          <Fact label="finished" value={fmtWhenFull(st().finished_at)} />
                          {/* The D4 sentence from the merged facts, the raw token beneath it in the data
                              face (the only place the token appears); one `dd`, so the facts grid keeps
                              its pairs. The sentence is the dash where the state or the error says it. */}
                          <Show when={st().stopped_reason} fallback={<Fact label="stopped" field="stopped" value={null} />}>
                            {(reason) => (
                              <>
                                <dt>stopped</dt>
                                <dd>
                                  <div data-field="stopped">
                                    {stoppedReasonText(reason(), j().state, j().probes.budget, st().error) ?? <Dash />}
                                  </div>
                                  <span class={css.mono} data-field="stopped-raw">
                                    {rawReasonLine(reason())}
                                  </span>
                                </dd>
                              </>
                            )}
                          </Show>
                          <Show when={crawlTroubleLine(st().crawl)}>
                            {(line) => <Fact label="crawl" field="crawl" value={line()} />}
                          </Show>
                          <Show when={st().error !== null}>
                            <Fact label="error" field="error" value={st().error} mono />
                          </Show>
                        </>
                      )}
                    </Show>
                  </dl>
                </Section>

                <Section title="Probes">
                  <dl class={css.facts}>
                    <Fact label="sent / budget" value={`${j().probes.sent}/${j().probes.budget}`} mono />
                    <Fact label="errors" value={j().probes.errors} mono />
                    <Fact label="timeouts" value={j().probes.timeouts} mono />
                    <Fact label="rate waits" value={j().probes.rate_waits} mono />
                    <Fact label="by lane" value={byLane(j().probes.by_lane)} mono />
                  </dl>
                </Section>

                <Show when={detail()}>
                  {(st) => (
                    <Section title="Crawl">
                      <dl class={css.facts}>
                        <Fact label="pages" value={st().crawl.pages} mono />
                        <Fact label="queued" value={st().crawl.queued} mono />
                        <Fact label="depth" value={st().crawl.depth} mono />
                        <Fact label="forms submitted" value={st().crawl.forms_submitted} mono />
                        <Fact label="errors" value={st().crawl.errors} field="crawl-errors" mono />
                        <Fact label="forms skipped" value={st().crawl.forms_skipped} field="crawl-forms-skipped" mono />
                      </dl>
                    </Section>
                  )}
                </Show>

                <Section title="Points">
                  <dl class={css.facts}>
                    <Fact label="found" value={j().points.found} mono />
                    <Fact label="queued" value={j().points.queued} mono />
                    <Fact label="audited" value={j().points.audited} mono />
                    <Fact
                      label="skipped"
                      value={`ignored ${j().points.skipped.ignored} · frequent ${j().points.skipped.frequent} · limit ${j().points.skipped.limit}`}
                      mono
                    />
                  </dl>
                </Section>

                <Show when={detail()}>
                  {(st) => (
                    <Section title="Checks">
                      <dl class={css.facts}>
                        <Fact label="scheduled / done" value={`${st().checks.scheduled}/${st().checks.done}`} mono />
                        <Fact label="running" value={list(st().checks.running)} mono />
                      </dl>
                    </Section>
                  )}
                </Show>

                <Section title="Issues">
                  <dl class={css.facts}>
                    <Fact label="total" value={j().issues.total} mono />
                    <Fact label="by severity" value={<SeverityBar by={j().issues.by_severity} />} />
                    <Fact
                      label="counts"
                      value={SEVERITY_ORDER.map((sev) => `${sev} ${j().issues.by_severity[sev]}`).join(' · ')}
                      mono
                    />
                    <Fact
                      label="by confidence"
                      value={`certain ${j().issues.by_confidence.certain} · firm ${j().issues.by_confidence.firm} · tentative ${j().issues.by_confidence.tentative}`}
                      mono
                    />
                  </dl>
                </Section>

                <Show when={detail()}>
                  {(st) => (
                    <>
                      <Show when={st().l4}>
                        {(l4) => (
                          <Section title="L4">
                            <dl class={css.facts}>
                              <Fact label="cases" value={l4().cases} mono />
                              <Fact label="crashes" value={l4().crashes} mono />
                              <Fact label="liveness failures" value={l4().liveness_failures} mono />
                              <Fact label="retired elements" value={l4().retired_elements} mono />
                            </dl>
                          </Section>
                        )}
                      </Show>

                      <Show when={st().session}>
                        {(session) => (
                          <Section title="Session">
                            <dl class={css.facts}>
                              <Fact label="reused" value={session().reused} />
                              <Fact label="lost" value={session().lost} />
                              <Fact label="canary" value={canaryText(st())} mono />
                              <Fact label="browser partial" value={session().browser_partial} />
                            </dl>
                          </Section>
                        )}
                      </Show>

                      <Section title="Lanes">
                        <dl class={css.facts}>
                          <Fact label="requested" value={list(st().lanes.requested)} mono />
                          <Fact label="run" value={list(st().lanes.run)} mono />
                          <Fact label="skipped" value={list(st().lanes.skipped.map((sk) => `${sk.lane}: ${sk.reason}`))} mono />
                        </dl>
                      </Section>

                      <Section title="Clamped">
                        <Show when={st().clamped.length > 0} fallback={<p class={css.note}>Nothing was clamped.</p>}>
                          <table class={css.table}>
                            <thead>
                              <tr>
                                <th>field</th>
                                <th>requested</th>
                                <th>applied</th>
                              </tr>
                            </thead>
                            <tbody>
                              <For each={st().clamped}>
                                {(c) => (
                                  <tr>
                                    <td>{c.field}</td>
                                    <td>{c.requested}</td>
                                    <td>{c.applied}</td>
                                  </tr>
                                )}
                              </For>
                            </tbody>
                          </table>
                        </Show>
                      </Section>
                    </>
                  )}
                </Show>
              </div>
            )}
          </Show>
        </div>
      </Show>
    </div>
  );
};
