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

import { createEffect, createMemo, createSignal, For, Match, on, Show, Switch, type Component, type JSX } from 'solid-js';
import { Button } from '~/components';
import { fmtWhenFull } from '~/panels/findings/model';
import { useApp } from '~/state/context';
import { fmtElapsed, isTerminal, stateWords, stoppedReasonText } from './helpers';
import { jobOf, StateDot } from './JobStrip';
import { SEVERITY_ORDER, type JobStatus, type JobSummary, type Lane, type StartResult } from './model';
import { SeverityBar } from './SeverityBar';
import { scanStore } from './store';
import css from './scanner.module.css';

/** A grey dash for a missing value (foundation §2.8); zero is printed as `0`, never dashed. */
const Dash: Component = () => <span class={css.dash}>—</span>;

/** One `dt`/`dd` pair of a `.facts` list; `null`/`undefined` prints the dash. */
const Fact: Component<{ k: string; v: JSX.Element | string | number | boolean | null | undefined; field?: string | undefined; mono?: boolean | undefined }> = (
  props,
) => (
  <>
    <dt>{props.k}</dt>
    <dd data-field={props.field} class={props.mono ? css.mono : undefined}>
      <Show when={props.v !== null && props.v !== undefined} fallback={<Dash />}>
        {typeof props.v === 'boolean' ? String(props.v) : props.v}
      </Show>
    </dd>
  </>
);

const Section: Component<{ title: string; children: JSX.Element }> = (props) => (
  <section class={css.section}>
    <h3 class={css.sectionTitle}>{props.title}</h3>
    {props.children}
  </section>
);

const yesNo = (v: boolean): string => (v ? 'yes' : 'no');
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

  // A selected job whose full status is not held yet is read once; the live poll takes over for a
  // live job, and a finished job's detail is complete after this one read.
  createEffect(
    on(selectedId, (id) => {
      if (id !== null && s.status(id) === null) void s.refreshStatus(id);
    }),
  );

  // "Last good": when this view last saw the list answer without an error (D-T8.10).
  const [lastGood, setLastGood] = createSignal<number | null>(null);
  createEffect(() => {
    s.jobs();
    if (s.jobsLoaded() && s.jobsError() === null) setLastGood(Date.now());
  });

  let detailEl: HTMLDivElement | undefined;

  const select = (id: string, fromKeyboard = false) => {
    s.setSelectedJob(id);
    if (fromKeyboard) document.getElementById(`job-${id}`)?.scrollIntoView?.({ block: 'nearest' });
  };
  const move = (delta: number) => {
    const all = rows();
    if (!all.length) return;
    const i = all.findIndex((j) => j.job === selectedId());
    const next = i < 0 ? (delta > 0 ? 0 : all.length - 1) : Math.max(0, Math.min(all.length - 1, i + delta));
    select(all[next]!.job, true);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        move(1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        move(-1);
        break;
      case 'Home':
        e.preventDefault();
        if (rows().length) select(rows()[0]!.job, true);
        break;
      case 'End':
        e.preventDefault();
        if (rows().length) select(rows()[rows().length - 1]!.job, true);
        break;
      case 'Enter':
        e.preventDefault();
        detailEl?.focus({ preventScroll: true });
        break;
    }
  };

  const canCancel = (j: JobSummary): boolean => !isTerminal(j.state) && !s.busy() && !offline();

  return (
    <div class={css.layout} data-empty={s.jobsLoaded() && rows().length === 0 ? 'true' : undefined}>
      <section class={css.list}>
        <div class={css.listHead}>
          <span class={css.listTitle}>
            Jobs
            <span class={css.n}>· {rows().length}</span>
          </span>
          <Show when={offline()}>
            <p class={css.note}>reconnecting: controls are disabled until the bus is back</p>
          </Show>
        </div>
        <Show when={s.jobsError()}>
          {(err) => (
            <div class={css.errorBlock} role="alert">
              <p>{err()}</p>
              <span class={css.mono}>
                last good:{' '}
                <Show when={lastGood()} fallback={<Dash />}>
                  {(t) => fmtWhenFull(t())}
                </Show>
              </span>
              <Button variant="small" class={css.retry} disabled={offline()} onClick={() => void s.refreshJobs()}>
                Retry
              </Button>
            </div>
          )}
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
              <div class={css.loading} aria-busy="true">
                <i />
                <i />
                <i />
                <i />
              </div>
            </Match>
            <Match when={rows().length === 0}>
              <div class={css.empty}>No jobs yet: start one from Profiles</div>
            </Match>
            <Match when={rows().length > 0}>
              <For each={rows()}>
                {(summary) => {
                  const j = () => jobOf(s, summary.job) ?? summary;
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
                    <Fact k="state" v={stateWords(j())} />
                    <Fact k="phase" v={j().phase} />
                    <Fact k="elapsed" v={fmtElapsed(j().elapsed_ms)} mono />
                    <Show when={detail()}>
                      {(st) => (
                        <>
                          <Fact k="profile" v={st().profile_name} />
                          <Fact k="targets" v={list(st().targets)} mono />
                          <Fact
                            k="started by"
                            v={st().started_by.client_label === null ? st().started_by.frontend : `${st().started_by.frontend} · ${st().started_by.client_label}`}
                          />
                          <Fact k="started" v={fmtWhenFull(st().started_at)} />
                          <Fact k="finished" v={fmtWhenFull(st().finished_at)} />
                          <Fact k="stopped" field="stopped" v={st().stopped_reason === null ? null : stoppedReasonText(st().stopped_reason!)} />
                          <Show when={st().error !== null}>
                            <Fact k="error" field="error" v={st().error} mono />
                          </Show>
                        </>
                      )}
                    </Show>
                  </dl>
                </Section>

                <Section title="Probes">
                  <dl class={css.facts}>
                    <Fact k="sent / budget" v={`${j().probes.sent}/${j().probes.budget}`} mono />
                    <Fact k="errors" v={j().probes.errors} mono />
                    <Fact k="timeouts" v={j().probes.timeouts} mono />
                    <Fact k="rate waits" v={j().probes.rate_waits} mono />
                    <Fact k="by lane" v={byLane(j().probes.by_lane)} mono />
                  </dl>
                </Section>

                <Show when={detail()}>
                  {(st) => (
                    <Section title="Crawl">
                      <dl class={css.facts}>
                        <Fact k="pages" v={st().crawl.pages} mono />
                        <Fact k="queued" v={st().crawl.queued} mono />
                        <Fact k="depth" v={st().crawl.depth} mono />
                        <Fact k="forms submitted" v={st().crawl.forms_submitted} mono />
                      </dl>
                    </Section>
                  )}
                </Show>

                <Section title="Points">
                  <dl class={css.facts}>
                    <Fact k="found" v={j().points.found} mono />
                    <Fact k="queued" v={j().points.queued} mono />
                    <Fact k="audited" v={j().points.audited} mono />
                    <Fact
                      k="skipped"
                      v={`ignored ${j().points.skipped.ignored} · frequent ${j().points.skipped.frequent} · limit ${j().points.skipped.limit}`}
                      mono
                    />
                  </dl>
                </Section>

                <Show when={detail()}>
                  {(st) => (
                    <Section title="Checks">
                      <dl class={css.facts}>
                        <Fact k="scheduled / done" v={`${st().checks.scheduled}/${st().checks.done}`} mono />
                        <Fact k="running" v={list(st().checks.running)} mono />
                      </dl>
                    </Section>
                  )}
                </Show>

                <Section title="Issues">
                  <dl class={css.facts}>
                    <Fact k="total" v={j().issues.total} mono />
                    <Fact k="by severity" v={<SeverityBar by={j().issues.by_severity} />} />
                    <Fact
                      k="counts"
                      v={SEVERITY_ORDER.map((sev) => `${sev} ${j().issues.by_severity[sev]}`).join(' · ')}
                      mono
                    />
                    <Fact
                      k="by confidence"
                      v={`certain ${j().issues.by_confidence.certain} · firm ${j().issues.by_confidence.firm} · tentative ${j().issues.by_confidence.tentative}`}
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
                              <Fact k="cases" v={l4().cases} mono />
                              <Fact k="crashes" v={l4().crashes} mono />
                              <Fact k="liveness failures" v={l4().liveness_failures} mono />
                              <Fact k="retired elements" v={l4().retired_elements} mono />
                            </dl>
                          </Section>
                        )}
                      </Show>

                      <Show when={st().session}>
                        {(session) => (
                          <Section title="Session">
                            <dl class={css.facts}>
                              <Fact k="reused" v={yesNo(session().reused)} />
                              <Fact k="lost" v={yesNo(session().lost)} />
                              <Fact k="canary" v={canaryText(st())} mono />
                              <Fact k="browser partial" v={yesNo(session().browser_partial)} />
                            </dl>
                          </Section>
                        )}
                      </Show>

                      <Section title="Lanes">
                        <dl class={css.facts}>
                          <Fact k="requested" v={list(st().lanes.requested)} mono />
                          <Fact k="run" v={list(st().lanes.run)} mono />
                          <Fact k="skipped" v={list(st().lanes.skipped.map((sk) => `${sk.lane}: ${sk.reason}`))} mono />
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
