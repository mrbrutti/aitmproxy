// The jobs table (spec D18 W2, D10, D12, D14; plan Task 3.8b): the hidden header row over the
// `role="listbox" aria-label="Jobs"` listbox the live script and the tests select by, described by
// the Kit's caption (`4 jobs · 1 running`) on a visually hidden span, and one `role="option"` row
// per job in the list's order (the core lists newest first, spec D3) with the Kit's nine cells:
// the ring (a live job) or the tone dot (breathing while cancelling), the agent dot, the state
// word and the sub-line; the profile; the hosts; the progress text; the probes with the budget
// muted; the points; the severity words in their inks; the elapsed time. Every number is a `Tick`,
// so a changed value plays `jobsTick` once and an unchanged one keeps its node (D12); rows are keyed
// by the job id, so a poll's fresh facts objects never remount a row. The action column holds the
// hover `Cancel`, pointer-only (`aria-hidden`, out of the tab order): an option may not own a
// control, so the keyboard and screen-reader path is the card's `Cancel scan <job>` (D14); it sits
// on running and queued rows only (one cancel per job, D2) and is disabled while the bus is away or
// the store is busy (AC38). Selection is reported with its cause (`pointer` from a click, `keyboard`
// from the arrows) so the view can play the entrance for one and not the other (D12); Enter and →
// hand focus to the card. The table's own `.enter` block carries `data-entrance` on the tab's
// first generation only: on a row click the operator is pointing at the table, which must not move.

import { createMemo, createUniqueId, For, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import {
  agentOriginated,
  fmtElapsed,
  grouped,
  hostsText,
  isTerminal,
  jobAccessibilityLabel,
  jobProgress,
  jobsCaptionFor,
  ofText,
  probeBudgetText,
  profileText,
  rowSubLine,
  severityWordParts,
  severityWords,
  stateWords,
  TABLE_HEADERS,
  tone,
  type JobFacts,
} from './helpers';
import { AgentDot, JobDot, Ring, SeverityWords, Tick, type SelectCause } from './jobParts';
import { listboxKeys } from './primitives';
import { scanStore, type ScanStore } from './store';
import css from './jobs.module.css';

export interface JobsTableProps {
  /** One facts per job, in display order; the rows are keyed by `summary.job`. */
  rows: JobFacts[];
  selected: string | null;
  onSelect: (job: string, cause: SelectCause) => void;
  /**
   * Enter and →: move focus to the card's primary verb (`Cancel scan <job>` / `Scan again <job>`)
   * when enabled, else its first enabled verb (D14 as gap 77 amends it).
   */
  onFocusCard: () => void;
  /** Whether the current generation's entrance plays. */
  play: boolean;
  /** `generation <= 1`: the table enters with the card on the tab's first selection only. */
  first: boolean;
}

const domId = (job: string): string => `job-${job}`;

export const JobsTable: Component<JobsTableProps> = (props) => {
  const s = scanStore(useApp());
  const captionId = createUniqueId();
  /** The facts by job id; the rows render from this so a job's row finds its facts by key, not by index. */
  const byId = createMemo(() => new Map(props.rows.map((f) => [f.summary.job, f])));
  const ids = createMemo(() => props.rows.map((f) => f.summary.job));
  const caption = () => jobsCaptionFor(props.rows);

  const keys = listboxKeys({
    ids,
    selectedId: () => props.selected,
    select: (id) => props.onSelect(id, 'keyboard'),
    focusDetail: () => props.onFocusCard(),
    domId,
  });
  const onKeyDown = (e: KeyboardEvent): void => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      props.onFocusCard();
      return;
    }
    keys(e);
  };

  return (
    <>
      <div class={css.head} aria-hidden="true">
        <For each={TABLE_HEADERS}>{(label) => <div class={css.cell}>{label}</div>}</For>
        <div class={css.cell} />
      </div>
      <span id={captionId} class={css.visuallyHidden}>
        {caption()}
      </span>
      <div
        class={`${css.rows} ${css.enter}`}
        style={{ '--jobs-i': 2 }}
        data-entrance={props.first ? (props.play ? 'play' : 'none') : undefined}
        role="listbox"
        aria-label="Jobs"
        aria-describedby={captionId}
        tabIndex={0}
        aria-activedescendant={props.selected === null ? undefined : domId(props.selected)}
        onKeyDown={onKeyDown}
      >
        <For each={ids()}>
          {(id) => (
            <Show when={byId().get(id)}>
              {(f) => <JobRow facts={f()} selected={props.selected === id} store={s} onSelect={(cause) => props.onSelect(id, cause)} />}
            </Show>
          )}
        </For>
      </div>
    </>
  );
};

interface JobRowProps {
  facts: JobFacts;
  selected: boolean;
  store: ScanStore;
  onSelect: (cause: SelectCause) => void;
}

/** One row: the nine cells of D18 W2 and the action column, every word from `helpers.ts`. */
const JobRow: Component<JobRowProps> = (props) => {
  const f = () => props.facts;
  const j = () => f().summary;
  const live = () => !isTerminal(j().state);
  const cancelling = () => j().state === 'cancelling';
  /** The ring draws for a running or queued job; cancelling and the terminal states take the dot (D10). */
  const ringed = () => live() && !cancelling();
  const progress = createMemo(() => jobProgress(f()));
  const sub = () => rowSubLine(f());
  const hosts = () => hostsText(f());
  const agent = () => {
    const st = f().status;
    return st !== null && agentOriginated(st.started_by);
  };
  /** The hover Cancel is laid out on running and queued rows; it works only while the bus is open and the store idle. */
  const mayCancel = () => props.store.busOpen() && !props.store.busy();

  return (
    <div
      id={domId(j().job)}
      class={css.row}
      role="option"
      data-job={j().job}
      data-state={j().state}
      aria-selected={props.selected}
      aria-label={jobAccessibilityLabel(f())}
      onClick={() => props.onSelect('pointer')}
    >
      <div class={css.cell}>
        <Show when={ringed()} fallback={<JobDot tone={tone(f())} breathing={cancelling()} />}>
          <Ring ring={progress().ring} />
        </Show>
        <Show when={agent()}>
          <AgentDot />
        </Show>
        <span>
          <span class={css.stateWord} data-field="state">
            {stateWords(j())}
          </span>
          <Show when={sub()}>
            {(text) => (
              <span class={css.sub} data-field="sub" title={text()}>
                {text()}
              </span>
            )}
          </Show>
        </span>
      </div>
      <div class={css.cell} data-field="profile">
        {profileText(f())}
      </div>
      <div class={`${css.cell} ${css.unit}`} data-field="target" title={hosts()}>
        {hosts()}
      </div>
      <div class={`${css.cell} ${css.unit}`} data-field="progress">
        <Tick text={progress().rowText} />
      </div>
      <div class={`${css.cell} ${css.unit}`} data-field="probes">
        <Show when={j().probes.budget > 0} fallback={<Tick text={probeBudgetText(j().probes.sent, j().probes.budget)} />}>
          <Tick text={grouped(j().probes.sent)} /> <span data-ink="muted">{ofText(j().probes.budget)}</span>
        </Show>
      </div>
      <div class={`${css.cell} ${css.unit}`} data-field="points">
        <Tick text={grouped(j().points.audited)} /> {ofText(j().points.found)}
      </div>
      <div class={css.cell}>
        <span class={css.unit} data-field="issues">
          <SeverityWords parts={severityWordParts(j().issues.by_severity)} empty={severityWords(j().issues.by_severity, live())} />
        </span>
      </div>
      <div class={`${css.cell} ${css.unit}`} data-field="elapsed">
        <Tick text={fmtElapsed(j().elapsed_ms)} />
      </div>
      <div class={css.cell}>
        <Show when={ringed()}>
          <button
            type="button"
            class={css.hoverCancel}
            data-action="cancel"
            aria-hidden="true"
            tabIndex={-1}
            disabled={!mayCancel()}
            onClick={(e) => {
              e.stopPropagation();
              void props.store.cancel(j().job);
            }}
          >
            Cancel
          </button>
        </Show>
      </div>
    </div>
  );
};
