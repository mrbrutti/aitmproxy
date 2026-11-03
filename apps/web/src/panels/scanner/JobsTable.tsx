// The jobs table (spec D18 W2, D10; plan Task 3.8 skeleton, Task 3.8b fills it): the hidden
// header row over the `role="listbox" aria-label="Jobs"` listbox the live script and the tests
// select by, one `role="option"` row per job with the Kit's nine cells. Selection is reported with
// its cause (`pointer` from a click, `keyboard` from the arrows) so the view can play the entrance
// for one and not the other (D12); Enter hands focus to the card. The table's own `.enter` block
// carries `data-entrance` on the tab's first generation only: on a row click the operator is
// pointing at the table, which must not move. The skeleton renders the cells as plain text inside
// their `data-field` elements; Task 3.8b adds the ring, the dots, the ticks and the hover Cancel.

import { For, type Component } from 'solid-js';
import {
  fmtElapsed,
  grouped,
  hostsText,
  isTerminal,
  jobAccessibilityLabel,
  jobProgress,
  ofText,
  probeBudgetText,
  profileText,
  rowSubLine,
  severityWordParts,
  severityWords,
  stateWords,
  TABLE_HEADERS,
  type JobFacts,
} from './helpers';
import { SeverityWords } from './jobParts';
import { listboxKeys } from './primitives';
import css from './jobs.module.css';

export interface JobsTableProps {
  /** One facts per job, in display order. Task 3.8b keys the rows by `summary.job`. */
  rows: JobFacts[];
  selected: string | null;
  onSelect: (job: string, cause: 'pointer' | 'keyboard') => void;
  /** Enter (and, in 3.8b, →): move focus to the card's first enabled verb. */
  onFocusCard: () => void;
  /** Whether the current generation's entrance plays. */
  play: boolean;
  /** `generation <= 1`: the table enters with the card on the tab's first selection only. */
  first: boolean;
  generation: number;
}

const domId = (job: string): string => `job-${job}`;

export const JobsTable: Component<JobsTableProps> = (props) => {
  const onKeyDown = listboxKeys({
    ids: () => props.rows.map((f) => f.summary.job),
    selectedId: () => props.selected,
    select: (id) => props.onSelect(id, 'keyboard'),
    focusDetail: () => props.onFocusCard(),
    domId,
  });

  return (
    <>
      <div class={css.head} aria-hidden="true">
        <For each={TABLE_HEADERS}>{(label) => <div class={css.cell}>{label}</div>}</For>
        <div class={css.cell} />
      </div>
      <div
        class={`${css.rows} ${css.enter}`}
        style={{ '--jobs-i': 2 }}
        data-entrance={props.first ? (props.play ? 'play' : 'none') : undefined}
        role="listbox"
        aria-label="Jobs"
        tabIndex={0}
        aria-activedescendant={props.selected === null ? undefined : domId(props.selected)}
        onKeyDown={onKeyDown}
      >
        <For each={props.rows}>
          {(f) => {
            const j = f.summary;
            const live = !isTerminal(j.state);
            const progress = jobProgress(f);
            const sub = rowSubLine(f);
            return (
              <div
                id={domId(j.job)}
                class={css.row}
                role="option"
                data-job={j.job}
                data-state={j.state}
                aria-selected={props.selected === j.job}
                aria-label={jobAccessibilityLabel(f)}
                onClick={() => props.onSelect(j.job, 'pointer')}
              >
                <div class={css.cell}>
                  <span>
                    <span class={css.stateWord} data-field="state">
                      {stateWords(j)}
                    </span>
                    {sub === null ? null : (
                      <span class={css.sub} data-field="sub">
                        {sub}
                      </span>
                    )}
                  </span>
                </div>
                <div class={css.cell} data-field="profile">
                  {profileText(f)}
                </div>
                <div class={`${css.cell} ${css.unit}`} data-field="target">
                  {hostsText(f)}
                </div>
                <div class={`${css.cell} ${css.unit}`} data-field="progress">
                  {progress.rowText}
                </div>
                <div class={`${css.cell} ${css.unit}`} data-field="probes">
                  {probeBudgetText(j.probes.sent, j.probes.budget)}
                </div>
                <div class={`${css.cell} ${css.unit}`} data-field="points">
                  {`${grouped(j.points.audited)} ${ofText(j.points.found)}`}
                </div>
                <div class={css.cell}>
                  <span class={css.unit} data-field="issues">
                    <SeverityWords parts={severityWordParts(j.issues.by_severity)} empty={severityWords(j.issues.by_severity, live)} />
                  </span>
                </div>
                <div class={`${css.cell} ${css.unit}`} data-field="elapsed">
                  {fmtElapsed(j.elapsed_ms)}
                </div>
                <div class={css.cell} />
              </div>
            );
          }}
        </For>
      </div>
    </>
  );
};
