// The persistent job strip (D-T8.2; spec D18 W2): one dense line for the selected job on the tabs
// other than Jobs — the state dot and word, the row's progress text, the severity words, elapsed,
// and Cancel. On the Jobs tab it renders nothing: the card is the selected job's region there. It
// renders nothing when no job exists. Every value is read from the store's held truth (`status(id)`,
// the full `scan.status`) merged over the `scan.list` summary (D2); nothing here counts or ticks on
// its own (D-T8.3: push is a trigger, poll is truth).

import { createMemo, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { useApp } from '~/state/context';
import { fmtElapsed, isTerminal, jobFacts, jobProgress, jobTone, severityWordParts, severityWords, stateWords, type JobFacts } from './helpers';
import { SeverityWords } from './jobParts';
import type { JobSummary } from './model';
import { scanStore, type ScanStore } from './store';
import css from './scanner.module.css';

/**
 * What the strip shows for a job: the same `JobFacts` the Jobs view builds — the list summary and
 * the held status merged by D2's rule (`mergeJob`: a terminal status is final, else a terminal list
 * row, else the later of the two) beside the status. A job the list does not carry yet renders
 * from its status alone (`JobStatus` is a structural superset of `JobSummary`); `null` with neither.
 */
export function jobOf(s: ScanStore, id: string): JobFacts | null {
  const summary = s.jobs().find((j) => j.job === id) ?? null;
  const status = s.status(id);
  if (summary === null) return status === null ? null : jobFacts(status, status);
  return jobFacts(summary, status);
}

/** The state token dot (plan P2): a local class with `--color-state-*` tones, not `StatusDot`. */
export const StateDot: Component<{ state: JobSummary['state'] }> = (props) => (
  <i class={css.stateDot} data-tone={jobTone(props.state)} aria-hidden="true" />
);

export const JobStrip: Component = () => {
  const s = scanStore(useApp());
  const facts = createMemo<JobFacts | null>(() => {
    const id = s.selectedJob();
    return id === null ? null : jobOf(s, id);
  });
  /**
   * Disabled once terminal (D-T8.7) and while the merged state is `cancelling` (D2: a second
   * scan.cancel is never sent); every control is off while the bus is away.
   */
  const canCancel = (j: JobSummary): boolean =>
    !isTerminal(j.state) && j.state !== 'cancelling' && !s.busy() && s.busOpen();

  return (
    <Show when={s.tab() !== 'jobs'}>
      <Show when={facts()}>
        {(f) => {
          /** The merged row (D2); the strip reads it, never re-merging on its own. */
          const j = () => f().summary;
          return (
            <div
              class={css.strip}
              role="region"
              aria-label="Selected job"
              data-job={j().job}
              data-state={j().state}
              data-tone={jobTone(j().state)}
            >
              <StateDot state={j().state} />
              <span class={css.stripWords} data-field="state">
                {stateWords(j())}
              </span>
              <span class={`${css.stripMetric} ${css.mono}`} data-field="progress">
                {jobProgress(f()).rowText}
              </span>
              <span class={css.stripMetric} data-field="issues">
                <SeverityWords parts={severityWordParts(j().issues.by_severity)} empty={severityWords(j().issues.by_severity, !isTerminal(j().state))} />
              </span>
              <span class={css.stripMetric}>
                <span>elapsed</span>
                <span data-field="elapsed">{fmtElapsed(j().elapsed_ms)}</span>
              </span>
              <Button
                variant="small"
                aria-label={`Cancel scan ${j().job}`}
                disabled={!canCancel(j())}
                onClick={() => void s.cancel(j().job)}
              >
                Cancel
              </Button>
            </div>
          );
        }}
      </Show>
    </Show>
  );
};
