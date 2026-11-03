// The persistent job strip (D-T8.2): one dense line for the selected job — state dot and words,
// probes sent/budget, points audited/found, the severity bar, elapsed, and Cancel. It renders
// nothing when no job exists. Every value is read from the store's held truth (`status(id)`, the
// full `scan.status`) and falls back to the `scan.list` summary while that is all we hold; nothing
// here counts or ticks on its own (D-T8.3: push is a trigger, poll is truth).

import { createMemo, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { useApp } from '~/state/context';
import { fmtElapsed, isTerminal, jobTone, mergeJob, stateWords } from './helpers';
import type { JobSummary } from './model';
import { SeverityBar } from './SeverityBar';
import { scanStore, type ScanStore } from './store';
import css from './scanner.module.css';

/**
 * What the strip, a Jobs row and the detail show for a job: the list summary and the held status
 * merged by D2's rule (`mergeJob`: a terminal status is final, else a terminal list row, else the
 * later of the two), so the row and the detail can never disagree. A job the list does not carry
 * yet renders from its status alone (`JobStatus` is a structural superset of `JobSummary`).
 */
export function jobOf(s: ScanStore, id: string): JobSummary | null {
  const summary = s.jobs().find((j) => j.job === id) ?? null;
  const status = s.status(id);
  return summary === null ? status : mergeJob(summary, status);
}

/** The state token dot (plan P2): a local class with `--color-state-*` tones, not `StatusDot`. */
export const StateDot: Component<{ state: JobSummary['state'] }> = (props) => (
  <i class={css.stateDot} data-tone={jobTone(props.state)} aria-hidden="true" />
);

export const JobStrip: Component = () => {
  const s = scanStore(useApp());
  const job = createMemo<JobSummary | null>(() => {
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
    <Show when={job()}>
      {(j) => (
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
          <span class={css.stripMetric}>
            <span>probes</span>
            <span data-field="probes">{`${j().probes.sent}/${j().probes.budget}`}</span>
          </span>
          <span class={css.stripMetric}>
            <span>points</span>
            <span data-field="points">{`${j().points.audited}/${j().points.found}`}</span>
          </span>
          <SeverityBar by={j().issues.by_severity} />
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
      )}
    </Show>
  );
};
