// The Jobs view (spec D18 W2, the locked comp): one column on the surface holding the bus banner
// (D15), the selected job's card, the jobs table and the two wells, each a component of its own
// (`JobCard`, `JobsTable`, `JobWells`) over `jobFacts(summary, status)` — the list row merged with
// the held status by D2's rule, so the card, the row and the wells can never disagree. States:
// grey bars until the first list answers, the Kit's empty sentence with an `Open Profiles` button,
// the core's error text with the last good time and Retry, and the banner with the values' age
// while the bus is away (every control disabled, the data kept).
//
// The entrance (D12): `{ generation, play }`. A pointer selection, a start or the first list bump
// the generation and play; a keyboard selection changes the job and plays nothing. The view
// decides by the cause it was given (`selectJob`) or, for a selection it did not make (the store's
// after-start pick, the first list), by an effect on the store's selection. No timer lives here:
// the banner's age is read when the bus goes away, the counters come from the poll (AC32).

import { createEffect, createMemo, createSignal, Match, on, Show, Switch, type Component } from 'solid-js';
import { Button } from '~/components';
import { useApp } from '~/state/context';
import { clampedText, jobFacts, NO_JOBS_TEXT, skippedLaneText, type JobFacts } from './helpers';
import { JobCard } from './JobCard';
import { type SelectCause } from './jobParts';
import { JobsTable } from './JobsTable';
import { JobWells } from './JobWells';
import { ErrorBlock, LoadingBars, ReconnectNote } from './primitives';
import { scanStore } from './store';
import css from './scanner.module.css';
import jobsCss from './jobs.module.css';

interface Entrance {
  generation: number;
  play: boolean;
}

export const JobsView: Component = () => {
  const s = scanStore(useApp());
  const rows = createMemo<JobFacts[]>(() => s.jobs().map((summary) => jobFacts(summary, s.status(summary.job))));
  const selectedId = () => s.selectedJob();
  const selected = createMemo<JobFacts | null>(() => {
    const id = selectedId();
    return id === null ? null : (rows().find((f) => f.summary.job === id) ?? null);
  });
  const offline = () => !s.busOpen();

  /**
   * The age of the values the banner shows (D15): `jobsLoadedAt` against the clock when the bus
   * went away; `null` before the first list. Read once per bus state change — the polls stop with
   * the bus, so nothing else ticks it (no view timer).
   */
  const valuesAgeMs = createMemo<number | null>(() => {
    if (!offline()) return null;
    const at = s.jobsLoadedAt();
    return at === null ? null : Math.max(0, Date.now() - at);
  });

  /** The launch's notices for the selected job, in the Kit's words (the mac's `launchNotices[job]`). */
  const launchNotices = createMemo<string[]>(() => {
    const n = s.startNotice();
    if (n === null || n.job !== selectedId()) return [];
    return [...n.clamped.map(clampedText), ...n.lanes.skipped.map(skippedLaneText)];
  });

  // A selected job whose full status is not held yet is read once; the live poll takes over for a
  // live job, and a finished job's facts are complete after this one read (W1).
  createEffect(
    on(selectedId, (id) => {
      if (id !== null && s.status(id) === null) void s.refreshStatus(id);
    }),
  );

  /* ---- the entrance */
  const [entrance, setEntrance] = createSignal<Entrance>({ generation: 0, play: false });
  /** The cause of the selection change the view is making; `null` while a change is not ours. */
  let cause: SelectCause | null = null;
  const bump = (): void => {
    setEntrance((e) => ({ generation: e.generation + 1, play: true }));
  };
  const hold = (): void => {
    setEntrance((e) => ({ generation: e.generation, play: false }));
  };

  const selectJob = (job: string, c: SelectCause): void => {
    cause = c;
    s.setSelectedJob(job);
    cause = null;
  };
  // The store's selection changed: by us (the cause says how) or by a start / the first list.
  createEffect(
    on(selectedId, (id) => {
      if (id === null) return;
      if (cause === 'keyboard') hold();
      else bump();
    }),
  );

  let root: HTMLDivElement | undefined;
  /** Enter in the listbox: the card's first enabled verb, else the card itself (D14). */
  const focusCard = (): void => {
    const card = root?.querySelector<HTMLElement>('section[role=region][aria-label="Selected job"]');
    const verb = card?.querySelector<HTMLElement>('button:not([disabled])');
    (verb ?? card)?.focus({ preventScroll: true });
  };

  return (
    <div ref={root} class={jobsCss.jobs}>
      <Show when={offline()}>
        <div class={jobsCss.banner}>
          <ReconnectNote valuesAgeMs={valuesAgeMs()} />
        </div>
      </Show>
      {/* The "last good" is when the list was last read without an error (D-T8.10): the store's
          time, so a remount after a long gap does not pass itself off as fresh. */}
      <Show when={s.jobsError()}>
        {(err) => <ErrorBlock text={err()} lastGood={s.jobsLoadedAt()} onRetry={() => void s.refreshJobs()} disabled={offline()} />}
      </Show>
      <Switch>
        <Match when={!s.jobsLoaded()}>
          <LoadingBars label="Loading jobs" />
        </Match>
        <Match when={rows().length === 0}>
          <div class={css.empty}>
            <p>{NO_JOBS_TEXT}</p>
            <Button variant="outline" disabled={offline()} onClick={() => s.setTab('profiles')}>
              Open Profiles
            </Button>
          </div>
        </Match>
        <Match when={rows().length > 0}>
          <Show when={selected()}>
            {(f) => <JobCard facts={f()} generation={entrance().generation} play={entrance().play} launchNotices={launchNotices()} />}
          </Show>
          <JobsTable
            rows={rows()}
            selected={selectedId()}
            onSelect={selectJob}
            onFocusCard={focusCard}
            play={entrance().play}
            first={entrance().generation <= 1}
            generation={entrance().generation}
          />
          <Show when={selected()}>{(f) => <JobWells facts={f()} generation={entrance().generation} play={entrance().play} />}</Show>
        </Match>
      </Switch>
    </div>
  );
};
