// The Jobs view (spec D18 W2, the locked comp): one column on the surface holding the bus banner
// (D15), the selected job's card, the jobs table and the two wells, each a component of its own
// (`JobCard`, `JobsTable`, `JobWells`) over `jobFacts(summary, status)` — the list row merged with
// the held status by D2's rule, so the card, the row and the wells can never disagree. States:
// grey bars until the first list answers, the Kit's empty sentence with an `Open Profiles` button,
// the core's error text with the last good time and Retry, and the banner with the values' age
// while the bus is away (every control disabled, the data kept).
//
// The entrance (D12): `{ generation, play }`. A pointer selection, a start or the first list bump
// the generation and play; a keyboard selection changes the job and plays nothing. A selection the
// view makes (`selectJob`) decides by its cause before it reaches the store; a selection it did not
// make (the store's after-start pick, the first list, another client's job) is caught by an effect
// on the store's selection and plays. No timer lives here: the banner's age is the store's 1 s
// clock against `jobsLoadedAt` (D16), the counters come from the poll (AC32).

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
   * The age of the values the banner shows (D15): `jobsLoadedAt` against the store's clock
   * (`nowMs`, the one 1 s interval, D6 amendment), so the clause counts up while the bus is away
   * and the polls are stopped; `null` before the first list. Clamped at 0: two wall-clock stamps
   * within one tick can otherwise read negative for a beat. The clock is not read while online,
   * so the view does not re-render on it then.
   */
  const valuesAgeMs = createMemo<number | null>(() => {
    if (!offline()) return null;
    const at = s.jobsLoadedAt();
    return at === null ? null : Math.max(0, s.nowMs() - at);
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
  const bump = (): void => {
    setEntrance((e) => ({ generation: e.generation + 1, play: true }));
  };
  const hold = (): void => {
    setEntrance((e) => ({ generation: e.generation, play: false }));
  };

  /** The job the view is selecting itself, while the store takes it; `null` otherwise. */
  let own: string | null = null;
  /** The table's selection: the cause decides the entrance here; a click on the selected row changes nothing. */
  const selectJob = (job: string, cause: SelectCause): void => {
    if (job === selectedId()) return;
    if (cause === 'keyboard') hold();
    else bump();
    own = job;
    s.setSelectedJob(job);
    own = null;
  };
  // A selection the view did not make (a start, the first list, another client's job) plays.
  createEffect(
    on(selectedId, (id) => {
      if (id === null || id === own) return;
      bump();
    }),
  );

  let root: HTMLDivElement | undefined;
  /**
   * Enter in the listbox: the card's primary verb (`Cancel scan <job>` / `Scan again <job>`) when
   * enabled, else its first enabled verb, else the card itself (D14 as gap 77 amends it: the comp
   * lists Show Site Map and Show Issues before the primary, and the mac's Return goes to Cancel Scan).
   */
  const focusCard = (): void => {
    const card = root?.querySelector<HTMLElement>('section[role=region][aria-label="Selected job"]');
    const primary = card?.querySelector<HTMLElement>(
      'button[aria-label^="Cancel scan "]:not([disabled]), button[aria-label^="Scan again "]:not([disabled])',
    );
    const verb = primary ?? card?.querySelector<HTMLElement>('button:not([disabled])');
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
          />
          <Show when={selected()}>{(f) => <JobWells facts={f()} generation={entrance().generation} play={entrance().play} />}</Show>
        </Match>
      </Switch>
    </div>
  );
};
