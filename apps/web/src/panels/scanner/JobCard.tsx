// The selected job's card (spec D18 W2, D11; plan Task 3.8 skeleton, Task 3.8a fills it). The
// `role="region" aria-label="Selected job"` section the live script calls `STRIP` on the Jobs tab:
// `data-job`, `data-state`, `data-tone`, and the entrance's `data-generation` / `data-entrance`
// (D12: the pointer, a start and the first list play it; the keyboard never does). The skeleton
// renders the Kit's words as plain text inside the final `data-field` elements — the state chip,
// the heading, the reason line, the finding line, the primary verb, the attention block with the
// raw token and the notices — so the W1 tests hold; Task 3.8a replaces the markup inside with the
// comp's blocks (lane, ledger, gauge, KPI strip, end swap). No timer lives here (AC32).

import { createMemo, For, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { useApp } from '~/state/context';
import {
  attention,
  CANCEL_SCAN_HELP,
  CANCELLING_TITLE,
  findingLine,
  isTerminal,
  jobHeading,
  jobHeadingHelp,
  notices,
  rawCrawlErrorLine,
  rawReasonLine,
  reasonLine,
  SCAN_AGAIN_HELP_GENERIC,
  scanAgainHelp,
  stateWords,
  tone,
  type JobFacts,
} from './helpers';
import { StateChip } from './jobParts';
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

/** The Jobs view's time zone for the finding line's clock (`started 11:32`). */
const zone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;

export const JobCard: Component<JobCardProps> = (props) => {
  const s = scanStore(useApp());
  const f = () => props.facts;
  const j = () => f().summary;
  const terminal = () => isTerminal(j().state);
  const cancelling = () => j().state === 'cancelling';
  const offline = () => !s.busOpen();
  /** Off once terminal and while the merged state is `cancelling` (D2: one scan.cancel per job). */
  const canCancel = () => !terminal() && !cancelling() && !s.busy() && !offline();
  /** Scan Again: a terminal job, no launch in flight or awaiting confirmation, the bus open (D13). */
  const canScanAgain = () => terminal() && !s.busy() && s.pendingConfirm() === null && !offline();
  const scanAgainTitle = () => {
    const st = f().status;
    return st === null ? SCAN_AGAIN_HELP_GENERIC : scanAgainHelp(st);
  };
  const cancelError = s.errorFor(['cancel']);
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

  return (
    <section
      class={css.card}
      role="region"
      aria-label="Selected job"
      tabIndex={-1}
      data-job={j().job}
      data-state={j().state}
      data-tone={tone(f())}
      data-generation={props.generation}
      data-entrance={props.play ? 'play' : 'none'}
    >
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
            {finding().text}
          </p>
        </div>
        <div class={css.verbs}>
          <Show
            when={terminal()}
            fallback={
              <Button
                variant="primary"
                aria-label={`Cancel scan ${j().job}`}
                title={CANCEL_SCAN_HELP}
                disabled={!canCancel()}
                onClick={() => void s.cancel(j().job)}
              >
                {cancelling() ? CANCELLING_TITLE : 'Cancel Scan'}
              </Button>
            }
          >
            <Button
              variant="primary"
              aria-label={`Scan again ${j().job}`}
              title={scanAgainTitle()}
              disabled={!canScanAgain()}
              onClick={() => void s.scanAgain(j().job)}
            >
              Scan Again
            </Button>
          </Show>
        </div>
      </div>

      {/* A failed per-job read (PA4): the core's text with Retry, above the facts. */}
      <Show when={s.statusError(j().job)}>
        {(err) => <ErrorBlock text={err()} onRetry={() => void s.refreshStatus(j().job)} disabled={offline()} />}
      </Show>
      {/* The one store error this view owns (PA5): a refused cancel, beside the toast. */}
      <Show when={cancelError()}>
        {(err) => (
          <p class={css.errorText} role="alert" data-error="cancel">
            {err().text}
          </p>
        )}
      </Show>

      {/* The attention block (D9, D11 §6): the count lines, the error, the raw lines, the notices. */}
      <Show when={hasAttention()}>
        <div class={css.attention} data-field="attention">
          <For each={attentionLines()}>{(line) => <p>{line.text}</p>}</For>
          <Show when={f().status}>
            {(st) => (
              <>
                <Show when={st().error !== null}>
                  <p class={css.errorText} data-field="error">
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
            <ul class={css.notices} data-field="notices">
              <For each={noticeLines()}>{(line) => <li>{line}</li>}</For>
            </ul>
          </Show>
        </div>
      </Show>
    </section>
  );
};
