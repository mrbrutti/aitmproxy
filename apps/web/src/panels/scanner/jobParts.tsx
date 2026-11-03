// The Jobs view's shared parts (spec D18 W2, plan Task 3.8): what `JobCard.tsx` and `JobsTable.tsx`
// both draw. A counter is a span keyed by its text, so a new value remounts it and `jobsTick`
// plays once with no timer (D12); the ring puts the fraction on `--jobs-f` and lets the stylesheet
// draw the arc (`pathLength="1"`, no circumference constant); the dots, the chip, the severity
// words and the finding-line parts carry the `data-*` hooks `jobs.module.css` paints by. Nothing
// here reads the store or owns a timer; every word arrives as a prop from `helpers.ts`.

import { For, Show, type Component } from 'solid-js';
import { AGENT_DOT_HELP, type Part, type Ring as RingValue, type SeverityPart, type Tone } from './helpers';
import css from './jobs.module.css';

/**
 * How the table selected a job: the entrance plays for the pointer and never for the keyboard
 * (D12). A selection the view did not make (a start, the first list) has no cause and plays.
 */
export type SelectCause = 'pointer' | 'keyboard';

const classes = (...names: (string | undefined)[]): string => names.filter((n) => n !== undefined && n !== '').join(' ');

/**
 * A live counter. `<Show keyed>` on the text: a new text is a new span, so the `jobsTick`
 * keyframe plays once per change; the same text keeps its node and plays nothing.
 */
export const Tick: Component<{ text: string; class?: string | undefined }> = (props) => (
  <Show keyed when={props.text}>
    {(text) => <span class={classes(css.tick, props.class)}>{text}</span>}
  </Show>
);

/** The fraction a determinate ring draws; `null` when there is no arc to draw. */
const ringFraction = (ring: RingValue): number | null =>
  typeof ring === 'object' && 'determinate' in ring ? ring.determinate : null;

/**
 * The row's ring (D10): hidden from readers (the row's label carries the percent). Determinate
 * rings set `--jobs-f` and `data-fraction` (4 decimals); an indeterminate ring is marked and the
 * stylesheet draws its static quarter arc; `none` and `finished` draw nothing.
 */
export const Ring: Component<{ ring: RingValue }> = (props) => {
  const fraction = () => ringFraction(props.ring);
  const draws = () => props.ring === 'indeterminate' || fraction() !== null;
  return (
    <Show when={draws()}>
      <svg
        class={css.ring}
        viewBox="0 0 18 18"
        aria-hidden="true"
        data-indeterminate={props.ring === 'indeterminate' ? 'true' : undefined}
        data-fraction={fraction() === null ? undefined : fraction()!.toFixed(4)}
        style={fraction() === null ? undefined : { '--jobs-f': String(fraction()) }}
      >
        <circle class={css.ringTrack} cx="9" cy="9" r="7" />
        <circle class={css.ringArc} cx="9" cy="9" r="7" pathLength="1" />
      </svg>
    </Show>
  );
};

/** A row's tone dot when it has no ring; breathes while cancelling (D12's two breathing dots). */
export const JobDot: Component<{ tone: Tone; breathing: boolean }> = (props) => (
  <i class={classes(css.dot, props.breathing ? css.breathe : undefined)} data-tone={props.tone} aria-hidden="true" />
);

/** The agent dot beside the state word of a job an agent started (D10). */
export const AgentDot: Component = () => <i class={css.agentDot} title={AGENT_DOT_HELP} aria-hidden="true" />;

/** The card's state chip (D11 §1): the tone pair, a dot that breathes only while cancelling, the word. */
export const StateChip: Component<{ word: string; tone: Tone; breathing: boolean }> = (props) => (
  <span class={css.chip} data-field="state" data-tone={props.tone}>
    <i class={classes(css.chipDot, props.breathing ? css.breathe : undefined)} aria-hidden="true" />
    {props.word}
  </span>
);

/**
 * Severity words in their inks (`severityWordParts`): one `.sev[data-severity]` span per part with
 * `, ` between; with no parts the empty words (`no issues yet` / `no issues`) in the muted ink.
 */
export const SeverityWords: Component<{ parts: SeverityPart[]; empty: string; class?: string | undefined }> = (props) => (
  <Show
    when={props.parts.length > 0}
    fallback={
      <span class={props.class} data-ink="muted">
        {props.empty}
      </span>
    }
  >
    <span class={props.class}>
      <For each={props.parts}>
        {(part, i) => (
          <>
            <Show when={i() > 0}>, </Show>
            <span class={css.sev} data-severity={part.severity}>
              {part.word}
            </span>
          </>
        )}
      </For>
    </span>
  </Show>
);

/** The finding line's or the now tag's parts: a `.part[data-role]` span each (D11 §1, D21). */
export const Parts: Component<{ parts: Part[] }> = (props) => (
  <For each={props.parts}>
    {(part) => (
      <span class={css.part} data-role={part.role}>
        {part.text}
      </span>
    )}
  </For>
);
