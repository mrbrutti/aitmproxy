// The view primitives every T8 list and detail shares (plan amendment PA8, spec A9): the missing-value
// dash, a `dt`/`dd` fact, a titled section, the grey loading bars, the error block with the core's
// text and the last good time, the one reconnecting sentence, and the listbox keyboard contract of
// `panels/findings/Findings.tsx` (ArrowUp/Down/Home/End move the selection, Enter hands focus to the
// detail). Nothing here reads the store: each view passes what it owns.

import { Show, type Component, type JSX, type ParentComponent } from 'solid-js';
import { Button } from '~/components';
import { fmtClock } from '~/lib/format';
import { fmtWhenFull } from '~/panels/findings/model';
import css from './scanner.module.css';

/** The reconnecting note (D-T8.10), the one sentence every view prints while the bus is away. */
export const RECONNECT_NOTE = 'reconnecting: controls are disabled until the bus is back';

/** A grey dash for a missing value (foundation §2.8); zero is printed as `0`, never dashed. */
export const Dash: Component = () => <span class={css.dash}>—</span>;

export const yesNo = (v: boolean): string => (v ? 'yes' : 'no');

/** The "last good" instant of an error block: date and clock, so an overnight panel is not misread. */
export function fmtLastGood(ms: number): string {
  return fmtWhenFull(ms) ?? fmtClock(ms);
}

/** One `dt`/`dd` pair of a `.facts` list; `null`/`undefined` prints the dash, a boolean its word. */
export const Fact: Component<{
  label: string;
  value: JSX.Element | string | number | boolean | null | undefined;
  field?: string | undefined;
  mono?: boolean | undefined;
}> = (props) => (
  <>
    <dt>{props.label}</dt>
    <dd data-field={props.field} class={props.mono ? css.mono : undefined}>
      <Show when={props.value !== null && props.value !== undefined} fallback={<Dash />}>
        {typeof props.value === 'boolean' ? yesNo(props.value) : props.value}
      </Show>
    </dd>
  </>
);

export const Section: ParentComponent<{ title: string }> = (props) => (
  <section class={css.section}>
    <h3 class={css.sectionTitle}>{props.title}</h3>
    {props.children}
  </section>
);

/** Four grey bars (W-16 loading): no animation, labelled for a reader. */
export const LoadingBars: Component<{ label: string }> = (props) => (
  <div class={css.loading} aria-busy="true" aria-label={props.label}>
    <i />
    <i />
    <i />
    <i />
  </div>
);

/**
 * The error state (D-T8.10): the core's text verbatim, when the data on screen was last read
 * without an error (`lastGood` omitted hides the line; `null` prints the dash), and Retry.
 */
export const ErrorBlock: Component<{
  text: string;
  lastGood?: number | null | undefined;
  onRetry: () => void;
  disabled: boolean;
}> = (props) => (
  <div class={css.errorBlock} role="alert" data-state="error">
    <p>{props.text}</p>
    <Show when={props.lastGood !== undefined}>
      <span class={css.mono}>
        last good:{' '}
        <Show when={props.lastGood} fallback={<Dash />}>
          {(t) => fmtLastGood(t())}
        </Show>
      </span>
    </Show>
    <Button variant="small" class={css.retry} disabled={props.disabled} onClick={() => props.onRetry()}>
      Retry
    </Button>
  </div>
);

export const ReconnectNote: Component = () => (
  <p class={css.note} role="status" data-reconnect>
    {RECONNECT_NOTE}
  </p>
);

export interface ListboxKeys {
  /** The row ids in display order (the keyboard's order). */
  ids: () => readonly string[];
  selectedId: () => string | null;
  select: (id: string) => void;
  /** Enter: hand focus to the detail region (`tabIndex={-1}`). */
  focusDetail: () => void;
  /** The `id` attribute of a row, looked up with `getElementById` so a wire string is never a selector. */
  domId: (id: string) => string;
}

/**
 * The `onKeyDown` of a `role="listbox"` (W-17, `Findings.tsx:46-72`): ArrowDown/ArrowUp move one
 * row (from nothing: first / last), Home/End jump, Enter focuses the detail; a keyboard selection
 * scrolls its row into view. Every move is clamped; an empty list is a no-op. Nothing animates.
 */
export function listboxKeys(opts: ListboxKeys): (e: KeyboardEvent) => void {
  const pick = (id: string): void => {
    opts.select(id);
    document.getElementById(opts.domId(id))?.scrollIntoView?.({ block: 'nearest' });
  };
  const move = (delta: number): void => {
    const all = opts.ids();
    if (all.length === 0) return;
    const at = all.indexOf(opts.selectedId() ?? '');
    const next = at < 0 ? (delta > 0 ? 0 : all.length - 1) : Math.max(0, Math.min(all.length - 1, at + delta));
    const id = all[next];
    if (id !== undefined) pick(id);
  };
  const edge = (last: boolean): void => {
    const all = opts.ids();
    const id = last ? all[all.length - 1] : all[0];
    if (id !== undefined) pick(id);
  };
  return (e: KeyboardEvent): void => {
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
        edge(false);
        break;
      case 'End':
        e.preventDefault();
        edge(true);
        break;
      case 'Enter':
        e.preventDefault();
        opts.focusDetail();
        break;
    }
  };
}
