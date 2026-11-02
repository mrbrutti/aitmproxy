// The severity stacked bar (D-T8.7): one segment per non-zero level, worst first, width
// proportional to the count. Hue lives only here, on the pill and on chips (W-18); the colour comes
// from `.barSeg[data-severity]` in the stylesheet, never from this file. A bar with no issues keeps
// its frame and says so, both to the eye (grey) and to a reader (`aria-label`).

import { For, type Component } from 'solid-js';
import { SEVERITY_ORDER, type BySeverity } from './model';
import css from './scanner.module.css';

/** `issues: high 1, medium 1, low 1` — the non-zero levels, worst first; `issues: none` when empty. */
export function severityLabel(by: BySeverity): string {
  const parts = SEVERITY_ORDER.filter((s) => by[s] > 0).map((s) => `${s} ${by[s]}`);
  return parts.length > 0 ? `issues: ${parts.join(', ')}` : 'issues: none';
}

export const SeverityBar: Component<{ by: BySeverity; class?: string | undefined }> = (props) => {
  const levels = () => SEVERITY_ORDER.filter((s) => props.by[s] > 0);
  const label = () => severityLabel(props.by);
  return (
    <div
      class={`${css.bar}${props.class ? ` ${props.class}` : ''}`}
      data-empty={levels().length === 0 ? 'true' : undefined}
      role="img"
      aria-label={label()}
      title={label()}
    >
      <For each={levels()}>
        {(s) => <i class={css.barSeg} data-severity={s} style={{ 'flex-grow': String(props.by[s]) }} />}
      </For>
    </div>
  );
};
