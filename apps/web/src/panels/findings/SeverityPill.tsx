// Severity pill (§2.2): tint background + deep text, 18px, 4px radius, 11/600 uppercase mono —
// the method badge's construction with the severity hue pairs. Badge has no severity hue, so it
// lives here. A missing or unknown severity prints as a grey dash (§2.8).
import { Show, type Component } from 'solid-js';
import { isSeverity } from './model';
import css from './findings.module.css';

export const SeverityPill: Component<{ severity: string | null | undefined; class?: string | undefined }> = (props) => (
  <Show when={isSeverity(props.severity)} fallback={<span class={css.dash}>—</span>}>
    <span class={`${css.pill}${props.class ? ` ${props.class}` : ''}`} data-severity={props.severity}>
      {props.severity}
    </span>
  </Show>
);
