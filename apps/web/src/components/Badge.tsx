// Method / status badge (§2.2): tint background + deep text, 18px, 4px radius, 11/600 uppercase
// mono. Status codes use the same construction with the status hue pair (owner decision after
// measuring Proxyman); `paused`, `killed` and `agent` are the state pills.
import type { ParentComponent } from 'solid-js';
import type { MethodHue, StatusHue } from '~/model/flow';
import css from './components.module.css';

export type BadgeHue = MethodHue | StatusHue | 'agent';

export interface BadgeProps {
  hue: BadgeHue;
  /** Hold a stable min-width (the Status column). */
  fixed?: boolean | undefined;
  class?: string | undefined;
  title?: string | undefined;
}

export const Badge: ParentComponent<BadgeProps> = (props) => (
  <span class={`${css.badge}${props.class ? ` ${props.class}` : ''}`} data-hue={props.hue} data-fixed={props.fixed ? 'true' : undefined} title={props.title}>
    {props.children}
  </span>
);
