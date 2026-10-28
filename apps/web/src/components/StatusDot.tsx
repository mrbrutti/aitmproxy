// The 8px status dot (§2.2 / §2.7). A graphic, so the pending/paused dot uses `intercept.base`.
import type { Component } from 'solid-js';
import type { StatusHue } from '~/model/flow';
import css from './components.module.css';

export type DotHue = StatusHue | 'armed' | 'grey' | 'agent';

export const StatusDot: Component<{ hue: DotHue; class?: string | undefined; title?: string | undefined }> = (props) => (
  <i class={`${css.dot}${props.class ? ` ${props.class}` : ''}`} data-hue={props.hue} title={props.title} aria-hidden="true" />
);
