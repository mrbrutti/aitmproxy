import type { ParentComponent } from 'solid-js';
import css from './components.module.css';

/** A printed shortcut hint (`⌘⏎`), tertiary, UI face (§2.7 "keyboard hints printed on buttons"). */
export const Kbd: ParentComponent<{ class?: string | undefined }> = (props) => (
  <kbd class={`${css.kbd}${props.class ? ` ${props.class}` : ''}`}>{props.children}</kbd>
);
