// Buttons (§2.7, §2.8): 28px in bars, press scale(.97) 120ms, hover 100ms. One primary per surface.
import { splitProps, type JSX, type ParentComponent } from 'solid-js';
import css from './components.module.css';

export type ButtonVariant = 'primary' | 'ghost' | 'outline' | 'toolbar' | 'small';

export interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  variant: ButtonVariant;
  /** Printed shortcut, e.g. `⌘⏎`. */
  kbd?: string | undefined;
  /** Toggle state for toolbar / small variants. */
  active?: boolean | undefined;
}

export const Button: ParentComponent<ButtonProps> = (props) => {
  const [local, rest] = splitProps(props, ['variant', 'kbd', 'active', 'class', 'children', 'type']);
  return (
    <button
      type={local.type ?? 'button'}
      class={`${css.btn}${local.class ? ` ${local.class}` : ''}`}
      data-variant={local.variant}
      data-active={local.active ? 'true' : undefined}
      aria-pressed={local.active != null && (local.variant === 'toolbar' || local.variant === 'small') ? local.active : undefined}
      {...rest}
    >
      {local.children}
      {local.kbd ? <kbd>{local.kbd}</kbd> : null}
    </button>
  );
};
