// A small anchored popover for inline confirmations and one-field inputs (clear, comment,
// PoC name). Same floating surface as Menu; focuses its first input on open.
import { onMount, type ParentComponent } from 'solid-js';
import { Portal } from 'solid-js/web';
import css from './components.module.css';
import { useFloating, type MenuProps } from './Menu';
import type { AnchorRect, Placement } from './floating';

export interface PopoverProps {
  anchor: AnchorRect;
  onClose: () => void;
  placement?: Placement | undefined;
  animate?: boolean | undefined;
  label?: string | undefined;
}

export const Popover: ParentComponent<PopoverProps> = (props) => {
  let root: HTMLDivElement | undefined;
  const floating = useFloating({ anchor: () => props.anchor, placement: props.placement ?? 'bottom-start', onClose: () => props.onClose() });
  onMount(() => {
    const first = root?.querySelector<HTMLElement>('input, textarea, select, button');
    (first ?? root)?.focus({ preventScroll: true });
  });
  return (
    <Portal>
      <div
        ref={(n) => {
          root = n;
          floating.ref(n);
        }}
        data-floating
        class={`${css.floating} ${css.popover}`}
        data-animate={props.animate === false ? 'false' : 'true'}
        role="dialog"
        aria-label={props.label}
        tabIndex={-1}
        style={{ left: `${floating.pos().left}px`, top: `${floating.pos().top}px`, '--origin': floating.pos().origin }}
      >
        {props.children}
      </div>
    </Portal>
  );
};

export type { MenuProps };
