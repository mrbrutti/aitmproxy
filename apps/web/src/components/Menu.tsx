// Floating menu (§2.7 / §2.8): radius 10, `floating` shadow, 160ms scale-from-.97 at the trigger,
// keyboard navigable, closes on Esc / outside click. Pass `animate={false}` when opened from the
// keyboard — keyboard-initiated actions never animate.
import { createSignal, For, onCleanup, onMount, Show, type Component, type JSX } from 'solid-js';
import { Portal } from 'solid-js/web';
import { Icon } from './Icon';
import css from './components.module.css';
import { place, type AnchorRect, type Placement } from './floating';

export type MenuEntry =
  | {
      type?: 'item';
      label: string;
      kbd?: string | undefined;
      onSelect?: (() => void) | undefined;
      disabled?: boolean | undefined;
      /** Tooltip; used for the disabled-reason on out-of-scope rows. */
      title?: string | undefined;
      danger?: boolean | undefined;
      checked?: boolean | undefined;
      /** A colour swatch before the label (mark colours); any CSS colour. */
      swatch?: string | undefined;
      children?: MenuEntry[] | undefined;
    }
  | { type: 'separator' };

type Item = Exclude<MenuEntry, { type: 'separator' }>;
const isItem = (e: MenuEntry): e is Item => e.type !== 'separator';

export interface MenuProps {
  anchor: AnchorRect;
  items: MenuEntry[];
  onClose: () => void;
  animate?: boolean | undefined;
  placement?: Placement | undefined;
  /** Submenu: ArrowLeft closes it and returns focus to the parent. */
  nested?: boolean | undefined;
  /** The parent menu's element id (submenus), so outside-click detection treats it as inside. */
  parentId?: string | undefined;
  /** Submenu: choosing an item closes the whole tree through this (the root's `onClose`), not just the submenu. */
  onCloseAll?: (() => void) | undefined;
  label?: string | undefined;
}

/** Shared behaviour for floating surfaces: positioning, outside click, Esc, focus restore. */
export function useFloating(opts: {
  anchor: () => AnchorRect;
  placement?: Placement | undefined;
  onClose: () => void;
  restoreFocus?: boolean | undefined;
}) {
  const [pos, setPos] = createSignal<{ left: number; top: number; origin: string }>({ left: -9999, top: -9999, origin: 'top left' });
  let el: HTMLDivElement | undefined;
  const previous = typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null;

  const reposition = () => {
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos(place(opts.anchor(), { width: r.width, height: r.height }, { width: window.innerWidth, height: window.innerHeight }, opts.placement));
  };

  onMount(() => {
    reposition();
    const onDown = (e: PointerEvent) => {
      const t = e.target as Element | null;
      if (t && el && (el.contains(t) || t.closest('[data-floating]') !== null && isDescendantFloating(el, t))) return;
      opts.onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        opts.onClose();
      }
    };
    const onScroll = () => opts.onClose();
    document.addEventListener('pointerdown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', onScroll);
    onCleanup(() => {
      document.removeEventListener('pointerdown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', onScroll);
      if (opts.restoreFocus !== false && previous && document.contains(previous)) previous.focus({ preventScroll: true });
    });
  });

  return { pos, ref: (node: HTMLDivElement) => (el = node), element: () => el };
}

/** True when `t` sits in a floating surface opened from inside `root` (a submenu). */
function isDescendantFloating(root: HTMLElement, t: Element): boolean {
  let f: Element | null = t.closest('[data-floating]');
  while (f) {
    const parentId = f.getAttribute('data-parent');
    if (!parentId) return false;
    if (parentId === root.id) return true;
    f = document.getElementById(parentId);
  }
  return false;
}

let seq = 0;

export const Menu: Component<MenuProps> = (props) => {
  const id = `menu-${++seq}`;
  const selectable = () => props.items.map((it, i) => (isItem(it) && !it.disabled ? i : -1)).filter((i) => i >= 0);
  const [active, setActive] = createSignal<number>(-1);
  const [sub, setSub] = createSignal<{ index: number; anchor: AnchorRect; fromKeyboard: boolean } | null>(null);
  let root: HTMLDivElement | undefined;
  const itemEls: HTMLButtonElement[] = [];

  const floating = useFloating({
    anchor: () => props.anchor,
    placement: props.placement ?? 'bottom-start',
    onClose: () => props.onClose(),
    restoreFocus: !props.nested,
  });

  onMount(() => {
    root?.focus({ preventScroll: true });
    if (props.nested || props.animate === false) {
      const first = selectable()[0];
      if (first != null && props.animate === false) setActive(first);
    }
  });

  const move = (delta: number) => {
    const list = selectable();
    if (!list.length) return;
    const cur = list.indexOf(active());
    const next = cur < 0 ? (delta > 0 ? 0 : list.length - 1) : (cur + delta + list.length) % list.length;
    setActive(list[next]!);
  };

  const openSub = (index: number, fromKeyboard: boolean) => {
    const el = itemEls[index];
    if (!el) return;
    const r = el.getBoundingClientRect();
    setSub({ index, anchor: { left: r.left, top: r.top, right: r.right, bottom: r.bottom }, fromKeyboard });
  };

  /** An item was chosen: the whole menu tree goes, however deep this menu sits. */
  const closeAll = () => (props.onCloseAll ?? props.onClose)();

  const activate = (index: number, fromKeyboard: boolean) => {
    const it = props.items[index];
    if (!it || !isItem(it) || it.disabled) return;
    if (it.children) {
      setActive(index);
      openSub(index, fromKeyboard);
      return;
    }
    closeAll();
    it.onSelect?.();
  };

  const onKeyDown: JSX.EventHandler<HTMLDivElement, KeyboardEvent> = (e) => {
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
        setActive(selectable()[0] ?? -1);
        break;
      case 'End':
        e.preventDefault();
        setActive(selectable().at(-1) ?? -1);
        break;
      case 'ArrowRight': {
        const it = props.items[active()];
        if (it && isItem(it) && it.children) {
          e.preventDefault();
          openSub(active(), true);
        }
        break;
      }
      case 'ArrowLeft':
        if (props.nested) {
          e.preventDefault();
          e.stopPropagation();
          props.onClose();
        }
        break;
      case 'Enter':
      case ' ':
        e.preventDefault();
        if (active() >= 0) activate(active(), true);
        break;
      case 'Tab':
        e.preventDefault();
        props.onClose();
        break;
    }
  };

  return (
    <Portal>
      <div
        ref={(n) => {
          root = n;
          floating.ref(n);
        }}
        id={id}
        data-floating
        data-parent={props.parentId}
        class={css.floating}
        data-animate={props.animate === false ? 'false' : 'true'}
        role="menu"
        aria-label={props.label}
        tabIndex={-1}
        style={{ left: `${floating.pos().left}px`, top: `${floating.pos().top}px`, '--origin': floating.pos().origin }}
        onKeyDown={onKeyDown}
        onPointerLeave={() => {
          if (!sub()) setActive(-1);
        }}
      >
        <For each={props.items}>
          {(entry, i) => (
            <Show when={isItem(entry)} fallback={<div class={css.separator} role="separator" />}>
              {(() => {
                const it = entry as Item;
                return (
                  <button
                    ref={(n) => (itemEls[i()] = n)}
                    type="button"
                    role={it.checked != null ? 'menuitemradio' : 'menuitem'}
                    aria-checked={it.checked != null ? it.checked : undefined}
                    aria-haspopup={it.children ? 'menu' : undefined}
                    aria-expanded={it.children ? sub()?.index === i() : undefined}
                    class={css.menuItem}
                    data-active={active() === i() ? 'true' : undefined}
                    data-danger={it.danger ? 'true' : undefined}
                    disabled={it.disabled}
                    title={it.title}
                    onPointerEnter={() => {
                      if (it.disabled) return;
                      setActive(i());
                      if (it.children) openSub(i(), false);
                      else if (sub()) setSub(null);
                    }}
                    onClick={() => activate(i(), false)}
                  >
                    <Show when={it.checked != null}>
                      <span class={css.check}>{it.checked ? <Icon name="check" size={12} /> : null}</span>
                    </Show>
                    <Show when={it.swatch}>
                      <i class={css.swatch} style={{ background: it.swatch }} aria-hidden="true" />
                    </Show>
                    <span class={css.label}>{it.label}</span>
                    <Show when={it.kbd}>
                      <kbd class={css.kbd}>{it.kbd}</kbd>
                    </Show>
                    <Show when={it.children}>
                      <Icon name="chevron-right" size={12} class={css.chev} />
                    </Show>
                  </button>
                );
              })()}
            </Show>
          )}
        </For>
        <Show when={sub()}>
          {(s) => (
            <Menu
              nested
              parentId={id}
              anchor={s().anchor}
              placement="right-start"
              animate={!s().fromKeyboard}
              items={(props.items[s().index] as Item).children ?? []}
              onClose={() => {
                setSub(null);
                root?.focus({ preventScroll: true });
              }}
              onCloseAll={closeAll}
            />
          )}
        </Show>
      </div>
    </Portal>
  );
};
