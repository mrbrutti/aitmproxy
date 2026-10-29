// Pane tab bar (§2.7): title 16/600, plain 13px tabs, the active one in the accent with a 2px
// underline flush with the bar's 1px rule, a tertiary `+`, and a right-hand slot. ←/→ move the
// selection when the bar has focus (roving tabindex); keyboard switches never animate.

import { For, Show, type Component, type JSX } from 'solid-js';
import css from './inspector.module.css';

export interface TabDef {
  id: string;
  label: string;
  /** Small count after the label, e.g. header count. */
  count?: number | null;
}

export interface TabsProps {
  title: string;
  tabs: TabDef[];
  active: string;
  onSelect: (id: string) => void;
  right?: JSX.Element;
  onPlus?: (() => void) | undefined;
  label?: string | undefined;
}

export const Tabs: Component<TabsProps> = (props) => {
  let bar!: HTMLDivElement;

  const move = (delta: number) => {
    const ids = props.tabs.map((t) => t.id);
    const i = ids.indexOf(props.active);
    const next = ids[(i + delta + ids.length) % ids.length];
    if (!next) return;
    props.onSelect(next);
    queueMicrotask(() => bar.querySelector<HTMLButtonElement>(`[data-tab="${next}"]`)?.focus());
  };

  return (
    <div class={css.tabs}>
      <h2 class={css.tabsTitle}>{props.title}</h2>
      <div
        ref={bar}
        class={css.tabList}
        role="tablist"
        aria-label={props.label ?? `${props.title} tabs`}
        onKeyDown={(e) => {
          if (e.key === 'ArrowRight') {
            e.preventDefault();
            move(1);
          } else if (e.key === 'ArrowLeft') {
            e.preventDefault();
            move(-1);
          } else if (e.key === 'Home') {
            e.preventDefault();
            props.tabs[0] && props.onSelect(props.tabs[0].id);
          } else if (e.key === 'End') {
            e.preventDefault();
            props.tabs.at(-1) && props.onSelect(props.tabs.at(-1)!.id);
          }
        }}
      >
        <For each={props.tabs}>
          {(t) => (
            <button
              type="button"
              role="tab"
              data-tab={t.id}
              data-label={t.label}
              class={css.tab}
              classList={{ [css.tabOn!]: props.active === t.id }}
              aria-selected={props.active === t.id}
              tabIndex={props.active === t.id ? 0 : -1}
              onClick={() => props.onSelect(t.id)}
            >
              <span class={css.tabLabel}>
                {t.label}
                <Show when={t.count != null && t.count > 0}>
                  <span class={css.tabCount}>{t.count}</span>
                </Show>
              </span>
            </button>
          )}
        </For>
        <button type="button" class={`${css.tab} ${css.tabPlus}`} title="Add a custom previewer (plugin tier, M3)" aria-label="Add viewer" tabIndex={-1} onClick={() => props.onPlus?.()}>
          +
        </button>
      </div>
      <div class={css.tabsRight}>{props.right}</div>
    </div>
  );
};
