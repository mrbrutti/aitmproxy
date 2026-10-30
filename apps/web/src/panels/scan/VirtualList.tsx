// A thin virtual list reusing the same @tanstack/solid-virtual primitive the flow list is built on
// (src/flows/FlowList.tsx): a fixed-height-row window over a potentially long array, so the endpoints
// and injection-points lists stay cheap even at the engine's 1024-item cap. One scroll element, one
// absolutely-positioned canvas, rows rendered through a render-prop.
import { For, type JSX } from 'solid-js';
import { createVirtualizer } from '@tanstack/solid-virtual';
import css from './scan.module.css';

const OVERSCAN = 12;

export interface VirtualListProps<T> {
  items: readonly T[];
  rowHeight: number;
  /** Accessible name of the list region. */
  label: string;
  children: (item: T, index: number) => JSX.Element;
}

export function VirtualList<T>(props: VirtualListProps<T>): JSX.Element {
  let scrollEl: HTMLDivElement | undefined;
  const virtualizer = createVirtualizer({
    get count() {
      return props.items.length;
    },
    getScrollElement: () => scrollEl ?? null,
    estimateSize: () => props.rowHeight,
    overscan: OVERSCAN,
  });
  return (
    <div ref={scrollEl} class={css.scroll} role="list" aria-label={props.label}>
      <div class={css.canvas} style={{ height: `${virtualizer.getTotalSize()}px` }}>
        <For each={virtualizer.getVirtualItems()}>
          {(row) => (
            <div class={css.vrow} role="listitem" data-index={row.index} style={{ transform: `translateY(${row.start}px)`, height: `${props.rowHeight}px` }}>
              {props.children(props.items[row.index]!, row.index)}
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
