// The flow list (§2.7): @tanstack/solid-virtual over app.visible() with fixed `--row` rows, a
// sticky 28px header (resizable, hideable, sortable), stick-to-bottom with a "↓ N new" pill,
// multi-select, the row context menu, and the §2.8 empty states.
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show, Switch, Match, type Component } from 'solid-js';
import { createVirtualizer } from '@tanstack/solid-virtual';
import { useApp, useL4 } from '~/state/context';
import type { FlowEntry } from '~/state/app';
import { Menu, type MenuEntry } from '~/components/Menu';
import { pointAnchor, type AnchorRect } from '~/components/floating';
import { EVENTS } from '~/shell/shortcuts';
import { httpVerbAllowed, isL4Chip, l4ChipMatches, L4_NO_HTTP_VERBS, type UnionRow } from '~/panels/l4/model';
import { compareFlows, createColumnState, type ColumnId, type ColumnStore } from './columns';
import { FlowRow } from './FlowRow';
import { L4FlowRow } from './L4FlowRow';
import { CommentPopover, flowMenu, markItems, PocPopover } from './ContextMenu';
import { isAtBottom } from './scroll';
import css from './FlowList.module.css';

const HEADER = 28;
const OVERSCAN = 12;

type Overlay =
  | { kind: 'menu'; entry: FlowEntry; anchor: AnchorRect; kb: boolean }
  | { kind: 'mark'; entry: FlowEntry; anchor: AnchorRect; kb: boolean }
  | { kind: 'comment'; entry: FlowEntry; anchor: AnchorRect }
  | { kind: 'poc'; entry: FlowEntry; anchor: AnchorRect }
  | { kind: 'columns'; anchor: AnchorRect; kb: boolean };

const readRowPx = (): number => {
  if (typeof getComputedStyle === 'undefined') return 28;
  const v = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--row'));
  return Number.isFinite(v) && v > 0 ? v : 28;
};

export interface FlowListProps {
  /** Column state; the default persists to localStorage. */
  columns?: ColumnStore;
}

export const FlowList: Component<FlowListProps> = (props) => {
  const app = useApp();
  const l4 = useL4();
  const cols = props.columns ?? createColumnState();
  const [rowPx, setRowPx] = createSignal(readRowPx());
  const [atBottom, setAtBottom] = createSignal(true);
  const [leftAt, setLeftAt] = createSignal(0);
  const [overlay, setOverlay] = createSignal<Overlay | null>(null);
  const [resizing, setResizing] = createSignal<ColumnId | null>(null);
  let scrollEl: HTMLDivElement | undefined;

  /** Sorting is a view transform; default is capture order. */
  const rows = createMemo<FlowEntry[]>(() => {
    const s = cols.sort();
    const v = app.visible();
    if (!s) return v;
    return [...v].sort((a, b) => compareFlows(s, a.raw, b.raw));
  });
  const count = () => rows().length;

  // L4 sessions are top-level rows in this one list (parity with TUI/macOS). They are appended
  // after the virtualised HTTP rows, and shown only in the unified view (chip "all") or under an
  // L4 chip that matches them (`TCP` / `UDP` / `L4`, spec §7(c)) — never under an HTTP-specific
  // chip or an app/domain/scope source. `matchesChip` already hides HTTP rows under an L4 chip.
  const l4Rows = createMemo<UnionRow[]>(() => {
    if (!l4 || !l4.present()) return [];
    const side = app.ui.sidebar.kind;
    if (side !== 'all' && side !== 'l4') return [];
    const chip = app.ui.chip;
    if (chip === 'all') return l4.rows();
    if (!isL4Chip(chip)) return [];
    return l4.rows().filter((row) => l4ChipMatches(chip, row));
  });

  const virtualizer = createVirtualizer({
    get count() {
      return count();
    },
    getScrollElement: () => scrollEl ?? null,
    estimateSize: () => rowPx(),
    overscan: OVERSCAN,
    scrollMargin: HEADER,
    scrollPaddingStart: HEADER,
    getItemKey: (i) => i,
  });

  // Density moves --row; re-measure once per change (one style read, no per-row work).
  createEffect(
    on(
      () => app.ui.density,
      () => {
        queueMicrotask(() => {
          const px = readRowPx();
          if (px !== rowPx()) {
            setRowPx(px);
            virtualizer.measure();
          }
        });
      },
      { defer: true },
    ),
  );

  const minWidth = createMemo(() => cols.visible().reduce((n, c) => n + cols.width(c.id), 0));

  // ---- stick to bottom -----------------------------------------------------------
  const scrollToEnd = () => {
    if (!scrollEl) return;
    scrollEl.scrollTop = scrollEl.scrollHeight;
    setAtBottom(true);
  };
  const onScroll = () => {
    if (!scrollEl) return;
    const bottom = isAtBottom(scrollEl.scrollTop, scrollEl.clientHeight, scrollEl.scrollHeight, rowPx());
    if (bottom !== atBottom()) {
      setAtBottom(bottom);
      if (!bottom) setLeftAt(count());
    }
  };
  createEffect(
    on(count, (n, prev) => {
      if (prev != null && n > prev && (atBottom() || app.ui.autoSelect)) queueMicrotask(scrollToEnd);
      if (prev != null && n < prev && leftAt() > n) setLeftAt(n);
    }),
  );
  const newRows = () => (atBottom() ? 0 : Math.max(0, count() - leftAt()));

  // ---- keep the selection in view (keyboard moves; align 'auto' is a no-op when visible) ----
  createEffect(
    on(app.selectedId, (id) => {
      if (!id) return;
      const i = rows().findIndex((e) => e.id === id);
      if (i >= 0) virtualizer.scrollToIndex(i, { align: 'auto' });
    }),
  );

  // ---- row geometry for keyboard-opened menus ----------------------------------------------
  const anchorFor = (id: string): AnchorRect => {
    const el = scrollEl?.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`);
    if (el) {
      const r = el.getBoundingClientRect();
      return { left: r.left + 48, top: r.top, right: r.left + 48, bottom: r.bottom };
    }
    const r = scrollEl?.getBoundingClientRect();
    return r ? pointAnchor(r.left + r.width / 2, r.top + r.height / 2) : pointAnchor(0, 0);
  };
  const entryOf = (id: string) => app.byId.get(id) ?? null;
  // D9 UI (parity spec §7(c), AC33): mark, comment and the row menu are HTTP verbs. An L4 id is
  // not in the HTTP map, so `entryOf` would already be null — but the refusal is deliberate, with
  // the notice, not incidental: no overlay opens and nothing reaches the bus.
  const l4Refused = (id: string): boolean => {
    if (httpVerbAllowed(id, app.l4Ids())) return false;
    app.notice(L4_NO_HTTP_VERBS);
    return true;
  };
  const idOf = (e: Event) => (e as CustomEvent<{ id: string }>).detail.id;

  onMount(() => {
    const onMark = (e: Event) => {
      const id = idOf(e);
      if (l4Refused(id)) return;
      const entry = entryOf(id);
      if (entry) setOverlay({ kind: 'mark', entry, anchor: anchorFor(entry.id), kb: true });
    };
    const onComment = (e: Event) => {
      const id = idOf(e);
      if (l4Refused(id)) return;
      const entry = entryOf(id);
      if (entry) setOverlay({ kind: 'comment', entry, anchor: anchorFor(entry.id) });
    };
    const onCtx = (e: Event) => {
      const id = idOf(e);
      if (l4Refused(id)) return;
      const entry = entryOf(id);
      if (entry) setOverlay({ kind: 'menu', entry, anchor: anchorFor(entry.id), kb: true });
    };
    window.addEventListener(EVENTS.mark, onMark);
    window.addEventListener(EVENTS.comment, onComment);
    window.addEventListener(EVENTS.contextMenu, onCtx);
    onCleanup(() => {
      window.removeEventListener(EVENTS.mark, onMark);
      window.removeEventListener(EVENTS.comment, onComment);
      window.removeEventListener(EVENTS.contextMenu, onCtx);
    });
  });

  // ---- pointer: one delegated handler for every row --------------------------------------
  const rowIdFrom = (e: Event): string | null => (e.target as Element | null)?.closest<HTMLElement>('[data-id]')?.dataset.id ?? null;
  const onClick = (e: MouseEvent) => {
    const id = rowIdFrom(e);
    if (!id) return;
    app.select(id, { additive: e.metaKey || e.ctrlKey, range: e.shiftKey });
  };
  const onDblClick = (e: MouseEvent) => {
    const id = rowIdFrom(e);
    if (id) window.dispatchEvent(new CustomEvent(EVENTS.focusInspector, { detail: { id } }));
  };
  const onContextMenu = (e: MouseEvent) => {
    const id = rowIdFrom(e);
    if (!id) return;
    e.preventDefault();
    // An `L4FlowRow` carries `data-id` too: right-click on it selects the row (the L4 inspector
    // opens) and refuses the HTTP menu with the notice (D9 UI).
    if (!app.selectedIds().has(id)) app.select(id);
    if (l4Refused(id)) return;
    const entry = entryOf(id);
    if (!entry) return;
    setOverlay({ kind: 'menu', entry, anchor: pointAnchor(e.clientX, e.clientY), kb: false });
  };

  // ---- header: sort on click, resize by the grip, columns menu on right-click -------------
  const onGripDown = (e: PointerEvent, id: ColumnId) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const el = e.currentTarget as HTMLElement;
    el.setPointerCapture(e.pointerId);
    const startX = e.clientX;
    const startW = cols.width(id);
    setResizing(id);
    const move = (ev: PointerEvent) => cols.setWidth(id, startW + (ev.clientX - startX));
    const up = () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
      setResizing(null);
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  };
  const onHeaderContext = (e: MouseEvent) => {
    e.preventDefault();
    setOverlay({ kind: 'columns', anchor: pointAnchor(e.clientX, e.clientY), kb: false });
  };
  const columnMenu = (): MenuEntry[] => [
    ...(['client', 'method', 'status', 'time', 'duration', 'req', 'res', 'ssl', 'edited', 'origin', 'mark'] as ColumnId[]).map((id) => ({
      label: labelOf(id),
      checked: !cols.isHidden(id),
      onSelect: () => cols.toggle(id),
    })),
    { type: 'separator' as const },
    { label: 'Reset columns', onSelect: () => cols.reset() },
    ...(cols.sort() ? [{ label: 'Clear sort', onSelect: () => cols.clearSort() }] : []),
  ];

  const clearFilters = () => {
    app.setChip('all');
    app.setFilters([]);
    app.setQuickFilter('');
    app.setSidebar({ kind: 'all' });
  };

  const closeOverlay = () => setOverlay(null);
  const hooks = {
    onComment: (entry: FlowEntry) => setOverlay({ kind: 'comment', entry, anchor: anchorFor(entry.id) }),
    onBuildPoc: (entry: FlowEntry) => setOverlay({ kind: 'poc', entry, anchor: anchorFor(entry.id) }),
  };

  return (
    <div class={css.list} style={{ '--cols': cols.template(), '--cols-min': `${minWidth()}px` }}>
      <div
        ref={scrollEl}
        class={css.scroll}
        role="grid"
        aria-label="Flows"
        aria-rowcount={count() + l4Rows().length + 1}
        aria-multiselectable="true"
        tabIndex={0}
        onScroll={onScroll}
        onClick={onClick}
        onDblClick={onDblClick}
        onContextMenu={onContextMenu}
      >
        <div class={css.header} role="row" onContextMenu={onHeaderContext}>
          <For each={cols.visible()}>
            {(c) => (
              <div
                class={css.th}
                role="columnheader"
                data-align={c.align}
                data-sortable={c.sortable ? 'true' : undefined}
                aria-sort={cols.sort()?.id === c.id ? (cols.sort()!.dir === 'asc' ? 'ascending' : 'descending') : c.sortable ? 'none' : undefined}
                title={c.sortable ? `Sort by ${c.label}` : undefined}
                onClick={(e) => {
                  if ((e.target as Element).closest(`.${css.grip}`)) return;
                  if (c.sortable) cols.cycleSort(c.id);
                }}
              >
                <span>{c.label}</span>
                <Show when={cols.sort()?.id === c.id}>
                  <span class={css.sort} aria-hidden="true">
                    {cols.sort()!.dir === 'asc' ? '↑' : '↓'}
                  </span>
                </Show>
                <Show when={c.resizable}>
                  <span
                    class={css.grip}
                    data-active={resizing() === c.id ? 'true' : undefined}
                    title="Drag to resize"
                    onPointerDown={(e) => onGripDown(e, c.id)}
                    onDblClick={(e) => {
                      e.stopPropagation();
                      cols.setWidth(c.id, c.width);
                    }}
                  />
                </Show>
              </div>
            )}
          </For>
        </div>

        <div class={css.canvas} style={{ height: `${virtualizer.getTotalSize()}px` }} role="rowgroup">
          <For each={virtualizer.getVirtualItems()}>
            {(item) => {
              const entry = () => rows()[item.index];
              return (
                <Show when={entry()}>
                  {(e) => (
                    <FlowRow entry={e()} selected={app.selectedIds().has(e().id)} cols={cols} top={item.start - HEADER} index={item.index} />
                  )}
                </Show>
              );
            }}
          </For>
        </div>

        <Show when={l4Rows().length}>
          <div class={css.l4Rows} role="rowgroup" aria-label="L4 sessions">
            <For each={l4Rows()}>
              {(row, i) => <L4FlowRow row={row} seq={i() + 1} cols={cols} selected={app.selectedIds().has(row.id)} />}
            </For>
          </div>
        </Show>

        <Switch>
          <Match when={app.total() === 0 && l4Rows().length === 0}>
            <div class={css.empty}>
              <span>
                No flows yet — point a client at <span class={css.mono}>{app.proxy.address || '127.0.0.1:8080'}</span> or open the browser.
              </span>
            </div>
          </Match>
          <Match when={count() === 0 && l4Rows().length === 0}>
            <div class={css.empty}>
              <span>No flows match</span>
              <button type="button" onClick={clearFilters}>
                Clear filters
              </button>
            </div>
          </Match>
        </Switch>
      </div>

      <Show when={newRows() > 0}>
        <button type="button" class={css.newPill} onClick={scrollToEnd} title="Jump to the newest flow">
          ↓ {newRows()} new
        </button>
      </Show>

      <Show when={overlay()}>
        {(o) => (
          <Switch>
            <Match when={o().kind === 'menu' && o()}>
              {(m) => {
                const v = m() as Extract<Overlay, { kind: 'menu' }>;
                return <Menu anchor={v.anchor} animate={!v.kb} label="Flow" onClose={closeOverlay} items={flowMenu(app, v.entry, hooks)} />;
              }}
            </Match>
            <Match when={o().kind === 'mark' && o()}>
              {(m) => {
                const v = m() as Extract<Overlay, { kind: 'mark' }>;
                return <Menu anchor={v.anchor} animate={!v.kb} label="Mark" onClose={closeOverlay} items={markItems(app, v.entry)} />;
              }}
            </Match>
            <Match when={o().kind === 'comment' && o()}>
              {(m) => {
                const v = m() as Extract<Overlay, { kind: 'comment' }>;
                return <CommentPopover app={app} entry={v.entry} anchor={v.anchor} onClose={closeOverlay} />;
              }}
            </Match>
            <Match when={o().kind === 'poc' && o()}>
              {(m) => {
                const v = m() as Extract<Overlay, { kind: 'poc' }>;
                return <PocPopover app={app} entry={v.entry} anchor={v.anchor} onClose={closeOverlay} />;
              }}
            </Match>
            <Match when={o().kind === 'columns' && o()}>
              {(m) => {
                const v = m() as Extract<Overlay, { kind: 'columns' }>;
                return <Menu anchor={v.anchor} animate={!v.kb} label="Columns" onClose={closeOverlay} items={columnMenu()} />;
              }}
            </Match>
          </Switch>
        )}
      </Show>
    </div>
  );
};

const LABELS: Record<ColumnId, string> = {
  dot: 'Status dot',
  seq: '#',
  url: 'URL',
  client: 'Client',
  method: 'Method',
  status: 'Status',
  time: 'Time',
  duration: 'Duration',
  req: 'Request size',
  res: 'Response size',
  ssl: 'SSL',
  edited: 'Edited',
  origin: 'Origin',
  mark: 'Mark',
};
const labelOf = (id: ColumnId) => LABELS[id];
