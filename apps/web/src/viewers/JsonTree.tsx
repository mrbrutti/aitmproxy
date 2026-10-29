// Response › JSON: a Solid-rendered tree over the parsed value. Lazily flattened (only expanded
// children become rows) and windowed (rows are 20px; only the visible slice is in the DOM).

import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show, type Component } from 'solid-js';
import { allContainerPaths, childEntries, describe, filterTree, flatten, jsonPath, kindOf, parentPath, preview, type Row } from './json-tree-model';
import s from './viewers.module.css';

const ROW = 20;
const OVERSCAN = 12;

export interface JsonTreeProps {
  value: unknown;
  /** Reset key: a new flow/body collapses to the default expansion. */
  docKey: string;
  onCopy?: (text: string, what: string) => void;
  class?: string;
}

function defaultExpanded(value: unknown): Set<string> {
  const set = new Set<string>(['$']);
  const k = kindOf(value);
  if (k === 'object' || k === 'array') {
    const entries = childEntries(value, false);
    // Open the first level when it is small; a 12k-item array stays folded.
    if (entries.length <= 24) for (const [key, v] of entries) if (kindOf(v) === 'object' || kindOf(v) === 'array') set.add(jsonPath('$', key));
  }
  return set;
}

function fmtPrimitive(v: unknown, kind: string): string {
  if (kind === 'string') return JSON.stringify(v);
  if (kind === 'null') return 'null';
  return String(v);
}

export const JsonTree: Component<JsonTreeProps> = (props) => {
  const [expanded, setExpanded] = createSignal<Set<string>>(defaultExpanded(props.value));
  const [sortKeys, setSortKeys] = createSignal(false);
  const [query, setQuery] = createSignal('');
  const [debounced, setDebounced] = createSignal('');
  const [focusIdx, setFocusIdx] = createSignal(0);
  const [hoverPath, setHoverPath] = createSignal<string | null>(null);
  const [scrollTop, setScrollTop] = createSignal(0);
  const [height, setHeight] = createSignal(400);
  let scroller!: HTMLDivElement;
  let filterInput!: HTMLInputElement;
  let timer: ReturnType<typeof setTimeout> | null = null;

  createEffect(on(() => props.docKey, () => {
    setExpanded(defaultExpanded(props.value));
    setFocusIdx(0);
    setQuery('');
    setDebounced('');
  }, { defer: true }));

  createEffect(on(query, (q) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => setDebounced(q), 120);
  }, { defer: true }));

  const filter = createMemo(() => filterTree(props.value, debounced()));
  const flat = createMemo(() => flatten(props.value, expanded(), { sortKeys: sortKeys(), filter: filter() }));
  const rows = () => flat().rows;

  const range = createMemo(() => {
    const total = rows().length;
    const start = Math.max(0, Math.floor(scrollTop() / ROW) - OVERSCAN);
    const end = Math.min(total, Math.ceil((scrollTop() + height()) / ROW) + OVERSCAN);
    return { start, end };
  });
  const slice = createMemo(() => rows().slice(range().start, range().end));

  onMount(() => {
    const ro = new ResizeObserver(() => setHeight(scroller.clientHeight));
    ro.observe(scroller);
    setHeight(scroller.clientHeight);
    onCleanup(() => ro.disconnect());
  });

  const toggle = (path: string, open?: boolean) => {
    const next = new Set(expanded());
    const isOpen = open ?? !next.has(path);
    if (isOpen) next.add(path);
    else next.delete(path);
    setExpanded(next);
  };

  const copy = (text: string, what: string) => props.onCopy?.(text, what);
  const copyValue = (r: Row) => copy(r.kind === 'string' ? (r.value as string) : (JSON.stringify(r.value, null, 2) ?? ''), 'value');
  const copyPath = (r: Row) => copy(r.path, 'path');

  const scrollIntoView = (i: number) => {
    const top = i * ROW;
    if (top < scroller.scrollTop) scroller.scrollTop = top;
    else if (top + ROW > scroller.scrollTop + scroller.clientHeight) scroller.scrollTop = top + ROW - scroller.clientHeight;
  };
  const focusRow = (i: number) => {
    const n = rows().length;
    if (!n) return;
    const j = Math.max(0, Math.min(n - 1, i));
    setFocusIdx(j);
    scrollIntoView(j);
  };

  const onKey = (e: KeyboardEvent) => {
    const list = rows();
    const i = focusIdx();
    const r = list[i];
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      e.stopPropagation();
      filterInput.focus();
      filterInput.select();
      return;
    }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'c' && r && !window.getSelection()?.toString()) {
      e.preventDefault();
      copyValue(r);
      return;
    }
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusRow(i + 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusRow(i - 1);
        break;
      case 'ArrowRight':
        if (!r) return;
        e.preventDefault();
        if (r.expandable && !r.expanded) toggle(r.path, true);
        else if (r.expandable) focusRow(i + 1);
        break;
      case 'ArrowLeft': {
        if (!r) return;
        e.preventDefault();
        if (r.expandable && r.expanded) toggle(r.path, false);
        else {
          const p = parentPath(r.path);
          const j = p ? list.findIndex((x) => x.path === p) : -1;
          if (j >= 0) focusRow(j);
        }
        break;
      }
      case 'Enter':
      case ' ':
        if (r?.expandable) {
          e.preventDefault();
          toggle(r.path);
        }
        break;
      case 'Home':
        e.preventDefault();
        focusRow(0);
        break;
      case 'End':
        e.preventDefault();
        focusRow(list.length - 1);
        break;
    }
  };

  const expandAll = () => {
    const { paths, truncated } = allContainerPaths(props.value);
    setExpanded(paths);
    if (truncated) props.onCopy?.('', 'expand-capped');
  };
  const collapseAll = () => setExpanded(new Set(['$']));

  const statusRow = createMemo(() => {
    const hp = hoverPath();
    const list = rows();
    return (hp ? list.find((r) => r.path === hp) : undefined) ?? list[focusIdx()] ?? null;
  });

  return (
    <div class={`${s.tree} ${props.class ?? ''}`}>
      <div class={s.treeBar}>
        <input
          ref={filterInput}
          class={s.treeFilter}
          type="search"
          placeholder="Filter keys and values"
          value={query()}
          onInput={(e) => setQuery(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation();
              if (query()) setQuery('');
              else scroller.focus();
            }
            if (e.key === 'Enter' || e.key === 'ArrowDown') {
              e.preventDefault();
              scroller.focus();
            }
          }}
          aria-label="Filter JSON tree"
        />
        <Show when={filter()}>
          {(f) => (
            <span class={s.treeMeta}>
              {f().matches.size}
              {f().truncated ? '+' : ''} {f().matches.size === 1 ? 'match' : 'matches'}
            </span>
          )}
        </Show>
        <span class={s.treeSpacer} />
        <button type="button" class={`${s.treeBtn} ${sortKeys() ? s.treeBtnOn : ''}`} onClick={() => setSortKeys(!sortKeys())} aria-pressed={sortKeys()} title="Sort object keys alphabetically">
          Sort keys
        </button>
        <button type="button" class={s.treeBtn} onClick={expandAll} title="Expand every node">
          Expand all
        </button>
        <button type="button" class={s.treeBtn} onClick={collapseAll} title="Collapse to the root">
          Collapse all
        </button>
      </div>
      <div
        ref={scroller}
        class={s.treeScroll}
        tabIndex={0}
        role="tree"
        aria-label="JSON tree"
        onScroll={() => setScrollTop(scroller.scrollTop)}
        onKeyDown={onKey}
        onMouseLeave={() => setHoverPath(null)}
      >
        <div class={s.treeSpace} style={{ height: `${rows().length * ROW}px` }}>
          <For each={slice()}>
            {(r, i) => {
              const idx = () => range().start + i();
              return (
                <div
                  class={s.treeRow}
                  classList={{ [s.treeRowFocus!]: idx() === focusIdx(), [s.treeRowMatch!]: !!filter()?.matches.has(r.path) }}
                  style={{ transform: `translateY(${idx() * ROW}px)`, 'padding-left': `${12 + r.depth * 16}px` }}
                  role="treeitem"
                  aria-level={r.depth + 1}
                  aria-expanded={r.expandable ? r.expanded : undefined}
                  onMouseEnter={() => setHoverPath(r.path)}
                  onClick={() => {
                    setFocusIdx(idx());
                    if (r.expandable) toggle(r.path);
                  }}
                >
                  <span class={s.treeChevron} aria-hidden="true">
                    {r.expandable ? (r.expanded ? '▾' : '▸') : ''}
                  </span>
                  <Show when={r.key !== null}>
                    <span class={typeof r.key === 'number' ? s.synIndex : s.synKey}>{typeof r.key === 'number' ? r.key : JSON.stringify(r.key)}</span>
                    <span class={s.synPunct}>: </span>
                  </Show>
                  <Show
                    when={r.expandable}
                    fallback={
                      <span class={s[`syn_${r.kind}`] ?? ''} title={r.kind === 'string' && (r.value as string).length > 80 ? (r.value as string) : undefined}>
                        {r.kind === 'string' && (r.value as string).length > 400 ? JSON.stringify((r.value as string).slice(0, 400)) + '…' : fmtPrimitive(r.value, r.kind)}
                      </span>
                    }
                  >
                    <span class={s.synBracket}>{r.kind === 'array' ? '[' : '{'}</span>
                    <Show when={!r.expanded}>
                      <span class={s.treePreview}> {preview(r.value)} </span>
                      <span class={s.synBracket}>{r.kind === 'array' ? ']' : '}'}</span>
                    </Show>
                  </Show>
                  <Show when={r.comma && (!r.expandable || !r.expanded)}>
                    <span class={s.synPunct}>,</span>
                  </Show>
                  <span class={s.treeRowActions}>
                    <button type="button" class={s.treeMini} title="Copy value" onClick={(e) => (e.stopPropagation(), copyValue(r))}>
                      value
                    </button>
                    <button type="button" class={s.treeMini} title="Copy JSONPath" onClick={(e) => (e.stopPropagation(), copyPath(r))}>
                      path
                    </button>
                  </span>
                </div>
              );
            }}
          </For>
        </div>
        <Show when={!rows().length}>
          <div class={s.treeEmpty}>{filter() ? 'No matches' : 'Empty'}</div>
        </Show>
      </div>
      <div class={s.treeStatus}>
        <Show when={statusRow()} fallback={<span>&nbsp;</span>}>
          {(r) => (
            <>
              <span class={s.treePath}>{r().path}</span>
              <span class={s.treeDesc}>{describe(r().value)}</span>
            </>
          )}
        </Show>
        <Show when={flat().truncated}>
          <span class={s.treeDesc}>· showing the first {rows().length.toLocaleString()} rows</span>
        </Show>
      </div>
    </div>
  );
};
