// Stacked filter bar (§2.7): rows of `Field · Operator · Value`, combined AND / OR. Rows live in
// app.ui.filters; a row with an empty value is ignored by the store, so an empty row costs nothing.
import { createEffect, For, onCleanup, onMount, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { FilterField, FilterOp, FilterRow } from '~/state/app';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { EVENTS } from '~/shell/shortcuts';
import css from './FilterBar.module.css';

const FIELDS: { id: FilterField; label: string }[] = [
  { id: 'url', label: 'URL' },
  { id: 'host', label: 'Host' },
  { id: 'path', label: 'Path' },
  { id: 'query', label: 'Query' },
  { id: 'method', label: 'Method' },
  { id: 'status', label: 'Status' },
  { id: 'req-header', label: 'Request header' },
  { id: 'res-header', label: 'Response header' },
  { id: 'req-body', label: 'Request body' },
  { id: 'res-body', label: 'Response body' },
  { id: 'content-type', label: 'Content-type' },
  { id: 'client', label: 'Client' },
  { id: 'duration', label: 'Duration (ms)' },
  { id: 'size', label: 'Size (B)' },
  { id: 'comment', label: 'Comment' },
  { id: 'origin', label: 'Origin' },
  { id: 'scope', label: 'Scope' },
];
const OPS: { id: FilterOp; label: string }[] = [
  { id: 'contains', label: 'contains' },
  { id: 'not-contains', label: "doesn't contain" },
  { id: 'equals', label: 'equals' },
  { id: 'wildcard', label: 'wildcard' },
  { id: 'regex', label: 'regex' },
  { id: 'gt', label: 'greater than' },
  { id: 'lt', label: 'less than' },
];

const PLACEHOLDER: Partial<Record<FilterField, string>> = {
  url: 'https://api.example.com/login',
  host: 'api.example.com',
  path: '/api/',
  method: 'POST',
  status: '200',
  origin: 'human | agent',
  scope: 'in | out',
  duration: '500',
  size: '1024',
};

export const FilterBar: Component = () => {
  const app = useApp();
  let bar: HTMLDivElement | undefined;
  let nextId = 1;

  const rows = () => app.ui.filters;
  const update = (list: FilterRow[]) => app.setFilters(list);
  const add = () => {
    nextId = Math.max(nextId, ...rows().map((r) => r.id + 1));
    update([...rows(), { id: nextId++, field: 'url', op: 'contains', value: '' }]);
  };
  const patch = (id: number, p: Partial<FilterRow>) => update(rows().map((r) => (r.id === id ? { ...r, ...p } : r)));
  const remove = (id: number) => {
    const next = rows().filter((r) => r.id !== id);
    update(next.length ? next : [{ id: nextId++, field: 'url', op: 'contains', value: '' }]);
  };
  const focusFirst = () => {
    const el = bar?.querySelector<HTMLInputElement>('input');
    el?.focus();
    el?.select();
  };

  createEffect(() => {
    if (rows().length === 0) add();
  });

  onMount(() => {
    window.addEventListener(EVENTS.focusFilter, focusFirst);
    queueMicrotask(focusFirst);
    onCleanup(() => window.removeEventListener(EVENTS.focusFilter, focusFirst));
  });

  return (
    <div ref={bar} id="aitm-filter-bar" class={css.bar} role="group" aria-label="Filters">
      <For each={rows()}>
        {(row, i) => (
          <div class={css.row}>
            <Show
              when={i() === 0}
              fallback={
                <div class={css.mode} role="group" aria-label="Combine">
                  <button type="button" aria-pressed={app.ui.filterMode === 'and'} onClick={() => app.setFilterMode('and')}>
                    AND
                  </button>
                  <button type="button" aria-pressed={app.ui.filterMode === 'or'} onClick={() => app.setFilterMode('or')}>
                    OR
                  </button>
                </div>
              }
            >
              <span class={css.modeGhost} aria-hidden="true" />
            </Show>
            <span class={`${css.selectWrap} ${css.field}`}>
              <select class={css.select} aria-label="Field" value={row.field} onChange={(e) => patch(row.id, { field: e.currentTarget.value as FilterField })}>
                <For each={FIELDS}>{(f) => <option value={f.id}>{f.label}</option>}</For>
              </select>
              <Icon name="chevron-down" size={12} />
            </span>
            <span class={`${css.selectWrap} ${css.op}`}>
              <select class={css.select} aria-label="Operator" value={row.op} onChange={(e) => patch(row.id, { op: e.currentTarget.value as FilterOp })}>
                <For each={OPS}>{(o) => <option value={o.id}>{o.label}</option>}</For>
              </select>
              <Icon name="chevron-down" size={12} />
            </span>
            <input
              class={css.input}
              type="text"
              aria-label="Value"
              placeholder={PLACEHOLDER[row.field] ?? 'value'}
              value={row.value}
              spellcheck={false}
              autocapitalize="off"
              onInput={(e) => patch(row.id, { value: e.currentTarget.value })}
              onKeyDown={(e) => {
                if (e.key === 'Escape') {
                  if (row.value) patch(row.id, { value: '' });
                  else app.toggleFilters(false);
                  e.stopPropagation();
                } else if (e.key === 'Enter' && e.metaKey) add();
              }}
            />
            <Button variant="toolbar" class={css.iconBtn} title="Remove filter" onClick={() => remove(row.id)}>
              <Icon name="minus" size={12} />
            </Button>
            <Show when={i() === rows().length - 1}>
              <Button variant="toolbar" class={css.iconBtn} title="Add filter" onClick={add}>
                <Icon name="plus" size={12} />
              </Button>
              <span class={css.hint}>{app.visible().length} match</span>
            </Show>
          </div>
        )}
      </For>
    </div>
  );
};
