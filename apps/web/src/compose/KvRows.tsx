// Editable key : value rows (headers, query, form fields). Always one trailing blank row so a
// new pair is typed, not "added"; rows that become blank are dropped when focus leaves the group.
// Rendered with <Index> so editing a row never recreates its inputs (focus stays put).
import { Index, Show, type Component, type JSX } from 'solid-js';
import { Icon } from '~/components/Icon';
import { isBlankKV, type KV } from './model';
import css from './compose.module.css';

export interface KvRowsProps<T extends KV = KV> {
  rows: T[];
  onChange: (rows: T[]) => void;
  blank: () => T;
  namePlaceholder: string;
  valuePlaceholder: string;
  label: string;
  /** Rows rendered above the editable ones (the automatic content-type). */
  leading?: JSX.Element | undefined;
  /** Replace the value cell for a row (multipart file cell). `last` is the trailing blank row. */
  valueCell?: ((row: T, i: number, set: (patch: Partial<T>) => void, last: boolean) => JSX.Element) | undefined;
}

const keeps = (r: KV): boolean => !isBlankKV(r) || !!(r as { file?: unknown }).file;

export function KvRows<T extends KV>(props: KvRowsProps<T>): JSX.Element {
  const list = () => [...props.rows, props.blank()];
  const update = (i: number, patch: Partial<T>) => {
    const next = list().map((r, j) => (j === i ? { ...r, ...patch } : r));
    if (!keeps(next[next.length - 1]!)) next.pop();
    props.onChange(next);
  };
  const remove = (i: number) => props.onChange(props.rows.filter((_, j) => j !== i));
  const prune = () => {
    const kept = props.rows.filter(keeps);
    if (kept.length !== props.rows.length) props.onChange(kept);
  };
  return (
    <div
      class={css.rows}
      role="group"
      aria-label={props.label}
      onFocusOut={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) prune();
      }}
    >
      {props.leading}
      <Index each={list()}>
        {(row, i) => {
          const last = () => i === list().length - 1;
          return (
            <div class={css.kv}>
              <input
                class={css.k}
                value={row().name}
                placeholder={last() ? props.namePlaceholder : ''}
                aria-label={`${props.label} name ${i + 1}`}
                autocomplete="off"
                spellcheck={false}
                onInput={(e) => update(i, { name: e.currentTarget.value } as Partial<T>)}
              />
              <Show
                when={props.valueCell}
                fallback={
                  <input
                    class={css.v}
                    value={row().value}
                    placeholder={last() ? props.valuePlaceholder : ''}
                    aria-label={`${props.label} value ${i + 1}`}
                    autocomplete="off"
                    spellcheck={false}
                    onInput={(e) => update(i, { value: e.currentTarget.value } as Partial<T>)}
                  />
                }
              >
                {(cell) => cell()(row(), i, (patch) => update(i, patch), last())}
              </Show>
              <Show when={!last()} fallback={<span />}>
                <button type="button" class={css.remove} aria-label={`Remove ${props.label.toLowerCase()} ${row().name || i + 1}`} tabIndex={-1} onClick={() => remove(i)}>
                  <Icon name="x" size={12} />
                </button>
              </Show>
            </div>
          );
        }}
      </Index>
    </div>
  );
}

export type { Component };
