// Two-column key : value header table (§2.7): mono 13, 28px rows, hairline rules, lowercase names
// in `syntax.key`, long values wrap. Hover reveals a copy-row button. In edit mode the rows are
// inputs with add/remove, and rows that differ from the original get the amber left edge.

import { createMemo, For, Show, type Component } from 'solid-js';
import type { Header } from '~/model/flow';
import { Icon } from '~/components';
import { Centered, copyText, Quiet } from './ui';
import css from './inspector.module.css';

export interface HeaderTableProps {
  headers: Header[];
  editable?: boolean;
  onChange?: (headers: Header[]) => void;
  /** Reference list for the edited-row marker (edit mode). */
  original?: Header[] | undefined;
  label?: string;
  onCopied?: (what: string) => void;
}

export const HeaderTable: Component<HeaderTableProps> = (props) => {
  const originalSet = createMemo(() => new Set((props.original ?? []).map((h) => `${h.name.toLowerCase()}: ${h.value}`)));
  const isEdited = (h: Header) => !!props.original && !originalSet().has(`${h.name.toLowerCase()}: ${h.value}`);

  const update = (i: number, patch: Partial<Header>) => {
    const next = props.headers.map((h, j) => (j === i ? { ...h, ...patch } : h));
    props.onChange?.(next);
  };
  const remove = (i: number) => props.onChange?.(props.headers.filter((_, j) => j !== i));
  const add = () => props.onChange?.([...props.headers, { name: '', value: '' }]);

  const copyRow = async (h: Header) => {
    if (await copyText(`${h.name}: ${h.value}`)) props.onCopied?.(h.name);
  };

  return (
    <Show when={props.headers.length || props.editable} fallback={<Centered>No headers</Centered>}>
      <div class={css.table} role="table" aria-label={props.label ?? 'Headers'}>
        <For each={props.headers}>
          {(h, i) => (
            <div class={css.row} classList={{ [css.rowEdited!]: isEdited(h), [css.rowEditable!]: !!props.editable }} role="row">
              <Show
                when={props.editable}
                fallback={
                  <>
                    <span class={css.cellKey} role="cell">
                      {h.name.toLowerCase()}
                    </span>
                    <span class={css.cellVal} role="cell">
                      {h.value}
                    </span>
                    <Quiet class={css.rowAction} title="Copy header" aria-label={`Copy ${h.name}`} onClick={() => void copyRow(h)}>
                      <Icon name="copy" size={12} />
                    </Quiet>
                  </>
                }
              >
                <input
                  class={`${css.input} ${css.inputKey}`}
                  value={h.name}
                  placeholder="name"
                  spellcheck={false}
                  autocapitalize="off"
                  aria-label={`Header ${i() + 1} name`}
                  onInput={(e) => update(i(), { name: e.currentTarget.value })}
                />
                <input
                  class={css.input}
                  value={h.value}
                  placeholder="value"
                  spellcheck={false}
                  autocapitalize="off"
                  aria-label={`Header ${i() + 1} value`}
                  onInput={(e) => update(i(), { value: e.currentTarget.value })}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && i() === props.headers.length - 1) {
                      e.preventDefault();
                      add();
                      queueMicrotask(() => (e.currentTarget.closest(`.${css.table}`)?.querySelector(`.${css.row}:last-of-type input`) as HTMLInputElement | null)?.focus());
                    }
                  }}
                />
                <Quiet class={css.rowActionAlways} title="Remove header" aria-label={`Remove ${h.name || 'header'}`} onClick={() => remove(i())}>
                  <Icon name="x" size={12} />
                </Quiet>
              </Show>
            </div>
          )}
        </For>
        <Show when={props.editable}>
          <button type="button" class={css.addRow} onClick={add}>
            <Icon name="plus" size={12} />
            Add header
          </button>
        </Show>
      </div>
    </Show>
  );
};
