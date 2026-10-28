// Query tab: `flow.query` parsed into key · value, URL-decoded; the raw pair is the tooltip.

import { createMemo, For, Show, type Component } from 'solid-js';
import { parseQuery } from '~/viewers/pretty';
import { Centered } from './ui';
import css from './inspector.module.css';

export const QueryTable: Component<{ query: string | null }> = (props) => {
  const rows = createMemo(() => (props.query ? parseQuery(props.query) : []));
  return (
    <Show when={rows().length} fallback={<Centered>No query string</Centered>}>
      <div class={css.table} role="table" aria-label="Query parameters">
        <For each={rows()}>
          {(r) => (
            <div class={css.row} role="row" title={r.raw}>
              <span class={css.cellKey} role="cell">
                {r.name}
              </span>
              <span class={css.cellVal} role="cell">
                {r.value || <span class={css.dash}>—</span>}
              </span>
            </div>
          )}
        </For>
      </div>
    </Show>
  );
};
