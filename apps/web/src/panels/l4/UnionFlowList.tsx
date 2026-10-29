// The union flow list (ui-ext §3.1, L4OPS-AC7/AC12): one list that renders every flow kind through
// the shared kind model — HTTP, WebSocket, and L4 rows each carry their kind badge, and an
// absent/unknown kind renders a labelled placeholder, never an empty row. Presentational: it takes
// already-merged `UnionRow`s (the store merges `flow.list` + `l4.flow.list`), so it is trivially
// testable and never "only renders HTTP".
import { For, Show, type Component } from 'solid-js';
import { Badge, type BadgeHue } from '~/components/Badge';
import type { UnionRow } from './model';
import css from './l4.module.css';

export interface UnionFlowListProps {
  rows: readonly UnionRow[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export const UnionFlowList: Component<UnionFlowListProps> = (props) => (
  <div class={css.unionList} role="grid" aria-label="Flows (all kinds)">
    <Show
      when={props.rows.length}
      fallback={<div class={css.unionEmpty}>No flows yet. HTTP, WebSocket and L4 flows all appear here.</div>}
    >
      <For each={props.rows}>
        {(row) => (
          <div
            class={css.unionRow}
            role="row"
            data-id={row.id}
            data-kind={row.kind}
            data-known={row.known ? 'true' : 'false'}
            data-oos={row.inScope ? undefined : 'true'}
            aria-selected={props.selectedId === row.id}
            title={row.inScope ? undefined : row.scopeReason}
            onClick={() => props.onSelect(row.id)}
          >
            <span class={css.unionBadge} role="gridcell">
              <Badge hue={row.badgeHue as BadgeHue}>{row.badge}</Badge>
              <Show when={row.subLabel}>
                <span class={css.sub}>{row.subLabel}</span>
              </Show>
            </span>
            <span class={css.unionLabel} role="gridcell" title={row.label}>
              {row.label}
            </span>
            <Show when={row.kind === 'l4' && row.known}>
              <span class={css.unionState} role="gridcell">
                {row.state}
              </span>
              <span class={css.unionCounts} role="gridcell" title="packets · injected">
                {row.packetCount ?? 0} pkt
                <Show when={(row.injectedCount ?? 0) > 0}>
                  <span class={css.inj}> · {row.injectedCount} inj</span>
                </Show>
              </span>
            </Show>
            <Show when={!row.known}>
              <span class={css.placeholder} role="gridcell">
                unsupported kind
              </span>
            </Show>
          </div>
        )}
      </For>
    </Show>
  </div>
);
