// One L4 session row in the unified flow list — the web's match for the TUI `l4_row_line`
// (crates/aitm-tui/src/ui/flows.rs) and macOS `FlowCellView` L4 cells. L4 sessions are top-level
// rows alongside HTTP, filling the SAME columns per docs/design/languages/flow-kinds.json:
// url = target (iface · filter), method = L4 badge + TCP/UDP/ICMP sub-label, status = session
// state, req = packet count, res = injected count; time/duration/client/ssl/edited/origin blank.
// Selecting one opens the L4 inspector (dispatched by kind in the shell), not the HTTP inspector.
import { Show, type Component } from 'solid-js';
import { Badge, type BadgeHue } from '~/components/Badge';
import type { UnionRow } from '~/panels/l4/model';
import type { ColumnStore } from './columns';
import css from './FlowList.module.css';

export interface L4FlowRowProps {
  row: UnionRow;
  /** 1-based position among the L4 rows (the `#` cell — L4 flows carry no capture seq). */
  seq: number;
  selected: boolean;
  cols: ColumnStore;
}

const Dash = () => <span class={css.dash}>—</span>;

export const L4FlowRow: Component<L4FlowRowProps> = (props) => {
  const r = () => props.row;
  const show = (id: Parameters<ColumnStore['isHidden']>[0]) => !props.cols.isHidden(id);
  return (
    <div
      class={`${css.row} ${css.l4Row}`}
      role="row"
      aria-selected={props.selected}
      data-id={r().id}
      data-kind="l4"
      data-oos={!r().inScope ? 'true' : undefined}
      title={r().inScope ? undefined : r().scopeReason}
    >
      <span class={`${css.cell} ${css.cDot}`} role="gridcell">
        <i class={css.l4Dot} aria-hidden="true" />
      </span>
      <span class={`${css.cell} ${css.cSeq}`} role="gridcell" data-align="right">
        {props.seq}
      </span>
      <span class={`${css.cell} ${css.url}`} role="gridcell" title={r().label}>
        <Show when={r().known} fallback={<span class={css.host}>{r().label}</span>}>
          <span class={css.host}>{r().target}</span>
        </Show>
      </span>
      <Show when={show('client')}>
        <span class={`${css.cell} ${css.client}`} role="gridcell">
          <span class={css.clientName}>
            <Dash />
          </span>
        </span>
      </Show>
      <Show when={show('method')}>
        <span class={css.cell} role="gridcell">
          <span class={css.l4Method}>
            <Badge hue={r().badgeHue as BadgeHue}>{r().badge}</Badge>
            <Show when={r().subLabel}>
              <span class={css.l4Sub}>{r().subLabel}</span>
            </Show>
          </span>
        </span>
      </Show>
      <Show when={show('status')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-l4state={r().state}>
          <Show when={r().state} fallback={<Dash />}>
            {r().state}
          </Show>
        </span>
      </Show>
      <Show when={show('time')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell">
          <Dash />
        </span>
      </Show>
      <Show when={show('duration')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Dash />
        </span>
      </Show>
      <Show when={show('req')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Show when={r().known} fallback={<Dash />}>
            {r().packetCount ?? 0} pkt
          </Show>
        </span>
      </Show>
      <Show when={show('res')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Show when={r().known && (r().injectedCount ?? 0) > 0} fallback={<Dash />}>
            {r().injectedCount} inj
          </Show>
        </span>
      </Show>
      <Show when={show('ssl')}>
        <span class={`${css.cell} ${css.ssl}`} role="gridcell" data-align="center" />
      </Show>
      <Show when={show('edited')}>
        <span class={`${css.cell} ${css.edited}`} role="gridcell" data-align="center" />
      </Show>
      <Show when={show('origin')}>
        <span class={`${css.cell} ${css.origin}`} role="gridcell" />
      </Show>
      <Show when={show('mark')}>
        <span class={css.cell} role="gridcell" data-align="center" />
      </Show>
    </div>
  );
};
