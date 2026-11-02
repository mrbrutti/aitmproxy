// The L4 packet list (ui-ext §3.2): time · dir · headline · injected tick. The shared
// "message/packet stream" idea as the WS frame list; here fed from `l4.flow.get`'s packet log. Each
// row's headline comes from `packetHeadline` (spec §2 addresses, or the layer stack on an older core)
// and its time from `formatPacketTime` when the core sent a `timestamp`. Out-of-scope packets are
// dimmed (scope-as-authorization). A `truncated` window (spec §2 byte budget) ends in a "load more"
// that asks the store for the next window from `next_offset`.
import { For, Show, type Component } from 'solid-js';
import { formatPacketTime, packetHeadline, type L4PacketWire } from './model';
import css from './l4.module.css';

export interface PacketListProps {
  packets: readonly L4PacketWire[];
  selected: number | null;
  inScope: boolean;
  /** The reply's `truncated` (spec §2): more packets of this flow remain after the loaded window. */
  truncated: boolean;
  onSelect: (index: number) => void;
  onLoadMore: () => void;
}

export const PacketList: Component<PacketListProps> = (props) => (
  <div role="list" aria-label="Packets">
    <Show when={props.packets.length} fallback={<p class={css.note}>No packets yet. Start capture, or inject a crafted packet.</p>}>
      <For each={props.packets}>
        {(pkt, i) => (
          <div
            class={css.packetRow}
            role="listitem"
            aria-selected={props.selected === i()}
            data-oos={props.inScope ? undefined : 'true'}
            onClick={() => props.onSelect(i())}
          >
            <Show when={pkt.timestamp != null}>
              <span class={css.sub}>{formatPacketTime(pkt.timestamp!)}</span>
            </Show>
            <span class={css.dir} data-dir={pkt.dir}>
              {pkt.dir === 'outbound' ? '↑' : '↓'}
            </span>
            <span>{packetHeadline(pkt)}</span>
            <span>{pkt.injected ? '• injected' : ''}</span>
          </div>
        )}
      </For>
    </Show>
    <Show when={props.truncated}>
      <button type="button" class={css.input} data-testid="l4-load-more" onClick={() => props.onLoadMore()}>
        load more
      </button>
    </Show>
  </div>
);
