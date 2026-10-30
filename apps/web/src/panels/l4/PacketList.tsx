// The L4 packet list (ui-ext §3.2): dir · length · decoded one-line summary · injected tick. The
// shared "message/packet stream" idea as the WS frame list; here fed from `l4.flow.get`'s packet
// log. Out-of-scope packets are dimmed (scope-as-authorization).
import { For, Show, type Component } from 'solid-js';
import type { L4PacketWire } from './model';
import css from './l4.module.css';

export interface PacketListProps {
  packets: readonly L4PacketWire[];
  selected: number | null;
  inScope: boolean;
  onSelect: (index: number) => void;
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
            <span class={css.dir} data-dir={pkt.dir}>
              {pkt.dir === 'outbound' ? '↑' : '↓'}
            </span>
            <span>{pkt.length}B</span>
            <span>{pkt.layers.join(' / ') || 'raw'}</span>
            <span>{pkt.injected ? '• injected' : ''}</span>
          </div>
        )}
      </For>
    </Show>
  </div>
);
