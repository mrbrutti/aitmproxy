// A selected packet's layer tree and bytes (ui-ext §3.2; parity spec §2, §2.3). The tree renders the
// decoded layer stack (Ether → IPv4/6 → TCP/UDP/ICMP → Raw) the core summarised, never a fabricated
// field decode. Below it, the packet's bytes (when the core sent them: trusted callers always, an
// agent per its gates, spec §2.2) as a hex/ASCII dump built by `hexRows`: every byte outside
// 0x20–0x7e is `.`, and the rows reach the DOM only as the text of a `<pre>`, never by raw HTML
// insertion (AC40). Without `bytes` the pane says so and shows nothing else.
import { For, Show, type Component } from 'solid-js';
import { base64ToBytes } from '~/lib/bytes';
import { hexRows, type L4PacketWire } from './model';
import css from './l4.module.css';

/** What the bytes pane says when the reply carried no `bytes` key for this packet (spec §2.2). */
export const NO_BYTES_NOTE = 'no bytes from this core';

export interface LayerTreeProps {
  packet: L4PacketWire;
}

export const LayerTree: Component<LayerTreeProps> = (props) => {
  const rows = () => (props.packet.bytes != null ? hexRows(base64ToBytes(props.packet.bytes)) : null);
  return (
    <div class={css.section} aria-label="Packet layers">
      <div class={css.sectionHead}>Layers · {props.packet.length} bytes</div>
      <div class={css.layerTree} role="tree">
        <Show when={props.packet.layers.length} fallback={<div class={css.layerNode}>raw bytes (no decode)</div>}>
          <For each={props.packet.layers}>
            {(layer, i) => (
              <div class={css.layerNode} role="treeitem" style={{ 'padding-left': `${i() * 12}px` }}>
                {i() > 0 ? '└ ' : ''}
                {layer}
              </div>
            )}
          </For>
        </Show>
      </div>
      <Show when={rows()} fallback={<p class={css.note}>{NO_BYTES_NOTE}</p>}>
        {(r) => (
          <pre class={`${css.layerTree} ${css.hexWrap}`} aria-label="Packet bytes" data-testid="l4-packet-hex">
            {r().join('\n')}
          </pre>
        )}
      </Show>
    </div>
  );
};
