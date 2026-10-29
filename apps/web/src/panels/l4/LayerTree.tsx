// A selected packet's layer tree (ui-ext §3.2). The live `l4.flow.get` summary carries the decoded
// layer *names* + total length, not per-field values or the raw bytes, so the tree renders the
// layer stack (Ether → IPv4/6 → TCP/UDP/ICMP → Raw) honestly and says what the summary does not
// carry — never a fabricated field decode or a blank hex pane. A crafted packet's bytes (and hex)
// come from `l4.craft` in the craft editor, where they are available.
import { For, Show, type Component } from 'solid-js';
import css from './l4.module.css';

export interface LayerTreeProps {
  layers: readonly string[];
  length: number;
}

export const LayerTree: Component<LayerTreeProps> = (props) => (
  <div class={css.section} aria-label="Packet layers">
    <div class={css.sectionHead}>Layers · {props.length} bytes</div>
    <div class={css.layerTree} role="tree">
      <Show when={props.layers.length} fallback={<div class={css.layerNode}>raw bytes (no decode)</div>}>
        <For each={props.layers}>
          {(layer, i) => (
            <div class={css.layerNode} role="treeitem" style={{ 'padding-left': `${i() * 12}px` }}>
              {i() > 0 ? '└ ' : ''}
              {layer}
            </div>
          )}
        </For>
      </Show>
    </div>
    <p class={css.note}>Raw bytes are not carried by `l4.flow.get`; a crafted packet's hex is shown by Build in the craft editor.</p>
  </div>
);
