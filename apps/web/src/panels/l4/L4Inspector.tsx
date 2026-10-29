// The L4 inspector (ui-ext §3.2): for a selected L4 flow — the packet list, a selected packet's
// layer tree + hex-availability note, the craft editor (YAML build → hex preview → guarded inject),
// and the feature-detected in-path intercept bar. Presentational: the panel wires the bus.
import { createSignal, Show, type Component } from 'solid-js';
import { CraftEditor } from './CraftEditor';
import { LayerTree } from './LayerTree';
import { PacketList } from './PacketList';
import { L4InterceptBar } from './L4InterceptBar';
import type { InjectArgs } from './inject';
import type { L4Caps } from './store';
import type { L4CraftResult, L4FlowWire, PacketSpec, UnionRow } from './model';
import css from './l4.module.css';

export interface L4InspectorProps {
  flow: L4FlowWire;
  row: UnionRow;
  caps: L4Caps;
  interceptParked: number;
  onBuild: (spec: PacketSpec) => Promise<L4CraftResult>;
  onInject: (args: InjectArgs) => void;
  onForward: () => void;
  onMutate: () => void;
  onDrop: () => void;
}

export const L4Inspector: Component<L4InspectorProps> = (props) => {
  const [sel, setSel] = createSignal<number | null>(props.flow.packets.length ? 0 : null);
  const packet = () => {
    const i = sel();
    return i != null ? (props.flow.packets[i] ?? null) : null;
  };
  return (
    <div class={css.inspector}>
      <div class={css.section}>
        <div class={css.sectionHead}>
          {props.row.target} · {props.row.state} · {props.flow.packet_count} pkt / {props.flow.injected_count} inj
          <Show when={props.row.subLabel}>
            <span class={css.sub}>· {props.row.subLabel}</span>
          </Show>
        </div>
        <Show when={!props.row.inScope}>
          <p class={css.dimReason}>{props.row.scopeReason}</p>
        </Show>
      </div>

      <div class={css.section}>
        <div class={css.sectionHead}>Packets</div>
        <PacketList packets={props.flow.packets} selected={sel()} inScope={props.row.inScope} onSelect={setSel} />
      </div>

      <Show when={packet()}>{(p) => <LayerTree layers={p().layers} length={p().length} />}</Show>

      <CraftEditor
        interface={props.flow.interface}
        inScope={props.row.inScope}
        scopeReason={props.row.scopeReason}
        canCraft={props.caps.craft}
        canInject={props.caps.inject}
        onBuild={props.onBuild}
        onInject={props.onInject}
      />

      <L4InterceptBar
        available={props.caps.intercept}
        parked={props.interceptParked}
        inScope={props.row.inScope}
        scopeReason={props.row.scopeReason}
        onForward={props.onForward}
        onMutate={props.onMutate}
        onDrop={props.onDrop}
      />
    </div>
  );
};
