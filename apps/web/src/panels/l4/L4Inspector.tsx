// The L4 inspector (ui-ext §3.2): for a selected L4 flow — the packet list, a selected packet's
// layer tree + inert hex dump, the craft editor (YAML build → hex preview → guarded inject),
// and the in-path intercept bar driven by `interceptBarModel` (parity spec §4). Presentational: the
// panel wires the bus. Mutate sends the craft editor's spec: the editor hands each spec it builds
// through `onBuild`, the inspector keeps the last one, and Mutate is off with a reason until a
// packet has been built. Role (spec §7(c) D12, AC24): inject and the verdicts are operator-only. The
// inspector reads the connection role (`useApp().bus.role()`), hands the intercept bar its reason,
// and gates Inject itself — the craft editor's button is told `canInject={false}` and `onInject`
// returns here before the confirm path, so a forced click sends nothing.
import { createSignal, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { CraftEditor } from './CraftEditor';
import { LayerTree } from './LayerTree';
import { PacketList } from './PacketList';
import { L4InterceptBar } from './L4InterceptBar';
import type { InjectArgs } from './inject';
import type { L4Caps } from './store';
import { operatorOnlyReason, type InterceptBarModel, type L4CraftResult, type L4FlowWire, type PacketSpec, type UnionRow } from './model';
import css from './l4.module.css';

/** Mutate's tooltip until the craft editor has built a spec to send. */
export const MUTATE_NEEDS_BUILD = 'Build a packet in the craft editor first';

export interface L4InspectorProps {
  flow: L4FlowWire;
  row: UnionRow;
  caps: L4Caps;
  /** What the intercept bar shows for this flow (`interceptBarModel(avail, parked, flow.id)`). */
  interceptModel: InterceptBarModel;
  onBuild: (spec: PacketSpec) => Promise<L4CraftResult>;
  onInject: (args: InjectArgs) => void;
  onForward: (parkedId: string) => void;
  /** Mutate the parked packet into the spec the craft editor last built. */
  onMutate: (parkedId: string, spec: PacketSpec) => void;
  onDrop: (parkedId: string) => void;
  onRevert: (parkedId: string) => void;
  /** Read the next packet window from the flow's `next_offset` after a `truncated` reply (spec §2). */
  onLoadMore: () => void;
}

export const L4Inspector: Component<L4InspectorProps> = (props) => {
  const bus = useApp().bus;
  /** The D12 gate: `null` on an operator connection, else the reason inject and the verdicts show. */
  const operatorOnly = () => operatorOnlyReason(bus.role());
  const [sel, setSel] = createSignal<number | null>(props.flow.packets.length ? 0 : null);
  /** The spec the craft editor last built successfully; what Mutate sends. */
  const [lastBuilt, setLastBuilt] = createSignal<PacketSpec | null>(null);
  const packet = () => {
    const i = sel();
    return i != null ? (props.flow.packets[i] ?? null) : null;
  };
  const build = async (spec: PacketSpec): Promise<L4CraftResult> => {
    const result = await props.onBuild(spec);
    setLastBuilt(spec);
    return result;
  };
  const inject = (args: InjectArgs) => {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    props.onInject(args);
  };
  const mutate = (parkedId: string) => {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    const spec = lastBuilt();
    if (spec) props.onMutate(parkedId, spec);
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
        <PacketList
          packets={props.flow.packets}
          selected={sel()}
          inScope={props.row.inScope}
          truncated={props.flow.truncated === true}
          onSelect={setSel}
          onLoadMore={props.onLoadMore}
        />
      </div>

      <Show when={packet()}>{(p) => <LayerTree packet={p()} />}</Show>

      <Show when={operatorOnly()}>
        {(reason) => (
          <p class={css.dimReason} role="status" data-testid="l4-inject-operator-only" data-operator-only="true">
            Inject: {reason()}
          </p>
        )}
      </Show>
      <CraftEditor
        interface={props.flow.interface}
        inScope={props.row.inScope}
        scopeReason={props.row.scopeReason}
        canCraft={props.caps.craft}
        canInject={operatorOnly() === null && props.caps.inject}
        onBuild={build}
        onInject={inject}
      />

      <L4InterceptBar
        model={props.interceptModel}
        inScope={props.row.inScope}
        scopeReason={props.row.scopeReason}
        mutateBlocked={lastBuilt() ? null : MUTATE_NEEDS_BUILD}
        operatorOnly={operatorOnly()}
        onForward={props.onForward}
        onMutate={mutate}
        onDrop={props.onDrop}
        onRevert={props.onRevert}
      />
    </div>
  );
};
