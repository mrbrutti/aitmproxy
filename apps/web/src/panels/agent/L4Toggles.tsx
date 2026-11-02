// The per-feature MCP enable/disable toggles (ui-ext §3.5, L4OPS-AC11). One switch per L4 capability
// — Capture, Inject, Intercept, Widen — each reflecting the `l4.allow_agent_*` gate that actually
// governs the agent (MCP) L4 path (not a cosmetic switch). Where the core exposes `l4.agent.set`
// the operator flips the gate live; where it does not, the switch is read-only with an honest note
// (config + restart). An agent can never flip its own gate — the core refuses `l4.agent.set` from
// an MCP caller; this panel is the operator's control. Role (parity spec §7(c) D12, AC24): on a
// connection that is not the operator's (`useApp().bus.role()` is `agent` or unknown) every switch
// renders disabled with `OPERATOR_ONLY_REASON` and its handler returns before `onSet`. The panel
// requires `AppProvider` (like the other gated L4 controls): there is no provider-less mount path.
import { For, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { AGENT_CAPS, AGENT_CAP_LABEL, operatorOnlyReason, type AgentCap, type AgentGates } from '~/panels/l4/model';
import css from '~/panels/l4/l4.module.css';

export interface L4TogglesProps {
  /** The four gate states from `l4.agent.status`, or null when the status command is absent. */
  gates: AgentGates | null;
  /** `l4.agent.set` present → the switches set the gate live; absent → read-only. */
  canSet: boolean;
  onSet: (capability: AgentCap, allowed: boolean) => void;
}

export const L4Toggles: Component<L4TogglesProps> = (props) => {
  const bus = useApp().bus;
  /** The D12 gate: `null` on an operator connection, else the reason every switch shows. */
  const operatorOnly = () => operatorOnlyReason(bus.role());

  function set(cap: AgentCap, allowed: boolean): void {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    if (!props.canSet) return;
    props.onSet(cap, allowed);
  }

  return (
    <section class={css.section} aria-label="L4 agent capabilities">
      <div class={css.sectionHead}>L4 agent capabilities</div>
      <Show
        when={props.gates}
        fallback={<p class={css.note}>L4 agent gates are unavailable — this core does not expose `l4.agent.status`.</p>}
      >
        {(gates) => (
          <div class={css.toggles} role="group" aria-label="L4 capability toggles">
            <For each={AGENT_CAPS}>
              {(cap) => {
                const on = () => gates()[cap];
                return (
                  <div class={css.toggleRow}>
                    <button
                      type="button"
                      role="switch"
                      class={css.switch}
                      data-cap={cap}
                      aria-checked={on()}
                      aria-label={`Agent ${AGENT_CAP_LABEL[cap]}`}
                      disabled={operatorOnly() !== null || !props.canSet}
                      title={
                        operatorOnly() ??
                        (props.canSet ? undefined : 'Read-only: set `l4.allow_agent_*` in config and restart (this core has no live setter).')
                      }
                      data-operator-only={operatorOnly() !== null ? 'true' : undefined}
                      onClick={() => set(cap, !on())}
                    />
                    <label>{AGENT_CAP_LABEL[cap]}</label>
                    <Show when={operatorOnly()} fallback={<Show when={!props.canSet}><span class={css.reason}>config only</span></Show>}>
                      <span class={css.reason}>operator only</span>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        )}
      </Show>
      <p class={css.note}>
        An agent cannot change its own L4 gates; only an operator sets them. Each gate is the second of
        two dimensions — the agent policy must also allow the call.
      </p>
    </section>
  );
};
