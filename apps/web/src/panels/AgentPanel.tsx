// The Agent panel (foundation §2.7 "Agent toggle", §4.8, principle 4): the policy control, the
// pending-confirmation queue (empty until F1) and the activity log of every command from every
// frontend. Shown in the lower region when app.ui.panel === 'agent'.
import { createMemo, createResource, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components';
import { PolicyControl } from './agent/PolicyControl';
import { ActivityLog } from './agent/ActivityLog';
import { L4Toggles } from './agent/L4Toggles';
import type { AgentCap, AgentGates } from './l4/model';
import css from './agent/AgentPanel.module.css';

export const AgentPanel: Component = () => {
  const app = useApp();
  const has = (name: string) => app.proxy.tools.some((t) => t.name === name);
  const canSet = createMemo(() => has('agent.set'));

  // `connected_clients` lives only in `agent.status` (§4.8); the store keeps policy and the
  // per-minute count, so ask once per panel mount and again after each policy change.
  const [status, { refetch }] = createResource(
    () => has('agent.status'),
    async (ok) => (ok ? await app.call<{ connected_clients?: number }>('agent.status').catch(() => null) : null),
  );
  const clients = () => status()?.connected_clients;

  // L4 per-capability agent gates (ui-ext §3.5): read `l4.agent.status`, set via `l4.agent.set`
  // when present. The L4 flow kind need not be enabled for the gate states to exist.
  const hasL4Gates = createMemo(() => has('l4.agent.status'));
  const canSetL4 = createMemo(() => has('l4.agent.set'));
  const [l4Gates, { refetch: refetchL4 }] = createResource(
    () => hasL4Gates(),
    async (ok) => (ok ? await app.call<AgentGates>('l4.agent.status').catch(() => null) : null),
  );
  const setL4 = async (capability: AgentCap, allowed: boolean) => {
    const r = await app.call<AgentGates>('l4.agent.set', { capability, allowed }).catch((e) => {
      app.notice(`l4.agent.set: ${(e as Error).message}`, 'error');
      return null;
    });
    if (r) void refetchL4();
  };

  return (
    <section class={css.panel} aria-label="Agent">
      <header class={css.header}>
        <Icon name="bot" class={css.icon} />
        <h2 class={css.title}>Agent</h2>
        <div class={css.meta}>
          <span>
            <b>{app.proxy.agentActionsLastMinute}</b> {app.proxy.agentActionsLastMinute === 1 ? 'action' : 'actions'} / min
          </span>
          <Show when={clients() != null}>
            <span>
              <b>{clients()}</b> connected {clients() === 1 ? 'client' : 'clients'}
            </span>
          </Show>
        </div>
      </header>

      <div class={css.scroll}>
        <PolicyControl
          value={app.proxy.agent}
          disabled={!canSet()}
          disabledReason="agent.set is a core follow-up (F1): the policy is read-only until the core exposes it."
          onChange={(p) => void app.setAgentPolicy(p).then(() => void refetch())}
        />

        <Show when={hasL4Gates()}>
          <L4Toggles gates={l4Gates() ?? null} canSet={canSetL4()} onSet={(cap, allowed) => void setL4(cap, allowed)} />
        </Show>

        <section class={css.section} aria-label="Pending confirmations">
          <div class={css.sectionHead}>
            <h3 class={css.sectionTitle}>Pending confirmations</h3>
          </div>
          {/* F1: map the confirmation stream to <PendingConfirmation …/> rows here. */}
          <p class={css.quiet}>
            Confirmations arrive with the agent stream (F1): this stays empty until the core exposes it — it is not a live “nothing pending”.
          </p>
        </section>

        <ActivityLog entries={app.proxy.activity} />
      </div>
    </section>
  );
};
