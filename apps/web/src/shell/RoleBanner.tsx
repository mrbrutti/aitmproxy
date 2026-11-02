// Resolved-role banner (Task 6, AC7/AC8). The bus client reads the `role` the server echoes in
// `initialize` (Decision C) and compares it to the `expect` carried in the launch URL (Decision B).
// An operator session gets a quiet elevated strip; a mismatch — notably an operator URL that
// connected as agent — gets a loud warning instead of silently proceeding as agent. A connection that
// is open but not the operator's (agent, or no role echo) also gets one quiet line saying the L4
// actions need the Operator URL (parity spec §7(c) D12, AC24), beside whatever else is shown.
import { Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components/Icon';
import css from './RoleBanner.module.css';

export const RoleBanner: Component = () => {
  const bus = useApp().bus;
  const open = () => bus.state() === 'open';
  const warn = () => open() && bus.roleMismatch();
  const operator = () => open() && !bus.roleMismatch() && bus.role() === 'operator';
  /** Open as agent, or open with no role echo: every Sensitive L4 control is disabled (D12). */
  const l4OperatorOnly = () => open() && bus.role() !== 'operator';

  const message = () => {
    if (warn()) {
      const want = bus.expectRole ?? 'operator';
      const got = bus.role();
      if (got == null) {
        return `Expected ${want} access, but the proxy did not confirm a role. Sensitive commands may be refused.`;
      }
      return `Expected ${want} access, but this session connected as ${got}. Sensitive commands will be refused.`;
    }
    return 'Operator session — sensitive commands are enabled.';
  };

  return (
    <>
      <Show when={warn() || operator()}>
        <div
          class={css.banner}
          classList={{ [css.warn!]: warn() }}
          role={warn() ? 'alert' : 'status'}
          aria-live="polite"
        >
          <Icon name={warn() ? 'triangle-alert' : 'shield'} size={16} />
          <span>{message()}</span>
        </div>
      </Show>
      <Show when={l4OperatorOnly()}>
        <div class={css.banner} role="status" aria-live="polite" data-testid="l4-operator-only-banner">
          <Icon name="lock" size={16} />
          <span>L4 actions (capture, inject, scope, intercept) need the Operator URL.</span>
        </div>
      </Show>
    </>
  );
};
