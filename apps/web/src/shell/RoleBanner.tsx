// Resolved-role banner (Task 6, AC7/AC8). The bus client reads the `role` the server echoes in
// `initialize` (Decision C) and compares it to the `expect` carried in the launch URL (Decision B).
// An operator session gets a quiet elevated strip; a mismatch — notably an operator URL that
// connected as agent — gets a loud warning instead of silently proceeding as agent.
import { Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components/Icon';
import css from './RoleBanner.module.css';

export const RoleBanner: Component = () => {
  const bus = useApp().bus;
  const open = () => bus.state() === 'open';
  const warn = () => open() && bus.roleMismatch();
  const operator = () => open() && !bus.roleMismatch() && bus.role() === 'operator';

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
  );
};
