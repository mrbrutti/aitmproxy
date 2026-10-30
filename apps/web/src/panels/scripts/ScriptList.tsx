// The loaded scripts, one row each: an enable/disable switch, the name, its hooks as chips, its API,
// an error badge when its last hook run failed (the message itself is in the console), and Reload.
// Every control waits for an in-flight call and is switched off, with the reason as its tooltip, when
// the session or the core cannot author.
import { For, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { AGENT_REASON, type ScriptsStore } from './store';
import css from './ScriptsPanel.module.css';

export const ScriptList: Component<{ store: ScriptsStore }> = (props) => {
  const s = props.store;
  const reason = (can: boolean, tool: string): string | undefined => (s.agent() ? AGENT_REASON : can ? undefined : `${tool} is not offered by this core`);

  return (
    <section class={css.list} aria-label="Loaded scripts">
      <div class={css.sectionTitle}>
        <h3>Loaded</h3>
        <Show when={s.loaded()}>
          <span class={css.n}>{s.rows().length}</span>
        </Show>
      </div>
      <Show when={s.loaded()} fallback={<p class={css.quiet}>Loading scripts…</p>}>
        <Show when={s.rows().length > 0} fallback={<p class={css.empty}>No scripts loaded.</p>}>
          <ul class={css.rows}>
            <For each={s.rows()}>
              {(row) => (
                <li class={css.row} data-script={row.name} data-enabled={row.enabled ? 'true' : 'false'}>
                  <button
                    type="button"
                    role="switch"
                    class={css.switch}
                    aria-checked={row.enabled}
                    aria-label={`${row.name} enabled`}
                    disabled={!s.canToggle() || s.busy()}
                    title={reason(s.canToggle(), 'script.enable / script.disable') ?? (row.enabled ? `Disable ${row.name}` : `Enable ${row.name}`)}
                    onClick={() => void s.toggle(row)}
                  />
                  <div>
                    <div class={css.name} title={row.path || row.name}>
                      {row.name}
                    </div>
                    <div class={css.meta}>
                      <For each={row.hooks} fallback={<span class={css.api}>no hooks</span>}>
                        {(hook) => (
                          <span class={css.hook} data-hook>
                            {hook}
                          </span>
                        )}
                      </For>
                      <Show when={row.api}>
                        <span class={css.api}>api {row.api}</span>
                      </Show>
                      <Show when={row.lastError}>
                        {(message) => (
                          <span class={css.errBadge} data-last-error title={message()}>
                            error
                          </span>
                        )}
                      </Show>
                    </div>
                  </div>
                  <Button
                    variant="small"
                    aria-label={`Reload ${row.name}`}
                    disabled={!s.canReload() || s.busy()}
                    title={reason(s.canReload(), 'script.reload') ?? `Recompile ${row.name} from its file`}
                    onClick={() => void s.reload(row)}
                  >
                    Reload
                  </Button>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Show>
    </section>
  );
};
