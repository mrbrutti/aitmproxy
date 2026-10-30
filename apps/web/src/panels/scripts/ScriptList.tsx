// The loaded scripts, one row each: an enable/disable switch, the name, its hooks as chips, its API,
// an error badge when its last hook run failed (the message itself is in the console), and Reload.
// A control is really `disabled`, with the reason as its tooltip, only when the session or the core
// cannot author; while a call is in flight it is `aria-disabled` and its handler returns early, so a
// keyboard user keeps focus on the control they just used. A failed `script.list` is shown as a failure
// (the core's text and a Retry), never as an empty list.
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
        {/* A row count is a fact only about a list that was read and has not since failed to re-read. */}
        <Show when={s.listed() && !s.listError()}>
          <span class={css.n}>{s.rows().length}</span>
        </Show>
      </div>
      <Show when={s.loaded()} fallback={<p class={css.quiet}>Loading scripts…</p>}>
        <Show when={s.listError()}>
          {(message) => (
            <div class={css.listError} data-list-error>
              <p class={css.listErrorTitle}>Could not read the scripts{s.rows().length > 0 ? ' — showing the last list' : ''}.</p>
              <pre class={css.pre}>{message()}</pre>
              <Button variant="small" onClick={() => void s.refresh()}>
                Retry
              </Button>
            </div>
          )}
        </Show>
        <Show
          when={s.rows().length > 0}
          fallback={
            <Show when={s.listed() && !s.listError()}>
              <p class={css.empty}>No scripts loaded.</p>
            </Show>
          }
        >
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
                    disabled={!s.canToggle()}
                    aria-disabled={s.busy() ? 'true' : undefined}
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
                    class={css.guarded}
                    disabled={!s.canReload()}
                    aria-disabled={s.busy() ? 'true' : undefined}
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
