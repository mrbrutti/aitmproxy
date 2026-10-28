// The Scope panel (foundation §2.7 "Scope panel", §3.9 scope-as-authorisation). Shown in the lower
// region when app.ui.panel === 'scope'. Hosts in scope with their read-only rate-limit / back-off
// config and the flows seen under each; below, the hosts seen on the wire that are not authorised,
// each with an `Add` — widening authorisation is a human act (the agent cannot).
import { createMemo, For, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components';
import { pluralize } from '~/lib/format';
import { AddHost } from './scope/AddHost';
import { countSeen, fmtBackoff, fmtRateLimit, outOfScopeHosts } from './scope/scope';
import css from './scope/ScopePanel.module.css';

const Dash: Component = () => (
  <span class={css.dash} aria-label="none">
    —
  </span>
);

export const ScopePanel: Component = () => {
  const app = useApp();
  const scope = () => app.proxy.scope;
  const hosts = createMemo(() => scope().map((s) => s.host));
  const canRemove = createMemo(() => app.proxy.tools.some((t) => t.name === 'scope.remove'));

  // One pass over the raw flows per frame-batched version bump; wildcard matches included.
  const authorities = createMemo(() => {
    app.version();
    return app.entries.map((e) => e.raw.authority);
  });
  const seen = createMemo(() => outOfScopeHosts(app.groups().domains, scope()));

  return (
    <section class={css.panel} aria-label="Scope">
      <header class={css.header}>
        <Icon name="crosshair" class={css.icon} />
        <h2 class={css.title}>Scope</h2>
        <span class={css.count}>{pluralize(scope().length, 'host')}</span>
      </header>

      <div class={css.scroll}>
        <AddHost existing={hosts()} onAdd={(h) => app.addScope(h)} />

        <div class={css.table} role="table" aria-label="Hosts in scope" data-empty={scope().length === 0 ? 'true' : undefined}>
          <Show
            when={scope().length > 0}
            fallback={<p class={css.empty}>No hosts in scope — add the hosts you are authorised to test.</p>}
          >
            <div role="row" style={{ display: 'contents' }}>
              <div role="columnheader" class={css.th}>
                host
              </div>
              <div role="columnheader" class={css.th}>
                rate limit
              </div>
              <div role="columnheader" class={css.th}>
                back-off
              </div>
              <div role="columnheader" class={`${css.th} ${css.num}`}>
                flows seen
              </div>
              <div role="columnheader" class={css.th} aria-label="actions" />
            </div>
            <For each={scope()}>
              {(entry) => {
                const rate = () => fmtRateLimit(entry.rate_limit);
                const back = () => fmtBackoff(entry.backoff);
                const n = createMemo(() => countSeen(authorities(), entry.host));
                return (
                  <div role="row" style={{ display: 'contents' }}>
                    <div role="cell" class={css.td} title={entry.host}>
                      <span>{entry.host}</span>
                    </div>
                    <div role="cell" class={`${css.td} ${css.cfg}`}>
                      <Show when={rate()} fallback={<Dash />}>
                        {rate()}
                      </Show>
                    </div>
                    <div role="cell" class={`${css.td} ${css.cfg}`}>
                      <Show when={back()} fallback={<Dash />}>
                        {back()}
                      </Show>
                    </div>
                    <div role="cell" class={`${css.td} ${css.num}`}>
                      {n()}
                    </div>
                    <div role="cell" class={`${css.td} ${css.actions}`}>
                      <button
                        type="button"
                        class={css.remove}
                        disabled={!canRemove()}
                        aria-label={`Remove ${entry.host} from scope`}
                        title={canRemove() ? `Remove ${entry.host}` : 'scope.remove is a core follow-up (F12)'}
                        onClick={() => void app.removeScope(entry.host)}
                      >
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </Show>
        </div>

        <section class={css.section} aria-label="Seen but out of scope">
          <h3 class={css.sectionTitle}>
            Seen but out of scope
            <Show when={seen().length > 0}>
              <span class={css.n}>{seen().length}</span>
            </Show>
          </h3>
          <Show when={seen().length > 0} fallback={<p class={css.quiet}>Every host seen so far is in scope.</p>}>
            <div class={css.seen} role="table" aria-label="Out-of-scope hosts">
              <For each={seen()}>
                {(d) => (
                  <div role="row" style={{ display: 'contents' }}>
                    <div role="cell" class={css.td} title={d.host}>
                      <span>{d.host}</span>
                    </div>
                    <div role="cell" class={`${css.td} ${css.num}`}>
                      {d.count}
                    </div>
                    <div role="cell" class={`${css.td} ${css.actions}`}>
                      <button type="button" class={css.link} onClick={() => void app.addScope(d.host)} aria-label={`Add ${d.host} to scope`}>
                        Add
                      </button>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </section>

        <p class={css.footer}>
          Out-of-scope flows are visible but dimmed; mutating actions on them are disabled. The agent cannot widen scope.
        </p>
      </div>
    </section>
  );
};
