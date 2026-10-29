// The activity log (§2.7, §4.8): every command invocation from any frontend, newest at the top,
// 28px mono rows. Agent rows carry the teal `agent` tag; the human surfaces are grey text. The
// store caps the log at 500 so the table renders plainly (rows are `contain: content`); new
// entries appear at the top with no animation (§2.8). Filters and "Clear view" are local.
import { createMemo, createSignal, For, Show, type Component } from 'solid-js';
import { Badge, Icon } from '~/components';
import { fmtClock } from '~/lib/format';
import type { ActivityEntry } from '~/state/app';
import { ACTIVITY_KINDS, atMs, filterActivity, fullArgs, isAgent, originLabel, summarizeArgs, type ActivityKind } from './activity';
import css from './AgentPanel.module.css';

export const ActivityLog: Component<{ entries: readonly ActivityEntry[] }> = (props) => {
  const [kind, setKind] = createSignal<ActivityKind>('all');
  const [query, setQuery] = createSignal('');
  const [clearedThrough, setClearedThrough] = createSignal(0);

  const rows = createMemo(() => filterActivity(props.entries, { kind: kind(), query: query(), clearedThrough: clearedThrough() }));
  const latestSeq = () => props.entries[props.entries.length - 1]?.seq ?? 0;
  const anyVisible = () => props.entries.some((e) => e.seq > clearedThrough());

  return (
    <section class={css.section} aria-label="Activity log">
      <div class={css.sectionHead}>
        <h3 class={css.sectionTitle}>
          Activity log
          <Show when={rows().length > 0}>
            <span class={css.n}>{rows().length}</span>
          </Show>
        </h3>
        <div class={css.tools}>
          <For each={ACTIVITY_KINDS}>
            {(k) => (
              <button type="button" class={css.chip} aria-pressed={kind() === k.id} onClick={() => setKind(k.id)}>
                {k.label}
              </button>
            )}
          </For>
          <label class={css.search}>
            <Icon name="search" size={12} />
            <input
              type="search"
              value={query()}
              placeholder="Search"
              aria-label="Search activity"
              autocomplete="off"
              spellcheck={false}
              onInput={(e) => setQuery(e.currentTarget.value)}
            />
          </label>
          <button
            type="button"
            class={css.clear}
            disabled={!anyVisible()}
            title="Hide what is shown now; new activity still appears"
            onClick={() => setClearedThrough(latestSeq())}
          >
            Clear view
          </button>
        </div>
      </div>

      <Show when={rows().length > 0} fallback={<p class={css.empty}>{props.entries.length === 0 || !anyVisible() ? 'No activity yet.' : 'Nothing matches.'}</p>}>
        <div class={css.log} role="table" aria-label="Command invocations">
          <div role="row" class={css.row}>
            <div role="columnheader" class={css.th}>
              time
            </div>
            <div role="columnheader" class={css.th}>
              origin
            </div>
            <div role="columnheader" class={css.th}>
              command
            </div>
            <div role="columnheader" class={css.th}>
              args
            </div>
            <div role="columnheader" class={css.th} aria-label="result" />
          </div>
          <For each={rows()}>
            {(e) => {
              const ms = atMs(e);
              const args = summarizeArgs(e.args);
              return (
                <div role="row" class={css.row} data-seq={e.seq} data-agent={isAgent(e) ? 'true' : undefined}>
                  <div role="cell" class={`${css.td} ${css.time}`}>
                    {ms == null ? <span class={css.dash}>—</span> : fmtClock(ms)}
                  </div>
                  <div role="cell" class={`${css.td} ${css.origin}`}>
                    <Show when={isAgent(e)} fallback={<span>{originLabel(e.origin)}</span>}>
                      <Badge hue="agent">agent</Badge>
                    </Show>
                  </div>
                  <div role="cell" class={css.td} title={e.command}>
                    <span>{e.command}</span>
                  </div>
                  <div role="cell" class={`${css.td} ${css.args}`} title={args ? fullArgs(e.args) : undefined}>
                    <Show when={args} fallback={<span class={css.dash}>—</span>}>
                      <span>{args}</span>
                    </Show>
                  </div>
                  <div role="cell" class={`${css.td} ${css.result}`} data-result={e.result} title={e.detail ?? (e.result === 'ok' ? 'ok' : 'error')}>
                    <Icon name={e.result === 'ok' ? 'check' : 'x'} size={12} label={e.result === 'ok' ? 'ok' : 'error'} />
                  </div>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
    </section>
  );
};
