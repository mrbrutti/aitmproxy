// The console under the editor: each script's latest hook error (from `script.list`) and the findings
// scripts emitted with `finding(...)` this run (from `script.findings`, newest first, bounded, with the
// count the core's sink dropped). Refresh re-reads both. Everything renders as text; nothing here is a
// link or an action on the wire.
import { For, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { SeverityPill } from '~/panels/findings/SeverityPill';
import { fmtWhen, fmtWhenFull } from '~/panels/findings/model';
import type { ScriptsStore } from './store';
import css from './ScriptsPanel.module.css';

export const ScriptConsole: Component<{ store: ScriptsStore }> = (props) => {
  const s = props.store;
  const failing = () => s.rows().filter((r) => r.lastError !== null);

  return (
    <section class={css.console} aria-label="Console">
      <div class={css.sectionTitle}>
        <h3>Console</h3>
        {/* Never really `disabled`: while a call is in flight it is aria-disabled and ignores the click, so focus stays put. */}
        <Button
          variant="small"
          class={`${css.spacer} ${css.guarded}`}
          aria-disabled={s.busy() ? 'true' : undefined}
          title="Re-read the scripts and their findings"
          onClick={() => !s.busy() && void s.refresh()}
        >
          Refresh
        </Button>
      </div>

      <div class={css.consoleGroup} aria-label="Script errors" role="group">
        <div class={css.groupTitle}>
          <h4>Errors</h4>
          <Show when={failing().length > 0}>
            <span class={css.n}>{failing().length}</span>
          </Show>
        </div>
        <Show
          when={failing().length > 0}
          fallback={
            // "Nothing has failed" is a claim about a list that was read: not before it answers, not after it failed.
            <Show
              when={s.listError()}
              fallback={
                <Show when={s.listed()}>
                  <p class={css.quiet}>No script has failed.</p>
                </Show>
              }
            >
              <p class={css.quiet}>Unknown — the scripts could not be read.</p>
            </Show>
          }
        >
          <ul>
            <For each={failing()}>
              {(row) => (
                <li class={css.errorItem} data-console-error={row.name}>
                  <div class={css.errName}>{row.name}</div>
                  <pre class={css.pre}>{row.lastError}</pre>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </div>

      <Show when={s.hasFindings()}>
        <div class={css.consoleGroup} aria-label="Script findings" role="group">
          <div class={css.groupTitle}>
            <h4>Findings</h4>
            <Show when={s.findings().findings.length > 0}>
              <span class={css.n}>{s.findings().findings.length}</span>
            </Show>
            <Show when={s.findings().dropped > 0}>
              <span class={css.n}>{s.findings().dropped} dropped</span>
            </Show>
          </div>
          <Show when={s.findings().findings.length > 0} fallback={<p class={css.quiet}>No script has emitted a finding this run.</p>}>
            <ol>
              <For each={s.findings().findings}>
                {(f) => (
                  <li class={css.finding} data-finding>
                    <SeverityPill severity={f.severity} />
                    <span class={css.findingName} data-finding-name>
                      {f.name}
                    </span>
                    <Show when={f.at > 0}>
                      <span class={css.when} title={fmtWhenFull(f.at) ?? undefined}>
                        {fmtWhen(f.at)}
                      </span>
                    </Show>
                    <div class={css.findingMeta}>
                      <Show when={f.source}>
                        <span>{f.source}</span>
                      </Show>
                      <Show when={f.flowId}>
                        <span>{f.flowId}</span>
                      </Show>
                      <For each={f.tags}>{(tag) => <span>{tag}</span>}</For>
                    </div>
                    <Show when={f.detail}>
                      <p class={css.findingDetail}>{f.detail}</p>
                    </Show>
                  </li>
                )}
              </For>
            </ol>
          </Show>
        </div>
      </Show>
    </section>
  );
};
