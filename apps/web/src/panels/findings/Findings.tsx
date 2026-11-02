// Findings (§2.7 "PoC panel"): a 320px list of PoC runs on the left, the selected run's detail on
// the right; stacked under 900px. Selection and local YAML edits live at module scope so they
// survive the panel unmounting when the inspector takes the lower region.

import { createEffect, createMemo, createSignal, For, on, onCleanup, Show, type Component } from 'solid-js';
import type { PocRun } from '~/bus/types';
import { Icon } from '~/components';
import { useApp } from '~/state/context';
import { FindingDetail } from './FindingDetail';
import { SEVERITIES, filterRuns, fmtWhen, fmtWhenFull, sortNewest, verdictOf, whenOf, type Severity } from './model';
import { SeverityPill } from './SeverityPill';
import { findingsState } from './state';
import css from './findings.module.css';

export const Findings: Component = () => {
  const app = useApp();
  const { selectedId, setSelectedId } = findingsState(app);
  const [query, setQuery] = createSignal('');
  const [sevs, setSevs] = createSignal<ReadonlySet<Severity>>(new Set<Severity>());
  const [now, setNow] = createSignal(Date.now());
  const tick = setInterval(() => setNow(Date.now()), 30_000);
  onCleanup(() => clearInterval(tick));

  const sorted = createMemo(() => sortNewest(app.proxy.findings));
  const rows = createMemo(() => filterRuns(sorted(), query(), sevs()));
  const total = () => app.proxy.findings.length;
  const selected = createMemo<PocRun | null>(() => rows().find((r) => r.id === selectedId()) ?? null);

  // Keep a selection whenever there is something to select (newest when nothing was chosen).
  createEffect(
    on(rows, (list) => {
      if (!list.length) return;
      if (!list.some((r) => r.id === selectedId())) setSelectedId(list[0]!.id);
    }),
  );

  let detailEl: HTMLDivElement | undefined;

  const select = (id: string, fromKeyboard = false) => {
    setSelectedId(id);
    if (fromKeyboard) document.getElementById(`finding-${id}`)?.scrollIntoView?.({ block: 'nearest' });
  };
  const move = (delta: number) => {
    const list = rows();
    if (!list.length) return;
    const i = list.findIndex((r) => r.id === selectedId());
    const next = i < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.max(0, Math.min(list.length - 1, i + delta));
    select(list[next]!.id, true);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        move(1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        move(-1);
        break;
      case 'Home':
        e.preventDefault();
        if (rows().length) select(rows()[0]!.id, true);
        break;
      case 'End':
        e.preventDefault();
        if (rows().length) select(rows()[rows().length - 1]!.id, true);
        break;
      case 'Enter':
        e.preventDefault();
        detailEl?.focus({ preventScroll: true });
        break;
    }
  };

  const toggleSev = (s: Severity) => {
    const next = new Set(sevs());
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSevs(next);
  };

  return (
    <div class={css.root} aria-label="Findings">
      <div class={css.layout} data-empty={total() === 0 ? 'true' : undefined}>
      <Show
        when={total() > 0}
        fallback={
          <div class={css.empty} role="status">
            <div>
              No findings — build a PoC from any flow with <kbd>p</kbd>.
            </div>
          </div>
        }
      >
        <section class={css.list} aria-label="PoC runs">
          <div class={css.listHead}>
            <span class={css.listTitle}>
              Findings
              <span class={css.n}>· {total()}</span>
            </span>
            <input
              class={css.filter}
              type="search"
              placeholder="Filter"
              aria-label="Filter findings by title or target"
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
            />
          </div>
          <div class={css.chips} role="group" aria-label="Severity filter">
            <For each={SEVERITIES}>
              {(s) => (
                <button type="button" class={css.chip} data-severity={s} aria-pressed={sevs().has(s)} onClick={() => toggleSev(s)}>
                  <i class={css.dot} aria-hidden="true" />
                  {s}
                </button>
              )}
            </For>
            <Show when={sevs().size > 0 || query()}>
              <button
                type="button"
                class={`${css.chip} ${css.chipClear}`}
                onClick={() => {
                  setSevs(new Set<Severity>());
                  setQuery('');
                }}
              >
                Clear
              </button>
            </Show>
          </div>
          <div
            class={css.rows}
            role="listbox"
            aria-label="Findings"
            tabIndex={0}
            aria-activedescendant={selectedId() ? `finding-${selectedId()}` : undefined}
            onKeyDown={onKeyDown}
          >
            <Show when={rows().length > 0} fallback={<div class={css.emptyList}>No findings match</div>}>
              <For each={rows()}>
                {(r) => (
                  <div
                    id={`finding-${r.id}`}
                    data-id={r.id}
                    class={css.row}
                    role="option"
                    aria-selected={selectedId() === r.id}
                    onClick={() => select(r.id)}
                  >
                    <div class={css.rowTitle}>{r.title || <span class={css.dash}>—</span>}</div>
                    <div class={css.rowMeta}>
                      <span class={css.target}>{r.target || '—'}</span>
                      <span class={css.sep}>·</span>
                      <span class={css.when} title={fmtWhenFull(whenOf(r)) ?? undefined}>
                        {fmtWhen(whenOf(r), now()) ?? '—'}
                      </span>
                      <Show when={r.origin === 'agent'}>
                        <span class={css.tag}>agent</span>
                      </Show>
                    </div>
                    <div class={css.rowRight}>
                      <Show
                        when={verdictOf(r) !== 'not-run'}
                        fallback={
                          <span class={css.notRun} title="Not run yet">
                            not run
                          </span>
                        }
                      >
                        <span class={css.verdict} data-ok={r.passed ? 'true' : 'false'} title={r.passed ? 'Passed' : 'Failed'}>
                          <Icon name={r.passed ? 'check' : 'x'} size={12} label={r.passed ? 'Passed' : 'Failed'} />
                        </span>
                      </Show>
                      <SeverityPill severity={r.severity} />
                    </div>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </section>
        <Show when={selected()} fallback={<div class={css.empty}>No finding matches the filter.</div>}>
          {(run) => <FindingDetail run={run()} ref={(el) => (detailEl = el)} onSelect={(id) => select(id)} />}
        </Show>
      </Show>
      </div>
    </div>
  );
};
