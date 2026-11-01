// The Issues view (D-T8.9 list half, D-T8.10 states): the loaded `scan.issues` page for the
// selected job (or, under "All jobs", for every job) grouped under severity headers with the group
// count, critical first. Filtering is **client-side** over the loaded page — chips for confidence,
// lane, class (the classes present in the rows) and status, plus a text box — so a keystroke never
// costs a bus call. The page itself comes from the live model (`live.ts`): this view asks for the
// first read when the page has none, tells the model it is mounted so a live job's page is
// re-read on the heartbeat, and renders what the model holds. Selection and the filter live in
// the store so they survive the panel unmounting under the inspector.
//
// Keyboard follows `panels/findings/Findings.tsx`: ArrowUp/Down/Home/End move the selection,
// Enter moves focus to the detail region. Hover never moves selection (§2.8).

import { createEffect, createMemo, For, on, onCleanup, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { fmtClock } from '~/lib/format';
import { SeverityPill } from '~/panels/findings/SeverityPill';
import { useApp } from '~/state/context';
import { filterIssues, groupBySeverity, type IssueFilter } from './helpers';
import { IssueDetail } from './IssueDetail';
import { CONFIDENCES, ISSUE_STATUSES, LANES, type Confidence, type IssueStatus, type IssueSummary, type Lane } from './model';
import { scanStore } from './store';
import css from './scanner.module.css';

/** A set with one member toggled: the chips' only edit. */
function toggled<T>(set: ReadonlySet<T>, v: T): Set<T> {
  const next = new Set(set);
  if (next.has(v)) next.delete(v);
  else next.add(v);
  return next;
}

export const IssuesView: Component = () => {
  const app = useApp();
  const s = scanStore(app);
  const scope = () => s.issuesScope();
  const page = () => s.issues(scope());
  const offline = (): boolean => !s.busOpen();

  // First read per page, and the mounted flag for the heartbeat (`setIssuesMounted`) — both keyed
  // on the scope, so switching job or toggling "All jobs" re-arms them for the new page.
  createEffect(
    on(scope, (sc) => {
      if (s.issues(sc).loadedAt === null) void s.refreshIssues(sc);
      s.setIssuesMounted(sc, true);
      onCleanup(() => s.setIssuesMounted(sc, false));
    }),
  );

  const filtered = createMemo<IssueSummary[]>(() => filterIssues(page().rows, s.filter()));
  const groups = createMemo(() => groupBySeverity(filtered()));
  /** The class chips are the classes present in the loaded rows, alphabetical. */
  const classes = createMemo(() => Array.from(new Set(page().rows.map((r) => r.class))).sort());
  const loadingFirst = () => page().loading && page().loadedAt === null;
  const isEmpty = () => page().loadedAt !== null && page().error === null && page().rows.length === 0;

  const setFilter = (patch: Partial<IssueFilter>) => s.setFilter({ ...s.filter(), ...patch });

  let layoutEl: HTMLDivElement | undefined;

  const select = (id: string, fromKeyboard = false) => {
    s.setSelectedIssue(id);
    if (fromKeyboard) document.getElementById(`issue-${id}`)?.scrollIntoView?.({ block: 'nearest' });
  };
  const move = (delta: number) => {
    const list = filtered();
    if (!list.length) return;
    const i = list.findIndex((r) => r.id === s.selectedIssue());
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
        if (filtered().length) select(filtered()[0]!.id, true);
        break;
      case 'End':
        e.preventDefault();
        if (filtered().length) select(filtered()[filtered().length - 1]!.id, true);
        break;
      case 'Enter':
        e.preventDefault();
        layoutEl?.querySelector<HTMLElement>('[role="region"][aria-label="Issue detail"]')?.focus({ preventScroll: true });
        break;
    }
  };

  return (
    <div class={css.layout} ref={layoutEl} data-empty={page().rows.length === 0 ? 'true' : undefined}>
      <section class={css.list} aria-label="Issues list">
        <div class={css.listHead}>
          <span class={css.listTitle}>
            Issues
            <span class={css.n}>· {filtered().length}</span>
          </span>
          <input
            type="search"
            aria-label="Filter issues"
            placeholder="Filter"
            value={s.filter().text}
            disabled={offline()}
            onInput={(e) => setFilter({ text: e.currentTarget.value })}
          />
          <Show when={offline()}>
            <span class={css.reconnectNote} role="status">
              reconnecting…
            </span>
          </Show>
          <Button variant="small" active={s.allJobs()} disabled={offline()} onClick={() => s.setAllJobs(!s.allJobs())}>
            All jobs
          </Button>
        </div>
        <div>
          <div class={css.chips} role="group" aria-label="Confidence">
            <For each={CONFIDENCES}>
              {(c: Confidence) => (
                <button
                  type="button"
                  class={css.chip}
                  aria-pressed={s.filter().confidence.has(c)}
                  disabled={offline()}
                  onClick={() => setFilter({ confidence: toggled(s.filter().confidence, c) })}
                >
                  {c}
                </button>
              )}
            </For>
          </div>
          <div class={css.chips} role="group" aria-label="Lane">
            <For each={LANES}>
              {(l: Lane) => (
                <button
                  type="button"
                  class={css.chip}
                  aria-pressed={s.filter().lanes.has(l)}
                  disabled={offline()}
                  onClick={() => setFilter({ lanes: toggled(s.filter().lanes, l) })}
                >
                  {l}
                </button>
              )}
            </For>
          </div>
          <div class={css.chips} role="group" aria-label="Class">
            <For each={classes()}>
              {(c) => (
                <button
                  type="button"
                  class={css.chip}
                  data-raw="true"
                  aria-pressed={s.filter().classes.has(c)}
                  disabled={offline()}
                  onClick={() => setFilter({ classes: toggled(s.filter().classes, c) })}
                >
                  {c}
                </button>
              )}
            </For>
          </div>
          <div class={css.chips} role="group" aria-label="Status">
            <For each={ISSUE_STATUSES}>
              {(st: IssueStatus) => (
                <button
                  type="button"
                  class={css.chip}
                  aria-pressed={s.filter().statuses.has(st)}
                  disabled={offline()}
                  onClick={() => setFilter({ statuses: toggled(s.filter().statuses, st) })}
                >
                  {st}
                </button>
              )}
            </For>
          </div>
        </div>
        <div
          class={css.rows}
          role="listbox"
          aria-label="Issues"
          tabIndex={0}
          aria-activedescendant={s.selectedIssue() ? `issue-${s.selectedIssue()}` : undefined}
          onKeyDown={onKeyDown}
        >
          <Show when={page().error !== null}>
            <div class={css.errorBlock} role="alert" data-state="error">
              <p>{page().error}</p>
              <span class={css.mono}>
                last good: <Show when={page().loadedAt !== null} fallback={<span class={css.dash}>—</span>}>{fmtClock(page().loadedAt!)}</Show>
              </span>
              <Button variant="small" class={css.retry} disabled={offline()} onClick={() => void s.refreshIssues(scope())}>
                Retry
              </Button>
            </div>
          </Show>
          <Show when={loadingFirst()}>
            <div class={css.loading} aria-busy="true" aria-label="Loading issues">
              <i />
              <i />
              <i />
              <i />
            </div>
          </Show>
          <Show when={isEmpty()}>
            <div class={css.empty} role="status">
              No issues for this job
            </div>
          </Show>
          <For each={groups()}>
            {(g) => (
              <>
                <div role="presentation" class={css.sectionTitle} data-severity={g.severity} data-count={g.rows.length}>
                  {g.severity} · {g.rows.length}
                </div>
                <For each={g.rows}>
                  {(r) => (
                    <div
                      id={`issue-${r.id}`}
                      data-issue={r.id}
                      class={css.row}
                      role="option"
                      aria-selected={s.selectedIssue() === r.id}
                      onClick={() => select(r.id)}
                    >
                      <div class={css.rowMain}>
                        <SeverityPill severity={r.severity} />
                        <span>{r.name}</span>
                      </div>
                      <div class={css.rowMeta}>
                        <span class={css.mono}>{r.location.method ? `${r.location.method} ${r.location.path_template}` : r.location.path_template}</span>
                        <span class={css.sep}>·</span>
                        <span class={css.mono}>{`${r.location.kind}:${r.location.name}`}</span>
                        <Show when={r.status !== 'open'}>
                          <span class={css.tag} data-field="status">
                            {r.status}
                          </span>
                        </Show>
                        <Show when={r.occurrences > 1}>
                          <span class={css.kv} data-field="occurrences">
                            ×{r.occurrences}
                          </span>
                        </Show>
                      </div>
                      <div class={css.rowSecondary}>
                        <span>{r.confidence}</span>
                        <span class={css.sep}>·</span>
                        <span>{r.lane}</span>
                      </div>
                    </div>
                  )}
                </For>
              </>
            )}
          </For>
          <Show when={page().nextCursor !== null}>
            <Button variant="small" disabled={offline() || page().loading} onClick={() => void s.loadMoreIssues(scope())}>
              Load more
            </Button>
          </Show>
        </div>
      </section>
      <Show
        when={s.selectedIssue()}
        fallback={
          <div class={css.empty} role="status">
            <Show when={page().rows.length > 0} fallback={<span />}>
              Select an issue
            </Show>
          </div>
        }
      >
        {(id) => <IssueDetail id={id()} />}
      </Show>
    </div>
  );
};
