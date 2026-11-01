// Site map (D-T8.8): the selected job's `scan.sitemap` page, read through the store and paged with
// "Load more" while the core hands back a `next_cursor`. Left, a listbox of nodes grouped by
// `host[:port]`; right, the selected node's facts, its flows (each a crossing into the app's own
// flow selection, never a copy of the flow) and the insertion points that belong to it — every
// point when nothing is selected. The `example` of a point is printed exactly as the engine gave
// it: the engine redacted it, so `<redacted>` is the honest text and this view invents no value.
//
// The view holds no state of its own: tab, job, node selection and the loaded pages live in the
// store, so leaving for the inspector and coming back restores all of them (D-T8.8). States are
// D-T8.10's four: grey bars until the first read answers, "No site map for this job yet", the
// core's error text with the last good time and Retry, and every control disabled while the bus
// reconnects (data kept).

import { createEffect, createMemo, For, on, Show, type Component } from 'solid-js';
import { Badge, Button, Icon } from '~/components';
import { methodHue } from '~/model/flow';
import { useApp } from '~/state/context';
import { nodesByHost } from './helpers';
import type { InsertionPoint, SiteNode } from './model';
import { scanStore } from './store';
import css from './scanner.module.css';

/** Missing prints as a grey dash (foundation §2.8); zero prints as `0`. */
const Dash: Component = () => <span class={css.dash}>—</span>;

const fmtTime = (ms: number): string => new Date(ms).toLocaleTimeString();

/** `method url` from the two nullable halves; a dash only when both are missing. */
function requestText(p: InsertionPoint): string | null {
  const parts = [p.method, p.url].filter((x): x is string => x !== null);
  return parts.length > 0 ? parts.join(' ') : null;
}

export const SitemapView: Component = () => {
  const s = scanStore(useApp());

  // A memo so the mount read fires once per job change, not once per job-list poll.
  const job = createMemo(() => s.selectedJob());
  const page = () => {
    const j = job();
    return j === null ? null : s.sitemap(j);
  };
  const groups = createMemo(() => nodesByHost(page()?.nodes ?? []));
  /** Nodes in display order (host groups, first-seen), the keyboard's row order. */
  const ordered = createMemo(() => groups().flatMap((g) => g.nodes));
  /** The selection resolved against this job's nodes: a stale id from another job selects nothing. */
  const selected = createMemo<SiteNode | null>(() => {
    const id = s.selectedNode();
    return id === null ? null : (ordered().find((n) => n.id === id) ?? null);
  });
  const points = createMemo<InsertionPoint[]>(() => {
    const all = page()?.points ?? [];
    const node = selected();
    return node === null ? all : all.filter((p) => p.site_node === node.id);
  });

  const disabled = () => !s.busOpen();
  const loading = () => {
    const p = page();
    return p !== null && p.loadedAt === null && p.error === null;
  };
  const empty = () => {
    const p = page();
    return p !== null && p.loadedAt !== null && p.error === null && p.nodes.length === 0;
  };
  const hasMore = () => page()?.nextCursor != null;

  // First read: a page nobody has read yet, once the bus is open (W-16). A page in error is left
  // to Retry; a page in flight is not read twice.
  createEffect(
    on([job, () => s.busOpen()], ([j, open]) => {
      if (j === null || !open) return;
      const p = s.sitemap(j);
      if (p.loadedAt === null && !p.loading && p.error === null) void s.refreshSitemap(j);
    }),
  );

  const retry = () => {
    const j = job();
    if (j !== null) void s.refreshSitemap(j);
  };
  const loadMore = () => {
    const j = job();
    if (j !== null) void s.loadMoreSitemap(j);
  };

  let detailEl: HTMLDivElement | undefined;

  const select = (id: string, fromKeyboard = false) => {
    s.setSelectedNode(id);
    if (fromKeyboard) document.getElementById(`sitemap-node-${id}`)?.scrollIntoView?.({ block: 'nearest' });
  };
  const move = (delta: number) => {
    const list = ordered();
    if (!list.length) return;
    const i = list.findIndex((n) => n.id === s.selectedNode());
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
        if (ordered().length) select(ordered()[0]!.id, true);
        break;
      case 'End':
        e.preventDefault();
        if (ordered().length) select(ordered()[ordered().length - 1]!.id, true);
        break;
      case 'Enter':
        e.preventDefault();
        detailEl?.focus({ preventScroll: true });
        break;
    }
  };

  const hue = (method: string) => methodHue({ method, kind: 'http' });

  return (
    <div class={css.layout}>
      <section class={css.list} aria-label="Site map nodes">
        <div class={css.listHead}>
          <span class={css.listTitle}>
            Site map
            <span class={css.n}>· {ordered().length}</span>
          </span>
          <Show when={disabled()}>
            <span class={css.reconnectNote} role="status">
              reconnecting: controls paused
            </span>
          </Show>
          <Show when={hasMore()}>
            <Button variant="small" disabled={disabled() || page()?.loading === true} onClick={loadMore}>
              Load more
            </Button>
          </Show>
        </div>
        {/* The middle grid row: the error block or the grey bars; empty (zero height) otherwise. */}
        <div>
          <Show
            when={page()?.error}
            fallback={
              <Show when={loading()}>
                <div class={css.loading} aria-busy="true" aria-label="Loading site map">
                  <i />
                  <i />
                  <i />
                  <i />
                </div>
              </Show>
            }
          >
            {(err) => (
              <div class={css.errorBlock} role="alert">
                <p>{err()}</p>
                <Show when={page()?.loadedAt}>{(at) => <span class={css.mono}>last good {fmtTime(at())}</span>}</Show>
                <Button variant="small" class={css.retry} disabled={disabled()} onClick={retry}>
                  Retry
                </Button>
              </div>
            )}
          </Show>
        </div>
        <div
          class={css.rows}
          role="listbox"
          aria-label="Site map"
          tabIndex={0}
          aria-activedescendant={s.selectedNode() ? `sitemap-node-${s.selectedNode()}` : undefined}
          onKeyDown={onKeyDown}
        >
          <Show when={job() !== null} fallback={<div class={css.empty}>No jobs yet: start one from Profiles</div>}>
            <Show when={empty()}>
              <div class={css.empty}>No site map for this job yet</div>
            </Show>
            <For each={groups()}>
              {(g) => (
                <div class={css.tree} role="group" aria-label={g.host}>
                  <div class={css.treeHost} role="presentation">
                    {g.host}
                  </div>
                  <For each={g.nodes}>
                    {(n) => (
                      <div
                        id={`sitemap-node-${n.id}`}
                        class={css.row}
                        role="option"
                        data-node={n.id}
                        aria-selected={s.selectedNode() === n.id}
                        onClick={() => select(n.id)}
                      >
                        <div class={css.rowMain}>
                          <Badge hue={hue(n.method)}>{n.method}</Badge>
                          <span>{n.path_template}</span>
                          <span class={css.tag} data-field="points" title="insertion points">
                            {n.points}
                          </span>
                          <Show when={n.audited}>
                            <span title="audited">
                              <Icon name="check" size={12} label="audited" />
                            </span>
                          </Show>
                          <Show when={n.auth}>
                            <span title="authenticated">
                              <Icon name="lock" size={12} label="authenticated" />
                            </span>
                          </Show>
                        </div>
                        <div class={css.rowSecondary}>{g.host}</div>
                      </div>
                    )}
                  </For>
                </div>
              )}
            </For>
          </Show>
        </div>
      </section>

      <div class={css.detail} role="region" aria-label="Node detail" tabIndex={-1} ref={detailEl}>
        <div class={css.body}>
          <Show
            when={selected()}
            fallback={
              <section class={css.section}>
                <h2>Site map</h2>
                <p class={css.note}>Select a node for its facts and flows; every insertion point is listed below.</p>
              </section>
            }
          >
            {(n) => (
              <>
                <h2>
                  {n().method} {n().path_template}
                </h2>
                <section class={css.section} aria-label="Node">
                  <dl class={css.facts}>
                    <dt>Method</dt>
                    <dd>
                      <Badge hue={hue(n().method)}>{n().method}</Badge>
                    </dd>
                    <dt>Origin</dt>
                    <dd class={css.mono}>{`${n().scheme}://${n().host}:${n().port}`}</dd>
                    <dt>Template</dt>
                    <dd class={css.mono}>{n().path_template}</dd>
                    <dt>Params</dt>
                    <dd>
                      <Show when={n().params.length > 0} fallback={<Dash />}>
                        <For each={n().params}>{(p) => <span class={css.tag}>{`${p.kind}:${p.name}`}</span>}</For>
                      </Show>
                    </dd>
                    <dt>Points</dt>
                    <dd>{n().points}</dd>
                    <dt>Audited</dt>
                    <dd>{n().audited ? 'yes' : 'no'}</dd>
                    <dt>Auth</dt>
                    <dd>{n().auth ? 'authenticated' : 'no'}</dd>
                    <dt>Flows</dt>
                    <dd>
                      <Show when={n().flows.length > 0} fallback={<Dash />}>
                        <For each={n().flows}>
                          {(id) => (
                            <Button
                              variant="small"
                              class={css.mono}
                              aria-label={`Open flow ${id}`}
                              title="Open in the inspector"
                              disabled={disabled()}
                              onClick={() => void s.openFlow(id)}
                            >
                              {id}
                            </Button>
                          )}
                        </For>
                      </Show>
                    </dd>
                  </dl>
                </section>
              </>
            )}
          </Show>

          <section class={css.section}>
            <h3 class={css.sectionTitle}>
              Insertion points
              <span class={css.n}>{points().length}</span>
            </h3>
            <ul class={css.tree} aria-label="Insertion points">
              <For each={points()}>
                {(p) => (
                  <li data-point={p.id} data-lane={p.lane}>
                    <div class={css.rowMain}>
                      <span class={css.tag}>{p.kind}</span>
                      <span class={css.mono} data-field="kind-name">
                        {`${p.kind}:${p.name}`}
                      </span>
                      <span class={css.mono} data-field="path">
                        {p.path ?? <Dash />}
                      </span>
                    </div>
                    <div class={css.rowMeta}>
                      <For each={p.traits}>{(t) => <span class={css.chip}>{t}</span>}</For>
                      <span title="frequency">
                        ×<span data-field="frequency">{p.frequency}</span>
                      </span>
                      <span class={css.sep}>·</span>
                      <span class={css.mono} data-field="request">
                        {requestText(p) ?? <Dash />}
                      </span>
                    </div>
                    <div class={css.mono} data-field="example" title="example (as the engine recorded it)">
                      {p.example ?? <Dash />}
                    </div>
                  </li>
                )}
              </For>
            </ul>
          </section>
        </div>
      </div>
    </div>
  );
};
