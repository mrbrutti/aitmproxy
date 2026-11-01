// The v2 Scan surface shell (D-T8.1, D-T8.2, D-T8.10): the header with the title and the four-tab
// strip, the persistent job strip, and the selected view below. The shell owns no data — every
// count and every row comes from `scanStore(app)`, which lives per app store and outlives this
// panel (the lower region swaps to the inspector constantly, and a live job keeps polling without a
// panel mounted, W-6). The tab, the selections and the loaded pages all live in the store, so
// leaving for the inspector and coming back restores the surface exactly.
//
// Keyboard (W-17): ArrowLeft / ArrowRight move the selected tab (wrapping) and focus it, the WAI-ARIA
// tabs pattern. While the bus is not open (D-T8.10) a one-line note appears and every control in the
// surface is disabled; the views keep their data and re-enable when the bus returns.

import { For, Match, Switch, onMount, type Component, type JSX } from 'solid-js';
import { Icon } from '~/components';
import { useApp } from '~/state/context';
import { IssuesView } from './IssuesView';
import { JobStrip } from './JobStrip';
import { JobsView } from './JobsView';
import { ProfilesView } from './ProfilesView';
import { SitemapView } from './SitemapView';
import { scanStore, type Tab } from './store';
import css from './scanner.module.css';

interface TabDef {
  id: Tab;
  label: string;
}

/** The tab strip, in order (W-17). The live script matches `data-tab` and the labels verbatim. */
const TABS: readonly TabDef[] = [
  { id: 'profiles', label: 'Profiles' },
  { id: 'jobs', label: 'Jobs' },
  { id: 'sitemap', label: 'Site map' },
  { id: 'issues', label: 'Issues' },
];

export const Scanner: Component = () => {
  const app = useApp();
  const s = scanStore(app);
  const busOpen = (): boolean => s.busOpen();

  // Read what the surface needs the first time the panel mounts (the store's own bootstrap may have
  // read some already, hence the loaded guards). Checks and the L4 scope have no store bootstrap, so
  // they are read here; each call is a no-op unless the bus is open on a v2 core.
  onMount(() => {
    if (!s.profilesLoaded()) void s.loadProfiles();
    if (!s.checksLoaded()) void s.loadChecks();
    if (!s.jobsLoaded()) void s.refreshJobs();
    if (s.l4Offered()) void s.loadL4Scope();
  });

  /** The count shown beside each tab (D-T8.2): profiles, live/total jobs, nodes, issues by severity. */
  const tabCount = (id: Tab): string => {
    switch (id) {
      case 'profiles':
        return String(s.profiles().length);
      case 'jobs': {
        const total = s.jobs().length;
        const live = s.liveCount() ?? 0;
        return live > 0 ? `${live} live / ${total}` : String(total);
      }
      case 'sitemap': {
        const job = s.selectedJob();
        return String(job === null ? 0 : s.sitemap(job).nodes.length);
      }
      case 'issues': {
        const b = s.issues(s.issuesScope()).bySeverity;
        return String(b.critical + b.high + b.medium + b.low + b.info);
      }
    }
  };

  let tablist: HTMLDivElement | undefined;
  const focusTab = (id: Tab): void => {
    tablist?.querySelector<HTMLButtonElement>(`button[role=tab][data-tab="${id}"]`)?.focus();
  };

  const onKeyDown: JSX.EventHandler<HTMLDivElement, KeyboardEvent> = (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const at = TABS.findIndex((t) => t.id === s.tab());
    const delta = e.key === 'ArrowRight' ? 1 : -1;
    const next = TABS[(at + delta + TABS.length) % TABS.length]!;
    s.setTab(next.id);
    focusTab(next.id);
  };

  return (
    <section class={css.root} aria-label="Scanner">
      <header class={css.header}>
        <h2 class={css.title}>
          <Icon name="search" size={16} />
          Scan
        </h2>
        <div ref={tablist} class={css.tabs} role="tablist" aria-label="Scan views" onKeyDown={onKeyDown}>
          <For each={TABS}>
            {(t) => {
              const selected = (): boolean => s.tab() === t.id;
              return (
                <button
                  type="button"
                  role="tab"
                  id={`scan-tab-${t.id}`}
                  data-tab={t.id}
                  class={css.tab}
                  aria-controls="scan-tabpanel"
                  aria-selected={selected() ? 'true' : 'false'}
                  tabindex={selected() ? 0 : -1}
                  disabled={!busOpen()}
                  onClick={() => s.setTab(t.id)}
                >
                  {t.label}
                  <span class={css.tabCount}>{tabCount(t.id)}</span>
                </button>
              );
            }}
          </For>
        </div>
        <Switch>
          <Match when={!busOpen()}>
            <p class={css.reconnectNote} role="status">
              reconnecting…
            </p>
          </Match>
        </Switch>
      </header>

      <JobStrip />

      <div id="scan-tabpanel" role="tabpanel" aria-labelledby={`scan-tab-${s.tab()}`}>
        <Switch>
          <Match when={s.tab() === 'profiles'}>
            <ProfilesView />
          </Match>
          <Match when={s.tab() === 'jobs'}>
            <JobsView />
          </Match>
          <Match when={s.tab() === 'sitemap'}>
            <SitemapView />
          </Match>
          <Match when={s.tab() === 'issues'}>
            <IssuesView />
          </Match>
        </Switch>
      </div>
    </section>
  );
};
