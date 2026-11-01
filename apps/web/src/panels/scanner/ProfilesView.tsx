// The Profiles view (D-T8.5, D-T8.10): the profile list on the left, the editor for the selected
// profile on the right — the surface a scan is started from.
//
// The list is the core's `scan.profile.list`, built-ins first and saved profiles after, each row
// carrying what the summary says and a dot when an unsaved draft is open on it. Selecting a profile
// loads it (`store.loadProfile` never overwrites a draft in progress), and `standard` is selected
// once, the first time a list arrives, so the surface opens on something runnable.

import { createEffect, createMemo, For, Match, onMount, Show, Switch, untrack, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { ProfileEditor } from './ProfileEditor';
import { ErrorBlock, listboxKeys, LoadingBars } from './primitives';
import { scanStore } from './store';
import type { ProfileListEntry } from './model';
import css from './scanner.module.css';

/** A row's DOM id: looked up with `getElementById`, so a wire profile name is never part of a selector. */
const domId = (name: string): string => `profile-${name}`;

export const ProfilesView: Component = () => {
  const app = useApp();
  const s = scanStore(app);

  // The editor needs all three: the list, the check catalogue (the tree and the lane tags) and the
  // L4 scope (the pre-flight reason). The memoised `ensure*` join a read in flight and do nothing
  // once loaded (A3): mounting beside the shell costs no second verb. Retry below uses the bare `load`.
  onMount(() => {
    void s.ensureProfiles();
    void s.ensureChecks();
    void s.ensureL4Scope();
  });

  /** Built-ins first, then saved; first-seen order inside each group (the sort is stable). */
  const rows = createMemo<ProfileListEntry[]>(() =>
    [...s.profiles()].sort((a, b) => Number(b.builtin) - Number(a.builtin)),
  );

  let detail: HTMLDivElement | undefined;

  const select = (name: string): void => {
    s.setSelectedProfile(name);
    void s.loadProfile(name);
  };

  // Default selection `standard` (D-T8.5), set once on the first list that arrives so a later
  // reload — or a profile the operator picked meanwhile — is never overridden.
  let defaulted = false;
  createEffect(() => {
    if (defaulted || !s.profilesLoaded()) return;
    const list = rows();
    if (list.length === 0) return;
    defaulted = true;
    untrack(() => {
      if (s.selectedProfile() !== null) return;
      select((list.find((e) => e.name === 'standard') ?? list[0]!).name);
    });
  });

  const onKeyDown = listboxKeys({
    ids: () => rows().map((e) => e.name),
    selectedId: () => s.selectedProfile(),
    select,
    focusDetail: () => detail?.focus({ preventScroll: true }),
    domId,
  });

  return (
    <div class={css.layout}>
      <div class={css.list}>
        <div class={css.listHead}>
          <span class={css.listTitle}>
            Profiles <span class={css.n}>{rows().length}</span>
          </span>
        </div>
        {/* A failed reload keeps the rows (data kept, D-T8.10): the block sits above them, with the
            time the list was last read without an error (the store's, not this mount's). */}
        <Show when={s.profilesLoaded() && s.profilesError()}>
          {(error) => <ErrorBlock text={error()} lastGood={s.profilesLoadedAt()} onRetry={() => void s.loadProfiles()} disabled={!s.busOpen()} />}
        </Show>
        <Switch>
          <Match when={!s.profilesLoaded()}>
            <LoadingBars label="Loading profiles" />
          </Match>
          <Match when={rows().length === 0 && s.profilesError() === null}>
            <div class={css.empty} role="status" aria-label="Profiles">
              No profiles
            </div>
          </Match>
          <Match when={rows().length > 0}>
            <div class={css.rows} role="listbox" aria-label="Profiles" tabindex={0} onKeyDown={onKeyDown}>
              <For each={rows()}>
                {(entry) => (
                  <div
                    id={domId(entry.name)}
                    class={css.row}
                    role="option"
                    data-profile={entry.name}
                    aria-selected={s.selectedProfile() === entry.name}
                    data-dirty={s.draft(entry.name)?.dirty ? 'true' : undefined}
                    onClick={() => select(entry.name)}
                  >
                    <div class={css.rowMain}>
                      <span>{entry.name}</span>
                      <Show when={entry.builtin}>
                        <span class={css.tag}>builtin</span>
                      </Show>
                      <Show when={s.draft(entry.name)?.dirty}>
                        <span class={css.stateDot} data-tone="warning" title="unsaved changes" />
                      </Show>
                    </div>
                    <div class={css.rowMeta}>
                      <span>{entry.summary.lanes.join(' ')}</span>
                      <span class={css.sep}>·</span>
                      <span>{entry.summary.intensity}</span>
                      <span class={css.sep}>·</span>
                      <span>{entry.summary.speed}</span>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Match>
        </Switch>
      </div>
      <div class={css.detail} ref={detail} tabindex={-1}>
        <Show
          when={s.selectedProfile()}
          fallback={
            <div class={css.empty} role="status">
              Select a profile
            </div>
          }
        >
          {(name) => <ProfileEditor name={name()} />}
        </Show>
      </div>
    </div>
  );
};
