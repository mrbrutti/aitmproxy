// Tab strip (36px): one tab per `browser.tabs` entry, or the single local tab when the server has
// no tab list yet. Closing and opening tabs are not bus commands until F14, so those controls
// are present, disabled, and say why.
import { For, type Component } from 'solid-js';
import { Icon } from '~/components/Icon';
import { hostOf } from './url';
import { useBrowser } from './use-browser';
import css from './browser.module.css';

export const TabStrip: Component = () => {
  const s = useBrowser();
  return (
    <ul class={css.tabs} aria-label="Open tabs">
      <For each={s.tabs()}>
        {(t) => (
          <li class={css.tab} data-active={t.active ? 'true' : undefined} aria-current={t.active ? 'page' : undefined} title={t.url || undefined}>
            <Icon name="globe" size={12} class={css.tabIcon} />
            <span class={css.tabTitle}>{t.title || hostOf(t.url) || 'Untitled'}</span>
            <button type="button" class={css.tabClose} disabled title="Close tab — needs F14" aria-label="Close tab">
              <Icon name="x" size={12} />
            </button>
          </li>
        )}
      </For>
      <li class={css.tabNewItem}>
        <button type="button" class={css.tabNew} disabled title="New tab — needs F14" aria-label="New tab">
          <Icon name="plus" size={12} />
        </button>
      </li>
    </ul>
  );
};
