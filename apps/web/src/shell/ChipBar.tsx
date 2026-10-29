// Content-type chip bar (§2.7). One chip active (raised fill, 500); "Filters ▾" at the right
// toggles the stacked filter bar.
import { For, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components/Icon';
import { CHIPS } from './chips';
import css from './ChipBar.module.css';

export const ChipBar: Component = () => {
  const app = useApp();
  const activeFilters = () => app.ui.filters.filter((r) => r.value).length;
  return (
    <div class={css.chips} role="group" aria-label="Quick filter">
      <For each={CHIPS}>
        {(c, i) => (
          <>
            <Show when={c.group}>
              <span class={css.sep} aria-hidden="true" />
            </Show>
            <button
              type="button"
              class={css.chip}
              aria-pressed={app.ui.chip === c.id}
              title={i() < 9 ? `${c.label}  ⌘${i() + 1}` : c.label}
              onClick={() => app.setChip(c.id)}
            >
              {c.label}
            </button>
          </>
        )}
      </For>
      <button
        type="button"
        class={`${css.chip} ${css.filters}`}
        aria-pressed={app.ui.filtersOpen}
        aria-controls="aitm-filter-bar"
        data-count={activeFilters() > 0 ? activeFilters() : undefined}
        title="Filter bar  ⌘F"
        onClick={() => app.toggleFilters()}
      >
        Filters
        <Show when={activeFilters() > 0}>
          <span class={css.n}>{activeFilters()}</span>
        </Show>
        <Icon name="chevron-down" size={12} style={app.ui.filtersOpen ? { transform: 'rotate(180deg)' } : undefined} />
      </button>
    </div>
  );
};
