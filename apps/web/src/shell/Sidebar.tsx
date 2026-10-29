// Sidebar (§2.6): brand row, Working / All / aitmproxy groups, quick filter at the bottom.
import { createMemo, createSignal, For, onCleanup, onMount, Show, type Component, type JSX } from 'solid-js';
import { useApp } from '~/state/context';
import type { SidebarItem } from '~/state/app';
import { Icon, type IconName } from '~/components/Icon';
import { Kbd } from '~/components/Kbd';
import { EVENTS } from './shortcuts';
import css from './Sidebar.module.css';

const sameItem = (a: SidebarItem, b: SidebarItem) => a.kind === b.kind && ('key' in a ? a.key : null) === ('key' in b ? b.key : null);

const DOMAIN_LIMIT = 8;

interface ItemProps {
  icon?: IconName;
  monogram?: string;
  label: string;
  count?: string | number | null;
  countKind?: 'plain' | 'queue' | 'agent' | 'paused';
  sub?: boolean;
  current?: boolean;
  disabled?: boolean;
  expandable?: boolean;
  expanded?: boolean;
  title?: string;
  onClick: () => void;
}

const Item: Component<ItemProps> = (props) => (
  <button
    type="button"
    class={`${css.item}${props.sub ? ` ${css.sub}` : ''}`}
    aria-current={props.current ? 'true' : undefined}
    aria-disabled={props.disabled ? 'true' : undefined}
    aria-expanded={props.expandable ? props.expanded : undefined}
    title={props.title}
    onClick={props.onClick}
    data-sidebar-item
  >
    <Show when={props.expandable}>
      <Icon name="chevron-right" size={12} class={css.chev} style={props.expanded ? { transform: 'rotate(90deg)' } : undefined} />
    </Show>
    <Show when={props.icon}>{(n) => <Icon name={n()} size={12} class={css.icon} />}</Show>
    <Show when={props.monogram != null}>
      <span class={css.appdot} aria-hidden="true">
        {props.monogram}
      </span>
    </Show>
    <span class={css.label}>{props.label}</span>
    <Show when={props.count != null && props.count !== ''}>
      <span class={css.count} data-kind={props.countKind ?? 'plain'}>
        {props.count}
      </span>
    </Show>
  </button>
);

export const Sidebar: Component<{ class?: string }> = (props) => {
  const app = useApp();
  const [open, setOpen] = createSignal({ pinned: true, apps: true, domains: true });
  const [allDomains, setAllDomains] = createSignal(false);
  let input: HTMLInputElement | undefined;
  let nav: HTMLElement | undefined;

  const is = (item: SidebarItem) => sameItem(app.ui.sidebar, item);
  const pick = (item: SidebarItem) => () => app.setSidebar(item);
  const toggle = (k: 'pinned' | 'apps' | 'domains') => setOpen((o) => ({ ...o, [k]: !o[k] }));

  const domains = createMemo(() => {
    const all = app.groups().domains;
    return allDomains() ? all : all.slice(0, DOMAIN_LIMIT);
  });
  const hiddenDomains = () => Math.max(0, app.groups().domains.length - DOMAIN_LIMIT);

  onMount(() => {
    const focus = () => {
      input?.focus();
      input?.select();
    };
    window.addEventListener(EVENTS.focusSidebarFilter, focus);
    onCleanup(() => window.removeEventListener(EVENTS.focusSidebarFilter, focus));
  });

  /** ↑↓ moves focus between items when the sidebar has focus. */
  const onNavKey: JSX.EventHandler<HTMLElement, KeyboardEvent> = (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const items = Array.from(nav?.querySelectorAll<HTMLButtonElement>('[data-sidebar-item]') ?? []);
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === 'ArrowDown' ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1);
    items[next]?.focus();
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <aside class={`${css.sidebar}${props.class ? ` ${props.class}` : ''}`} aria-label="Sources">
      <div class={css.brand}>
        <svg class={css.mark} viewBox="0 0 16 16" aria-hidden="true">
          {/* ›•‹ — chevron tips stop at x=5/11 so the dot (r 1.6) keeps clear air at 16px. */}
          <path d="M2.5 4.5l2.5 3.5-2.5 3.5M13.5 4.5l-2.5 3.5 2.5 3.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round" />
          <circle cx="8" cy="8" r="1.6" fill="currentColor" />
        </svg>
        <h1 class={css.wordmark}>aitmproxy</h1>
        <span class={css.version}>{app.proxy.version}</span>
      </div>

      <nav ref={nav} class={css.nav} onKeyDown={onNavKey}>
        <div class={css.group}>Working</div>
        <Item
          icon="pin"
          label="Pinned"
          count={app.ui.pinned.length || null}
          expandable
          expanded={open().pinned}
          onClick={() => toggle('pinned')}
        />
        <Show when={open().pinned}>
          <For each={app.ui.pinned}>
            {(host) => <Item sub icon="pin" label={host} current={is({ kind: 'pinned', key: host })} onClick={pick({ kind: 'pinned', key: host })} />}
          </For>
        </Show>
        <Item icon="folder" label="Saved" count={0} disabled title="Saved sessions arrive with F10" onClick={() => {}} />

        <div class={css.group}>All</div>
        <Item
          icon="layout-grid"
          label="Apps"
          count={app.groups().apps.length}
          expandable
          expanded={open().apps}
          current={is({ kind: 'all' })}
          onClick={() => {
            if (is({ kind: 'all' })) toggle('apps');
            else app.setSidebar({ kind: 'all' });
          }}
        />
        <Show when={open().apps}>
          <For each={app.groups().apps}>
            {(a) => (
              <Item
                sub
                {...(a.id === 'unknown' ? {} : { monogram: a.name.slice(0, 1) })}
                label={a.name}
                count={a.count}
                current={is({ kind: 'app', key: a.id })}
                onClick={pick({ kind: 'app', key: a.id })}
              />
            )}
          </For>
        </Show>
        <Item icon="globe" label="Domains" count={app.groups().domains.length} expandable expanded={open().domains} onClick={() => toggle('domains')} />
        <Show when={open().domains}>
          <For each={domains()}>
            {(d) => <Item sub label={d.host} count={d.count} current={is({ kind: 'domain', key: d.host })} onClick={pick({ kind: 'domain', key: d.host })} />}
          </For>
          <Show when={!allDomains() && hiddenDomains() > 0}>
            <button type="button" class={`${css.item} ${css.sub} ${css.more}`} data-sidebar-item onClick={() => setAllDomains(true)}>
              {hiddenDomains()} more…
            </button>
          </Show>
        </Show>

        <div class={css.group}>aitmproxy</div>
        <Item icon="crosshair" label="Scope" count={app.proxy.scope.length} countKind="queue" current={is({ kind: 'scope' })} onClick={pick({ kind: 'scope' })} />
        <Item icon="flag" label="Findings" count={app.proxy.findings.length} countKind="queue" current={is({ kind: 'findings' })} onClick={pick({ kind: 'findings' })} />
        <Item icon="globe" label="Browser" count="1 tab" current={is({ kind: 'browser' })} onClick={pick({ kind: 'browser' })} />
        <Item icon="code" label="Scripts" count="0 active" current={is({ kind: 'scripts' })} onClick={pick({ kind: 'scripts' })} />
        <Item
          icon="circle-dot"
          label="L4"
          count={app.proxy.tools.some((t) => t.name === 'l4.flow.list') ? 'on' : 'off'}
          current={is({ kind: 'l4' })}
          onClick={pick({ kind: 'l4' })}
        />
        <Item
          icon="bot"
          label="Agent"
          count={`${app.proxy.agentActionsLastMinute}/min`}
          countKind="agent"
          current={is({ kind: 'agent' })}
          onClick={pick({ kind: 'agent' })}
        />
      </nav>

      <label class={css.filter}>
        <Icon name="search" size={12} />
        <input
          ref={input}
          type="search"
          placeholder="Filter"
          aria-label="Quick filter"
          value={app.ui.quickFilter}
          onInput={(e) => app.setQuickFilter(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              app.setQuickFilter('');
              e.currentTarget.blur();
            }
          }}
        />
        <Show when={!app.ui.quickFilter} fallback={<Kbd>esc</Kbd>}>
          <Kbd>⌘⇧F</Kbd>
        </Show>
      </label>
    </aside>
  );
};
