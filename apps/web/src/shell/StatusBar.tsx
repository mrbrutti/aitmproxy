// Status bar (§2.7): Clear · Filter · Auto-select | rows · paused · scope · findings | memory ·
// throughput · bus. A quiet ⋯ menu at the far right holds theme and density.
import { createSignal, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { Density, Theme } from '~/state/app';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { Menu, type MenuEntry } from '~/components/Menu';
import { StatusDot } from '~/components/StatusDot';
import { rectAnchor, type AnchorRect } from '~/components/floating';
import { fmtBytes, fmtRate, pluralize } from '~/lib/format';
import { ClearButton } from './Toolbar';
import css from './StatusBar.module.css';

const THEMES: { id: Theme; label: string }[] = [
  { id: 'system', label: 'System' },
  { id: 'light', label: 'Light' },
  { id: 'dark', label: 'Dark' },
];
const DENSITIES: { id: Density; label: string }[] = [
  { id: 'dense', label: 'Dense · 28px rows' },
  { id: 'default', label: 'Default · 32px rows' },
  { id: 'comfortable', label: 'Comfortable · 40px rows' },
];

export const StatusBar: Component<{ class?: string }> = (props) => {
  const app = useApp();
  const [menu, setMenu] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);
  const busHue = () => {
    const s = app.bus.state();
    if (s === 'open') return 'success';
    if (s === 'connecting' || s === 'reconnecting') return 'pending';
    return 'server-error'; // 'unauthorized', 'closed', 'idle'
  };
  const items = (): MenuEntry[] => [
    { label: 'Theme', disabled: true },
    ...THEMES.map((t) => ({ label: t.label, checked: app.ui.theme === t.id, onSelect: () => app.setTheme(t.id) })),
    { type: 'separator' },
    { label: 'Density', disabled: true },
    ...DENSITIES.map((d) => ({ label: d.label, checked: app.ui.density === d.id, onSelect: () => app.setDensity(d.id) })),
  ];

  return (
    <footer class={`${css.bar}${props.class ? ` ${props.class}` : ''}`}>
      <ClearButton variant="small" />
      <Button variant="small" active={app.ui.filtersOpen} onClick={() => app.toggleFilters()}>
        Filter
      </Button>
      <Button variant="small" active={app.ui.autoSelect} onClick={() => app.setAutoSelect(!app.ui.autoSelect)} title="Select each new flow as it arrives">
        Auto-select
      </Button>

      <div class={css.center}>
        <span>
          {app.visible().length} / {app.total()} rows
        </span>
        <span classList={{ [css.paused!]: app.proxy.pausedIds.length > 0 }}>{app.proxy.pausedIds.length} paused</span>
        <span>{pluralize(app.proxy.scope.length, 'host')} in scope</span>
        <span>{pluralize(app.proxy.findings.length, 'finding')}</span>
      </div>

      <div class={css.right}>
        <Show when={app.proxy.memoryBytes != null}>
          <span title="Proxy memory">{fmtBytes(app.proxy.memoryBytes)}</span>
        </Show>
        <span title="Upstream">↑ {fmtRate(app.proxy.throughput.up)}</span>
        <span title="Downstream">↓ {fmtRate(app.proxy.throughput.down)}</span>
        <span class={css.bus} title={app.bus.lastError() ?? `bus ${app.bus.state()}`}>
          <StatusDot hue={busHue()} />
          {app.bus.state() === 'unauthorized' ? 'bus token expired' : `bus ${app.bus.address}`}
        </span>
        <Button
          variant="toolbar"
          class={css.more}
          title="Appearance"
          aria-haspopup="menu"
          aria-expanded={menu() != null}
          onClick={(e) => setMenu({ anchor: rectAnchor(e.currentTarget.getBoundingClientRect()), kb: e.detail === 0 })}
        >
          <Icon name="ellipsis" size={12} />
        </Button>
      </div>
      <Show when={menu()}>
        {(m) => <Menu anchor={m().anchor} placement="top-start" animate={!m().kb} label="Appearance" onClose={() => setMenu(null)} items={items()} />}
      </Show>
    </footer>
  );
};
