// The primary screen (§2.6). Owns the grid, the splitter, global shortcuts and the dev perf probe;
// every region is its own component. The lower region shows the Inspector or the active panel.
import { createSignal, Match, onCleanup, onMount, Show, Switch, type Component } from 'solid-js';
import { useApp, useL4 } from '~/state/context';
import { Inspector } from '~/inspector/Inspector';
import { FindingsPanel } from '~/panels/FindingsPanel';
import { ScanPanel } from '~/panels/ScanPanel';
import { BrowserPanel } from '~/panels/BrowserPanel';
import { ScopePanel } from '~/panels/ScopePanel';
import { AgentPanel } from '~/panels/AgentPanel';
import { ScriptsPanel } from '~/panels/ScriptsPanel';
import { L4InspectorPanel } from '~/panels/l4/L4InspectorPanel';
import { L4CaptureBar } from '~/panels/l4/L4CaptureBar';
import { ComposeSheet } from '~/compose/ComposeSheet';
import { CommandPalette } from '~/palette/CommandPalette';
import { FlowList } from '~/flows/FlowList';
import { Sidebar } from './Sidebar';
import { Toolbar } from './Toolbar';
import { RoleBanner } from './RoleBanner';
import { ChipBar } from './ChipBar';
import { FilterBar } from '~/flows/FilterBar';
import { InterceptBar } from './InterceptBar';
import { StatusBar } from './StatusBar';
import { Toast } from './Toast';
import { installShortcuts } from './shortcuts';
import { maybeStartPerfProbe } from './perf';
import '~/components/marks.css';
import css from './Shell.module.css';

const SPLIT_KEYS = { horizontal: 'aitm.split.h', vertical: 'aitm.split.v' } as const;
const SPLIT_DEFAULT = { horizontal: 1.15 / 2.15, vertical: 0.5 } as const;

const readSplit = (key: string): number | null => {
  try {
    const v = localStorage.getItem(key);
    const n = v == null ? NaN : Number(v);
    return Number.isFinite(n) && n > 0 && n < 1 ? n : null;
  } catch {
    return null;
  }
};
const writeSplit = (key: string, v: number) => {
  try {
    localStorage.setItem(key, String(v));
  } catch {
    /* private mode */
  }
};

export const Shell: Component = () => {
  const app = useApp();
  const l4 = useL4();
  const [splits, setSplits] = createSignal<Record<'horizontal' | 'vertical', number | null>>({
    horizontal: readSplit(SPLIT_KEYS.horizontal),
    vertical: readSplit(SPLIT_KEYS.vertical),
  });
  const split = () => splits()[app.ui.layout] ?? SPLIT_DEFAULT[app.ui.layout];

  let body: HTMLDivElement | undefined;

  onMount(() => {
    const dispose = installShortcuts(app);
    maybeStartPerfProbe();
    onCleanup(dispose);
  });

  /** Drag the splitter: one rect read at pointerdown, then pure arithmetic per move. */
  const onSplitterDown = (e: PointerEvent) => {
    if (!body || e.button !== 0) return;
    const layout = app.ui.layout;
    const rect = body.getBoundingClientRect();
    const el = e.currentTarget as HTMLElement;
    el.setPointerCapture(e.pointerId);
    document.body.classList.add(css.dragging!);
    document.body.style.cursor = layout === 'horizontal' ? 'row-resize' : 'col-resize';
    const move = (ev: PointerEvent) => {
      const frac =
        layout === 'horizontal' ? (rect.bottom - ev.clientY) / rect.height : (rect.right - ev.clientX) / rect.width;
      const clamped = Math.min(0.85, Math.max(0.15, frac));
      setSplits((s) => ({ ...s, [layout]: clamped }));
    };
    const up = () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
      document.body.classList.remove(css.dragging!);
      document.body.style.cursor = '';
      const v = splits()[layout];
      if (v != null) writeSplit(SPLIT_KEYS[layout], v);
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  };

  const onSplitterKey = (e: KeyboardEvent) => {
    const layout = app.ui.layout;
    const dir = layout === 'horizontal' ? { grow: 'ArrowUp', shrink: 'ArrowDown' } : { grow: 'ArrowLeft', shrink: 'ArrowRight' };
    if (e.key !== dir.grow && e.key !== dir.shrink) return;
    e.preventDefault();
    const next = Math.min(0.85, Math.max(0.15, split() + (e.key === dir.grow ? 0.02 : -0.02)));
    setSplits((s) => ({ ...s, [layout]: next }));
    writeSplit(SPLIT_KEYS[layout], next);
  };

  return (
    <div class={css.app} data-sidebar={app.ui.sidebarOpen ? 'open' : 'closed'}>
      <Sidebar class={css.sidebar!} />
      <section class={css.main}>
        <Toolbar />
        {/* RoleBanner is a fragment of 0–2 banners; the always-present wrapper pins them to one
            `auto` row of .main so the chip bar, filter row and body never shift down a row. */}
        <div class={css.banners}>
          <RoleBanner />
        </div>
        <ChipBar />
        <Show when={app.ui.filtersOpen} fallback={<div />}>
          <FilterBar />
        </Show>
        <div ref={body} class={css.body} data-layout={app.ui.layout} style={{ '--split': `${(split() * 100).toFixed(2)}%` }}>
          <div class={css.listPane}>
            <Show when={l4 && app.ui.sidebar.kind === 'l4'}>
              <L4CaptureBar store={l4!} />
            </Show>
            {/* The list fills whatever the capture bar (L4 view) and the intercept bar (armed) leave;
                the wrapper is the one flex item that grows, so the bar is never height-constrained
                and the virtualised body keeps scrolling (min-height: 0). */}
            <div class={css.listFill}>
              <FlowList />
            </div>
            <Show when={app.proxy.armed}>
              <InterceptBar />
            </Show>
          </div>
          <div
            class={css.splitter}
            role="separator"
            aria-orientation={app.ui.layout === 'horizontal' ? 'horizontal' : 'vertical'}
            aria-label="Resize inspector"
            tabIndex={0}
            onPointerDown={onSplitterDown}
            onKeyDown={onSplitterKey}
          />
          <div class={css.lower} id="aitm-lower">
            {/* The lower region is a side panel when one is open, else the inspector for the
                selected flow — dispatched by kind: an L4 session opens the L4 inspector (packets +
                craft + intercept), every other flow the HTTP Request|Response inspector. */}
            <Switch fallback={l4 && app.selectedIsL4() ? <L4InspectorPanel store={l4} /> : <Inspector />}>
              <Match when={app.ui.panel === 'findings'}>
                <FindingsPanel />
              </Match>
              <Match when={app.ui.panel === 'scan'}>
                <ScanPanel />
              </Match>
              <Match when={app.ui.panel === 'browser'}>
                <BrowserPanel />
              </Match>
              <Match when={app.ui.panel === 'scope'}>
                <ScopePanel />
              </Match>
              <Match when={app.ui.panel === 'agent'}>
                <AgentPanel />
              </Match>
              <Match when={app.ui.panel === 'scripts'}>
                <ScriptsPanel />
              </Match>
            </Switch>
          </div>
        </div>
      </section>
      <StatusBar class={css.statusbar!} />
      <Toast />
      <Show when={app.ui.composeOpen}>
        <ComposeSheet />
      </Show>
      <Show when={app.ui.paletteOpen}>
        <CommandPalette />
      </Show>
    </div>
  );
};
