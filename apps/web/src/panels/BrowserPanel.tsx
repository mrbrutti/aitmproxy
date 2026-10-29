// The Browser panel (foundation §2.7 "Browser view (embedded obscura)"): tab strip, toolbar,
// the live screenshot viewport with an optional DOM pane at the right and an Eval drawer at the
// bottom. The shell mounts it in the lower region when app.ui.panel === 'browser'; its state
// lives in ~/panels/browser/state so leaving and returning keeps the last frame and history.
import { Show, type Component } from 'solid-js';
import { TabStrip } from './browser/TabStrip';
import { BrowserToolbar } from './browser/BrowserToolbar';
import { Viewport } from './browser/Viewport';
import { DomPane } from './browser/DomPane';
import { EvalDrawer } from './browser/EvalDrawer';
import { useBrowser } from './browser/use-browser';
import css from './browser/browser.module.css';

export const BrowserPanel: Component = () => {
  const s = useBrowser();
  return (
    <div class={css.panel} data-dom={s.domOpen() ? 'open' : undefined} data-eval={s.evalOpen() ? 'open' : undefined}>
      <TabStrip />
      <BrowserToolbar />
      <div class={css.main}>
        <Viewport />
        <Show when={s.domOpen()}>
          <DomPane />
        </Show>
      </div>
      <Show when={s.evalOpen()}>
        <EvalDrawer />
      </Show>
    </div>
  );
};
