// Toolbar (44px): back · forward · reload | URL field | live pill · Screenshot · Eval… · DOM | Flows ›.
// Back/forward/reload re-navigate over the view's own history (no bus commands for them yet).
import { type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { StatusDot } from '~/components/StatusDot';
import { BrowserIcon } from './icons';
import { useBrowser } from './use-browser';
import css from './browser.module.css';

export const BrowserToolbar: Component = () => {
  const app = useApp();
  const s = useBrowser();
  const off = () => !s.available();

  const showFlows = () => {
    app.setSidebar({ kind: 'app', key: 'obscura' });
    app.setPanel('inspector');
  };

  return (
    <div class={css.toolbar} role="toolbar" aria-label="Browser">
      <Button variant="toolbar" title="Back" disabled={off() || !s.history.canBack()} onClick={() => s.back()}>
        <BrowserIcon name="arrow-left" />
      </Button>
      <Button variant="toolbar" title="Forward" disabled={off() || !s.history.canForward()} onClick={() => s.forward()}>
        <BrowserIcon name="arrow-right" />
      </Button>
      <Button variant="toolbar" title="Reload" disabled={off() || !s.url() || s.navigating()} onClick={() => s.reload()}>
        <BrowserIcon name="rotate-cw" />
      </Button>

      <form
        class={css.urlForm}
        onSubmit={(e) => {
          e.preventDefault();
          void s.navigate(s.draft());
        }}
      >
        <Icon name="globe" size={12} class={css.urlIcon} />
        <input
          class={css.url}
          type="text"
          inputMode="url"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
          aria-label="Address"
          placeholder={off() ? '' : 'Enter a URL'}
          disabled={off()}
          value={s.draft()}
          onInput={(e) => s.setDraft(e.currentTarget.value)}
          onFocus={(e) => e.currentTarget.select()}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              s.setDraft(s.url());
              e.currentTarget.blur();
            }
          }}
        />
      </form>

      <button
        type="button"
        class={css.live}
        data-on={s.polling() ? 'true' : 'false'}
        aria-pressed={s.live()}
        disabled={off()}
        title={s.live() ? `Live: a screenshot every ${0.8}s while this view is visible — click to pause` : 'Live paused — click to resume'}
        onClick={() => s.setLive(!s.live())}
      >
        <StatusDot hue={s.polling() ? 'success' : 'grey'} />
        live
      </button>

      <Button variant="toolbar" title="Save a screenshot (PNG)" disabled={off()} onClick={() => void s.screenshot()}>
        <BrowserIcon name="camera" />
        Screenshot
      </Button>
      <Button variant="toolbar" title="Evaluate JavaScript in the page" disabled={off()} active={s.evalOpen()} onClick={() => s.setEvalOpen(!s.evalOpen())}>
        <BrowserIcon name="terminal" />
        Eval…
      </Button>
      <Button variant="toolbar" title="Show the page's DOM" disabled={off()} active={s.domOpen()} onClick={() => s.toggleDom()}>
        <Icon name="code" />
        DOM
      </Button>

      <span class={css.sep} aria-hidden="true" />
      <button type="button" class={css.flows} title="Show the flows this browser generated" onClick={showFlows}>
        Flows <span aria-hidden="true">›</span>
      </button>
    </div>
  );
};
