// The viewport: the latest screenshot, contained and centred on page ground; the last frame
// stays up while the next one decodes. Until F14's screencast carries element metadata a click
// cannot be mapped to a node, so clicking opens "Act on element" with a selector field.
import { createSignal, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import { Popover } from '~/components/Popover';
import { pointAnchor, type AnchorRect } from '~/components/floating';
import ccss from '~/components/components.module.css';
import { useBrowser } from './use-browser';
import css from './browser.module.css';

const ActOnElement: Component<{ anchor: AnchorRect; onClose: () => void }> = (props) => {
  const s = useBrowser();
  const [selector, setSelector] = createSignal('');
  const [text, setText] = createSignal('');
  const [mode, setMode] = createSignal<'click' | 'type'>('click');
  const [busy, setBusy] = createSignal(false);
  const ready = () => selector().trim().length > 0 && !busy();

  const submit = async () => {
    if (!ready()) return;
    setBusy(true);
    const ok = mode() === 'click' ? await s.clickSelector(selector().trim()) : await s.typeInto(selector().trim(), text());
    setBusy(false);
    if (ok) props.onClose();
  };

  return (
    <Popover anchor={props.anchor} onClose={props.onClose} label="Act on element">
      <form
        class={css.act}
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div class={css.actTitle}>Act on element</div>
        <input
          class={`${ccss.input} ${ccss.mono}`}
          type="text"
          aria-label="CSS selector"
          placeholder="CSS selector, e.g. button[type=submit]"
          autocomplete="off"
          spellcheck={false}
          value={selector()}
          onInput={(e) => setSelector(e.currentTarget.value)}
        />
        <Show when={mode() === 'type'}>
          <input
            ref={(n) => queueMicrotask(() => n.focus({ preventScroll: true }))}
            class={ccss.input}
            type="text"
            aria-label="Text to type"
            placeholder="Text to type"
            autocomplete="off"
            value={text()}
            onInput={(e) => setText(e.currentTarget.value)}
          />
        </Show>
        <div class={css.actRow}>
          <Show
            when={mode() === 'click'}
            fallback={
              <>
                <Button variant="outline" onClick={() => setMode('click')}>
                  Click instead
                </Button>
                <Button variant="primary" type="submit" kbd="⏎" disabled={!ready()}>
                  Type
                </Button>
              </>
            }
          >
            <Button variant="outline" onClick={() => setMode('type')}>
              Type…
            </Button>
            <Button variant="primary" type="submit" kbd="⏎" disabled={!ready()}>
              Click
            </Button>
          </Show>
        </div>
      </form>
    </Popover>
  );
};

export const Viewport: Component = () => {
  const s = useBrowser();
  const [act, setAct] = createSignal<AnchorRect | null>(null);

  const onStageClick = (e: MouseEvent) => {
    if (!s.available() || !s.frame() || e.button !== 0) return;
    setAct(pointAnchor(e.clientX, e.clientY));
  };

  return (
    <div class={css.view}>
      <div class={css.stage} data-frame={s.frame() ? 'true' : 'false'} onClick={onStageClick}>
        <Show when={s.available() && !s.frame()}>
          <div class={css.progress} role="progressbar" aria-label="Waiting for the first frame" />
        </Show>
        <Show when={s.frame()}>{(f) => <img class={css.frame} src={f()} alt={`Screenshot of ${s.url() || 'the page'}`} draggable={false} />}</Show>
        <Show when={s.availability() === 'no'}>
          <p class={css.empty}>
            <span>
              No embedded browser on this server — start aitm with <code>browser.engine: obscura</code>.
              <Show when={s.engineMissing()}>
                {' '}
                <button type="button" class={css.retry} disabled={s.probing()} onClick={() => void s.retry()}>
                  Retry
                </button>
              </Show>
            </span>
          </p>
        </Show>
      </div>
      <p class={css.note}>Clicks are relayed by CSS selector until the screencast lands (F14).</p>
      <Show when={act()}>{(a) => <ActOnElement anchor={a()} onClose={() => setAct(null)} />}</Show>
    </div>
  );
};
