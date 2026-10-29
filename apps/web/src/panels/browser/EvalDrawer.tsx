// Eval drawer: a one-line expression input over a mono result log. ↑/↓ walk previous
// expressions, Enter evaluates, Esc closes. Results and errors stay in the log; errors also
// surface as a notice like every other bus error.
import { createEffect, createSignal, For, on, onMount, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { BrowserIcon } from './icons';
import { useBrowser } from './use-browser';
import css from './browser.module.css';

export const EvalDrawer: Component = () => {
  const s = useBrowser();
  const [expr, setExpr] = createSignal('');
  const [cursor, setCursor] = createSignal<number | null>(null);
  let input: HTMLInputElement | undefined;
  let log: HTMLOListElement | undefined;

  const scripts = () => s.evalLog().map((e) => e.script);

  onMount(() => input?.focus({ preventScroll: true }));
  createEffect(
    on(
      () => s.evalLog(),
      () => {
        if (log) log.scrollTop = log.scrollHeight;
      },
    ),
  );

  const walk = (delta: number) => {
    const h = scripts();
    if (!h.length) return;
    const cur = cursor();
    const next = cur == null ? (delta < 0 ? h.length - 1 : null) : cur + delta;
    if (next == null || next >= h.length) {
      setCursor(null);
      setExpr('');
      return;
    }
    const i = Math.max(0, next);
    setCursor(i);
    setExpr(h[i]!);
  };

  const run = () => {
    const v = expr();
    if (!v.trim()) return;
    void s.evaluate(v);
    setExpr('');
    setCursor(null);
  };

  return (
    <section class={css.drawer} aria-label="Eval">
      <div class={css.drawerHead}>
        <BrowserIcon name="terminal" size={12} />
        <span>Eval</span>
        <span class={css.drawerHint}>JavaScript in the page · ↑↓ history · Esc closes</span>
        <Button variant="toolbar" class={css.drawerClose!} aria-label="Close eval" title="Close" onClick={() => s.setEvalOpen(false)}>
          <Icon name="x" size={12} />
        </Button>
      </div>
      <ol ref={log} class={css.evalLog} aria-live="polite">
        <Show when={s.evalLog().length === 0}>
          <li class={css.evalEmpty}>No results yet — type an expression and press Enter.</li>
        </Show>
        <For each={s.evalLog()}>
          {(e) => (
            <li class={css.evalEntry}>
              <div class={css.evalIn}>
                <span class={css.prompt} aria-hidden="true">
                  ›
                </span>
                {e.script}
              </div>
              <div class={css.evalOut} data-error={e.error ? 'true' : undefined} data-pending={e.error == null && e.result == null ? 'true' : undefined}>
                {e.error ?? e.result ?? '…'}
              </div>
            </li>
          )}
        </For>
      </ol>
      <form
        class={css.evalForm}
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <span class={css.prompt} aria-hidden="true">
          ›
        </span>
        <input
          ref={input}
          class={css.evalInput}
          type="text"
          aria-label="Expression"
          placeholder="document.title"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
          value={expr()}
          onInput={(e) => {
            setExpr(e.currentTarget.value);
            setCursor(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowUp') {
              e.preventDefault();
              walk(-1);
            } else if (e.key === 'ArrowDown') {
              e.preventDefault();
              walk(1);
            } else if (e.key === 'Escape') {
              e.preventDefault();
              s.setEvalOpen(false);
            }
          }}
        />
      </form>
    </section>
  );
};
