// DOM pane (320px, right): the serialised page from `browser.get_dom`, tinted by the small
// tokenizer (tag names in syntax.key, quoted values in syntax.string, text primary), with a
// line filter and Refresh. Very large documents are cut so the pane stays responsive.
import { createMemo, For, Show, type Component } from 'solid-js';
import { createSignal } from 'solid-js';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { filterLines, tokenizeHtml, type DomTokenKind } from './dom-tokens';
import { BrowserIcon } from './icons';
import { useBrowser } from './use-browser';
import css from './browser.module.css';

const MAX_CHARS = 300_000;

const TOKEN_CLASS: Record<DomTokenKind, string | undefined> = {
  text: undefined,
  punct: css.tkPunct,
  tag: css.tkTag,
  attr: css.tkAttr,
  string: css.tkString,
  comment: css.tkComment,
};

export const DomPane: Component = () => {
  const s = useBrowser();
  const [q, setQ] = createSignal('');

  const source = createMemo(() => {
    const d = s.dom() ?? '';
    return d.length > MAX_CHARS ? { text: d.slice(0, MAX_CHARS), cut: true } : { text: d, cut: false };
  });
  const filtered = createMemo(() => filterLines(source().text, q()));
  const tokens = createMemo(() => tokenizeHtml(filtered().lines.join('\n')));

  return (
    <aside class={css.dom} aria-label="DOM">
      <div class={css.domHead}>
        <input
          class={css.domFilter}
          type="search"
          aria-label="Filter DOM lines"
          placeholder="Filter lines"
          autocomplete="off"
          spellcheck={false}
          value={q()}
          onInput={(e) => setQ(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape' && q()) {
              e.stopPropagation();
              setQ('');
            }
          }}
        />
        <Show when={q().trim()}>
          <span class={css.domCount}>
            {filtered().lines.length} / {filtered().total}
          </span>
        </Show>
        <Button variant="toolbar" title="Fetch the DOM again" disabled={s.domLoading()} onClick={() => void s.refreshDom()}>
          <BrowserIcon name="rotate-cw" size={12} />
          Refresh
        </Button>
        <Button variant="toolbar" aria-label="Close DOM pane" title="Close" onClick={() => s.toggleDom(false)}>
          <Icon name="x" size={12} />
        </Button>
      </div>
      <pre class={css.domBody} data-empty={s.dom() == null ? 'true' : undefined}>
        <Show when={s.dom() != null} fallback={s.domLoading() ? '' : 'No DOM yet — navigate somewhere, then Refresh.'}>
          <Show when={tokens().length} fallback={<span class={css.tkComment}>No lines match “{q().trim()}”.</span>}>
            <For each={tokens()}>{(t) => <span class={TOKEN_CLASS[t.kind]}>{t.text}</span>}</For>
          </Show>
          <Show when={source().cut}>
            <span class={css.tkComment}>{'\n'}… truncated at 300 KB</span>
          </Show>
        </Show>
      </pre>
    </aside>
  );
};
