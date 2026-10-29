// FlowId fields (§4.2: "FlowId fields become flow pickers"): a mono typeahead over the captured
// flows by URL; the chosen flow shows as a one-line row with a clear button. A raw id can still
// be typed and committed with Enter.
import { createEffect, createMemo, createSignal, For, onCleanup, Show, type Component } from 'solid-js';
import { Portal } from 'solid-js/web';
import { useApp } from '~/state/context';
import { flowUrl } from '~/model/flow';
import { fuzzyRank } from '~/lib/fuzzy';
import { Icon } from '~/components/Icon';
import { FlowLine } from './FlowLine';
import css from './schema-form.module.css';

export interface FlowPickerProps {
  id?: string | undefined;
  value: string;
  onChange: (id: string) => void;
  onBlur?: (() => void) | undefined;
  placeholder?: string | undefined;
  invalid?: boolean | undefined;
  autofocus?: boolean | undefined;
  describedBy?: string | undefined;
}

const MAX = 8;

export const FlowPicker: Component<FlowPickerProps> = (props) => {
  const app = useApp();
  const [query, setQuery] = createSignal('');
  const [open, setOpen] = createSignal(false);
  const [active, setActive] = createSignal(0);
  let input: HTMLInputElement | undefined;

  const chosen = createMemo(() => {
    app.version();
    return props.value ? (app.byId.get(props.value) ?? null) : null;
  });

  const candidates = createMemo(() => {
    app.version();
    const q = query().trim();
    const all = app.entries;
    const recent = all.slice(Math.max(0, all.length - 200)).reverse();
    return fuzzyRank(recent, q, (e) => [flowUrl(e.raw), e.raw.method]).slice(0, MAX);
  });

  // The list floats in a portal (fixed, under the input) so scrolling or clipping ancestors —
  // the palette panel, a dialog body — cannot cut it off.
  const [rect, setRect] = createSignal<{ left: number; top: number; width: number } | null>(null);
  const measure = () => {
    if (!input) return;
    const r = input.getBoundingClientRect();
    const below = window.innerHeight - r.bottom - 12;
    setRect({ left: r.left, top: below < 160 && r.top > 240 ? r.top - 4 - Math.min(232, r.top - 12) : r.bottom + 4, width: r.width });
  };
  createEffect(() => {
    if (!open()) return;
    measure();
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    onCleanup(() => {
      window.removeEventListener('resize', measure);
      window.removeEventListener('scroll', measure, true);
    });
  });
  const listStyle = () => {
    const r = rect();
    return r ? { position: 'fixed' as const, left: `${r.left}px`, top: `${r.top}px`, width: `${Math.max(r.width, 320)}px`, right: 'auto' } : {};
  };

  const pick = (id: string) => {
    props.onChange(id);
    setQuery('');
    setOpen(false);
  };

  const onKey = (e: KeyboardEvent) => {
    const list = candidates();
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setOpen(true);
        setActive((a) => Math.min(list.length - 1, a + 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setActive((a) => Math.max(0, a - 1));
        break;
      case 'Enter': {
        if (e.metaKey || e.ctrlKey) return; // let ⌘⏎ submit the form
        const hit = open() ? list[active()] : undefined;
        if (hit) {
          e.preventDefault();
          pick(hit.item.id);
        } else if (query().trim()) {
          e.preventDefault();
          pick(query().trim());
        }
        break;
      }
      case 'Escape':
        if (open()) {
          e.preventDefault();
          e.stopPropagation();
          setOpen(false);
        }
        break;
    }
  };

  return (
    <div class={css.picker}>
      <Show
        when={chosen()}
        fallback={
          <>
            <input
              ref={(n) => {
                input = n;
                if (props.autofocus) queueMicrotask(() => n.focus());
              }}
              id={props.id}
              class={`${css.input} ${css.mono}`}
              role="combobox"
              aria-expanded={open()}
              aria-autocomplete="list"
              aria-invalid={props.invalid ? 'true' : undefined}
              aria-describedby={props.describedBy}
              placeholder={props.placeholder ?? 'Search flows by URL, or paste an id'}
              value={query()}
              autocomplete="off"
              spellcheck={false}
              onInput={(e) => {
                setQuery(e.currentTarget.value);
                setActive(0);
                setOpen(true);
              }}
              onFocus={() => setOpen(true)}
              onBlur={() => {
                // Let a click on an item land first.
                setTimeout(() => {
                  setOpen(false);
                  props.onBlur?.();
                }, 120);
              }}
              onKeyDown={onKey}
            />
            <Show when={open()}>
              <Portal>
              <div class={css.pickerList} role="listbox" data-floating style={listStyle()}>
                <For each={candidates()} fallback={<div class={css.pickerEmpty}>No flows match</div>}>
                  {(c, i) => (
                    <button
                      type="button"
                      role="option"
                      aria-selected={active() === i()}
                      class={css.pickerItem}
                      data-active={active() === i() ? 'true' : undefined}
                      onPointerEnter={() => setActive(i())}
                      onPointerDown={(e) => e.preventDefault()}
                      onClick={() => pick(c.item.id)}
                    >
                      <FlowLine flow={c.item.raw} hits={c.matches[0]} />
                    </button>
                  )}
                </For>
              </div>
              </Portal>
            </Show>
          </>
        }
      >
        {(entry) => (
          <div class={css.pickerChosen}>
            <FlowLine flow={entry().flow} />
            <button
              type="button"
              class={css.pickerClear}
              title="Choose another flow"
              aria-label="Clear flow"
              onClick={() => {
                props.onChange('');
                queueMicrotask(() => input?.focus());
              }}
            >
              <Icon name="x" size={12} />
            </button>
          </div>
        )}
      </Show>
    </div>
  );
};
