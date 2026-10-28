// CodeMirror host. One EditorView lives for the component's lifetime; documents are swapped with
// `view.setState` (cached per doc key, so folds/scroll survive a tab round-trip) or, when only the
// text of the current key changes (raw → pretty from the worker), with a single doc transaction.
// The tab switch therefore costs one setState, not an editor rebuild.

import { createEffect, createSignal, on, onCleanup, onMount, Show, type Component } from 'solid-js';
import type { Compartment, EditorState } from '@codemirror/state';
import type { EditorView } from '@codemirror/view';
import { loadCodeMirror, makeState, type CM, type Lang } from './codemirror';
import { perfMark } from './perf';
import s from './viewers.module.css';

export interface CodeDoc {
  /** Identity for the state cache: flow id + tab + variant. */
  key: string;
  text: string;
  lang: Lang;
  editable?: boolean;
  original?: string | undefined;
  onChange?: ((text: string) => void) | undefined;
}

export interface CodeViewerApi {
  find(): void;
  focus(): void;
  view(): EditorView | null;
  text(): string;
}

export interface CodeViewerProps {
  doc: CodeDoc | null;
  /** When false the host stays mounted but hidden; nothing is applied until it is active again. */
  active: boolean;
  class?: string;
  onReady?: (api: CodeViewerApi) => void;
  /** Called after each document swap with the measured cost. */
  onSwitch?: (timing: { key: string; switchMs: number; paintMs: number }) => void;
  label?: string;
}

export const CodeViewer: Component<CodeViewerProps> = (props) => {
  let host!: HTMLDivElement;
  let view: EditorView | null = null;
  let cm: CM | null = null;
  const states = new Map<string, EditorState>();
  let currentKey: string | null = null;
  let currentText: string | null = null;
  let currentOriginal: string | undefined;
  let lastEmitted: string | null = null;
  let editedCompartment: Compartment | null = null;
  const [failed, setFailed] = createSignal<string | null>(null);
  let disposed = false;

  const api: CodeViewerApi = {
    find() {
      if (view && cm) cm.search.openSearchPanel(view);
    },
    focus() {
      view?.focus();
    },
    view: () => view,
    text: () => view?.state.doc.toString() ?? '',
  };

  function apply(doc: CodeDoc) {
    if (!view || !cm) return;
    const t0 = performance.now();
    const syncOriginal = () => {
      // The reference text for the amber edges can arrive after the state exists (the draft
      // resets when the detail lands); swap it through the compartment, not a new state.
      if (doc.editable && editedCompartment && doc.original !== currentOriginal) {
        view!.dispatch({ effects: editedCompartment.reconfigure(doc.original != null ? cm!.editedLines(doc.original) : []) });
        currentOriginal = doc.original;
      }
    };
    if (currentKey === doc.key) {
      // Same document, new text (worker result, revert): one replace transaction.
      if (doc.text !== currentText && doc.text !== lastEmitted) {
        view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: doc.text } });
        currentText = doc.text;
        perfMark('inspector.docSwap', performance.now() - t0, { key: doc.key, chars: doc.text.length });
      }
      syncOriginal();
      return;
    }
    if (currentKey != null) states.set(currentKey, view.state);
    const cached = states.get(doc.key);
    const reuse = cached && cached.doc.length === doc.text.length && cached.doc.toString() === doc.text;
    editedCompartment ??= new cm.state.Compartment();
    const next =
      reuse && cached
        ? cached
        : makeState(cm, doc.text, {
            lang: doc.lang,
            editable: doc.editable ?? false,
            original: doc.original,
            editedCompartment,
            onChange: doc.editable
              ? (t) => {
                  lastEmitted = t;
                  currentText = t;
                  doc.onChange?.(t);
                }
              : undefined,
          });
    view.setState(next);
    currentKey = doc.key;
    currentText = doc.text;
    currentOriginal = reuse ? undefined : doc.original;
    lastEmitted = null;
    if (reuse) syncOriginal();
    const switchMs = performance.now() - t0;
    requestAnimationFrame(() => {
      const paintMs = performance.now() - t0;
      perfMark('inspector.tabSwitch', switchMs, { key: doc.key, paintMs: +paintMs.toFixed(1), chars: doc.text.length });
      props.onSwitch?.({ key: doc.key, switchMs, paintMs });
    });
  }

  onMount(() => {
    props.onReady?.(api);
    // Prefetch the chunk now so the first activation does not wait on the network.
    loadCodeMirror()
      .then((mod) => {
        if (disposed) return;
        cm = mod;
        view = new mod.view.EditorView({ parent: host, state: mod.state.EditorState.create({ doc: '' }) });
        if (props.active && props.doc) apply(props.doc);
      })
      .catch((e: Error) => setFailed(e.message));
  });

  createEffect(
    on(
      () => [props.active, props.doc] as const,
      ([active, doc]) => {
        if (active && doc) apply(doc);
      },
      { defer: true },
    ),
  );

  onCleanup(() => {
    disposed = true;
    view?.destroy();
    view = null;
    states.clear();
  });

  return (
    <div class={`${s.cmHost} ${props.class ?? ''}`} style={{ display: props.active ? undefined : 'none' }} aria-label={props.label}>
      <div ref={host} class={s.cmMount} />
      <Show when={failed()}>{(m) => <div class={s.cmError}>Viewer failed to load — {m()}</div>}</Show>
    </div>
  );
};
