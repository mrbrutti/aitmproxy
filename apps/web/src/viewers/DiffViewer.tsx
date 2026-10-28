// Two-document diff on @codemirror/merge: side-by-side MergeView or a unified view. Presentational;
// the picker that chooses the other flow lives in the inspector.

import { createEffect, createSignal, on, onCleanup, Show, type Component } from 'solid-js';
import type { EditorView } from '@codemirror/view';
import type { MergeView } from '@codemirror/merge';
import { baseExtensions, loadCodeMirror, loadMerge, type CM, type Lang, type MergeMod } from './codemirror';
import s from './viewers.module.css';

export interface DiffDoc {
  label: string;
  text: string;
}

export const DiffViewer: Component<{ a: DiffDoc; b: DiffDoc; unified: boolean; lang: Lang; class?: string }> = (props) => {
  let host!: HTMLDivElement;
  let cm: CM | null = null;
  let merge: MergeMod | null = null;
  let mv: MergeView | null = null;
  let uv: EditorView | null = null;
  const [ready, setReady] = createSignal(false);
  const [failed, setFailed] = createSignal<string | null>(null);
  let disposed = false;

  const mergeTheme = () =>
    cm!.view.EditorView.theme({
      '.cm-mergeView': { height: '100%' },
      '.cm-mergeViewEditors': { height: '100%' },
      '.cm-mergeViewEditor': { minWidth: '0' },
      '.cm-mergeViewEditor + .cm-mergeViewEditor': { borderLeft: '1px solid var(--color-line-border)' },
      '.cm-merge-a .cm-changedLine, .cm-deletedChunk': { backgroundColor: 'var(--color-syntax-diff-remove-bg)' },
      '.cm-merge-a .cm-changedText, .cm-deletedChunk .cm-deletedText': {
        background: 'color-mix(in srgb, var(--color-syntax-diff-remove-fg) 22%, transparent)',
        color: 'var(--color-syntax-diff-remove-fg)',
      },
      '.cm-merge-b .cm-changedLine, .cm-insertedLine': { backgroundColor: 'var(--color-syntax-diff-add-bg)' },
      '.cm-merge-b .cm-changedText, .cm-insertedLine .cm-changedText': {
        background: 'color-mix(in srgb, var(--color-syntax-diff-add-fg) 22%, transparent)',
        color: 'var(--color-syntax-diff-add-fg)',
      },
      '.cm-changeGutter': { width: '3px', paddingLeft: '0' },
      '.cm-merge-a .cm-changedLineGutter': { background: 'var(--color-syntax-diff-remove-fg)' },
      '.cm-merge-b .cm-changedLineGutter, .cm-insertedLine .cm-changedLineGutter': { background: 'var(--color-syntax-diff-add-fg)' },
      '.cm-deletedLineGutter': { background: 'var(--color-syntax-diff-remove-fg)' },
      '.cm-collapsedLines': {
        background: 'var(--color-ground-raised)',
        color: 'var(--color-text-tertiary)',
        fontFamily: 'var(--font-ui)',
        fontSize: 'var(--font-size-sm)',
        padding: '2px 12px',
      },
      '.cm-deletedChunk .cm-chunkButtons': { display: 'none' },
    });

  function build() {
    if (!cm || !merge || disposed) return;
    mv?.destroy();
    uv?.destroy();
    mv = null;
    uv = null;
    host.replaceChildren();
    const common = { lang: props.lang, editable: false } as const;
    if (props.unified) {
      uv = new cm.view.EditorView({
        parent: host,
        state: cm.state.EditorState.create({
          doc: props.b.text,
          extensions: [
            ...baseExtensions(cm, common),
            merge.unifiedMergeView({ original: props.a.text, mergeControls: false, highlightChanges: true, gutter: true, collapseUnchanged: { margin: 3, minSize: 6 } }),
            mergeTheme(),
          ],
        }),
      });
    } else {
      mv = new merge.MergeView({
        parent: host,
        a: { doc: props.a.text, extensions: [...baseExtensions(cm, common), mergeTheme()] },
        b: { doc: props.b.text, extensions: [...baseExtensions(cm, common), mergeTheme()] },
        highlightChanges: true,
        gutter: true,
        collapseUnchanged: { margin: 3, minSize: 6 },
      });
    }
  }

  Promise.all([loadCodeMirror(), loadMerge()])
    .then(([c, m]) => {
      if (disposed) return;
      cm = c;
      merge = m;
      setReady(true);
      build();
    })
    .catch((e: Error) => setFailed(e.message));

  createEffect(on(() => [props.a.text, props.b.text, props.unified, props.lang] as const, () => ready() && build(), { defer: true }));

  onCleanup(() => {
    disposed = true;
    mv?.destroy();
    uv?.destroy();
  });

  return (
    <div class={`${s.diff} ${props.class ?? ''}`}>
      <Show when={!props.unified}>
        <div class={s.diffLabels}>
          <span class={s.diffLabel}>{props.a.label}</span>
          <span class={s.diffLabel}>{props.b.label}</span>
        </div>
      </Show>
      <div ref={host} class={s.diffHost} />
      <Show when={failed()}>{(m) => <div class={s.cmError}>Diff failed to load — {m()}</div>}</Show>
    </div>
  );
};
