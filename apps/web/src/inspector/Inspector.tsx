// The Request | Response inspector (foundation §2.7 "Inspector", §3.3, §4.5). The shell mounts it
// in the lower region. Summary strip over two panes; the paused-edit path; quick look; the
// keyboard: ⌘F find, Esc back to the list, ←/→ on a tab bar, ⌘C copies the body when nothing is
// selected, ⌘⏎ Apply & Resume while editing.

import { createEffect, createMemo, createSignal, on, onCleanup, onMount, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { FlowEntry } from '~/state/app';
import { createEditState } from './edit';
import { RequestPane, type PaneApi } from './RequestPane';
import { ResponsePane } from './ResponsePane';
import { SummaryStrip } from './SummaryStrip';
import { copyText } from './ui';
import css from './inspector.module.css';

export const Inspector: Component = () => {
  const app = useApp();
  const selected = app.selected;
  const detail = app.selectedDetail;
  const flow = () => selected()?.flow ?? null;

  const loading = () => {
    const s = selected();
    return !!s && !app.details[s.id] && app.detailLoading() === s.id;
  };
  const error = () => {
    const s = selected();
    return s && !app.details[s.id] && !loading() ? app.detailError() : null;
  };

  // "Last good" time per flow for the error block.
  const lastGood = new Map<string, number>();
  const [lastGoodAt, setLastGoodAt] = createSignal<number | null>(null);
  createEffect(() => {
    const d = detail();
    if (d) lastGood.set(d.id, Date.now());
    setLastGoodAt(selected() ? (lastGood.get(selected()!.id) ?? null) : null);
  });

  const retry = () => {
    const s = selected();
    if (s) void app.loadDetail(s.id, true);
  };

  // Editing: the Request pane is editable while the selected flow is paused.
  const editing = createMemo(() => flow()?.intercept === 'paused');
  const edit = createEditState(detail);
  const [busy, setBusy] = createSignal(false);

  const apply = async (resume: boolean) => {
    const s = selected();
    if (!s || busy()) return;
    if (edit.parseError()) return;
    setBusy(true);
    try {
      const edits = edit.edits();
      if (Object.keys(edits).length) {
        const r = await app.mutate(s.id, edits);
        if (r === null) return; // the store already showed the error
      }
      if (resume) await app.resume(s.id);
      else app.notice('Edits applied — the request is still paused');
    } finally {
      setBusy(false);
    }
  };

  // Previous response to this endpoint: the Diff default and the paused-request reference.
  const previous = createMemo<FlowEntry | null>(() => {
    app.version();
    const f = flow();
    if (!f) return null;
    for (let i = app.entries.length - 1; i >= 0; i--) {
      const e = app.entries[i]!;
      if (e.id === f.id) continue;
      if (e.raw.startedAt > f.startedAt) continue;
      if (e.raw.method === f.method && e.raw.authority === f.authority && e.raw.path === f.path && e.raw.status != null && e.raw.kind === 'http') return e;
    }
    return null;
  });

  const [quickLook, setQuickLook] = createSignal(false);
  createEffect(on(() => selected()?.id, () => setQuickLook(false), { defer: true }));

  let root!: HTMLDivElement;
  let reqApi: PaneApi | null = null;
  let resApi: PaneApi | null = null;
  const [lastPane, setLastPane] = createSignal<'req' | 'res'>('res');
  const activeApi = () => (lastPane() === 'req' && !quickLook() ? reqApi : resApi);

  onMount(() => {
    const onEditPaused = () => {
      if (!editing()) return;
      app.setRequestTab('raw');
      setLastPane('req');
      requestAnimationFrame(() => reqApi?.focus());
    };
    const onFocus = () => activeApi()?.focus();
    const onQuick = () => setQuickLook((v) => !v);
    window.addEventListener('aitm:edit-paused', onEditPaused);
    window.addEventListener('aitm:focus-inspector', onFocus);
    window.addEventListener('aitm:quick-look', onQuick);
    onCleanup(() => {
      window.removeEventListener('aitm:edit-paused', onEditPaused);
      window.removeEventListener('aitm:focus-inspector', onFocus);
      window.removeEventListener('aitm:quick-look', onQuick);
    });
  });

  const isTyping = (t: EventTarget | null) => {
    const el = t as HTMLElement | null;
    if (!el) return false;
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.defaultPrevented) return;
    const mod = e.metaKey || e.ctrlKey;
    if (e.key === 'Escape') {
      if (isTyping(e.target) && !(e.target as HTMLElement).classList.contains('cm-content')) return;
      e.preventDefault();
      if (quickLook()) setQuickLook(false);
      else window.dispatchEvent(new CustomEvent('aitm:focus-list'));
      return;
    }
    if (e.key === ' ' && quickLook() && !isTyping(e.target)) {
      e.preventDefault();
      setQuickLook(false);
      return;
    }
    if (mod && e.key === 'Enter' && editing()) {
      e.preventDefault();
      void apply(true);
      return;
    }
    if (mod && e.key.toLowerCase() === 'f' && !e.shiftKey) {
      // CodeMirror handles ⌘F itself when focused; elsewhere in the inspector, open the active viewer's find.
      if (!(e.target as HTMLElement).closest('.cm-editor') && activeApi()?.find()) e.preventDefault();
      return;
    }
    if (mod && e.key.toLowerCase() === 'c' && !isTyping(e.target)) {
      const sel = window.getSelection()?.toString();
      if (sel) return;
      const text = activeApi()?.bodyText();
      if (text != null) {
        e.preventDefault();
        void copyText(text).then((ok) => ok && app.notice('Copied body'));
      }
    }
  };

  return (
    <div
      ref={root}
      class={css.inspector}
      onKeyDown={onKeyDown}
      onFocusIn={(e) => {
        const pane = (e.target as HTMLElement).closest(`.${css.pane}`);
        if (pane) setLastPane(pane.getAttribute('aria-label')?.startsWith('Request') ? 'req' : 'res');
      }}
    >
      <SummaryStrip flow={flow()} detail={detail()} onCopied={() => app.notice('Copied URL')} />
      <div class={css.panes} classList={{ [css.panesQuick!]: quickLook() }}>
        <RequestPane
          flow={flow()}
          detail={detail()}
          loading={loading()}
          error={error()}
          lastGood={lastGoodAt()}
          onRetry={retry}
          editing={editing()}
          edit={edit}
          busy={busy()}
          onApply={() => void apply(false)}
          onApplyResume={() => void apply(true)}
          hidden={quickLook()}
          onApi={(a) => (reqApi = a)}
        />
        <ResponsePane
          flow={flow()}
          detail={detail()}
          loading={loading()}
          error={error()}
          lastGood={lastGoodAt()}
          onRetry={retry}
          previous={previous()}
          quickLook={quickLook()}
          onApi={(a) => (resApi = a)}
        />
        <Show when={!selected()}>
          <div class={css.empty}>Select a flow</div>
        </Show>
        <Show when={quickLook()}>
          <div class={css.quickHint}>Quick look · Esc or Space to return</div>
        </Show>
      </div>
    </div>
  );
};
