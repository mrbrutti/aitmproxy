// WebSocket flows: the Response pane becomes Frames — a list (direction, opcode, length, time,
// preview) with a sent/received filter and the selected frame in the body viewer below.

import { createEffect, createMemo, createSignal, For, on, Show, type Component } from 'solid-js';
import type { WsMessage } from '~/model/flow';
import { fmtBytes, fmtTime } from '~/lib/format';
import { base64ToBytes } from '~/lib/bytes';
import { CodeViewer, type CodeDoc, type CodeViewerApi } from '~/viewers/CodeViewer';
import { HexViewer } from '~/viewers/HexViewer';
import { prettyJson } from '~/viewers/pretty';
import { Centered } from './ui';
import css from './inspector.module.css';

type Dir = 'all' | 'up' | 'down';

export const WsFrames: Component<{ messages: WsMessage[]; flowId: string; onApi?: (api: CodeViewerApi) => void }> = (props) => {
  const [dir, setDir] = createSignal<Dir>('all');
  const [sel, setSel] = createSignal<number>(0);
  let list!: HTMLDivElement;

  const rows = createMemo(() => props.messages.map((m, i) => ({ m, i })).filter((r) => dir() === 'all' || r.m.dir === dir()));
  createEffect(on(() => props.flowId, () => setSel(0), { defer: true }));

  const current = () => rows()[Math.min(sel(), Math.max(rows().length - 1, 0))];
  const doc = createMemo<CodeDoc | null>(() => {
    const c = current();
    if (!c || c.m.text == null) return null;
    const pretty = c.m.text.trimStart()[0] === '{' || c.m.text.trimStart()[0] === '[' ? prettyJson(c.m.text) : null;
    return { key: `${props.flowId}:ws:${c.i}`, text: pretty ?? c.m.text, lang: pretty ? 'json' : 'text' };
  });
  const bytes = createMemo(() => {
    const c = current();
    return c && c.m.text == null && c.m.base64 ? base64ToBytes(c.m.base64) : null;
  });
  const counts = createMemo(() => ({
    up: props.messages.filter((m) => m.dir === 'up').length,
    down: props.messages.filter((m) => m.dir === 'down').length,
  }));

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = rows().length;
      if (!n) return;
      setSel(Math.max(0, Math.min(n - 1, sel() + (e.key === 'ArrowDown' ? 1 : -1))));
      list.querySelector<HTMLElement>(`[data-row="${sel()}"]`)?.scrollIntoView({ block: 'nearest' });
    }
  };

  const filterBtn = (d: Dir, label: string, n?: number) => (
    <button type="button" class={css.wsFilter} classList={{ [css.wsFilterOn!]: dir() === d }} aria-pressed={dir() === d} onClick={() => (setDir(d), setSel(0))}>
      {label}
      <Show when={n != null}>
        <span class={css.tabCount}>{n}</span>
      </Show>
    </button>
  );

  return (
    <div class={css.ws}>
      <div class={css.wsHead}>
        <span class={css.wsHeadLabel}>{props.messages.length} frames</span>
        <span class={css.spacer} />
        {filterBtn('all', 'All')}
        {filterBtn('up', 'Sent', counts().up)}
        {filterBtn('down', 'Received', counts().down)}
      </div>
      <div ref={list} class={css.wsList} role="listbox" aria-label="Frames" tabIndex={0} onKeyDown={onKey}>
        <Show when={rows().length} fallback={<Centered>No frames {dir() === 'all' ? 'yet' : dir() === 'up' ? 'sent' : 'received'}</Centered>}>
          <For each={rows()}>
            {(r, i) => (
              <div
                class={css.wsRow}
                classList={{ [css.wsRowOn!]: i() === sel() }}
                role="option"
                aria-selected={i() === sel()}
                data-row={i()}
                onClick={() => setSel(i())}
              >
                <span class={css.wsDir} data-dir={r.m.dir} title={r.m.dir === 'up' ? 'sent by client' : 'received from server'}>
                  {r.m.dir === 'up' ? '↑' : '↓'}
                </span>
                <span class={css.wsOp}>
                  {r.m.opcode}
                  <Show when={r.m.injected}> · injected</Show>
                </span>
                <span class={css.wsLen}>{fmtBytes(r.m.size)}</span>
                <span class={css.wsTime}>{fmtTime(r.m.at)}</span>
                <span class={css.wsPreview}>{r.m.text ?? (r.m.base64 ? '(binary)' : '')}</span>
              </div>
            )}
          </For>
        </Show>
      </div>
      <div class={css.wsViewer}>
        <CodeViewer doc={doc()} active={!!doc()} label="Frame body" onReady={(api) => props.onApi?.(api)} />
        <Show when={!doc() && bytes()}>{(b) => <HexViewer bytes={b()} />}</Show>
        <Show when={!doc() && !bytes()}>
          <Centered>{rows().length ? 'Empty frame' : 'Select a frame'}</Centered>
        </Show>
      </div>
    </div>
  );
};
