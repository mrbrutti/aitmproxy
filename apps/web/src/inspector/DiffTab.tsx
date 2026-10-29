// Response › Diff: left = the selected flow, right = app.ui.diff[1] (default: the previous
// response to this endpoint). Picker over the flow list, Body / Headers mode, side-by-side or
// unified, "Export patch" copies a unified diff.

import { createEffect, createMemo, createSignal, For, on, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { FlowEntry } from '~/state/app';
import type { FlowDetail } from '~/model/flow';
import { fmtClock } from '~/lib/format';
import { prettyJsonSync, SYNC_LIMIT } from '~/lib/json-worker';
import { detectBody } from '~/viewers/detect';
import { DiffViewer } from '~/viewers/DiffViewer';
import { unifiedDiff } from '~/viewers/udiff';
import { Centered, Control, copyText } from './ui';
import css from './inspector.module.css';

const DIFF_CAP = 2 * 1024 * 1024;

type Mode = 'body' | 'headers';

function textOf(d: FlowDetail, mode: Mode): { text: string; lang: 'json' | 'text' } {
  if (mode === 'headers') return { text: (d.response?.headers ?? []).map((h) => `${h.name.toLowerCase()}: ${h.value}`).join('\n'), lang: 'text' };
  const b = d.response?.body;
  if (!b || b.text == null) return { text: '', lang: 'text' };
  const det = detectBody(b);
  if (det.kind === 'json' && b.text.length <= SYNC_LIMIT) return { text: prettyJsonSync(`${d.id}:res:${b.size}`, b.text) ?? b.text, lang: 'json' };
  return { text: b.text, lang: det.kind === 'json' ? 'json' : 'text' };
}

export const DiffTab: Component<{ flow: FlowDetail; previous: FlowEntry | null }> = (props) => {
  const app = useApp();
  const [mode, setMode] = createSignal<Mode>('body');
  const [unified, setUnified] = createSignal(false);
  const [q, setQ] = createSignal('');
  const [open, setOpen] = createSignal(false);
  let input!: HTMLInputElement;

  const rightId = createMemo(() => app.ui.diff[1] ?? props.previous?.id ?? null);
  // A new selection starts from the default ("previous response to this endpoint") again.
  createEffect(on(() => props.flow.id, (id) => app.ui.diff[0] !== id && app.setDiff(id, null)));
  createEffect(on(rightId, (id) => id && void app.loadDetail(id)));

  const right = createMemo<FlowDetail | null>(() => {
    const id = rightId();
    return id ? (app.details[id] ?? null) : null;
  });

  const candidates = createMemo<FlowEntry[]>(() => {
    app.version();
    const needle = q().trim().toLowerCase();
    const sel = props.flow;
    const out: FlowEntry[] = [];
    for (let i = app.entries.length - 1; i >= 0 && out.length < 8; i--) {
      const e = app.entries[i]!;
      if (e.id === sel.id || e.raw.status == null) continue;
      const hay = `${e.raw.authority}${e.raw.path}`.toLowerCase();
      if (needle ? hay.includes(needle) || e.raw.method.toLowerCase() === needle : e.raw.authority === sel.authority && e.raw.path === sel.path) out.push(e);
    }
    if (!needle && !out.length) for (let i = app.entries.length - 1; i >= 0 && out.length < 8; i--) {
      const e = app.entries[i]!;
      if (e.id !== sel.id && e.raw.status != null) out.push(e);
    }
    return out;
  });

  const a = createMemo(() => textOf(props.flow, mode()));
  const b = createMemo(() => (right() ? textOf(right()!, mode()) : null));
  const labelOf = (d: FlowDetail) => `#${d.seq} · ${d.method} ${d.path} · ${d.status ?? '—'} · ${fmtClock(d.startedAt)}`;
  const tooBig = () => a().text.length > DIFF_CAP || (b()?.text.length ?? 0) > DIFF_CAP;

  const exportPatch = async () => {
    const r = right();
    if (!r) return;
    const patch = unifiedDiff(b()!.text, a().text, `flow-${r.seq}`, `flow-${props.flow.seq}`);
    if (await copyText(patch || '(no differences)\n')) app.notice('Copied unified diff');
  };

  const segBtn = (m: Mode, label: string) => (
    <button type="button" class={css.seg} classList={{ [css.segOn!]: mode() === m }} aria-pressed={mode() === m} onClick={() => setMode(m)}>
      {label}
    </button>
  );

  return (
    <div class={css.diffTab}>
      <div class={css.diffBar}>
        <span class={css.diffWith}>against</span>
        <div class={css.diffPick}>
          <input
            ref={input}
            class={css.diffInput}
            placeholder={props.previous ? 'previous response to this endpoint' : 'host/path of another flow'}
            value={open() ? q() : right() ? labelOf(right()!) : q()}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 120)}
            onInput={(e) => setQ(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                e.stopPropagation();
                setOpen(false);
                input.blur();
              }
              if (e.key === 'Enter') {
                const c = candidates()[0];
                if (c) {
                  app.setDiff(props.flow.id, c.id);
                  setOpen(false);
                  input.blur();
                }
              }
            }}
            aria-label="Flow to compare with"
            aria-expanded={open()}
          />
          <Show when={open()}>
            <div class={css.diffList} role="listbox">
              <Show when={candidates().length} fallback={<div class={css.diffEmpty}>No flows match</div>}>
                <For each={candidates()}>
                  {(e) => (
                    <button
                      type="button"
                      role="option"
                      class={css.diffItem}
                      classList={{ [css.diffItemOn!]: e.id === rightId() }}
                      aria-selected={e.id === rightId()}
                      onMouseDown={(ev) => ev.preventDefault()}
                      onClick={() => {
                        app.setDiff(props.flow.id, e.id);
                        setOpen(false);
                        input.blur();
                      }}
                    >
                      <span class={css.diffSeq}>#{e.flow.seq}</span>
                      <span class={css.diffMethod}>{e.flow.method}</span>
                      <span class={css.diffPath}>
                        {e.flow.authority}
                        {e.flow.path}
                      </span>
                      <span class={css.diffStatus}>{e.flow.status}</span>
                      <span class={css.diffTime}>{fmtClock(e.flow.startedAt)}</span>
                    </button>
                  )}
                </For>
              </Show>
            </div>
          </Show>
        </div>
        <span class={css.segGroup} role="group" aria-label="Compare">
          {segBtn('body', 'Body')}
          {segBtn('headers', 'Headers')}
        </span>
        <Control onClick={() => setUnified(!unified())} aria-pressed={unified()}>
          {unified() ? 'Unified' : 'Side by side'}
        </Control>
        <Control onClick={() => void exportPatch()} disabled={!right()} title="Copy a unified diff">
          Export patch
        </Control>
      </div>
      <div class={css.diffBody}>
        <Show when={right()} fallback={<Centered>{rightId() ? 'Loading the other flow…' : 'Pick a flow to compare with'}</Centered>}>
          {(r) => (
            <Show when={!tooBig()} fallback={<Centered>Bodies over 2 MB are not diffed in the viewer — use Export patch on smaller bodies</Centered>}>
              <DiffViewer a={{ label: labelOf(r()), text: b()!.text }} b={{ label: labelOf(props.flow), text: a().text }} unified={unified()} lang={a().lang} />
            </Show>
          )}
        </Show>
      </div>
    </div>
  );
};
