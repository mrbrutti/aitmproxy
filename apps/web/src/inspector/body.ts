// Body model for one pane: detection → the viewer to show and the CodeMirror document to load,
// including the raw-first / pretty-later swap for large JSON (worker) and the per-flow caches.

import { createEffect, createMemo, createSignal, on, type Accessor } from 'solid-js';
import type { Body } from '~/model/flow';
import { base64ToBytes, utf8Encode } from '~/lib/bytes';
import { cachedValue, parseJsonAsync, prettyJsonAsync, prettyJsonSync, PRETTY_CAP, SYNC_LIMIT } from '~/lib/json-worker';
import type { CodeDoc } from '~/viewers/CodeViewer';
import { detectBody, kindLabel, type BodyKind, type Detection } from '~/viewers/detect';
import { formatForm, formatMultipart } from '~/viewers/pretty';
import { perfMark } from '~/viewers/perf';

export type Format = 'auto' | 'pretty' | 'raw' | 'hex' | 'tree' | 'image' | 'text';
export const FORMATS: { id: Format; label: string }[] = [
  { id: 'auto', label: 'Auto' },
  { id: 'pretty', label: 'Pretty' },
  { id: 'raw', label: 'Raw' },
  { id: 'hex', label: 'Hex' },
  { id: 'tree', label: 'Tree' },
  { id: 'image', label: 'Image' },
  { id: 'text', label: 'Text' },
];

export type BodyView =
  | { type: 'code'; doc: CodeDoc }
  | { type: 'image'; base64: string; mime: string; size: number }
  | { type: 'hex'; bytes: Uint8Array }
  | { type: 'tree'; value: unknown; loading: boolean; error: string | null }
  | { type: 'empty'; text: string };

export type PrettyState = 'idle' | 'formatting' | 'capped' | 'invalid';

const FORMAT_CAP = 2 * 1024 * 1024;

export interface BodyModelInput {
  flowId: Accessor<string | null>;
  side: 'req' | 'res';
  body: Accessor<Body | null>;
  /** 'body' honours the format picker; 'raw' is the exact text (or hex); 'tree' forces the tree. */
  tab: Accessor<'body' | 'raw' | 'tree' | 'other'>;
  format: Accessor<Format>;
}

export function createBodyModel(i: BodyModelInput) {
  const detection = createMemo<Detection>(() => detectBody(i.body()));
  const key = createMemo(() => `${i.flowId() ?? '-'}:${i.side}:${i.body()?.size ?? 0}`);
  const text = () => i.body()?.text ?? '';

  // ---- pretty JSON (sync for small bodies, worker above SYNC_LIMIT) -----------------------
  const [pretty, setPretty] = createSignal<{ key: string; text: string } | null>(null);
  const [prettyState, setPrettyState] = createSignal<PrettyState>('idle');

  const wantsPretty = createMemo(() => {
    const t = i.tab();
    if (t !== 'body') return false;
    const f = i.format();
    const k = detection().kind;
    return (f === 'auto' && k === 'json') || f === 'pretty';
  });

  createEffect(
    on([key, wantsPretty], ([k, want]) => {
      if (!want) return;
      if (pretty()?.key === k) return;
      const b = i.body();
      if (!b?.text) return;
      if (b.size > PRETTY_CAP) {
        setPrettyState('capped');
        return;
      }
      if (b.text.length <= SYNC_LIMIT) {
        const out = prettyJsonSync(k, b.text);
        if (out == null) setPrettyState('invalid');
        else {
          setPretty({ key: k, text: out });
          setPrettyState('idle');
        }
        return;
      }
      setPrettyState('formatting');
      const t0 = performance.now();
      prettyJsonAsync(k, b.text)
        .then((r) => {
          if (key() !== k) return;
          setPretty({ key: k, text: r.value });
          setPrettyState('idle');
          perfMark('inspector.prettyWorker', r.workerMs, { totalMs: +(performance.now() - t0).toFixed(1), fromCache: r.fromCache, chars: b.text!.length });
        })
        .catch(() => key() === k && setPrettyState('invalid'));
    }),
  );

  // ---- parsed value for the tree ---------------------------------------------------------------
  const [tree, setTree] = createSignal<{ key: string; value: unknown; error: string | null } | null>(null);
  const [treeLoading, setTreeLoading] = createSignal(false);
  const wantsTree = createMemo(() => i.tab() === 'tree' || (i.tab() === 'body' && i.format() === 'tree'));
  createEffect(
    on([key, wantsTree], ([k, want]) => {
      if (!want || tree()?.key === k) return;
      const b = i.body();
      if (!b?.text) {
        setTree({ key: k, value: undefined, error: 'No body' });
        return;
      }
      const cached = cachedValue(k);
      if (cached !== undefined) {
        setTree({ key: k, value: cached, error: null });
        return;
      }
      if (b.text.length <= SYNC_LIMIT) {
        try {
          setTree({ key: k, value: JSON.parse(b.text), error: null });
        } catch (e) {
          setTree({ key: k, value: undefined, error: (e as Error).message });
        }
        return;
      }
      setTreeLoading(true);
      parseJsonAsync(k, b.text)
        .then((r) => {
          if (key() !== k) return;
          setTree({ key: k, value: r.value, error: null });
          perfMark('inspector.treeParseWorker', r.workerMs, { totalMs: +r.totalMs.toFixed(1), fromCache: r.fromCache });
        })
        .catch((e: Error) => key() === k && setTree({ key: k, value: undefined, error: e.message }))
        .finally(() => key() === k && setTreeLoading(false));
    }),
  );

  const bytes = createMemo<Uint8Array>(() => {
    const b = i.body();
    if (!b) return new Uint8Array();
    if (b.base64) return base64ToBytes(b.base64);
    return utf8Encode(b.text ?? '');
  });

  const lang = (k: BodyKind) => (k === 'json' ? 'json' : 'text');

  /** The viewer the pane should show now. */
  const view = createMemo<BodyView | null>(() => {
    const b = i.body();
    const t = i.tab();
    if (t === 'other') return null;
    const d = detection();
    const k = key();
    const id = i.flowId() ?? '-';
    if (!b || d.kind === 'empty') return { type: 'empty', text: b && b.size > 0 ? `Body not captured (${b.size} bytes on the wire)` : 'No body' };

    if (t === 'tree' || (t === 'body' && i.format() === 'tree')) {
      const tr = tree();
      return { type: 'tree', value: tr?.key === k ? tr.value : undefined, loading: treeLoading() || tr?.key !== k, error: tr?.key === k ? tr.error : null };
    }

    const f: Format = t === 'raw' ? (b.text == null ? 'hex' : 'raw') : i.format();
    const eff: Format = f === 'auto' ? autoFormat(d.kind) : f;

    switch (eff) {
      case 'image':
        return b.base64 ? { type: 'image', base64: b.base64, mime: d.mime ?? 'image/*', size: b.size } : { type: 'empty', text: 'No image bytes in this capture' };
      case 'hex':
        return { type: 'hex', bytes: bytes() };
      case 'raw':
        return b.text == null ? { type: 'hex', bytes: bytes() } : { type: 'code', doc: { key: `${id}:${i.side}:raw`, text: b.text, lang: lang(d.kind) } };
      case 'text':
        return b.text == null ? { type: 'hex', bytes: bytes() } : { type: 'code', doc: { key: `${id}:${i.side}:text`, text: b.text, lang: 'text' } };
      case 'pretty':
      default: {
        if (b.text == null) return { type: 'hex', bytes: bytes() };
        if (d.kind === 'json' || eff === 'pretty') {
          const p = pretty();
          const txt = p?.key === k ? p.text : b.text; // raw first, pretty when the worker returns
          return { type: 'code', doc: { key: `${id}:${i.side}:pretty`, text: txt, lang: 'json' } };
        }
        if (d.kind === 'form' && b.text.length <= FORMAT_CAP) return { type: 'code', doc: { key: `${id}:${i.side}:form`, text: formatForm(b.text), lang: 'text' } };
        if (d.kind === 'multipart' && d.boundary && b.text.length <= FORMAT_CAP)
          return { type: 'code', doc: { key: `${id}:${i.side}:multipart`, text: formatMultipart(b.text, d.boundary), lang: 'text' } };
        return { type: 'code', doc: { key: `${id}:${i.side}:text`, text: b.text, lang: 'text' } };
      }
    }
  });

  const label = createMemo(() => {
    const f = i.format();
    if (f !== 'auto') return FORMATS.find((x) => x.id === f)!.label;
    return kindLabel(detection().kind);
  });

  return { detection, view, prettyState, label, text, bytes, key };
}

function autoFormat(kind: BodyKind): Format {
  switch (kind) {
    case 'image':
      return 'image';
    case 'binary':
      return 'hex';
    case 'json':
    case 'form':
    case 'multipart':
      return 'pretty';
    default:
      return 'text';
  }
}

export type BodyModel = ReturnType<typeof createBodyModel>;
