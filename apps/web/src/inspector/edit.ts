// Draft state for editing a paused request (§2.7 intercept bar, §4.5). The structured draft
// (method, path, headers, body) is canonical; the Raw tab's text is kept in step and parsed back
// on every keystroke so a parse error shows inline before Apply.

import { createEffect, createMemo, createSignal, on, type Accessor } from 'solid-js';
import { createStore, reconcile, unwrap } from 'solid-js/store';
import type { FlowDetail, Header } from '~/model/flow';
import { parseRaw, serializeRaw, type RawRequest } from './rawdoc';

export interface Draft {
  method: string;
  path: string;
  version: string;
  headers: Header[];
  body: string;
}

export interface MutateEdits {
  method?: string;
  path?: string;
  headers?: { name: string; value: string }[];
  body?: string;
}

const EMPTY: Draft = { method: 'GET', path: '/', version: 'HTTP/1.1', headers: [], body: '' };

function fromDetail(d: FlowDetail): Draft {
  return {
    method: d.method,
    path: d.path + (d.query ? `?${d.query}` : ''),
    version: d.httpVersion ?? 'HTTP/1.1',
    headers: d.request.headers.map((h) => ({ name: h.name, value: h.value })),
    body: d.request.body.text ?? '',
  };
}

const toRaw = (d: Draft): RawRequest => ({ method: d.method, path: d.path, version: d.version, headers: d.headers, body: d.body });
const lines = (h: Header[]) => h.map((x) => `${x.name.toLowerCase()}: ${x.value}`);

export function createEditState(detail: Accessor<FlowDetail | null>) {
  const [draft, setDraft] = createStore<Draft>({ ...EMPTY, headers: [] });
  const [rawText, setRawText] = createSignal('');
  const [parseError, setParseError] = createSignal<string | null>(null);

  // The original is a memo (not an effect) so anything reading it in the same tick as a new
  // detail already sees the right reference text.
  const original = createMemo<Draft>(() => {
    const d = detail();
    return d ? fromDetail(d) : { ...EMPTY, headers: [] };
  });

  const reset = (o: Draft) => {
    setDraft(reconcile({ ...o, headers: o.headers.map((h) => ({ ...h })) }));
    setRawText(serializeRaw(toRaw(o)));
    setParseError(null);
  };
  createEffect(on(original, reset));

  const syncRaw = () => setRawText(serializeRaw(toRaw(unwrap(draft))));

  const originalRaw = createMemo(() => serializeRaw(toRaw(original())));

  /** Changed header rows by position: a modified, added or removed header each counts once. */
  const headerDelta = createMemo(() => {
    const a = lines(original().headers);
    const b = lines(draft.headers);
    let n = 0;
    for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) n++;
    return n;
  });

  const editCount = createMemo(() => {
    const o = original();
    let n = headerDelta();
    if (draft.method !== o.method) n++;
    if (draft.path !== o.path) n++;
    if (draft.body !== o.body) n++;
    return n;
  });
  const dirty = createMemo(() => editCount() > 0);

  /** The `flow.mutate` payload: only what changed. */
  const edits = (): MutateEdits => {
    const o = original();
    const out: MutateEdits = {};
    if (draft.method !== o.method) out.method = draft.method;
    if (draft.path !== o.path) out.path = draft.path;
    if (headerDelta() > 0) out.headers = draft.headers.filter((h) => h.name.trim()).map((h) => ({ name: h.name.trim(), value: h.value }));
    if (draft.body !== o.body) out.body = draft.body;
    return out;
  };

  return {
    draft,
    original,
    originalRaw,
    rawText,
    parseError,
    dirty,
    editCount,
    edits,
    setHeaders(h: Header[]) {
      setDraft('headers', h.map((x) => ({ ...x })));
      syncRaw();
    },
    setBody(text: string) {
      setDraft('body', text);
      syncRaw();
    },
    setMethod(m: string) {
      setDraft('method', m);
      syncRaw();
    },
    setPath(p: string) {
      setDraft('path', p);
      syncRaw();
    },
    /** Raw tab edits: keep the text as typed; adopt it into the draft when it parses. */
    setRaw(text: string) {
      setRawText(text);
      const r = parseRaw(text);
      if (r.ok) {
        setDraft({ method: r.value.method, path: r.value.path, version: r.value.version, body: r.value.body });
        setDraft('headers', r.value.headers);
        setParseError(null);
      } else setParseError(r.error);
    },
    revert() {
      reset(original());
    },
  };
}

export type EditState = ReturnType<typeof createEditState>;
