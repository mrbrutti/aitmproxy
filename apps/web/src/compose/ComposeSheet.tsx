// The Compose / repeat sheet (foundation §2.7, §4.6). Rendered by the shell when
// app.ui.composeOpen; closes via app.openCompose(false). Centred modal: 720 wide, radius 10,
// floating shadow, 220ms ease-out (no motion when opened from the keyboard), focus trapped,
// focus returned on close. One primary button: `Send ⌘⏎`.
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show, type Component } from 'solid-js';
import { Portal } from 'solid-js/web';
import { createStore, reconcile } from 'solid-js/store';
import { useApp } from '~/state/context';
import { METHODS } from '~/model/flow';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { Menu, type MenuEntry } from '~/components/Menu';
import { Popover } from '~/components/Popover';
import { rectAnchor, type AnchorRect } from '~/components/floating';
import { FlowLine } from '~/lib/schema-form/FlowLine';
import { parseCurl, CurlParseError } from '~/lib/curl-parse';
import { openedByPointer } from '~/lib/pointer';
import { fmtClock } from '~/lib/format';
import { KvRows } from './KvRows';
import { consumePrefill, pendingPrefill } from './prefill';
import {
  applyQuery,
  autoContentType,
  BODY_MODES,
  buildBody,
  curlToDraft,
  detailToDraft,
  effectiveHeaders,
  emptyDraft,
  formatHeaderLines,
  hasBody,
  jsonProblem,
  newBoundary,
  parseHeaderLines,
  parseQuery,
  pushHistory,
  readHistory,
  scopeCheck,
  templateDraft,
  TEMPLATES,
  type Draft,
  type HistoryEntry,
  type KV,
  type MultipartRow,
} from './model';
import css from './compose.module.css';
import formCss from '~/lib/schema-form/schema-form.module.css';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="file"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

async function readFile(file: File) {
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return { name: file.name, type: file.type, size: file.size, base64: btoa(bin) };
}

export const ComposeSheet: Component = () => {
  const app = useApp();
  const animate = openedByPointer();
  const boundary = newBoundary();
  const [draft, setDraft] = createStore<Draft>(emptyDraft());
  const [queryRows, setQueryRows] = createSignal<KV[]>([]);
  const [bulk, setBulk] = createSignal(false);
  const [bulkText, setBulkText] = createSignal('');
  const [sending, setSending] = createSignal(false);
  const [source, setSource] = createSignal<string | null>(null);
  const [menu, setMenu] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);
  const [importPop, setImportPop] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);
  const [historyPop, setHistoryPop] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);

  let sheet: HTMLDivElement | undefined;
  let urlInput: HTMLInputElement | undefined;
  let templatesBtn: HTMLButtonElement | undefined;
  const previous = document.activeElement as HTMLElement | null;

  const close = () => app.openCompose(false);

  const apply = (d: Draft) => {
    setDraft(reconcile(d));
    setQueryRows(parseQuery(d.url));
    setBulkText(formatHeaderLines(d.headers));
  };

  // ---- prefill (Edit & repeat) ----
  const prefillFrom = async (id: string) => {
    setSource(id);
    const detail = app.details[id] ?? (await app.loadDetail(id));
    if (detail) apply(detailToDraft(detail));
    else {
      const e = app.byId.get(id);
      if (e) apply({ ...emptyDraft(), method: e.raw.method, url: `${e.raw.scheme}://${e.raw.authority}${e.raw.path}${e.raw.query ? `?${e.raw.query}` : ''}` });
    }
  };
  createEffect(
    on(pendingPrefill, (id) => {
      if (id) void prefillFrom(consumePrefill()!);
    }),
  );

  onMount(() => {
    const id = consumePrefill();
    if (id) void prefillFrom(id);
    queueMicrotask(() => urlInput?.focus());
  });
  onCleanup(() => {
    if (previous && document.contains(previous)) previous.focus({ preventScroll: true });
  });

  // ---- derived ----
  const scope = createMemo(() => scopeCheck(draft.url, app.proxy.scope));
  const problem = createMemo(() => (draft.bodyMode === 'json' ? jsonProblem(draft.raw) : null));
  const canSend = createMemo(() => !sending() && scope().host != null && scope().inScope && !problem());
  const auto = createMemo(() => autoContentType(draft, boundary));
  const headerCount = createMemo(() => draft.headers.filter((h) => h.name.trim()).length + (auto() ? 1 : 0));
  const sourceEntry = createMemo(() => {
    app.version();
    const id = source();
    return id ? (app.byId.get(id) ?? null) : null;
  });

  // ---- actions ----
  const send = async () => {
    if (!canSend()) return;
    setSending(true);
    const req = { method: draft.method, url: draft.url.trim(), headers: effectiveHeaders(draft, boundary), body: buildBody(draft, boundary) };
    const id = await app.compose(req);
    setSending(false);
    if (!id) return;
    pushHistory(JSON.parse(JSON.stringify(draft)) as Draft);
    app.select(id);
    app.notice('Sent');
  };
  const sendUnchanged = async () => {
    const id = source();
    if (!id) return;
    setSending(true);
    const newId = await app.replay(id);
    setSending(false);
    if (newId) {
      close();
      app.select(newId);
    }
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void send();
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
      return;
    }
    if (e.key === 'Tab' && sheet) {
      const nodes = [...sheet.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((n) => n.offsetParent !== null);
      if (!nodes.length) return;
      const first = nodes[0]!;
      const last = nodes[nodes.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const setUrl = (v: string) => {
    setDraft('url', v);
    setQueryRows(parseQuery(v));
  };
  const setQuery = (rows: KV[]) => {
    setQueryRows(rows);
    setDraft('url', applyQuery(draft.url, rows));
  };
  const setHeaders = (rows: KV[]) => {
    setDraft('headers', rows);
    setBulkText(formatHeaderLines(rows));
  };
  const toggleBulk = () => {
    if (!bulk()) setBulkText(formatHeaderLines(draft.headers));
    else setDraft('headers', parseHeaderLines(bulkText()));
    setBulk(!bulk());
  };

  const templateItems = (): MenuEntry[] => [
    ...TEMPLATES.map((t) => ({ label: t.label, disabled: t.disabled, title: t.title, onSelect: () => apply(templateDraft(t.id, draft.url)) })),
    { type: 'separator' as const },
    {
      label: 'Import cURL…',
      onSelect: () => {
        if (templatesBtn) setImportPop({ anchor: rectAnchor(templatesBtn.getBoundingClientRect()), kb: menu()?.kb ?? false });
      },
    },
  ];

  return (
    <Portal>
      <div
        class={css.scrim}
        data-animate={animate ? 'true' : 'false'}
        onPointerDown={(e) => {
          if (e.target === e.currentTarget) close();
        }}
      >
        <div ref={sheet} class={css.sheet} role="dialog" aria-modal="true" aria-labelledby="compose-title" tabIndex={-1} onKeyDown={onKeyDown}>
          <header class={css.head}>
            <h2 id="compose-title" class={css.title}>
              Compose
            </h2>
            <Show when={sourceEntry()}>{(e) => <span class={css.from}>from <b>#{e().flow.seq}</b></span>}</Show>
            <span class={css.spacer} />
            <button
              ref={templatesBtn}
              type="button"
              class={css.headBtn}
              aria-haspopup="menu"
              aria-expanded={menu() != null}
              onClick={(e) => setMenu({ anchor: rectAnchor(e.currentTarget.getBoundingClientRect()), kb: e.detail === 0 })}
            >
              Templates
              <Icon name="chevron-down" size={12} />
            </button>
            <button
              type="button"
              class={`${css.headBtn} ${css.iconBtn}`}
              title="History"
              aria-label="Send history"
              aria-haspopup="dialog"
              aria-expanded={historyPop() != null}
              onClick={(e) => setHistoryPop({ anchor: rectAnchor(e.currentTarget.getBoundingClientRect()), kb: e.detail === 0 })}
            >
              <Icon name="rotate-ccw" />
            </button>
            <button type="button" class={`${css.headBtn} ${css.iconBtn}`} title="Close  Esc" aria-label="Close" onClick={close}>
              <Icon name="x" />
            </button>
          </header>

          <div class={css.body}>
            <div class={css.line}>
              <span class={css.methodWrap}>
                <select class={css.method} aria-label="Method" value={draft.method} onChange={(e) => setDraft('method', e.currentTarget.value)}>
                  <For each={[...METHODS]}>{(m) => <option value={m}>{m}</option>}</For>
                  <Show when={!(METHODS as readonly string[]).includes(draft.method)}>
                    <option value={draft.method}>{draft.method}</option>
                  </Show>
                </select>
                <Icon name="chevron-down" size={12} />
              </span>
              <input
                ref={urlInput}
                class={css.url}
                type="url"
                aria-label="URL"
                placeholder="https://host/path?query"
                value={draft.url}
                autocomplete="off"
                spellcheck={false}
                onInput={(e) => setUrl(e.currentTarget.value)}
                onPaste={(e) => {
                  const text = e.clipboardData?.getData('text') ?? '';
                  if (/^\s*(\$\s*)?curl\b/.test(text)) {
                    try {
                      apply(curlToDraft(parseCurl(text)));
                      e.preventDefault();
                      app.notice('Imported from cURL');
                    } catch {
                      /* paste as plain text */
                    }
                  }
                }}
              />
            </div>

            <section class={css.section} aria-labelledby="compose-headers">
              <div class={css.sectionHead}>
                <h3 id="compose-headers" class={css.sectionTitle}>
                  Headers
                </h3>
                <span class={css.count}>{headerCount() || ''}</span>
                <span class={css.spacer} />
                <button type="button" class={css.linkBtn} aria-pressed={bulk()} onClick={toggleBulk}>
                  Bulk edit
                </button>
              </div>
              <Show
                when={!bulk()}
                fallback={
                  <textarea
                    class={css.bulk}
                    aria-label="Headers, one per line as name: value"
                    placeholder={'Accept: application/json\nAuthorization: Bearer …'}
                    value={bulkText()}
                    spellcheck={false}
                    onInput={(e) => {
                      setBulkText(e.currentTarget.value);
                      setDraft('headers', parseHeaderLines(e.currentTarget.value));
                    }}
                  />
                }
              >
                <KvRows
                  label="Header"
                  rows={draft.headers}
                  onChange={setHeaders}
                  blank={() => ({ name: '', value: '' })}
                  namePlaceholder="name"
                  valuePlaceholder="value"
                  leading={
                    <Show when={auto()}>
                      {(ct) => (
                        <div class={css.kv} data-ghost="true">
                          <input class={css.k} value="Content-Type" readOnly tabIndex={-1} aria-label="Content-Type (automatic)" />
                          <input
                            class={css.v}
                            value={ct()}
                            aria-label="Content-Type value (automatic; edit to override)"
                            onInput={(e) => setHeaders([...draft.headers, { name: 'Content-Type', value: e.currentTarget.value }])}
                          />
                          <span class={css.tag}>auto</span>
                        </div>
                      )}
                    </Show>
                  }
                />
              </Show>
            </section>

            <section class={css.section} aria-labelledby="compose-query">
              <div class={css.sectionHead}>
                <h3 id="compose-query" class={css.sectionTitle}>
                  Query
                </h3>
                <span class={css.count}>{queryRows().filter((r) => r.name).length || ''}</span>
              </div>
              <KvRows label="Query parameter" rows={queryRows()} onChange={setQuery} blank={() => ({ name: '', value: '' })} namePlaceholder="name" valuePlaceholder="value" />
            </section>

            <section class={css.section} aria-labelledby="compose-body">
              <div class={css.sectionHead}>
                <h3 id="compose-body" class={css.sectionTitle}>
                  Body
                </h3>
                <span class={css.spacer} />
                <div class={formCss.seg} role="radiogroup" aria-label="Body format">
                  <For each={BODY_MODES}>
                    {(m) => (
                      <button type="button" role="radio" aria-checked={draft.bodyMode === m.id} onClick={() => setDraft('bodyMode', m.id)}>
                        {m.label}
                      </button>
                    )}
                  </For>
                </div>
              </div>
              <Show when={draft.bodyMode === 'raw' || draft.bodyMode === 'json'}>
                <textarea
                  class={css.bodyText}
                  aria-label="Request body"
                  aria-invalid={problem() ? 'true' : undefined}
                  placeholder={draft.bodyMode === 'json' ? '{ }' : 'Request body'}
                  value={draft.raw}
                  spellcheck={false}
                  onInput={(e) => setDraft('raw', e.currentTarget.value)}
                />
                <Show when={problem()}>
                  <span class={css.problem} role="alert">
                    {problem()}
                  </span>
                </Show>
                <Show when={draft.bodyMode === 'json' && !problem() && draft.raw.trim()}>
                  <div class={css.sectionHead} style={{ height: 'auto' }}>
                    <span class={css.spacer} />
                    <button type="button" class={css.linkBtn} onClick={() => setDraft('raw', JSON.stringify(JSON.parse(draft.raw), null, 2))}>
                      Format
                    </button>
                  </div>
                </Show>
              </Show>
              <Show when={draft.bodyMode === 'form'}>
                <KvRows label="Form field" rows={draft.form} onChange={(rows) => setDraft('form', rows)} blank={() => ({ name: '', value: '' })} namePlaceholder="field" valuePlaceholder="value" />
              </Show>
              <Show when={draft.bodyMode === 'multipart'}>
                <KvRows<MultipartRow>
                  label="Part"
                  rows={draft.multipart}
                  onChange={(rows) => setDraft('multipart', rows)}
                  blank={() => ({ name: '', value: '', file: null })}
                  namePlaceholder="part"
                  valuePlaceholder="value"
                  valueCell={(row, i, set, last) => (
                    <span class={css.fileCell}>
                      <Show
                        when={row.file}
                        fallback={
                          <input
                            value={row.value}
                            placeholder={last ? 'value' : ''}
                            aria-label={`Part value ${i + 1}`}
                            autocomplete="off"
                            spellcheck={false}
                            onInput={(e) => set({ value: e.currentTarget.value })}
                          />
                        }
                      >
                        {(f) => (
                          <span title={f().name}>
                            {f().name} · {f().size} B
                          </span>
                        )}
                      </Show>
                      <input
                        type="file"
                        id={`compose-part-file-${i}`}
                        tabIndex={-1}
                        onChange={async (e) => {
                          const file = e.currentTarget.files?.[0];
                          if (file) set({ file: await readFile(file), value: '' });
                        }}
                      />
                      <button type="button" class={css.fileBtn} onClick={() => (row.file ? set({ file: null }) : document.getElementById(`compose-part-file-${i}`)?.click())}>
                        {row.file ? 'text' : 'file'}
                      </button>
                    </span>
                  )}
                />
                <span class={css.hint}>Sent as raw multipart text with a generated boundary; file parts travel base64-encoded.</span>
              </Show>
            </section>
          </div>

          <footer class={css.foot}>
            <span class={css.scope} data-state={scope().host == null ? 'none' : scope().inScope ? 'in' : 'out'} aria-live="polite">
              <Show when={scope().host} fallback={<>Enter a URL with a scheme and host to send</>}>
                {(host) => (
                  <Show
                    when={scope().inScope}
                    fallback={
                      <>
                        <span class={css.dot} aria-hidden="true" />
                        Out of scope — add <code>{host()}</code> to scope to send
                        <button type="button" onClick={() => void app.addScope(host())}>
                          Add to scope
                        </button>
                      </>
                    }
                  >
                    <span class={css.dot} aria-hidden="true" />
                    <code>{host()}</code> · in scope
                  </Show>
                )}
              </Show>
            </span>
            <Show when={source()}>
              <Button variant="outline" disabled={sending()} title="Replay the captured request as it was" onClick={() => void sendUnchanged()}>
                Send unchanged
              </Button>
            </Show>
            <Button variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button variant="primary" kbd="⌘⏎" disabled={!canSend()} title={!scope().inScope && scope().host ? `Out of scope — add ${scope().host} to scope to send` : undefined} onClick={() => void send()}>
              {sending() ? 'Sending…' : 'Send'}
            </Button>
          </footer>
        </div>
      </div>

      <Show when={menu()}>
        {(m) => <Menu anchor={m().anchor} placement="bottom-end" animate={!m().kb} label="Templates" items={templateItems()} onClose={() => setMenu(null)} />}
      </Show>
      <Show when={importPop()}>
        {(p) => <ImportCurl anchor={p().anchor} animate={!p().kb} onClose={() => setImportPop(null)} onImport={(d) => apply(d)} />}
      </Show>
      <Show when={historyPop()}>
        {(p) => <History anchor={p().anchor} animate={!p().kb} onClose={() => setHistoryPop(null)} onPick={(d) => apply(d)} />}
      </Show>
    </Portal>
  );
};

/** Import cURL popover: paste auto-parses; typed text previews and imports on ⌘⏎ / Import. */
const ImportCurl: Component<{ anchor: AnchorRect; animate: boolean; onClose: () => void; onImport: (d: Draft) => void }> = (props) => {
  const [text, setText] = createSignal('');
  const parsed = createMemo(() => {
    const t = text().trim();
    if (!t) return null;
    try {
      return { ok: true as const, draft: curlToDraft(parseCurl(t)), ignored: parseCurl(t).ignored };
    } catch (e) {
      return { ok: false as const, error: e instanceof CurlParseError ? e.message : 'Could not parse' };
    }
  });
  const doImport = () => {
    const p = parsed();
    if (p?.ok) {
      props.onImport(p.draft);
      props.onClose();
    }
  };
  return (
    <Popover anchor={props.anchor} placement="bottom-end" animate={props.animate} label="Import cURL" onClose={props.onClose}>
      <div class={css.pop}>
        <span class={css.popTitle}>Import cURL</span>
        <textarea
          class={css.bodyText}
          style={{ 'min-height': '112px' }}
          aria-label="cURL command"
          placeholder={"curl -X POST 'https://…' -H 'Content-Type: application/json' --data-raw '{…}'"}
          value={text()}
          spellcheck={false}
          onInput={(e) => setText(e.currentTarget.value)}
          onPaste={(e) => {
            const t = e.clipboardData?.getData('text') ?? '';
            if (!t) return;
            try {
              const d = curlToDraft(parseCurl(t));
              e.preventDefault();
              props.onImport(d);
              props.onClose();
            } catch {
              /* let the paste land; the preview explains */
            }
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              e.stopPropagation();
              doImport();
            }
          }}
        />
        <div class={css.popFoot}>
          <span class={css.preview}>
            <Show when={parsed()}>
              {(p) => {
                const v = p();
                return v.ok ? (
                  <>
                    <code>{v.draft.method}</code> <code>{v.draft.url}</code> · {v.draft.headers.length} headers
                    {v.ignored.length ? ` · ignored ${v.ignored.join(' ')}` : ''}
                  </>
                ) : (
                  <span class={css.problem}>{v.error}</span>
                );
              }}
            </Show>
          </span>
          <span class={css.spacer} />
          <Button variant="primary" kbd="⌘⏎" disabled={!parsed()?.ok} onClick={doImport}>
            Import
          </Button>
        </div>
      </div>
    </Popover>
  );
};

/** The last 20 sends; pick one to prefill. */
const History: Component<{ anchor: AnchorRect; animate: boolean; onClose: () => void; onPick: (d: Draft) => void }> = (props) => {
  const entries = readHistory();
  const [active, setActive] = createSignal(0);
  const pick = (e: HistoryEntry) => {
    props.onPick(e.draft);
    props.onClose();
  };
  const row = (e: HistoryEntry) => {
    const u = (() => {
      try {
        return new URL(e.draft.url);
      } catch {
        return null;
      }
    })();
    return {
      id: '',
      seq: 0,
      kind: 'http' as const,
      method: e.draft.method,
      scheme: (u?.protocol === 'http:' ? 'http' : 'https') as 'http' | 'https',
      authority: u?.host ?? e.draft.url,
      path: u?.pathname ?? '',
      query: u?.search ? u.search.slice(1) : null,
      status: null,
      statusText: null,
      startedAt: e.at,
      durationMs: null,
      reqSize: null,
      resSize: null,
      client: { id: 'aitm-web', name: 'aitm-web' },
      tls: 'mitm' as const,
      httpVersion: null,
      intercept: 'none' as const,
      edited: false,
      isReplay: false,
      origin: 'human' as const,
      inScope: true,
      contentType: null,
      mark: null,
      comment: null,
    };
  };
  return (
    <Popover anchor={props.anchor} placement="bottom-end" animate={props.animate} label="Send history" onClose={props.onClose}>
      <div
        class={css.history}
        role="listbox"
        aria-label="Send history"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActive((a) => Math.min(entries.length - 1, a + 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === 'Enter') {
            e.preventDefault();
            const en = entries[active()];
            if (en) pick(en);
          }
        }}
      >
        <For each={entries} fallback={<div class={css.historyEmpty}>Nothing sent yet — the last 20 sends appear here.</div>}>
          {(e, i) => (
            <button type="button" role="option" aria-selected={active() === i()} class={css.historyItem} data-active={active() === i() ? 'true' : undefined} tabIndex={-1} onPointerEnter={() => setActive(i())} onClick={() => pick(e)} title={fmtClock(e.at)}>
              <FlowLine flow={row(e)} />
            </button>
          )}
        </For>
      </div>
    </Popover>
  );
};
