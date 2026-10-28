// Request pane: Headers · Cookies · Query · Body · Raw · Summary · Timing · Connection. One
// CodeMirror view for the pane's lifetime (Body, Raw and the paused-edit documents all swap into
// it). In edit mode Headers become editable rows, Raw an editable request document, Body editable.

import { createMemo, createSignal, Match, Show, Switch, type Component } from 'solid-js';
import type { FlowDetail, FlowSummary } from '~/model/flow';
import { useApp } from '~/state/context';
import { Button } from '~/components';
import { fmtClock } from '~/lib/format';
import { CodeViewer, type CodeDoc, type CodeViewerApi } from '~/viewers/CodeViewer';
import { HexViewer } from '~/viewers/HexViewer';
import { ImageViewer } from '~/viewers/ImageViewer';
import { JsonTree } from '~/viewers/JsonTree';
import { detectBody } from '~/viewers/detect';
import { parseQuery } from '~/viewers/pretty';
import { createBodyModel, type BodyView, type Format } from './body';
import { ConnectionTab } from './ConnectionTab';
import { CookieTable } from './CookieTable';
import { requestCookies } from './cookies';
import { EditBar } from './EditBar';
import type { EditState } from './edit';
import { HeaderTable } from './HeaderTable';
import { BodyControls, Pane } from './Pane';
import { QueryTable } from './QueryTable';
import { SummaryTab } from './SummaryTab';
import { TimingTab } from './TimingTab';
import { Bars, Centered, copyText } from './ui';
import css from './inspector.module.css';

export interface PaneApi {
  focus(): void;
  /** Opens find in the pane's code viewer; false when nothing searchable is showing. */
  find(): boolean;
  bodyText(): string | null;
}

export interface RequestPaneProps {
  flow: FlowSummary | null;
  detail: FlowDetail | null;
  loading: boolean;
  error: string | null;
  lastGood: number | null;
  onRetry: () => void;
  editing: boolean;
  edit: EditState;
  busy: boolean;
  onApply: () => void;
  onApplyResume: () => void;
  hidden: boolean;
  onApi?: (api: PaneApi) => void;
}

const TAB_IDS = ['headers', 'cookies', 'query', 'body', 'raw', 'summary', 'timing', 'connection'] as const;

export const RequestPane: Component<RequestPaneProps> = (props) => {
  const app = useApp();
  const [format, setFormat] = createSignal<Format>('auto');
  let codeApi: CodeViewerApi | null = null;
  let content: HTMLDivElement | undefined;

  const tab = () => (TAB_IDS.includes(app.ui.requestTab as (typeof TAB_IDS)[number]) ? app.ui.requestTab : 'headers');
  const headers = () => (props.editing ? props.edit.draft.headers : (props.detail?.request.headers ?? []));
  const body = () => props.detail?.request.body ?? null;
  const codeTab = () => tab() === 'body' || tab() === 'raw';

  const model = createBodyModel({
    flowId: () => props.flow?.id ?? null,
    side: 'req',
    body,
    tab: () => (tab() === 'body' ? 'body' : tab() === 'raw' ? 'raw' : 'other'),
    format,
  });

  // The document the single CodeMirror view shows now (edit documents take precedence).
  const editDoc = createMemo<CodeDoc | null>(() => {
    if (!props.editing || !props.flow) return null;
    const id = props.flow.id;
    if (tab() === 'raw')
      return { key: `${id}:req:raw:edit`, text: props.edit.rawText(), lang: 'text', editable: true, original: props.edit.originalRaw(), onChange: props.edit.setRaw };
    if (tab() === 'body') {
      const lang = detectBody(body()).kind === 'json' ? 'json' : 'text';
      return { key: `${id}:req:body:edit`, text: props.edit.draft.body, lang, editable: true, original: props.edit.original().body, onChange: props.edit.setBody };
    }
    return null;
  });
  const view = () => model.view();
  const codeDoc = createMemo<CodeDoc | null>(() => editDoc() ?? (view()?.type === 'code' ? (view() as { doc: CodeDoc }).doc : null));
  const ready = () => !!props.detail && !props.loading && !props.error;
  const codeActive = () => ready() && codeTab() && !!codeDoc();

  const tabs = createMemo(() => {
    const d = props.detail;
    const q = props.flow?.query ? parseQuery(props.flow.query).length : 0;
    return [
      { id: 'headers', label: 'Headers', count: headers().length },
      { id: 'cookies', label: 'Cookies', count: d ? requestCookies(d.request.headers).length : 0 },
      { id: 'query', label: 'Query', count: q },
      { id: 'body', label: 'Body' },
      { id: 'raw', label: 'Raw' },
      { id: 'summary', label: 'Summary' },
      { id: 'timing', label: 'Timing' },
      { id: 'connection', label: 'Connection' },
    ];
  });

  props.onApi?.({
    focus() {
      if (codeActive()) codeApi?.focus();
      else content?.focus();
    },
    find() {
      if (!codeActive() || !codeApi) return false;
      codeApi.find();
      return true;
    },
    bodyText() {
      if (props.editing) return tab() === 'raw' ? props.edit.rawText() : props.edit.draft.body;
      return body()?.text ?? null;
    },
  });

  const onCopy = (text: string, what: string) => void copyText(text).then((ok) => ok && app.notice(`Copied ${what}`));

  const right = () => (
    <>
      <Show when={props.editing}>
        <span class={css.quietNote}>editing</span>
      </Show>
      <Switch>
        <Match when={tab() === 'headers' && headers().length}>
          <span class={css.quietNote}>
            {headers().length} {headers().length === 1 ? 'header' : 'headers'}
          </span>
        </Match>
        <Match when={codeTab() && !props.editing && body() && body()!.size > 0}>
          <BodyControls
            format={format()}
            onFormat={setFormat}
            label={model.label()}
            prettyState={model.prettyState()}
            truncatedAt={body()?.truncated ? body()!.size : null}
            onFind={() => codeApi?.find()}
            pickerless={tab() === 'raw'}
          />
        </Match>
      </Switch>
    </>
  );

  return (
    <Pane
      title="Request"
      tabs={tabs()}
      active={tab()}
      onSelect={app.setRequestTab}
      right={right()}
      hidden={props.hidden}
      contentRef={(el) => (content = el)}
      onPlus={() => app.notice('Custom previewers arrive with the plugin tier (M3)')}
    >
      <div class={css.stack}>
        <div class={css.fill}>
          <Show when={props.flow}>
            <Switch>
              <Match when={props.loading}>
                <Bars rows={7} />
              </Match>
              <Match when={props.error}>
                <ErrorBlock message={props.error!} lastGood={props.lastGood} onRetry={props.onRetry} />
              </Match>
              <Match when={props.detail}>
                {(d) => (
                  <Switch>
                    <Match when={tab() === 'headers'}>
                      <div class={css.scroll}>
                        <HeaderTable
                          headers={headers()}
                          editable={props.editing}
                          original={props.editing ? props.edit.original().headers : undefined}
                          onChange={props.edit.setHeaders}
                          onCopied={(n) => app.notice(`Copied ${n}`)}
                        />
                      </div>
                    </Match>
                    <Match when={tab() === 'cookies'}>
                      <div class={css.scroll}>
                        <CookieTable headers={d().request.headers} mode="cookie" />
                      </div>
                    </Match>
                    <Match when={tab() === 'query'}>
                      <div class={css.scroll}>
                        <QueryTable query={props.flow?.query ?? null} />
                      </div>
                    </Match>
                    <Match when={tab() === 'summary'}>
                      <div class={css.scroll}>
                        <SummaryTab flow={props.flow!} detail={d()} />
                      </div>
                    </Match>
                    <Match when={tab() === 'timing'}>
                      <div class={css.scroll}>
                        <TimingTab timing={d().timing} durationMs={props.flow?.durationMs ?? null} />
                      </div>
                    </Match>
                    <Match when={tab() === 'connection'}>
                      <div class={css.scroll}>
                        <ConnectionTab conn={d().conn} flow={props.flow!} />
                      </div>
                    </Match>
                    <Match when={codeTab() && !codeDoc()}>
                      <NonCodeView view={view()} docKey={model.key()} onCopy={onCopy} />
                    </Match>
                  </Switch>
                )}
              </Match>
            </Switch>
          </Show>
          {/* Always mounted: the pane's single EditorView. */}
          <CodeViewer doc={codeDoc()} active={codeActive()} label="Request body" onReady={(api) => (codeApi = api)} />
        </div>
        <Show when={props.editing && ready()}>
          <EditBar edit={props.edit} busy={props.busy} onApply={props.onApply} onApplyResume={props.onApplyResume} />
        </Show>
      </div>
    </Pane>
  );
};

/** Image / hex / tree / empty for a body tab (anything but the CodeMirror document). */
export const NonCodeView: Component<{ view: BodyView | null; docKey: string; onCopy: (text: string, what: string) => void }> = (props) => (
  <Switch>
    <Match when={props.view?.type === 'image' && props.view}>{(v) => <ImageViewer base64={(v() as Extract<BodyView, { type: 'image' }>).base64} mime={(v() as Extract<BodyView, { type: 'image' }>).mime} size={(v() as Extract<BodyView, { type: 'image' }>).size} />}</Match>
    <Match when={props.view?.type === 'hex' && props.view}>{(v) => <HexViewer bytes={(v() as Extract<BodyView, { type: 'hex' }>).bytes} />}</Match>
    <Match when={props.view?.type === 'tree' && props.view}>
      {(v) => {
        const t = () => v() as Extract<BodyView, { type: 'tree' }>;
        return (
          <Show when={!t().loading} fallback={<Bars rows={7} height={20} />}>
            <Show when={!t().error} fallback={<Centered>Not JSON — {t().error}</Centered>}>
              <JsonTree value={t().value} docKey={props.docKey} onCopy={props.onCopy} />
            </Show>
          </Show>
        );
      }}
    </Match>
    <Match when={props.view?.type === 'empty' && props.view}>{(v) => <Centered>{(v() as Extract<BodyView, { type: 'empty' }>).text}</Centered>}</Match>
  </Switch>
);

export const ErrorBlock: Component<{ message: string; lastGood: number | null; onRetry: () => void }> = (props) => (
  <div class={css.errorBox} role="alert">
    <div class={css.errorTitle}>Could not load this flow</div>
    <div class={css.errorMeta}>{props.message}</div>
    <div class={css.errorMeta}>
      <Show when={props.lastGood} fallback={<>No earlier copy</>}>
        {(t) => <>Last good copy {fmtClock(t())}</>}
      </Show>
    </div>
    <Button variant="outline" onClick={props.onRetry}>
      Retry
    </Button>
  </div>
);
