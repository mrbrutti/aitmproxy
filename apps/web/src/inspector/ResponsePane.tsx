// Response pane: Headers · Set-Cookie · Body · Raw · JSON · Diff. For a WebSocket flow it becomes
// Frames. While a request is paused (no response yet) the Body shows the previous response to the
// same endpoint for reference, as the mockup does.

import { createEffect, createMemo, createSignal, Match, on, Show, Switch, type Component } from 'solid-js';
import type { FlowDetail, FlowSummary } from '~/model/flow';
import type { FlowEntry } from '~/state/app';
import { useApp } from '~/state/context';
import { CodeViewer, type CodeDoc, type CodeViewerApi } from '~/viewers/CodeViewer';
import { fmtClock } from '~/lib/format';
import { createBodyModel, type Format } from './body';
import { CookieTable } from './CookieTable';
import { responseCookies } from './cookies';
import { DiffTab } from './DiffTab';
import { HeaderTable } from './HeaderTable';
import { BodyControls, Pane } from './Pane';
import { responseDocument } from './rawdoc';
import { ErrorBlock, NonCodeView, type PaneApi } from './RequestPane';
import { WsFrames } from './WsFrames';
import { Bars, Centered, copyText } from './ui';
import css from './inspector.module.css';

export interface ResponsePaneProps {
  flow: FlowSummary | null;
  detail: FlowDetail | null;
  loading: boolean;
  error: string | null;
  lastGood: number | null;
  onRetry: () => void;
  /** The most recent earlier flow to the same endpoint that has a response. */
  previous: FlowEntry | null;
  quickLook: boolean;
  onApi?: (api: PaneApi) => void;
}

const HTTP_TABS = ['headers', 'set-cookie', 'body', 'raw', 'json', 'diff'] as const;
const WS_TABS = ['frames', 'headers'] as const;

export const ResponsePane: Component<ResponsePaneProps> = (props) => {
  const app = useApp();
  const [format, setFormat] = createSignal<Format>('auto');
  let codeApi: CodeViewerApi | null = null;
  let frameApi: CodeViewerApi | null = null;
  let content: HTMLDivElement | undefined;

  const isWs = () => props.flow?.kind === 'websocket';
  const tab = () => {
    const ids: readonly string[] = isWs() ? WS_TABS : HTTP_TABS;
    return ids.includes(app.ui.responseTab) ? app.ui.responseTab : ids[0]!;
  };

  // Reference response while the request is paused / pending.
  const needsPrevious = () => (props.detail && !props.detail.response && props.previous ? props.previous.id : null);
  createEffect(on(needsPrevious, (id) => id && !app.details[id] && void app.loadDetail(id)));
  const previousDetail = createMemo<FlowDetail | null>(() => {
    const id = needsPrevious();
    return id ? (app.details[id] ?? null) : null;
  });
  const source = createMemo(() => props.detail?.response ?? previousDetail()?.response ?? null);
  const isReference = () => !props.detail?.response && !!previousDetail()?.response;
  const sourceId = () => (isReference() ? previousDetail()!.id : (props.flow?.id ?? null));
  const headers = () => source()?.headers ?? [];
  const body = () => source()?.body ?? null;
  const codeTab = () => tab() === 'body' || tab() === 'raw';

  // The Raw tab is the whole response document (rawdoc.ts); the body model serves Body and JSON.
  const model = createBodyModel({
    flowId: sourceId,
    side: 'res',
    body,
    tab: () => (tab() === 'body' ? 'body' : tab() === 'json' ? 'tree' : 'other'),
    format,
  });
  /** Read-only raw response: status line, headers, blank line, body (of the reference flow while paused). */
  const rawDoc = createMemo<CodeDoc | null>(() => {
    if (tab() !== 'raw') return null;
    const d = isReference() ? previousDetail() : props.detail;
    const text = d ? responseDocument(d) : null;
    return d && text != null ? { key: `${d.id}:res:raw:doc`, text, lang: 'text' } : null;
  });
  const view = () => model.view();
  const codeDoc = createMemo<CodeDoc | null>(() => rawDoc() ?? (view()?.type === 'code' ? (view() as { doc: CodeDoc }).doc : null));
  const ready = () => !!props.detail && !props.loading && !props.error;
  const codeActive = () => ready() && codeTab() && !!codeDoc();

  const tabs = createMemo(() =>
    isWs()
      ? [
          { id: 'frames', label: 'Frames', count: props.detail?.wsMessages?.length ?? 0 },
          { id: 'headers', label: 'Headers', count: headers().length },
        ]
      : [
          { id: 'headers', label: 'Headers', count: headers().length },
          { id: 'set-cookie', label: 'Set-Cookie', count: responseCookies(headers()).length },
          { id: 'body', label: 'Body' },
          { id: 'raw', label: 'Raw' },
          { id: 'json', label: 'JSON' },
          { id: 'diff', label: 'Diff' },
        ],
  );

  props.onApi?.({
    focus() {
      if (codeActive()) codeApi?.focus();
      else if (isWs() && tab() === 'frames') frameApi?.focus();
      else content?.focus();
    },
    find() {
      if (codeActive() && codeApi) codeApi.find();
      else if (isWs() && tab() === 'frames' && frameApi) frameApi.find();
      else return false;
      return true;
    },
    bodyText: () => (tab() === 'raw' ? (rawDoc()?.text ?? null) : (body()?.text ?? null)),
  });

  const onCopy = (text: string, what: string) => void copyText(text).then((ok) => ok && app.notice(`Copied ${what}`));

  const right = () => (
    <Switch>
      <Match when={tab() === 'headers' && headers().length}>
        <span class={css.quietNote}>
          {headers().length} {headers().length === 1 ? 'header' : 'headers'}
        </span>
      </Match>
      <Match when={tab() === 'body' && body() && body()!.size > 0}>
        <BodyControls format={format()} onFormat={setFormat} label={model.label()} prettyState={model.prettyState()} truncatedAt={body()?.truncated ? body()!.size : null} onFind={() => codeApi?.find()} />
      </Match>
    </Switch>
  );

  const noResponse = () =>
    props.flow?.intercept === 'paused'
      ? 'No response yet — the request is paused'
      : props.flow?.intercept === 'killed'
        ? 'Killed before a response'
        : props.flow?.error
          ? props.flow.error
          : 'No response yet';

  return (
    <Pane
      title={isWs() ? 'Frames' : 'Response'}
      tabs={tabs()}
      active={tab()}
      onSelect={app.setResponseTab}
      right={right()}
      contentRef={(el) => (content = el)}
      label={props.quickLook ? 'Response (quick look)' : 'Response'}
      onPlus={() => app.notice('Custom previewers arrive with the plugin tier (M3)')}
    >
      <div class={css.stack}>
        <Show when={ready() && isReference()}>
          <div class={css.hint}>
            {noResponse()}. Showing the last response to this endpoint (flow {previousDetail()!.seq}, {fmtClock(previousDetail()!.startedAt)}) for reference.
          </div>
        </Show>
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
                    <Match when={isWs() && tab() === 'frames'}>
                      <WsFrames messages={d().wsMessages ?? []} flowId={d().id} onApi={(a) => (frameApi = a)} />
                    </Match>
                    <Match when={tab() === 'headers'}>
                      <Show when={source()} fallback={<Centered>{noResponse()}</Centered>}>
                        <div class={css.scroll}>
                          <HeaderTable headers={headers()} onCopied={(n) => app.notice(`Copied ${n}`)} />
                        </div>
                      </Show>
                    </Match>
                    <Match when={tab() === 'set-cookie'}>
                      <Show when={source()} fallback={<Centered>{noResponse()}</Centered>}>
                        <div class={css.scroll}>
                          <CookieTable headers={headers()} mode="set-cookie" />
                        </div>
                      </Show>
                    </Match>
                    <Match when={tab() === 'diff'}>
                      <DiffTab flow={d()} previous={props.previous} />
                    </Match>
                    <Match when={tab() === 'json'}>
                      <Show when={source()} fallback={<Centered>{noResponse()}</Centered>}>
                        <NonCodeView view={view()} docKey={model.key()} onCopy={onCopy} />
                      </Show>
                    </Match>
                    <Match when={codeTab() && !source()}>
                      <Centered>{noResponse()}</Centered>
                    </Match>
                    <Match when={codeTab() && !codeDoc()}>
                      <NonCodeView view={view()} docKey={model.key()} onCopy={onCopy} />
                    </Match>
                  </Switch>
                )}
              </Match>
            </Switch>
          </Show>
          <CodeViewer doc={codeDoc()} active={codeActive()} label="Response body" onReady={(api) => (codeApi = api)} />
        </div>
      </div>
    </Pane>
  );
};
