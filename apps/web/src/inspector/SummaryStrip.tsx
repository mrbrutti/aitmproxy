// The 40px summary strip (§2.7): method badge, status pill, full URL, copy, right-aligned meta.
// One calm mono line; every missing value is a grey dash.

import { Show, type Component } from 'solid-js';
import { Badge, Icon } from '~/components';
import { flowUrl, methodHue, type FlowDetail, type FlowSummary } from '~/model/flow';
import { fmtBytes, fmtDuration } from '~/lib/format';
import { copyText, Dash, Quiet, StatusPill } from './ui';
import css from './inspector.module.css';

export const SummaryStrip: Component<{ flow: FlowSummary | null; detail: FlowDetail | null; onCopied?: () => void }> = (props) => {
  const protocol = () => {
    const f = props.flow;
    const c = props.detail?.conn;
    if (!f) return null;
    const tls = c?.tlsVersion ?? (f.tls === 'plain' ? 'plain' : null);
    const parts = [f.httpVersion, tls, c?.alpn];
    return parts.some(Boolean) ? parts.map((p) => p ?? '—').join(' · ') : null;
  };
  const copy = async () => {
    if (props.flow && (await copyText(flowUrl(props.flow)))) props.onCopied?.();
  };

  return (
    <div class={css.summary} role="region" aria-label="Flow summary">
      <Show when={props.flow}>
        {(f) => (
          <>
            <Badge hue={methodHue(f())}>{f().kind === 'websocket' ? 'WS' : f().method}</Badge>
            <StatusPill flow={f()} />
            <span class={css.summaryUrl} title={flowUrl(f())}>
              <span class={css.host}>
                {f().scheme}://{f().authority}
              </span>
              <span class={css.path}>{f().path}</span>
              <Show when={f().query}>
                <span class={css.query}>?{f().query}</span>
              </Show>
            </span>
            <Quiet title="Copy URL" aria-label="Copy URL" onClick={() => void copy()}>
              <Icon name="copy" size={12} />
            </Quiet>
            <div class={css.meta}>
              <span class={css.metaMid}>{protocol() ?? <Dash />}</span>
              <span>
                req <b>{fmtBytes(f().reqSize) ?? <Dash />}</b>
              </span>
              <span>
                res <b>{fmtBytes(f().resSize) ?? <Dash />}</b>
              </span>
              <span>{fmtDuration(f().durationMs) ?? <Dash />}</span>
              <span class={css.metaLow}>
                client <b>{f().client.addr ?? f().client.name}</b>
              </span>
              <span class={`${css.scope} ${css.metaLow}`}>{f().inScope ? 'in scope' : 'out of scope'}</span>
            </div>
          </>
        )}
      </Show>
    </div>
  );
};
