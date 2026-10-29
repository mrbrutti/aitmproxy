// Request › Summary: the flow's facts as a key : value list.

import type { Component } from 'solid-js';
import { flowOrigin, flowUrl, type FlowDetail, type FlowSummary } from '~/model/flow';
import { fmtBytes, fmtDuration, fmtTime } from '~/lib/format';
import { KvList } from './ui';

const TLS: Record<FlowSummary['tls'], string> = {
  mitm: 'Decrypted (MITM)',
  tunnel: 'Tunnelled — not decrypted',
  pinned: 'Pinned — tunnelled',
  plain: 'Plain HTTP',
};

export const SummaryTab: Component<{ flow: FlowSummary; detail: FlowDetail | null }> = (props) => {
  const f = () => props.flow;
  const status = () => {
    if (f().intercept === 'paused') return 'Paused';
    if (f().intercept === 'killed') return 'Killed';
    if (f().status == null) return f().error ?? null;
    return `${f().status}${f().statusText ? ` ${f().statusText}` : ''}`;
  };
  return (
    <KvList
      label="Flow summary"
      rows={[
        { k: 'URL', v: flowUrl(f()) },
        { k: 'Method', v: f().kind === 'websocket' ? 'WS (GET upgrade)' : f().method },
        { k: 'Status', v: status() },
        { k: 'Protocol', v: [f().httpVersion, props.detail?.conn.tlsVersion, props.detail?.conn.alpn].filter(Boolean).join(' · ') || null },
        { k: 'Request size', v: fmtBytes(f().reqSize) },
        { k: 'Response size', v: fmtBytes(f().resSize) },
        { k: 'Duration', v: fmtDuration(f().durationMs) },
        { k: 'Started', v: fmtTime(f().startedAt) },
        { k: 'Client', v: `${f().client.name}${f().client.addr ? ` · ${f().client.addr}` : ''}`, ui: true },
        { k: 'TLS', v: TLS[f().tls], ui: true },
        { k: 'Scope', v: f().inScope ? 'in scope' : 'out of scope', ui: true },
        { k: 'Flow id', v: f().id },
        { k: 'Origin', v: `${f().origin}${f().isReplay ? ' · replay' : ''}${f().edited ? ' · edited' : ''}`, ui: true },
        { k: 'Site', v: flowOrigin(f()) },
        { k: 'Comment', v: f().comment, ui: true },
        { k: 'Mark', v: f().mark, ui: true },
      ]}
    />
  );
};
