// Request › Connection: the transport facts from `detail.conn`.

import type { Component } from 'solid-js';
import type { ConnInfo, FlowSummary } from '~/model/flow';
import { KvList } from './ui';

const TLS: Record<FlowSummary['tls'], string> = {
  mitm: 'Decrypted (MITM)',
  tunnel: 'Tunnelled — not decrypted',
  pinned: 'Pinned — tunnelled',
  plain: 'Plain HTTP',
};

export const ConnectionTab: Component<{ conn: ConnInfo | null; flow: FlowSummary }> = (props) => (
  <KvList
    label="Connection"
    rows={[
      { k: 'Client', v: props.conn?.peer ?? props.flow.client.addr ?? null },
      { k: 'Process', v: props.flow.client.name, ui: true },
      { k: 'Upstream', v: props.conn?.upstream ?? null },
      { k: 'SNI', v: props.conn?.sni ?? null },
      { k: 'ALPN', v: props.conn?.alpn ?? null },
      { k: 'HTTP', v: props.flow.httpVersion },
      { k: 'TLS', v: TLS[props.flow.tls], ui: true },
      { k: 'TLS version', v: props.conn?.tlsVersion ?? null },
      { k: 'Cipher', v: props.conn?.cipher ?? null },
    ]}
  />
);
