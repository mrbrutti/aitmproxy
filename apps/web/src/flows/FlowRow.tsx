// One flow row. Reads from `entry.flow` (a Solid store) so a response arriving updates the cells
// in place; no per-row effects, no transitions (§2.8: new flows append with no animation).
import { Show, type Component } from 'solid-js';
import type { FlowEntry } from '~/state/app';
import { methodHue, statusHue, type FlowSummary, type TlsState } from '~/model/flow';
import { fmtBytes, fmtDuration, fmtTime } from '~/lib/format';
import { Badge } from '~/components/Badge';
import { Icon } from '~/components/Icon';
import { StatusDot } from '~/components/StatusDot';
import type { ColumnStore } from './columns';
import css from './FlowList.module.css';

const SSL_TITLE: Record<TlsState, string> = {
  mitm: 'Decrypted (MITM)',
  tunnel: 'Tunnelled — not decrypted',
  pinned: 'Upstream cert pinned — tunnelled',
  plain: 'Plain HTTP',
};

export interface FlowRowProps {
  entry: FlowEntry;
  selected: boolean;
  cols: ColumnStore;
  top: number;
  index: number;
}

const Dash = () => <span class={css.dash}>—</span>;

/** Status pill text: the code, `Paused`, `killed`, `error` (transport failure) or `—` while in flight. */
export const statusLabel = (f: Pick<FlowSummary, 'status' | 'intercept' | 'error'>): string => {
  if (f.intercept === 'paused') return 'Paused';
  if (f.intercept === 'killed') return 'killed';
  if (f.status != null) return String(f.status);
  return f.error ? 'error' : '—';
};

export const FlowRow: Component<FlowRowProps> = (props) => {
  const f = () => props.entry.flow;
  const show = (id: Parameters<ColumnStore['isHidden']>[0]) => !props.cols.isHidden(id);
  return (
    <div
      class={css.row}
      role="row"
      aria-rowindex={props.index + 2}
      aria-selected={props.selected}
      data-id={props.entry.id}
      data-paused={f().intercept === 'paused' ? 'true' : undefined}
      data-agent={f().origin === 'agent' && f().intercept !== 'paused' ? 'true' : undefined}
      data-killed={f().intercept === 'killed' ? 'true' : undefined}
      data-oos={!f().inScope ? 'true' : undefined}
      style={{ transform: `translateY(${props.top}px)` }}
    >
      <span class={`${css.cell} ${css.cDot}`} role="gridcell">
        <StatusDot hue={statusHue(f())} />
      </span>
      <span class={`${css.cell} ${css.cSeq}`} role="gridcell" data-align="right">
        {f().seq}
        <Show when={f().isReplay}> ↻</Show>
      </span>
      <span class={`${css.cell} ${css.url}`} role="gridcell" title={`${f().scheme}://${f().authority}${f().path}${f().query ? `?${f().query}` : ''}`}>
        <span class={css.host}>
          {f().scheme}://{f().authority}
        </span>
        <span class={css.path}>{f().path}</span>
        <Show when={f().query}>
          <span class={css.q}>?{f().query}</span>
        </Show>
      </span>
      <Show when={show('client')}>
        <span class={`${css.cell} ${css.client}`} role="gridcell" title={f().client.addr ?? f().client.name}>
          {/* Until the core resolves peer → process (F5) the client is unknown: a dash, no disc. */}
          <Show when={f().client.id !== 'unknown'} fallback={<span class={css.clientName}>—</span>}>
            <span class={css.appdot} aria-hidden="true">
              {f().client.name.slice(0, 1)}
            </span>
            <span class={css.clientName}>{f().client.name}</span>
          </Show>
        </span>
      </Show>
      <Show when={show('method')}>
        <span class={css.cell} role="gridcell">
          <Badge hue={methodHue(f())}>{f().kind === 'websocket' ? 'WS' : f().method}</Badge>
        </span>
      </Show>
      <Show when={show('status')}>
        <span class={css.cell} role="gridcell">
          <Badge hue={statusHue(f())} fixed title={f().error ?? f().statusText ?? undefined}>
            {statusLabel(f())}
          </Badge>
        </span>
      </Show>
      <Show when={show('time')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell">
          {fmtTime(f().startedAt)}
        </span>
      </Show>
      <Show when={show('duration')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Show when={f().durationMs != null} fallback={f().status == null && f().intercept === 'none' ? <span class={css.dash}>…</span> : <Dash />}>
            {fmtDuration(f().durationMs)}
          </Show>
        </span>
      </Show>
      <Show when={show('req')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Show when={f().kind === 'websocket'} fallback={<Show when={f().reqSize != null} fallback={<Dash />}>{fmtBytes(f().reqSize)}</Show>}>
            {f().ws?.up ?? 0} ↑
          </Show>
        </span>
      </Show>
      <Show when={show('res')}>
        <span class={`${css.cell} ${css.muted}`} role="gridcell" data-align="right">
          <Show when={f().kind === 'websocket'} fallback={<Show when={f().resSize != null} fallback={<Dash />}>{fmtBytes(f().resSize)}</Show>}>
            {f().ws?.down ?? 0} ↓
          </Show>
        </span>
      </Show>
      <Show when={show('ssl')}>
        <span class={`${css.cell} ${css.ssl}`} role="gridcell" data-align="center" data-tls={f().tls} title={SSL_TITLE[f().tls]}>
          <Show when={f().tls === 'mitm'}>
            <Icon name="lock-open" size={12} />
          </Show>
          <Show when={f().tls === 'tunnel'}>
            <Icon name="lock" size={12} />
          </Show>
          <Show when={f().tls === 'pinned'}>
            <Icon name="triangle-alert" size={12} />
          </Show>
        </span>
      </Show>
      <Show when={show('edited')}>
        <span class={`${css.cell} ${css.edited}`} role="gridcell" data-align="center" title={f().edited ? 'Edited while paused' : undefined}>
          <Show when={f().edited}>
            <Icon name="pencil" size={12} />
          </Show>
        </span>
      </Show>
      <Show when={show('origin')}>
        <span class={`${css.cell} ${css.origin}`} role="gridcell">
          <Show when={f().origin === 'agent'}>
            <span class={css.tag}>agent</span>
          </Show>
        </span>
      </Show>
      <Show when={show('mark')}>
        <span class={css.cell} role="gridcell" data-align="center" title={f().mark ? `Marked ${f().mark}` : undefined}>
          <Show when={f().mark}>{(m) => <i class={css.mark} style={{ background: `var(--mark-${m()})` }} />}</Show>
        </span>
      </Show>
    </div>
  );
};
