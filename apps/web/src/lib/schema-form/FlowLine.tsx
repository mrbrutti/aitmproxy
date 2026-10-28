// A one-line flow row: method badge · status · URL (host in ink, path secondary) · time.
// Used by the flow picker, the palette's Flows group and the compose history.
import { For, Show, type Component } from 'solid-js';
import { methodHue, statusHue, type FlowSummary } from '~/model/flow';
import { fmtClock } from '~/lib/format';
import { segments } from '~/lib/fuzzy';
import { Badge } from '~/components/Badge';
import css from './schema-form.module.css';

export interface FlowLineProps {
  flow: FlowSummary;
  /** Fuzzy-match indices into `flowUrl(flow)` to emphasise. */
  hits?: number[] | null | undefined;
  showTime?: boolean | undefined;
  class?: string | undefined;
}

export const statusText = (f: Pick<FlowSummary, 'status' | 'intercept' | 'error'>): string => {
  if (f.intercept === 'paused') return '⏸';
  if (f.intercept === 'killed') return '×';
  if (f.status != null) return String(f.status);
  return f.error ? 'err' : '—';
};

export const FlowLine: Component<FlowLineProps> = (props) => {
  const f = () => props.flow;
  const head = () => `${f().scheme}://${f().authority}`;
  const tail = () => `${f().path}${f().query ? `?${f().query}` : ''}`;
  return (
    <span class={`${css.flowLine}${props.class ? ` ${props.class}` : ''}`}>
      <Badge hue={methodHue(f())}>{f().kind === 'websocket' ? 'WS' : f().method}</Badge>
      <span class={css.status} data-hue={statusHue(f())}>
        {statusText(f())}
      </span>
      <span class={css.url} title={head() + tail()}>
        <Show when={props.hits && props.hits.length} fallback={
          <>
            <span class={css.host}>{head()}</span>
            <span class={css.path}>{tail()}</span>
          </>
        }>
          <For each={segments(head() + tail(), props.hits)}>
            {(s) => <span class={s.hit ? css.hit : undefined}>{s.text}</span>}
          </For>
        </Show>
      </span>
      <Show when={props.showTime !== false}>
        <span class={css.time}>{fmtClock(f().startedAt)}</span>
      </Show>
    </span>
  );
};
