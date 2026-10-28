// Request › Timing: a horizontal waterfall of the phases in neutral greys with labels and ms.
// Timing is a core follow-up (F5): null prints the trade's words, not an empty chart.

import { createMemo, For, Show, type Component } from 'solid-js';
import type { Timing } from '~/model/flow';
import { fmtDuration } from '~/lib/format';
import { Centered } from './ui';
import css from './inspector.module.css';

const PHASES: { key: keyof Timing; label: string }[] = [
  { key: 'dnsMs', label: 'DNS' },
  { key: 'connectMs', label: 'Connect' },
  { key: 'tlsMs', label: 'TLS' },
  { key: 'waitMs', label: 'Wait' },
  { key: 'downloadMs', label: 'Download' },
];

export const TimingTab: Component<{ timing: Timing | null; durationMs: number | null }> = (props) => {
  const rows = createMemo(() => {
    const t = props.timing;
    if (!t) return null;
    let offset = 0;
    const out = PHASES.map((p) => {
      const ms = t[p.key];
      const row = { label: p.label, ms: ms ?? null, offset };
      if (ms != null) offset += ms;
      return row;
    });
    return { rows: out, total: offset };
  });
  const span = () => Math.max(rows()?.total ?? 0, props.durationMs ?? 0, 1);

  return (
    <Show
      when={rows()}
      fallback={
        <Centered>
          <span>Timing needs core follow-up F5</span>
          <Show when={props.durationMs != null}>
            <span class={css.centeredSub}>total {fmtDuration(props.durationMs)}</span>
          </Show>
        </Centered>
      }
    >
      {(r) => (
        <div class={css.timing} role="table" aria-label="Timing waterfall">
          <For each={r().rows}>
            {(row) => (
              <div class={css.timingRow} role="row">
                <span class={css.timingLabel} role="cell">
                  {row.label}
                </span>
                <span class={css.timingTrack} role="cell" aria-hidden="true">
                  <Show when={row.ms != null}>
                    <i class={css.timingBar} style={{ left: `${(row.offset / span()) * 100}%`, width: `${Math.max((row.ms! / span()) * 100, 0.5)}%` }} />
                  </Show>
                </span>
                <span class={css.timingMs} role="cell">
                  {row.ms != null ? fmtDuration(row.ms) : <span class={css.dash}>—</span>}
                </span>
              </div>
            )}
          </For>
          <div class={`${css.timingRow} ${css.timingTotal}`} role="row">
            <span class={css.timingLabel} role="cell">
              Total
            </span>
            <span class={css.timingTrack} role="cell" aria-hidden="true">
              <i class={`${css.timingBar} ${css.timingBarTotal}`} style={{ left: '0', width: `${(r().total / span()) * 100}%` }} />
            </span>
            <span class={css.timingMs} role="cell">
              {fmtDuration(props.durationMs ?? r().total)}
            </span>
          </div>
        </div>
      )}
    </Show>
  );
};
