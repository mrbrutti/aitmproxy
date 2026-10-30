// Capture controls + the L4 scope view (ui-ext §3.3). `l4.capture.start/stop/status` bind an
// interface + optional filter; the scope panel shows the authorized L4 entries alongside. Adding an
// L4 scope entry is itself Sensitive (operator/widen-gated), so this view reads scope and points at
// where it is granted rather than silently offering a widen the core would refuse.
import { createSignal, For, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import type { L4ScopeEntryWire } from './model';
import css from './l4.module.css';

export interface CaptureControlsProps {
  canCapture: boolean;
  canScope: boolean;
  activeCaptures: number;
  scope: readonly L4ScopeEntryWire[];
  onStart: (iface: string, filter: string | null) => void;
}

export const CaptureControls: Component<CaptureControlsProps> = (props) => {
  const [iface, setIface] = createSignal('lo0');
  const [filter, setFilter] = createSignal('');
  return (
    <section class={css.section} aria-label="Capture">
      <div class={css.sectionHead}>
        Capture
        <Show when={props.activeCaptures > 0}>
          <span class={css.sub}>· {props.activeCaptures} active</span>
        </Show>
      </div>
      <div class={css.controls}>
        <label class={css.field}>
          interface
          <input class={css.input} value={iface()} onInput={(e) => setIface(e.currentTarget.value)} aria-label="Capture interface" />
        </label>
        <label class={css.field}>
          filter (optional)
          <input class={css.input} value={filter()} onInput={(e) => setFilter(e.currentTarget.value)} aria-label="Capture filter" placeholder="udp port 9" />
        </label>
        <Button variant="outline" disabled={!props.canCapture} title={props.canCapture ? undefined : 'l4.capture.start is not available on this core'} onClick={() => props.onStart(iface().trim(), filter().trim() || null)}>
          Start capture
        </Button>
      </div>
      <Show when={props.canScope} fallback={<p class={css.note}>L4 scope is not readable on this core (`l4.scope.list` absent).</p>}>
        <div class={css.scopeList}>
          <Show when={props.scope.length} fallback={<span>No L4 scope declared — every wire action is refused until an operator grants scope.</span>}>
            <For each={props.scope}>
              {(e) => (
                <div>
                  {e.interface} · {e.cidr}:{e.ports} · {e.capability} · {e.inject_rate.pps}pps
                </div>
              )}
            </For>
          </Show>
        </div>
      </Show>
    </section>
  );
};
