// Capture controls + the L4 scope view (ui-ext §3.3; parity spec §1, §7(c)). `l4.capture.start`
// takes an interface and a direction only: the core derives the BPF from L4 scope, so there is no
// free-form operator string here (a second, unguarded definition of what gets captured). Capture
// availability is the store's live `l4.capture.status` read; while it is unavailable, or still
// pending, Start is disabled and the core's own reason is shown beside it and as its tooltip, so
// no enabled control can only fail (AC33). The scope panel shows the authorized L4 entries
// alongside; adding one is Sensitive (operator/widen-gated) and is wired in task C7.
import { createSignal, For, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import type { L4Availability, L4Direction, L4ScopeEntryWire } from './model';
import css from './l4.module.css';

export interface CaptureControlsProps {
  /** `l4.capture.status` as the store last read it (`PENDING_AVAILABILITY` until the first reply). */
  capture: L4Availability;
  /** Running capture flow ids; one Stop button each. */
  running: readonly string[];
  canScope: boolean;
  scope: readonly L4ScopeEntryWire[];
  onStart: (iface: string, direction: L4Direction) => void;
  onStop: (id: string) => void;
}

/** The select's value as a direction; anything unexpected falls back to the default. */
const asDirection = (v: string): L4Direction => (v === 'outbound' ? 'outbound' : 'inbound');

export const CaptureControls: Component<CaptureControlsProps> = (props) => {
  const [iface, setIface] = createSignal('lo0');
  const [direction, setDirection] = createSignal<L4Direction>('inbound');
  return (
    <section class={css.section} aria-label="Capture">
      <div class={css.sectionHead}>
        Capture
        <Show when={props.running.length > 0}>
          <span class={css.sub}>· {props.running.length} active</span>
        </Show>
      </div>
      <div class={css.controls}>
        <label class={css.field}>
          interface
          <input class={css.input} value={iface()} onInput={(e) => setIface(e.currentTarget.value)} aria-label="Capture interface" />
        </label>
        <label class={css.field}>
          direction
          <select
            class={css.input}
            value={direction()}
            onChange={(e) => setDirection(asDirection(e.currentTarget.value))}
            aria-label="Capture direction"
          >
            <option value="inbound">inbound</option>
            <option value="outbound">outbound</option>
          </select>
        </label>
        <Button
          variant="outline"
          data-testid="l4-capture-start"
          disabled={!props.capture.available}
          title={props.capture.available ? undefined : (props.capture.reason ?? undefined)}
          onClick={() => props.onStart(iface().trim(), direction())}
        >
          Start capture
        </Button>
      </div>
      <Show when={!props.capture.available && props.capture.reason}>
        {(reason) => (
          <p class={css.note} data-testid="l4-capture-reason">
            {reason()}
          </p>
        )}
      </Show>
      <Show when={props.running.length > 0}>
        <div class={css.controls} role="group" aria-label="Running captures">
          <For each={props.running}>
            {(id) => (
              <Button variant="outline" aria-label={`Stop capture ${id}`} onClick={() => props.onStop(id)}>
                Stop {id}
              </Button>
            )}
          </For>
        </div>
      </Show>
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
