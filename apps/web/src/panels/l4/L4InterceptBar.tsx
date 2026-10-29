// The in-path intercept bar (ui-ext §3.2, L4OPS-AC12): Forward / Mutate / Drop on a parked packet,
// mirroring the HTTP intercept bar's mental model. Feature-detected from `l4.intercept.*`: where the
// commands are absent (macOS / unprivileged) it renders documented-limited, never a dead control.
// Forward and Drop reach the wire through the same guarded confirm path as inject.
import { Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import css from './l4.module.css';

export interface L4InterceptBarProps {
  /** `l4.intercept.*` present on this core. */
  available: boolean;
  /** Packets currently parked in-path (from `l4.intercept.status`). */
  parked: number;
  inScope: boolean;
  scopeReason: string;
  onForward: () => void;
  onMutate: () => void;
  onDrop: () => void;
}

export const L4InterceptBar: Component<L4InterceptBarProps> = (props) => (
  <div class={css.interceptBar} data-limited={props.available ? undefined : 'true'} role="status">
    <Show
      when={props.available}
      fallback={
        <span>
          In-path intercept is not available on this core (Linux NFQUEUE / CAP_NET_ADMIN required; macOS awaits the Phase-2
          Network Extension). Capture, craft and inject still work.
        </span>
      }
    >
      <span>
        <b>{props.parked}</b> parked in-path
      </span>
      <Button variant="primary" disabled={!props.inScope || props.parked === 0} title={props.inScope ? undefined : props.scopeReason} onClick={() => props.onForward()}>
        Forward
      </Button>
      <Button variant="ghost" disabled={!props.inScope || props.parked === 0} title={props.inScope ? undefined : props.scopeReason} onClick={() => props.onMutate()}>
        Mutate
      </Button>
      <Button variant="ghost" disabled={!props.inScope || props.parked === 0} title={props.inScope ? undefined : props.scopeReason} onClick={() => props.onDrop()}>
        Drop
      </Button>
    </Show>
  </div>
);
