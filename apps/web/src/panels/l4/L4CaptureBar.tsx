// The L4 capture + scope controls, shown above the flow list in the L4 focus view (sidebar → L4).
// L4 sessions now live in the one unified list, so the retired L4Panel's capture controls move here
// — reachable when the operator narrows to L4, out of the way otherwise. Honest degradation: when
// `l4.*` is not advertised it says so in place instead of faking an L4 surface.
import { Show, type Component } from 'solid-js';
import type { L4Store } from './store';
import { CaptureControls } from './CaptureControls';
import css from './l4.module.css';

export const L4CaptureBar: Component<{ store: L4Store }> = (props) => {
  const store = props.store;
  return (
    <Show
      when={store.present()}
      fallback={
        <p class={css.l4Empty}>
          L4 is not enabled on this core — no `l4.*` commands are advertised. Start the core with `l4.enabled: true` (and the
          privilege / scope to use it) to drive raw-packet capture, craft and inject from here.
        </p>
      }
    >
      <CaptureControls
        canCapture={store.caps().capture}
        canScope={store.caps().scope}
        activeCaptures={store.captureIds().length}
        scope={store.scope()}
        onStart={(iface) => void store.startCapture(iface, 'inbound')}
      />
    </Show>
  );
};
