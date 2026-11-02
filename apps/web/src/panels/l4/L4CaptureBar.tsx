// The L4 capture + scope controls, shown above the flow list in the L4 focus view (sidebar → L4).
// L4 sessions now live in the one unified list, so the retired L4Panel's capture controls move here
// — reachable when the operator narrows to L4, out of the way otherwise. Honest degradation: when
// `l4.*` is not advertised it says so in place instead of faking an L4 surface; when it is, the
// controls follow the store's live `l4.capture.status` availability (parity spec §1), and an
// unavailable in-path intercept is the same one documented-limited line the inspector shows (§4).
import { Show, type Component } from 'solid-js';
import type { L4Store } from './store';
import { CaptureControls } from './CaptureControls';
import { InterceptLimitedLine } from './L4InterceptBar';
import css from './l4.module.css';

export const L4CaptureBar: Component<{ store: L4Store }> = (props) => {
  const store = props.store;
  // One wrapper element so the bar is a single, content-sized item in the Shell's list column; on a
  // short window it scrolls inside itself (max-height) rather than clipping the scope rows or the form.
  return (
    <div class={css.captureBar} data-testid="l4-capture-bar">
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
          capture={store.captureAvailability()}
          running={store.captureIds()}
          canScope={store.caps().scope}
          scope={store.scope()}
          tools={store.tools()}
          onStart={(iface, direction) => void store.startCapture(iface, direction)}
          onStop={(id) => void store.stopCapture(id)}
          onAddScope={store.addScope}
          onConfirmAddScope={store.confirmAddScope}
        />
        <Show when={!store.interceptAvailability().available}>
          <InterceptLimitedLine reason={store.interceptAvailability().reason ?? ''} />
        </Show>
      </Show>
    </div>
  );
};
