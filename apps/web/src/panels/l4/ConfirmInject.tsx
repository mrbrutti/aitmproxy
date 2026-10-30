// The operator confirm-over-the-wire dialog (ui-ext §3.4, L4OPS-AC10). It surfaces EXACTLY what the
// core said will hit the wire — the full `needs_confirmation` prompt (destination, PacketSummary,
// count, matched scope entry, permit budget) — plus the known target facts, so the operator sees
// what they are authorizing before `_confirm` is sent. A guard refusal, if one comes back on
// confirm, is shown verbatim. There is no path to the wire that bypasses this dialog.
import { Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import type { InjectArgs } from './inject';
import css from './l4.module.css';

export interface ConfirmInjectProps {
  /** Dialog title; defaults to the inject wording. */
  title?: string | undefined;
  /** The `needs_confirmation` prompt text from the core (carries the full wire summary). */
  prompt: string;
  /** The target the operator authored, echoed as structured facts (inject path only). */
  args?: InjectArgs | undefined;
  /** A verbatim guard refusal surfaced after a failed confirm, if any. */
  refusal?: string | null | undefined;
  busy?: boolean | undefined;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmInject: Component<ConfirmInjectProps> = (props) => {
  const layers = () => props.args?.spec.layers.map((l) => Object.keys(l)[0]).join('/') ?? '';
  return (
    <div class={css.confirmBackdrop} role="presentation" onClick={() => props.onCancel()}>
      <div class={css.confirmCard} role="alertdialog" aria-modal="true" aria-label="Confirm L4 action over the wire" onClick={(e) => e.stopPropagation()}>
        <h2 class={css.confirmTitle}>{props.title ?? 'Confirm inject to the wire'}</h2>
        <p class={css.confirmPrompt}>{props.prompt}</p>
        <Show when={props.args}>
          {(a) => (
            <dl class={css.confirmFacts}>
              <dt>Destination</dt>
              <dd>
                {a().dst}
                <Show when={a().port != null}>:{a().port}</Show>
              </dd>
              <dt>Interface</dt>
              <dd>{a().interface}</dd>
              <dt>Packet</dt>
              <dd>{layers()}</dd>
              <dt>Count</dt>
              <dd>{a().count ?? 1}</dd>
            </dl>
          )}
        </Show>
        <Show when={props.refusal}>
          <p class={css.confirmRefusal} role="alert">
            Refused by the L4 guard: {props.refusal}
          </p>
        </Show>
        <div class={css.confirmActions}>
          <Button variant="ghost" disabled={props.busy} onClick={() => props.onCancel()}>
            Cancel
          </Button>
          <Button variant="primary" disabled={props.busy} onClick={() => props.onConfirm()}>
            Send to wire
          </Button>
        </div>
      </div>
    </div>
  );
};
