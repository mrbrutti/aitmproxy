// One pending confirmation (§2.7 "Agent toggle": a gated command the agent requests, e.g.
// `ca.install`, which the human can approve once). Nothing can arrive until the core's F1 lands;
// the panel renders the empty state today and this row is ready for the stream to plug in.
// The only amber in the panel: the 8px dot and the requester, because this is a request waiting.
import { Show, type Component } from 'solid-js';
import { Button, StatusDot } from '~/components';
import { fullArgs, summarizeArgs } from './activity';
import css from './AgentPanel.module.css';

export interface PendingConfirmationProps {
  command: string;
  args?: unknown;
  /** Who asked; shown after the command (`agent`). */
  requester?: string | undefined;
  /** The core's `confirm_prompt` text, if any — becomes the row's tooltip. */
  prompt?: string | undefined;
  onApprove: () => void;
  onDeny: () => void;
  busy?: boolean | undefined;
}

export const PendingConfirmation: Component<PendingConfirmationProps> = (props) => (
  <div class={css.pending} role="group" aria-label={`Approve ${props.command}`} title={props.prompt}>
    <StatusDot hue="armed" />
    <span>
      <span class={css.command}>{props.command}</span>
      <Show when={props.requester}>
        <span class={css.who}>{props.requester}</span>
      </Show>
    </span>
    <span class={css.args} title={fullArgs(props.args)}>
      {summarizeArgs(props.args)}
    </span>
    <span class={css.actions}>
      <Button variant="outline" disabled={props.busy} onClick={() => props.onApprove()}>
        Approve once
      </Button>
      <Button variant="ghost" disabled={props.busy} onClick={() => props.onDeny()}>
        Deny
      </Button>
    </span>
  </div>
);
