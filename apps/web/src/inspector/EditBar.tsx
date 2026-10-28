// The hint line at the bottom of the Request pane while a paused request is being edited (§2.7):
// "1 edit pending · Apply & Resume sends flow.mutate then flow.resume · Revert to original", with
// Apply & Resume ⌘⏎ / Apply / the parse error inline (never an alert).

import { Show, type Component } from 'solid-js';
import { Button } from '~/components';
import type { EditState } from './edit';
import css from './inspector.module.css';

export const EditBar: Component<{ edit: EditState; busy: boolean; onApply: () => void; onApplyResume: () => void }> = (props) => {
  const n = () => props.edit.editCount();
  const blocked = () => !!props.edit.parseError() || props.busy;
  return (
    <div class={css.editBar} role="region" aria-label="Pending edits">
      <Show
        when={!props.edit.parseError()}
        fallback={
          <span class={css.editError} role="alert">
            {props.edit.parseError()}
          </span>
        }
      >
        <span class={css.editHint}>
          <Show when={n() > 0} fallback={<>No edits · Apply &amp; Resume sends flow.resume</>}>
            {n()} {n() === 1 ? 'edit' : 'edits'} pending · Apply &amp; Resume sends flow.mutate then flow.resume ·{' '}
            <button type="button" class={css.editLink} onClick={() => props.edit.revert()}>
              Revert to original
            </button>
          </Show>
        </span>
      </Show>
      <span class={css.spacer} />
      <Show when={props.edit.parseError()}>
        <button type="button" class={css.editLink} onClick={() => props.edit.revert()}>
          Revert
        </button>
      </Show>
      <Button variant="outline" disabled={blocked() || n() === 0} onClick={props.onApply} title="flow.mutate only; the request stays paused">
        Apply
      </Button>
      <Button variant="primary" kbd="⌘⏎" disabled={blocked()} onClick={props.onApplyResume}>
        Apply &amp; Resume
      </Button>
    </div>
  );
};
