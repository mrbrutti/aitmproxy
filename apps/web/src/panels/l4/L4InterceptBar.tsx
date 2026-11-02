// The in-path intercept bar (ui-ext §3.2, L4OPS-AC12; parity spec §4, AC20): Forward / Mutate /
// Drop / Revert on the selected flow's parked packet, mirroring the HTTP intercept bar's mental
// model. It renders from `interceptBarModel`: when `l4.intercept.status` says the class is
// unavailable on this core (or availability is still pending) it is exactly one documented-limited
// line carrying the core's reason and NO verdict buttons — never a control that can only fail
// (AC33). Every verdict reaches the wire through the same guarded confirm path as inject, and
// every one takes the parked packet's id, never the flow id.
import { Show, Switch, Match, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import type { InterceptBarModel } from './model';
import css from './l4.module.css';

/** The one documented-limited line, shared by the inspector bar and the L4 focus view. */
export const InterceptLimitedLine: Component<{ reason: string }> = (props) => (
  <div class={css.interceptBar} data-limited="true" role="status" data-testid="l4-intercept-limited">
    <span>In-path intercept is not available on this core: {props.reason}</span>
  </div>
);

export interface L4InterceptBarProps {
  model: InterceptBarModel;
  inScope: boolean;
  scopeReason: string;
  /** Why Mutate is off right now (no built spec yet), or `null` when a spec is ready. */
  mutateBlocked: string | null;
  onForward: (parkedId: string) => void;
  onMutate: (parkedId: string) => void;
  onDrop: (parkedId: string) => void;
  onRevert: (parkedId: string) => void;
}

export const L4InterceptBar: Component<L4InterceptBarProps> = (props) => {
  const scopeTitle = () => (props.inScope ? undefined : props.scopeReason);
  return (
    <Switch>
      <Match when={props.model.kind === 'limited' && props.model}>{(m) => <InterceptLimitedLine reason={m().reason} />}</Match>
      <Match when={props.model.kind === 'idle'}>
        <div class={css.interceptBar} role="status" data-testid="l4-intercept-idle">
          <span>No packet parked in-path for this flow.</span>
          <Button variant="primary" disabled title="No parked packet">
            Forward
          </Button>
          <Button variant="ghost" disabled title="No parked packet">
            Mutate
          </Button>
          <Button variant="ghost" disabled title="No parked packet">
            Drop
          </Button>
          <Button variant="ghost" disabled title="No parked packet">
            Revert
          </Button>
        </div>
      </Match>
      <Match when={props.model.kind === 'parked' && props.model}>
        {(m) => (
          <div class={css.interceptBar} role="status" data-testid="l4-intercept-parked" data-parked-id={m().id}>
            <span>
              Parked in-path: <b>{m().id}</b>
            </span>
            <Button variant="primary" data-testid="l4-forward" disabled={!props.inScope} title={scopeTitle()} onClick={() => props.onForward(m().id)}>
              Forward
            </Button>
            <Button
              variant="ghost"
              data-testid="l4-mutate"
              disabled={!props.inScope || props.mutateBlocked !== null}
              title={scopeTitle() ?? props.mutateBlocked ?? undefined}
              onClick={() => props.onMutate(m().id)}
            >
              Mutate
            </Button>
            <Button variant="ghost" data-testid="l4-drop" disabled={!props.inScope} title={scopeTitle()} onClick={() => props.onDrop(m().id)}>
              Drop
            </Button>
            <Button variant="ghost" data-testid="l4-revert" disabled={!props.inScope} title={scopeTitle()} onClick={() => props.onRevert(m().id)}>
              Revert
            </Button>
            <Show when={!props.inScope}>
              <span class={css.sub}>{props.scopeReason}</span>
            </Show>
          </div>
        )}
      </Match>
    </Switch>
  );
};
