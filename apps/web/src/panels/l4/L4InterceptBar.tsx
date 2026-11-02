// The in-path intercept bar (ui-ext §3.2, L4OPS-AC12; parity spec §4, AC20): Forward / Mutate /
// Drop / Revert on the selected flow's parked packet, mirroring the HTTP intercept bar's mental
// model. It renders from `interceptBarModel`: when `l4.intercept.status` says the class is
// unavailable on this core (or availability is still pending) it is exactly one documented-limited
// line carrying the core's reason and NO verdict buttons — never a control that can only fail
// (AC33). Every verdict reaches the wire through the same guarded confirm path as inject, and
// every one takes the parked packet's id, never the flow id. Role (spec §7(c) D12, AC24): the
// verdicts are operator-only; with `operatorOnly` set (the inspector reads the connection role) each
// button renders disabled with that reason and its handler returns before calling out.
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
  /** `operatorOnlyReason(role)`: `null` on an operator connection, else the reason every verdict shows (D12). */
  operatorOnly: string | null;
  onForward: (parkedId: string) => void;
  onMutate: (parkedId: string) => void;
  onDrop: (parkedId: string) => void;
  onRevert: (parkedId: string) => void;
}

export const L4InterceptBar: Component<L4InterceptBarProps> = (props) => {
  const gated = () => props.operatorOnly !== null;
  /** Operator-only first, then the scope reason: the one tooltip a disabled verdict shows. */
  const scopeTitle = () => props.operatorOnly ?? (props.inScope ? undefined : props.scopeReason);
  const forRole = () => (gated() ? 'true' : undefined);

  // D12: on an agent connection every verdict returns here, before the confirm path and the bus.
  const forward = (id: string) => {
    if (gated()) return;
    props.onForward(id);
  };
  const mutate = (id: string) => {
    if (gated()) return;
    props.onMutate(id);
  };
  const drop = (id: string) => {
    if (gated()) return;
    props.onDrop(id);
  };
  const revert = (id: string) => {
    if (gated()) return;
    props.onRevert(id);
  };
  return (
    <Switch>
      <Match when={props.model.kind === 'limited' && props.model}>{(m) => <InterceptLimitedLine reason={m().reason} />}</Match>
      <Match when={props.model.kind === 'idle'}>
        <div class={css.interceptBar} role="status" data-testid="l4-intercept-idle">
          <span>No packet parked in-path for this flow.</span>
          <Button variant="primary" disabled title={props.operatorOnly ?? 'No parked packet'} data-operator-only={forRole()}>
            Forward
          </Button>
          <Button variant="ghost" disabled title={props.operatorOnly ?? 'No parked packet'} data-operator-only={forRole()}>
            Mutate
          </Button>
          <Button variant="ghost" disabled title={props.operatorOnly ?? 'No parked packet'} data-operator-only={forRole()}>
            Drop
          </Button>
          <Button variant="ghost" disabled title={props.operatorOnly ?? 'No parked packet'} data-operator-only={forRole()}>
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
            <Button
              variant="primary"
              data-testid="l4-forward"
              disabled={gated() || !props.inScope}
              title={scopeTitle()}
              data-operator-only={forRole()}
              onClick={() => forward(m().id)}
            >
              Forward
            </Button>
            <Button
              variant="ghost"
              data-testid="l4-mutate"
              disabled={gated() || !props.inScope || props.mutateBlocked !== null}
              title={scopeTitle() ?? props.mutateBlocked ?? undefined}
              data-operator-only={forRole()}
              onClick={() => mutate(m().id)}
            >
              Mutate
            </Button>
            <Button
              variant="ghost"
              data-testid="l4-drop"
              disabled={gated() || !props.inScope}
              title={scopeTitle()}
              data-operator-only={forRole()}
              onClick={() => drop(m().id)}
            >
              Drop
            </Button>
            <Button
              variant="ghost"
              data-testid="l4-revert"
              disabled={gated() || !props.inScope}
              title={scopeTitle()}
              data-operator-only={forRole()}
              onClick={() => revert(m().id)}
            >
              Revert
            </Button>
            <Show when={props.operatorOnly} fallback={<Show when={!props.inScope}><span class={css.sub}>{props.scopeReason}</span></Show>}>
              {(reason) => <span class={css.sub}>{reason()}</span>}
            </Show>
          </div>
        )}
      </Match>
    </Switch>
  );
};
