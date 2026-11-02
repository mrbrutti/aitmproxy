// Capture controls + the L4 scope view (ui-ext §3.3; parity spec §1, §3, §7(c)). `l4.capture.start`
// takes an interface and a direction only: the core derives the BPF from L4 scope, so there is no
// free-form operator string here (a second, unguarded definition of what gets captured). Capture
// availability is the store's live `l4.capture.status` read; while it is unavailable, or still
// pending, Start is disabled and the core's own reason is shown beside it and as its tooltip, so
// no enabled control can only fail (AC33). The scope panel shows the authorized L4 entries with
// their provenance (`config` / `runtime`). Adding one is Sensitive: the form renders ONLY when
// `tools/list` offers `l4.scope.add` with `confirmable: true` (spec §3, AC39) — against a core
// without the operator confirm there is no form, not a form that can only fail — and every add goes
// through the same confirm-over-the-wire dialog as inject, showing the core's prompt. Validation
// text is the core's; nothing here second-guesses the entry. Role (spec §7(c) D12, AC24): capture
// start/stop and the scope add are operator-only, so on a connection that is not the operator's
// (`useApp().bus.role()` is `agent` or unknown) each renders disabled with `OPERATOR_ONLY_REASON`
// and its handler returns before calling out — nothing reaches the bus even from a forced click.
import { createSignal, For, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import { useApp } from '~/state/context';
import { ConfirmInject } from './ConfirmInject';
import type { GuardedOutcome } from './inject';
import { operatorOnlyReason, supportsOperatorScopeAdd, type L4Availability, type L4Direction, type L4ScopeDraft, type L4ScopeEntryWire } from './model';
import css from './l4.module.css';

export interface CaptureControlsProps {
  /** `l4.capture.status` as the store last read it (`PENDING_AVAILABILITY` until the first reply). */
  capture: L4Availability;
  /** Running capture flow ids; one Stop button each. */
  running: readonly string[];
  canScope: boolean;
  scope: readonly L4ScopeEntryWire[];
  /** The app's `tools/list`; the add form exists iff `supportsOperatorScopeAdd(tools)`. */
  tools: readonly { name: string; confirmable?: unknown }[];
  onStart: (iface: string, direction: L4Direction) => void;
  onStop: (id: string) => void;
  /** First phase of the scope add (`l4.scope.add` without `_confirm`). */
  onAddScope: (draft: L4ScopeDraft) => Promise<GuardedOutcome>;
  /** Second phase: the same draft carrying the core's confirm token. */
  onConfirmAddScope: (draft: L4ScopeDraft, token: string) => Promise<GuardedOutcome>;
}

/** The select's value as a direction; anything unexpected falls back to the default. */
const asDirection = (v: string): L4Direction => (v === 'outbound' ? 'outbound' : 'inbound');
/** The select's value as a capability; anything unexpected falls back to the default. */
const asCapability = (v: string): L4ScopeDraft['capability'] => (v === 'inject' || v === 'intercept' ? v : 'capture');

/** A scope add awaiting the operator's confirmation: the core's prompt and token, the draft to re-send. */
interface PendingScopeAdd {
  prompt: string;
  token: string;
  draft: L4ScopeDraft;
  busy: boolean;
  /** A verbatim refusal from the confirming call, shown in the dialog. */
  refusal: string | null;
}

export const CaptureControls: Component<CaptureControlsProps> = (props) => {
  const bus = useApp().bus;
  /** The D12 gate: `null` on an operator connection, else the reason every Sensitive control shows. */
  const operatorOnly = () => operatorOnlyReason(bus.role());
  const [iface, setIface] = createSignal('lo0');
  const [direction, setDirection] = createSignal<L4Direction>('inbound');

  function start(): void {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    props.onStart(iface().trim(), direction());
  }

  function stop(id: string): void {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    props.onStop(id);
  }

  // The add form's draft, one signal per `l4.scope.add` argument.
  const [scopeCidr, setScopeCidr] = createSignal('127.0.0.1/32');
  const [scopePorts, setScopePorts] = createSignal('');
  const [scopeIface, setScopeIface] = createSignal('lo0');
  const [scopeDirection, setScopeDirection] = createSignal<L4Direction>('inbound');
  const [scopeCapability, setScopeCapability] = createSignal<L4ScopeDraft['capability']>('capture');
  const [submitting, setSubmitting] = createSignal(false);
  /** A refusal from the first phase (no dialog open yet), the core's text verbatim. */
  const [addRefusal, setAddRefusal] = createSignal<string | null>(null);
  const [pending, setPending] = createSignal<PendingScopeAdd | null>(null);

  const draft = (): L4ScopeDraft => ({
    cidr: scopeCidr().trim(),
    ports: scopePorts().trim(),
    interface: scopeIface().trim(),
    direction: scopeDirection(),
    capability: scopeCapability(),
  });

  async function submitScopeAdd(e: Event): Promise<void> {
    e.preventDefault();
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    if (submitting() || pending()) return;
    setSubmitting(true);
    setAddRefusal(null);
    const d = draft();
    try {
      const outcome = await props.onAddScope(d);
      if (outcome.kind === 'confirm') setPending({ prompt: outcome.prompt, token: outcome.token, draft: d, busy: false, refusal: null });
      else if (outcome.kind === 'refused') setAddRefusal(outcome.message);
      // `done`: the store re-read the list; nothing more to show.
    } finally {
      setSubmitting(false);
    }
  }

  async function confirmScopeAdd(): Promise<void> {
    if (operatorOnly() !== null) return; // D12: an agent connection sends nothing
    const p = pending();
    if (!p || p.busy) return;
    setPending({ ...p, busy: true, refusal: null });
    const outcome = await props.onConfirmAddScope(p.draft, p.token);
    // The operator dismissed the dialog while the core was answering: nothing to show or re-open.
    if (pending() === null) return;
    if (outcome.kind === 'done') {
      setPending(null);
      return;
    }
    setPending({ ...p, busy: false, refusal: outcome.kind === 'refused' ? outcome.message : 'the core did not accept the confirmation' });
  }

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
          disabled={operatorOnly() !== null || !props.capture.available}
          title={operatorOnly() ?? (props.capture.available ? undefined : (props.capture.reason ?? undefined))}
          data-operator-only={operatorOnly() !== null ? 'true' : undefined}
          onClick={() => start()}
        >
          Start capture
        </Button>
      </div>
      <Show when={operatorOnly() ?? (props.capture.available ? null : props.capture.reason)}>
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
              <Button
                variant="outline"
                aria-label={`Stop capture ${id}`}
                disabled={operatorOnly() !== null}
                title={operatorOnly() ?? undefined}
                data-operator-only={operatorOnly() !== null ? 'true' : undefined}
                onClick={() => stop(id)}
              >
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
                <div data-testid="l4-scope-entry" data-source={e.source}>
                  {e.interface} · {e.cidr}:{e.ports} · {e.capability} · {e.inject_rate.pps}pps
                  <Show when={e.source}>{(source) => <span class={css.sub}> · {source()}</span>}</Show>
                </div>
              )}
            </For>
          </Show>
        </div>
      </Show>
      <Show when={supportsOperatorScopeAdd(props.tools)}>
        <form class={css.controls} aria-label="Add L4 scope" data-testid="l4-scope-add-form" onSubmit={(e) => void submitScopeAdd(e)}>
          <label class={css.field}>
            cidr
            <input class={css.input} value={scopeCidr()} onInput={(e) => setScopeCidr(e.currentTarget.value)} aria-label="Scope CIDR" />
          </label>
          <label class={css.field}>
            ports
            <input
              class={css.input}
              value={scopePorts()}
              onInput={(e) => setScopePorts(e.currentTarget.value)}
              aria-label="Scope ports"
              placeholder="all ports"
            />
          </label>
          <label class={css.field}>
            interface
            <input class={css.input} value={scopeIface()} onInput={(e) => setScopeIface(e.currentTarget.value)} aria-label="Scope interface" />
          </label>
          <label class={css.field}>
            direction
            <select
              class={css.input}
              value={scopeDirection()}
              onChange={(e) => setScopeDirection(asDirection(e.currentTarget.value))}
              aria-label="Scope direction"
            >
              <option value="inbound">inbound</option>
              <option value="outbound">outbound</option>
            </select>
          </label>
          <label class={css.field}>
            capability
            <select
              class={css.input}
              value={scopeCapability()}
              onChange={(e) => setScopeCapability(asCapability(e.currentTarget.value))}
              aria-label="Scope capability"
            >
              <option value="capture">capture</option>
              <option value="inject">inject</option>
              <option value="intercept">intercept</option>
            </select>
          </label>
          <Button
            variant="outline"
            type="submit"
            data-testid="l4-scope-add"
            disabled={operatorOnly() !== null || submitting() || pending() !== null}
            title={operatorOnly() ?? undefined}
            data-operator-only={operatorOnly() !== null ? 'true' : undefined}
          >
            Add L4 scope
          </Button>
        </form>
        <Show when={addRefusal()}>
          {(message) => (
            <p role="alert" class={css.note} data-testid="l4-scope-add-refusal">
              {message()}
            </p>
          )}
        </Show>
        <Show when={pending()}>
          {(p) => (
            <ConfirmInject
              title="Confirm L4 scope add"
              prompt={p().prompt}
              refusal={p().refusal}
              busy={p().busy}
              onConfirm={() => void confirmScopeAdd()}
              onCancel={() => setPending(null)}
            />
          )}
        </Show>
      </Show>
    </section>
  );
};
