// The lower-region L4 inspector: shown (by kind) when the selected flow is an L4 session. It is the
// inspector half of the retired L4Panel — the packet list → layer tree → craft → intercept view
// plus the guarded inject/forward/drop/mutate/revert confirm path — now driven by the lifted L4
// store and the app's single selection, so L4 lives in the one unified flow list exactly like the
// TUI and macOS. The wire is reached only through `l4.inject` / `l4.intercept.*` via the confirm
// path, and every intercept verdict carries the parked packet's id (parity spec §4) built by the
// `model.ts` builders — never a hand-built literal.
import { createSignal, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { L4Store } from './store';
import { ConfirmInject } from './ConfirmInject';
import { L4Inspector } from './L4Inspector';
import { beginGuarded, beginInject, confirmGuarded, confirmInject, type InjectArgs } from './inject';
import { interceptBarModel, mutateArgs, revertArgs, verdictArgs, type PacketSpec } from './model';
import css from './l4.module.css';

interface Pending {
  title: string;
  prompt: string;
  token: string;
  injectArgs?: InjectArgs;
  tool: string;
  params: Record<string, unknown>;
  busy?: boolean;
  refusal?: string | null;
}

export const L4InspectorPanel: Component<{ store: L4Store }> = (props) => {
  const app = useApp();
  const store = props.store;
  const [pending, setPending] = createSignal<Pending | null>(null);

  const afterSend = (sent: number) => {
    app.notice(`Injected ${sent} packet${sent === 1 ? '' : 's'} to the wire`);
    setPending(null);
    void store.refresh();
  };

  const onInject = async (args: InjectArgs) => {
    const outcome = await beginInject(store.call, args);
    if (outcome.kind === 'confirm') {
      setPending({ title: 'Confirm inject to the wire', prompt: outcome.prompt, token: outcome.token, injectArgs: args, tool: 'l4.inject', params: injectParams(args) });
    } else if (outcome.kind === 'sent') afterSend(outcome.sent);
    else app.notice(outcome.message, 'error');
  };

  // Every intercept verdict takes the same guarded confirm path (operator confirm-over-the-wire):
  // `params` is the builder's output for that verb and is re-sent verbatim with `_confirm` on
  // confirm. The core may ask for confirmation on any of the four, so all four go through here.
  const verdict = async (tool: string, label: string, params: Record<string, unknown>) => {
    const outcome = await beginGuarded(store.call, tool, params);
    if (outcome.kind === 'confirm') setPending({ title: `Confirm ${label} the parked packet`, prompt: outcome.prompt, token: outcome.token, tool, params });
    else if (outcome.kind === 'done') {
      app.notice(`${label} done`);
      void store.refresh(true);
    } else app.notice(outcome.message, 'error');
  };
  const onForward = (parkedId: string) => void verdict('l4.intercept.forward', 'Forward', verdictArgs(parkedId));
  const onDrop = (parkedId: string) => void verdict('l4.intercept.drop', 'Drop', verdictArgs(parkedId));
  const onMutate = (parkedId: string, spec: PacketSpec) => void verdict('l4.intercept.mutate', 'Mutate', mutateArgs(parkedId, spec));
  const onRevert = (parkedId: string) => void verdict('l4.intercept.revert', 'Revert', revertArgs(parkedId));

  const confirm = async () => {
    const p = pending();
    if (!p) return;
    setPending({ ...p, busy: true, refusal: null });
    const outcome = p.injectArgs
      ? await confirmInject(store.call, p.injectArgs, p.token)
      : await confirmGuarded(store.call, p.tool, p.params, p.token);
    // The operator dismissed the dialog while the core was answering: nothing to show or re-open.
    if (pending() === null) return;
    if (p.injectArgs) {
      if (outcome.kind === 'sent') return afterSend(outcome.sent);
    } else if (outcome.kind === 'done') {
      app.notice(`${p.title} — done`);
      setPending(null);
      void store.refresh(true);
      return;
    }
    setPending({ ...p, busy: false, refusal: outcome.kind === 'refused' ? outcome.message : 'the core did not accept the confirmation' });
  };

  return (
    <div class={css.inspectorCol}>
      <Show
        when={store.selectedFlow() && store.selectedRow()}
        fallback={<p class={css.l4Empty}>Select an L4 session to inspect its packets and craft a packet.</p>}
      >
        <L4Inspector
          flow={store.selectedFlow()!}
          row={store.selectedRow()!}
          caps={store.caps()}
          interceptModel={interceptBarModel(store.interceptAvailability(), store.parked(), store.selectedFlow()!.id)}
          onBuild={store.craft}
          onInject={onInject}
          onForward={onForward}
          onMutate={onMutate}
          onDrop={onDrop}
          onRevert={onRevert}
          onLoadMore={() => void store.loadMore()}
        />
      </Show>

      <Show when={pending()}>
        {(p) => (
          <ConfirmInject
            title={p().title}
            prompt={p().prompt}
            args={p().injectArgs}
            refusal={p().refusal}
            busy={p().busy}
            onConfirm={() => void confirm()}
            onCancel={() => setPending(null)}
          />
        )}
      </Show>
    </div>
  );
};

function injectParams(args: InjectArgs): Record<string, unknown> {
  const w: Record<string, unknown> = { spec: args.spec, dst: args.dst, interface: args.interface };
  if (args.port != null) w.port = args.port;
  if (args.count != null) w.count = args.count;
  return w;
}
