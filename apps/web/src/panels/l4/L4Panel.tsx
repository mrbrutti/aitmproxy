// The web L4 operator surface (ui-ext Part 3, L4OPS Task 12): the union flow list (http/ws from the
// HTTP store + l4 from `l4.flow.list`), capture controls with the L4 scope view, the L4 inspector,
// and the guarded inject confirm dialog. Feature-detected throughout: when `l4.*` is absent the
// panel says so in place (honest degradation), it does not fake an L4 surface. The wire is reached
// only through `l4.inject` / `l4.intercept.*` via the confirm path.
import { createMemo, createSignal, onMount, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Icon } from '~/components';
import { CaptureControls } from './CaptureControls';
import { ConfirmInject } from './ConfirmInject';
import { L4Inspector } from './L4Inspector';
import { UnionFlowList } from './UnionFlowList';
import { createL4Store } from './store';
import { beginGuarded, beginInject, confirmGuarded, confirmInject, type InjectArgs } from './inject';
import { summaryRow, type UnionRow } from './model';
import css from './l4.module.css';

interface Pending {
  title: string;
  prompt: string;
  token: string;
  /** For an inject, the authored target (rendered as facts); absent for forward/drop. */
  injectArgs?: InjectArgs;
  /** The tool + params to re-issue with `_confirm`. */
  tool: string;
  params: Record<string, unknown>;
  busy?: boolean;
  refusal?: string | null;
}

export const L4Panel: Component = () => {
  const app = useApp();
  const store = createL4Store(app);
  const [pending, setPending] = createSignal<Pending | null>(null);

  onMount(() => void store.refresh());

  // The union list merges the HTTP/WS flows (already in the app store) with the L4 flows.
  const unionRows = createMemo<UnionRow[]>(() => {
    app.version();
    const http = app.entries.map((e) => summaryRow(e.raw));
    return [...http, ...store.rows()];
  });

  const onSelect = (id: string) => {
    if (store.ids().includes(id)) store.setSelectedId(id);
    else app.select(id); // an http/ws row — hand off to the main inspector
  };

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

  // Forward / Drop reach the wire through the same confirm path (operator confirm-over-the-wire).
  const onVerb = (tool: string, label: string) => async () => {
    const id = store.firstParkedId();
    if (!id) {
      app.notice('No parked packet to act on', 'error');
      return;
    }
    const params = { id };
    const outcome = await beginGuarded(store.call, tool, params);
    if (outcome.kind === 'confirm') setPending({ title: `Confirm ${label} the parked packet`, prompt: outcome.prompt, token: outcome.token, tool, params });
    else if (outcome.kind === 'done') {
      app.notice(`${label} done`);
      void store.refresh();
    } else app.notice(outcome.message, 'error');
  };

  const confirm = async () => {
    const p = pending();
    if (!p) return;
    setPending({ ...p, busy: true, refusal: null });
    const outcome = p.injectArgs
      ? await confirmInject(store.call, p.injectArgs, p.token)
      : await confirmGuarded(store.call, p.tool, p.params, p.token);
    if (p.injectArgs) {
      if (outcome.kind === 'sent') return afterSend(outcome.sent);
    } else if (outcome.kind === 'done') {
      app.notice(`${p.title} — done`);
      setPending(null);
      void store.refresh();
      return;
    }
    setPending({ ...p, busy: false, refusal: outcome.kind === 'refused' ? outcome.message : 'the core did not accept the confirmation' });
  };

  return (
    <section class={css.panel} aria-label="L4">
      <header class={css.header}>
        <Icon name="circle-dot" />
        <h2>L4 — raw packets</h2>
        <span class={css.headerMeta}>
          <Show when={store.present()} fallback="l4 disabled">
            {store.ids().length} session{store.ids().length === 1 ? '' : 's'}
          </Show>
        </span>
      </header>

      <Show
        when={store.present()}
        fallback={
          <p class={css.l4Empty}>
            L4 is not enabled on this core — no `l4.*` commands are advertised. Start the core with `l4.enabled: true` (and the
            privilege / scope to use it) to drive raw-packet capture, craft and inject from here.
          </p>
        }
      >
        <div class={css.body}>
          <div class={css.listCol}>
            <CaptureControls
              canCapture={store.caps().capture}
              canScope={store.caps().scope}
              activeCaptures={store.captureIds().length}
              scope={store.scope()}
              onStart={(iface, filter) => void store.startCapture(iface, filter)}
            />
            <UnionFlowList rows={unionRows()} selectedId={store.selectedId()} onSelect={onSelect} />
          </div>
          <div class={css.inspectorCol}>
            <Show when={store.selectedFlow() && store.selectedRow()} fallback={<p class={css.l4Empty}>Select an L4 session to inspect its packets and craft a packet.</p>}>
              <L4Inspector
                flow={store.selectedFlow()!}
                row={store.selectedRow()!}
                caps={store.caps()}
                interceptParked={store.interceptParked()}
                onBuild={store.craft}
                onInject={onInject}
                onForward={onVerb('l4.intercept.forward', 'Forward')}
                onMutate={() => app.notice('Author the mutation in the craft editor, then Forward the parked packet', 'info')}
                onDrop={onVerb('l4.intercept.drop', 'Drop')}
              />
            </Show>
          </div>
        </div>
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
    </section>
  );
};

function injectParams(args: InjectArgs): Record<string, unknown> {
  const w: Record<string, unknown> = { spec: args.spec, dst: args.dst, interface: args.interface };
  if (args.port != null) w.port = args.port;
  if (args.count != null) w.count = args.count;
  return w;
}
