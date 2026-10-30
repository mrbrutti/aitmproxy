// The Scan view (spec §Design, AC3/AC6 web). Shown in the lower region when app.ui.panel === 'scan'.
// Mirrors the Findings/Scope panels and reuses the schema-form, the scope surface and the virtual list
// rather than inventing new infrastructure. Viewing the panel calls nothing: a scan runs only on an
// explicit, scope-bound form submit (deny-by-default). The result renders the discovered endpoints and
// injection points; each injection point links back to its flow.
import { createMemo, createSignal, Show, type Component } from 'solid-js';
import { Icon } from '~/components';
import { useApp } from '~/state/context';
import type { ToolDef } from '~/bus/types';
import { LaunchForm } from './LaunchForm';
import { VirtualList } from './VirtualList';
import { parseScanResult, type InjectionPointRow, type ScanResult } from './model';
import css from './scan.module.css';

const ENDPOINT_ROW = 28;
const POINT_ROW = 44;

export const Scan: Component = () => {
  const app = useApp();
  const tool = createMemo<ToolDef | undefined>(() => app.proxy.tools.find((t) => t.name === 'scan.discover'));
  const scopeHosts = createMemo(() => app.proxy.scope.map((s) => s.host));
  const [running, setRunning] = createSignal(false);
  const [result, setResult] = createSignal<ScanResult | null>(null);

  const launch = async (args: Record<string, unknown>) => {
    if (running()) return;
    setRunning(true);
    try {
      const raw = await app.scanDiscover(args);
      if (raw != null) setResult(parseScanResult(raw));
    } finally {
      setRunning(false);
    }
  };

  // injection_points → flow: each point carries the flow it was found in; open it through the existing
  // detail loader, exactly as the flow list does.
  const openFlow = (flowId: string) => {
    if (flowId) void app.loadDetail(flowId);
  };

  return (
    <section class={css.panel} aria-label="Scan">
      <header class={css.header}>
        <Icon name="search" class={css.icon} />
        <h2 class={css.title}>Scan</h2>
        <span class={css.sub}>Discover reachable in-scope URLs and their injection points.</span>
      </header>

      <div class={css.scrollBody}>
        <Show when={tool()} fallback={<p class={css.empty}>scan.discover is not offered by this server.</p>}>
          {(t) => (
            <LaunchForm tool={t()} scopeHosts={scopeHosts()} running={running()} onAddHost={(h) => app.addScope(h)} onLaunch={(args) => void launch(args)} />
          )}
        </Show>

        <Show when={result()}>
          {(r) => (
            <>
              <section class={css.results}>
                <h3 class={css.sectionTitle}>
                  Endpoints <span class={css.n}>{r().endpoints.length}</span>
                </h3>
                {/* endpoint → flow is a Stage-1 parity gap (consistent with the TUI view): `endpoints`
                    are plain URL strings with no flow id, and the store resolves a flow only by id, so
                    linking an endpoint to its flow needs a backend flow-id-per-endpoint. Until then,
                    endpoints render as plain rows. */}
                <Show when={r().endpoints.length > 0} fallback={<p class={css.empty}>No endpoints reached.</p>}>
                  <VirtualList items={r().endpoints} rowHeight={ENDPOINT_ROW} label="Endpoints">
                    {(url) => (
                      <div class={css.endpoint} data-endpoint title={url}>
                        <span class={css.url}>{url}</span>
                      </div>
                    )}
                  </VirtualList>
                </Show>
              </section>

              <section class={css.results}>
                <h3 class={css.sectionTitle}>
                  Injection points <span class={css.n}>{r().injectionPoints.length}</span>
                </h3>
                <Show when={r().injectionPoints.length > 0} fallback={<p class={css.empty}>No injection points observed.</p>}>
                  <VirtualList items={r().injectionPoints} rowHeight={POINT_ROW} label="Injection points">
                    {(p) => <PointRow point={p} onOpen={() => openFlow(p.flow)} />}
                  </VirtualList>
                </Show>
              </section>

              <footer class={css.meta}>
                <span>{r().pagesCrawled ?? 0} pages crawled</span>
                <Show when={r().stoppedReason}>{(reason) => <span class={css.stopped}>stopped: {reason()}</span>}</Show>
              </footer>
            </>
          )}
        </Show>
      </div>
    </section>
  );
};

const PointRow: Component<{ point: InjectionPointRow; onOpen: () => void }> = (props) => (
  <button type="button" class={css.point} data-point data-flow={props.point.flow} title={`Open flow ${props.point.flow}`} onClick={props.onOpen}>
    <span class={css.loc} data-loc={props.point.location}>
      {props.point.location}
    </span>
    <span class={css.pname}>{props.point.name}</span>
    {/* Render the engine-redacted example verbatim — never reconstruct a raw value. */}
    <span class={css.example}>{props.point.example}</span>
  </button>
);
