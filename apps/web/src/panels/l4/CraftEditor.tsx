// The L4 craft editor (ui-ext §3.2, L4OPS-AC8/AC9/AC10): author a `PacketSpec` as human-friendly
// YAML in CodeMirror, `Build` it to bytes (a hex preview, via `l4.craft`), then `Inject` it — which
// goes through the guarded confirm path only. Scope-as-authorization: when the session is out of L4
// scope every craft/inject action is disabled with the scope reason as its tooltip (the Rhai craft
// path is deferred to the protocol-extensible seam — the hook is here, not the build).
import { createMemo, createSignal, Show, type Component } from 'solid-js';
import { Button } from '~/components/Button';
import { HexViewer } from '~/viewers/HexViewer';
import { CodeViewer } from '~/viewers/CodeViewer';
import { base64ToBytes } from '~/lib/bytes';
import { DEFAULT_CRAFT_YAML, parsePacketSpec, type L4CraftResult } from './model';
import type { InjectArgs } from './inject';
import css from './l4.module.css';

export interface CraftEditorProps {
  /** The bound interface for this L4 session (prefilled from the flow). */
  interface: string;
  inScope: boolean;
  scopeReason: string;
  /** `l4.craft` present on the bus. */
  canCraft: boolean;
  /** `l4.inject` present on the bus. */
  canInject: boolean;
  /** Build the current spec to bytes + summary (`l4.craft`); throws its error. */
  onBuild: (spec: { layers: Record<string, unknown>[] }) => Promise<L4CraftResult>;
  /** Hand the authored inject off to the guarded confirm path. */
  onInject: (args: InjectArgs) => void;
}

export const CraftEditor: Component<CraftEditorProps> = (props) => {
  const [yaml, setYaml] = createSignal(DEFAULT_CRAFT_YAML);
  const [dst, setDst] = createSignal('127.0.0.1');
  const [port, setPort] = createSignal('9');
  const [count, setCount] = createSignal('1');
  const [preview, setPreview] = createSignal<L4CraftResult | null>(null);
  const [buildError, setBuildError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const parsed = createMemo(() => parsePacketSpec(yaml()));
  const parseError = () => {
    const p = parsed();
    return 'error' in p ? p.error : null;
  };
  const disabledReason = () => (!props.inScope ? props.scopeReason : parseError() ? `Fix the PacketSpec: ${parseError()}` : null);

  const build = async () => {
    const p = parsed();
    if ('error' in p) {
      setBuildError(p.error);
      return;
    }
    setBusy(true);
    setBuildError(null);
    try {
      setPreview(await props.onBuild(p.spec));
    } catch (e) {
      setPreview(null);
      setBuildError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const inject = () => {
    const p = parsed();
    if ('error' in p) {
      setBuildError(p.error);
      return;
    }
    const portN = port().trim() === '' ? undefined : Number(port());
    const countN = count().trim() === '' ? undefined : Number(count());
    props.onInject({ spec: p.spec, dst: dst().trim(), interface: props.interface, port: portN, count: countN });
  };

  const previewBytes = () => {
    const pv = preview();
    return pv ? base64ToBytes(pv.bytes) : null;
  };

  return (
    <section class={css.section} aria-label="Craft">
      <div class={css.sectionHead}>Craft packet</div>
      <div class={css.craft}>
        <Show when={!props.inScope}>
          <p class={css.dimReason}>{props.scopeReason}</p>
        </Show>
        <div class={css.craftEditor}>
          <CodeViewer active label="PacketSpec (YAML)" doc={{ key: 'l4-craft', text: yaml(), lang: 'yaml', editable: true, onChange: setYaml }} />
        </div>
        <div class={css.craftRow}>
          <label class={css.field}>
            dst
            <input class={css.input} value={dst()} onInput={(e) => setDst(e.currentTarget.value)} aria-label="Destination IP" />
          </label>
          <label class={css.field}>
            port
            <input class={css.input} value={port()} onInput={(e) => setPort(e.currentTarget.value)} aria-label="Destination port" />
          </label>
          <label class={css.field}>
            count
            <input class={css.input} value={count()} onInput={(e) => setCount(e.currentTarget.value)} aria-label="Count" />
          </label>
        </div>
        <div class={css.craftRow}>
          <Button
            variant="outline"
            disabled={!props.canCraft || !props.inScope || busy()}
            title={!props.canCraft ? 'l4.craft is not available on this core' : (disabledReason() ?? undefined)}
            onClick={() => void build()}
          >
            Build
          </Button>
          <Button
            variant="primary"
            data-testid="l4-inject"
            disabled={!props.canInject || !props.inScope || !!parseError() || busy()}
            title={!props.canInject ? 'l4.inject is not available on this core' : (disabledReason() ?? undefined)}
            onClick={() => inject()}
          >
            Inject…
          </Button>
          <Show when={parseError()}>
            <span class={css.craftError}>{parseError()}</span>
          </Show>
        </div>
        <Show when={buildError()}>
          <p class={css.craftError} role="alert">
            {buildError()}
          </p>
        </Show>
        <Show when={preview()}>
          {(pv) => (
            <div class={css.craftPreview}>
              <div class={css.craftLayers}>
                {pv().summary.layers.join(' / ')} · {pv().length} bytes
              </div>
              <Show when={previewBytes()}>{(b) => <div class={css.hexWrap}><HexViewer bytes={b()} /></div>}</Show>
            </div>
          )}
        </Show>
      </div>
    </section>
  );
};
