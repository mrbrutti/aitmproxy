// The Scan launch header (spec §Design "Launch header"): a schema-driven form over `scan.discover`'s
// inputSchema, with the target bound to the authorized scope. The target is chosen from the in-scope
// hosts (deny-by-default: an out-of-scope target cannot be launched), scheme is https by default, and
// the remaining schema fields (max_depth / max_pages) come straight from the tool via SchemaForm. An
// "add to scope" affordance reuses the existing scope-add path.
import { createMemo, createSignal, For, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import type { ToolDef } from '~/bus/types';
import { SchemaForm, createFormState } from '~/lib/schema-form';
import { AddHost } from '~/panels/scope/AddHost';
import css from './scan.module.css';

export interface LaunchFormProps {
  tool: ToolDef;
  scopeHosts: readonly string[];
  running: boolean;
  onAddHost: (host: string) => void | Promise<unknown>;
  onLaunch: (args: Record<string, unknown>) => void;
}

export const LaunchForm: Component<LaunchFormProps> = (props) => {
  const [scheme, setScheme] = createSignal<'https' | 'http'>('https');
  const [host, setHost] = createSignal('');

  // Only a concrete host can be a crawl seed; a `*.wildcard` scope entry is authorization, not a URL.
  const hosts = createMemo(() => props.scopeHosts.filter((h) => !h.startsWith('*.')));

  // Build the form from the tool's inputSchema minus `target`: the target is scope-bound here, chosen
  // from the authorized hosts, never typed free-hand. The rest of the schema drives the form.
  // Built once from the (stable) scan.discover schema minus `target`; not reactive by design.
  const properties = { ...(props.tool.inputSchema.properties ?? {}) };
  delete properties.target;
  const formTool: Pick<ToolDef, 'inputSchema'> = {
    inputSchema: { ...props.tool.inputSchema, properties, required: (props.tool.inputSchema.required ?? []).filter((r) => r !== 'target') },
  };
  const form = createFormState(formTool);

  const target = () => `${scheme()}://${host()}/`;
  const canLaunch = () => !props.running && host() !== '' && form.result().valid;

  const launch = () => {
    form.touchAll();
    if (!canLaunch()) return;
    props.onLaunch({ target: target(), ...form.result().args });
  };

  return (
    <div class={css.launch}>
      <div class={css.targetRow}>
        <div class={css.field}>
          <label class={css.label} for="scan-scheme">
            Scheme
          </label>
          <span class={css.selectWrap}>
            <select id="scan-scheme" class={css.select} aria-label="Scheme" value={scheme()} onChange={(e) => setScheme(e.currentTarget.value === 'http' ? 'http' : 'https')}>
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
          </span>
        </div>
        <div class={`${css.field} ${css.grow}`}>
          <label class={css.label} for="scan-target">
            Target
          </label>
          <Show
            when={hosts().length > 0}
            fallback={<p class={css.note}>No in-scope host to target — add one below.</p>}
          >
            <span class={css.selectWrap}>
              <select id="scan-target" class={css.select} aria-label="Target" value={host()} onChange={(e) => setHost(e.currentTarget.value)}>
                <option value="">Choose an in-scope host…</option>
                <For each={hosts()}>{(h) => <option value={h}>{h}</option>}</For>
              </select>
            </span>
          </Show>
        </div>
      </div>

      <SchemaForm form={form} idPrefix="scan" onSubmit={launch} />

      <div class={css.actions}>
        <Button variant="primary" disabled={!canLaunch()} onClick={launch}>
          Discover
        </Button>
        <Show when={host()}>
          <span class={css.targetUrl} title={target()}>
            {target()}
          </span>
        </Show>
      </div>

      <div class={css.addWrap}>
        <span class={css.addLabel}>Widen scope</span>
        <AddHost existing={props.scopeHosts} onAdd={props.onAddHost} />
      </div>
    </div>
  );
};
