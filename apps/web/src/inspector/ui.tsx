// Small inspector-local primitives the shared components do not cover: the status pill, the
// 24px outlined control, key : value lists, the grey-bar skeleton, the clipboard helper.

import { For, Show, splitProps, type Component, type JSX, type ParentComponent } from 'solid-js';
import { statusHue, type FlowSummary } from '~/model/flow';
import css from './inspector.module.css';

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

/** Missing value → grey dash (§2.8). */
export const Dash: Component<{ class?: string }> = (props) => (
  <span class={`${css.dash}${props.class ? ` ${props.class}` : ''}`} aria-label="none">
    —
  </span>
);

/** `200 OK` tinted by status class; `Paused · request`; `Killed`; `—` pending. */
export const StatusPill: Component<{ flow: Pick<FlowSummary, 'status' | 'statusText' | 'intercept' | 'error'> }> = (props) => {
  const hue = () => statusHue(props.flow);
  const label = () => {
    switch (hue()) {
      case 'paused':
        return 'Paused · request';
      case 'killed':
        return 'Killed';
      case 'pending':
        return '—';
      default:
        return props.flow.status != null ? `${props.flow.status}${props.flow.statusText ? ` ${props.flow.statusText}` : ''}` : (props.flow.error ?? '—');
    }
  };
  return (
    <span class={css.statusPill} data-hue={hue()} title={props.flow.error ?? undefined}>
      {label()}
    </span>
  );
};

/** 24px, 1px outline, nothing filled: the format picker and the find button. */
export const Control: ParentComponent<JSX.ButtonHTMLAttributes<HTMLButtonElement> & { icon?: boolean }> = (props) => {
  const [local, rest] = splitProps(props, ['class', 'children', 'icon', 'type']);
  return (
    <button type={local.type ?? 'button'} class={`${css.control}${local.icon ? ` ${css.controlIcon}` : ''}${local.class ? ` ${local.class}` : ''}`} {...rest}>
      {local.children}
    </button>
  );
};

/** A plain 28px hover button (copy, retry): no border, hover fill only. */
export const Quiet: ParentComponent<JSX.ButtonHTMLAttributes<HTMLButtonElement>> = (props) => {
  const [local, rest] = splitProps(props, ['class', 'children', 'type']);
  return (
    <button type={local.type ?? 'button'} class={`${css.quiet}${local.class ? ` ${local.class}` : ''}`} {...rest}>
      {local.children}
    </button>
  );
};

export interface KvRow {
  k: string;
  v: JSX.Element | string | number | null | undefined;
  /** Render the value in the UI face instead of mono (prose, labels). */
  ui?: boolean;
  title?: string;
}

/** Hairline-ruled key : value list in the data face; nulls print as the dash. */
export const KvList: Component<{ rows: KvRow[]; class?: string; label?: string }> = (props) => (
  <dl class={`${css.kv}${props.class ? ` ${props.class}` : ''}`} aria-label={props.label}>
    <For each={props.rows}>
      {(r) => (
        <div class={css.kvRow}>
          <dt class={css.kvKey}>{r.k}</dt>
          <dd class={css.kvVal} classList={{ [css.kvUi!]: !!r.ui }} title={r.title}>
            <Show when={r.v != null && r.v !== ''} fallback={<Dash />}>
              {r.v}
            </Show>
          </dd>
        </div>
      )}
    </For>
  </dl>
);

/** Loading state: grey bars at the final row height, no shimmer, no layout shift (§2.8). */
export const Bars: Component<{ rows?: number; height?: number; label?: string }> = (props) => {
  const widths = [72, 96, 64, 112, 80, 56, 104, 88];
  const vals = [180, 320, 140, 260, 220, 120, 300, 200];
  return (
    <div class={css.bars} role="status" aria-label={props.label ?? 'Loading'} style={{ '--bar-h': `${props.height ?? 28}px` }}>
      <For each={Array.from({ length: props.rows ?? 6 }, (_, i) => i)}>
        {(i) => (
          <div class={css.barRow}>
            <i class={css.bar} style={{ width: `${widths[i % widths.length]}px` }} />
            <i class={css.bar} style={{ width: `${vals[i % vals.length]}px` }} />
          </div>
        )}
      </For>
    </div>
  );
};

/** Centred one-line message in the UI face (empty states inside a pane). */
export const Centered: ParentComponent<{ class?: string }> = (props) => <div class={`${css.centered}${props.class ? ` ${props.class}` : ''}`}>{props.children}</div>;
