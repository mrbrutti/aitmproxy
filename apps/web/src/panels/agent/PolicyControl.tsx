// The agent policy as a segmented control: Allow all tools · Read-only · Paused (§2.7 "Agent
// toggle", §4.8). A radiogroup: arrows move, the active segment carries the raised fill, and one
// line under it says what the choice means. Disabled, with the reason as a tooltip, until the
// core gains `agent.set` (F1).
import { For, type Component } from 'solid-js';
import { Eye, Pause, Shield } from 'lucide-solid';
import { Dynamic } from 'solid-js/web';
import type { AgentPolicy } from '~/state/app';
import { POLICY_OPTIONS } from './activity';
import css from './AgentPanel.module.css';

const ICONS = { all: Shield, readonly: Eye, paused: Pause } as const;

export const PolicyControl: Component<{
  value: AgentPolicy;
  onChange: (p: AgentPolicy) => void;
  disabled?: boolean | undefined;
  disabledReason?: string | undefined;
}> = (props) => {
  const buttons: HTMLButtonElement[] = [];
  const explain = () => POLICY_OPTIONS.find((o) => o.id === props.value)?.explain ?? '';

  const onKey = (e: KeyboardEvent, i: number) => {
    if (props.disabled) return;
    const delta = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = (i + delta + POLICY_OPTIONS.length) % POLICY_OPTIONS.length;
    const opt = POLICY_OPTIONS[next]!;
    buttons[next]?.focus();
    if (opt.id !== props.value) props.onChange(opt.id);
  };

  return (
    <div class={css.policy}>
      <div
        class={css.segmented}
        role="radiogroup"
        aria-label="Agent policy"
        aria-disabled={props.disabled ? 'true' : undefined}
        title={props.disabled ? props.disabledReason : undefined}
      >
        <For each={POLICY_OPTIONS}>
          {(opt, i) => (
            <button
              ref={(n) => (buttons[i()] = n)}
              type="button"
              role="radio"
              class={css.segment}
              aria-checked={props.value === opt.id}
              tabIndex={props.value === opt.id ? 0 : -1}
              disabled={props.disabled}
              data-policy={opt.id}
              onClick={() => {
                if (opt.id !== props.value) props.onChange(opt.id);
              }}
              onKeyDown={(e) => onKey(e, i())}
            >
              <Dynamic component={ICONS[opt.id]} size={12} strokeWidth={1.5} aria-hidden="true" />
              {opt.label}
            </button>
          )}
        </For>
      </div>
      <p class={css.explain} aria-live="polite">
        {explain()}
      </p>
    </div>
  );
};
