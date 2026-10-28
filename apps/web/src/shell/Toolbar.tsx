// Toolbar (§2.7): sidebar toggle · record/pause · compose · clear | listening pill | Agent toggle ·
// ⌘K · layout. Icons flat, 16px, secondary; nothing outlined except the Agent toggle and the
// segmented control.
import { createSignal, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { AgentPolicy } from '~/state/app';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { Menu } from '~/components/Menu';
import { Popover } from '~/components/Popover';
import { StatusDot } from '~/components/StatusDot';
import { rectAnchor, type AnchorRect } from '~/components/floating';
import { pluralize } from '~/lib/format';
import css from './Toolbar.module.css';

const POLICY_LABEL: Record<AgentPolicy, string> = { all: 'Allow all tools', readonly: 'Read-only', paused: 'Paused' };

/** Clear with a one-step inline confirm when there is anything to clear (never window.confirm). */
export const ClearButton: Component<{ variant: 'toolbar' | 'small'; label?: string }> = (props) => {
  const app = useApp();
  const [anchor, setAnchor] = createSignal<AnchorRect | null>(null);
  const [fromKeyboard, setFromKeyboard] = createSignal(false);
  const open = (e: MouseEvent) => {
    if (app.total() === 0) return;
    setFromKeyboard(e.detail === 0);
    setAnchor(rectAnchor((e.currentTarget as HTMLElement).getBoundingClientRect()));
  };
  const confirm = () => {
    setAnchor(null);
    void app.clear();
  };
  return (
    <>
      <Button
        variant={props.variant}
        title="Clear flows"
        aria-haspopup="dialog"
        aria-expanded={anchor() != null}
        disabled={app.total() === 0}
        onClick={open}
      >
        <Show when={props.variant === 'toolbar'} fallback={props.label ?? 'Clear'}>
          <Icon name="trash-2" />
        </Show>
      </Button>
      <Show when={anchor()}>
        {(a) => (
          <Popover anchor={a()} onClose={() => setAnchor(null)} animate={!fromKeyboard()} label="Clear flows" placement={props.variant === 'small' ? 'top-start' : 'bottom-start'}>
            <form
              class={css.confirm}
              onSubmit={(e) => {
                e.preventDefault();
                confirm();
              }}
            >
              <div>Clear {pluralize(app.total(), 'flow')}?</div>
              <div class={css.confirmActions}>
                <Button variant="outline" onClick={() => setAnchor(null)}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" kbd="⏎">
                  Clear
                </Button>
              </div>
            </form>
          </Popover>
        )}
      </Show>
    </>
  );
};

export const Toolbar: Component = () => {
  const app = useApp();
  const [agentMenu, setAgentMenu] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);

  const dotHue = () => (app.proxy.armed ? 'armed' : app.proxy.listening ? 'success' : 'grey');

  return (
    <header class={css.toolbar} role="toolbar" aria-label="Capture">
      <Button variant="toolbar" title={app.ui.sidebarOpen ? 'Hide sidebar' : 'Show sidebar'} active={app.ui.sidebarOpen} onClick={() => app.toggleSidebar()}>
        <Icon name="panel-left" />
      </Button>
      <Button
        variant="toolbar"
        title={app.proxy.listening ? 'Pause capture' : 'Resume capture'}
        active={app.proxy.listening}
        aria-pressed={undefined}
        onClick={() => void app.toggleCapture()}
      >
        <Show when={app.proxy.listening} fallback={<Icon name="circle-dot" size={18} class={css.record} />}>
          <Icon name="pause" size={18} />
        </Show>
      </Button>
      <Button variant="toolbar" title="Compose request  n" onClick={() => app.openCompose(true)}>
        <Icon name="square-pen" />
      </Button>
      <ClearButton variant="toolbar" />

      <span class={css.spacer} />
      <div class={css.listen} role="status" aria-live="polite">
        <StatusDot hue={dotHue()} />
        <span>
          <b>aitmproxy</b> · {app.proxy.listening ? 'listening' : 'paused'}
          <Show when={app.proxy.address}>
            {' '}
            <b class={css.mono}>{app.proxy.address}</b>
          </Show>
          <Show when={app.proxy.protocol}> · {app.proxy.protocol}</Show>
          <Show when={app.proxy.armed}> · intercept armed</Show>
        </span>
      </div>
      <span class={css.spacer} />

      <button
        type="button"
        class={css.agent}
        data-policy={app.proxy.agent}
        title={`Agent policy: ${POLICY_LABEL[app.proxy.agent].toLowerCase()}`}
        aria-haspopup="menu"
        aria-expanded={agentMenu() != null}
        onClick={(e) => setAgentMenu({ anchor: rectAnchor(e.currentTarget.getBoundingClientRect()), kb: e.detail === 0 })}
      >
        <span class={css.switch} data-policy={app.proxy.agent} aria-hidden="true" />
        Agent
        <span class={css.agentCount}>{app.proxy.agentActionsLastMinute}</span>
      </button>
      <Show when={agentMenu()}>
        {(m) => (
          <Menu
            anchor={m().anchor}
            placement="bottom-end"
            animate={!m().kb}
            label="Agent policy"
            onClose={() => setAgentMenu(null)}
            items={[
              ...(['all', 'readonly', 'paused'] as const).map((p) => ({
                label: POLICY_LABEL[p],
                checked: app.proxy.agent === p,
                onSelect: () => void app.setAgentPolicy(p),
              })),
              { type: 'separator' as const },
              { label: 'Activity log…', onSelect: () => app.setPanel('agent') },
            ]}
          />
        )}
      </Show>

      <Button variant="toolbar" title="Command palette  ⌘K" onClick={() => app.openPalette(true)}>
        <Icon name="command" />
      </Button>

      <div class={css.seg} role="group" aria-label="Layout">
        <Button variant="toolbar" title="Inspector below" active={app.ui.layout === 'horizontal'} onClick={() => app.setLayout('horizontal')}>
          <Icon name="panel-bottom" />
        </Button>
        <Button variant="toolbar" title="Inspector right" active={app.ui.layout === 'vertical'} onClick={() => app.setLayout('vertical')}>
          <Icon name="panel-right" />
        </Button>
      </div>
    </header>
  );
};
