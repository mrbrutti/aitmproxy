// Intercept bar (§2.7): hidden when disarmed (the Shell gates it on app.proxy.armed). Armed with
// nothing paused: tint fill, deep text. With paused flows: base fill, on-colour text, pulsing dot,
// the oldest paused flow as the target, Resume / Resume all / Kill ▾ / Rules… / Disarm.
import { createSignal, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import type { KillMode } from '~/state/app';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { Menu } from '~/components/Menu';
import { rectAnchor, type AnchorRect } from '~/components/floating';
import { flowUrl } from '~/model/flow';
import css from './InterceptBar.module.css';

export const InterceptBar: Component = () => {
  const app = useApp();
  const paused = () => app.proxy.pausedIds.length;
  const target = () => app.oldestPaused();
  const [killMenu, setKillMenu] = createSignal<{ anchor: AnchorRect; kb: boolean } | null>(null);

  const kill = (mode: KillMode) => {
    const t = target();
    if (t) void app.kill(t.id, mode);
  };

  return (
    <div class={css.bar} data-paused={paused() > 0 ? 'true' : 'false'} role="status" aria-live="polite">
      <Show
        when={paused() > 0}
        fallback={
          <>
            <Icon name="hand" class={css.icon} />
            <span class={css.text}>
              <b>Intercept armed</b> — every request pauses here
            </span>
            <div class={css.actions}>
              <Button variant="ghost" kbd="i" onClick={() => void app.arm(false)}>
                Disarm
              </Button>
              <Button variant="ghost" disabled title="Breakpoint rules need core follow-up F3">
                Rules…
              </Button>
            </div>
          </>
        }
      >
        <Icon name="hand" class={css.icon} />
        <span class={css.pulse} aria-hidden="true" />
        <span class={css.count}>{paused()} paused</span>
        <Show when={target()}>
          {(t) => (
            <span class={css.target} title={flowUrl(t().flow)}>
              <b>{t().flow.kind === 'websocket' ? 'WS' : t().flow.method}</b> {flowUrl(t().flow)}
              <Show when={t().flow.edited}> · edited</Show>
            </span>
          )}
        </Show>
        <div class={css.actions}>
          <Button variant="primary" kbd="⌘⏎" disabled={!target()} onClick={() => target() && void app.resume(target()!.id)}>
            {target()?.flow.edited ? 'Apply & Resume' : 'Resume'}
          </Button>
          <Button variant="ghost" onClick={() => void app.resumeAll()}>
            Resume all
          </Button>
          <Button
            variant="ghost"
            kbd="⌘\"
            disabled={!target()}
            aria-haspopup="menu"
            aria-expanded={killMenu() != null}
            onClick={(e) => setKillMenu({ anchor: rectAnchor(e.currentTarget.getBoundingClientRect()), kb: e.detail === 0 })}
          >
            Kill
            <Icon name="chevron-down" size={12} />
          </Button>
          <Button variant="ghost" disabled title="Breakpoint rules need core follow-up F3">
            Rules…
          </Button>
          <Button variant="ghost" kbd="i" onClick={() => void app.arm(false)}>
            Disarm
          </Button>
        </div>
        <Show when={killMenu()}>
          {(m) => (
            <Menu
              anchor={m().anchor}
              placement="top-start"
              animate={!m().kb}
              label="Kill"
              onClose={() => setKillMenu(null)}
              items={[
                { label: 'Reset connection', kbd: '⌘\\', onSelect: () => kill('reset') },
                { label: 'Respond 429 Too Many Requests', onSelect: () => kill('429') },
                { label: 'Respond 503 Service Unavailable', onSelect: () => kill('503') },
              ]}
            />
          )}
        </Show>
      </Show>
    </div>
  );
};
