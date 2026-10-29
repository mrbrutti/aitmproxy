// Toast: bottom-centre, quiet. Errors are text-primary with a red dot — never a coloured slab.
import { createEffect, createSignal, on, onCleanup, Show, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { StatusDot } from '~/components/StatusDot';
import css from './Toast.module.css';

export const Toast: Component = () => {
  const app = useApp();
  const [shown, setShown] = createSignal<{ text: string; kind: 'error' | 'info' } | null>(null);
  const [leaving, setLeaving] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  createEffect(
    on(app.toast, (t) => {
      if (timer) clearTimeout(timer);
      if (t) {
        setLeaving(false);
        setShown(t);
      } else if (shown()) {
        setLeaving(true);
        timer = setTimeout(() => {
          setShown(null);
          setLeaving(false);
        }, 160);
      }
    }),
  );
  onCleanup(() => timer && clearTimeout(timer));

  return (
    <Show when={shown()}>
      {(t) => (
        <div class={css.toast} data-leaving={leaving() ? 'true' : undefined} role={t().kind === 'error' ? 'alert' : 'status'} onClick={() => app.clearToast()}>
          <Show when={t().kind === 'error'}>
            <StatusDot hue="server-error" class={css.dot} />
          </Show>
          <span class={css.text}>{t().text}</span>
        </div>
      )}
    </Show>
  );
};
