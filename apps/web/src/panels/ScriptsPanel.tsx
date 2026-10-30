// The Scripts panel (foundation §2.7 "Script editor", §3.8). Shown in the lower region when
// app.ui.panel === 'scripts'. The core's Rhai tier serves `script.list/validate/reload/enable/disable/
// save/findings`; this panel is the operator's window onto them: the loaded scripts with an enable
// switch and Reload, a new-script editor (Validate / Save), and a console of script errors and
// findings. There is no command to read an existing script's source, so editing one means saving a
// new text under its name. Honest degradation: when `script.list` is not advertised it says so in place.
import { createEffect, on, Show, type Component } from 'solid-js';
import { Icon } from '~/components';
import { useApp } from '~/state/context';
import { ScriptConsole } from './scripts/ScriptConsole';
import { ScriptEditor } from './scripts/ScriptEditor';
import { ScriptList } from './scripts/ScriptList';
import { AGENT_REASON, scriptsStore } from './scripts/store';
import css from './scripts/ScriptsPanel.module.css';

export const ScriptsPanel: Component = () => {
  const store = scriptsStore(useApp());
  // Read on open and when the tool list arrives; the state itself outlives the panel (see ./scripts/store).
  createEffect(
    on(store.offered, (offered) => {
      if (offered) void store.refresh();
    }),
  );

  return (
    <section class={css.panel} aria-label="Scripts">
      <header class={css.header}>
        <Icon name="code" class={css.icon} />
        <h2 class={css.title}>Scripts</h2>
        {/* Not a fake zero: nothing until `script.list` has answered. */}
        <Show when={store.active() !== null}>
          <span class={css.count}>{store.active()} active</span>
        </Show>
      </header>

      <Show
        when={store.offered()}
        fallback={
          <p class={css.notOffered}>
            Scripts are not enabled on this core — no `script.*` commands are advertised. Start the core with the Rhai tier on (and a
            `rhai.scripts_dir`) to list, enable, write and test scripts from here.
          </p>
        }
      >
        <Show when={store.agent()}>
          <p class={css.note}>{AGENT_REASON} Validate and the console stay available.</p>
        </Show>
        <div class={css.body}>
          <ScriptList store={store} />
          <div class={css.work}>
            <ScriptEditor store={store} />
            <ScriptConsole store={store} />
          </div>
        </div>
      </Show>
    </section>
  );
};
