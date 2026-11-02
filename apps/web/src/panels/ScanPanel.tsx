// The Scan panel. The shell mounts it in the lower region when `app.ui.panel === 'scan'`. What it
// shows is a three-way switch on what the core offers (D-T8.1): the v2 Scanner for a core with the
// `scan.*` family, the shipped v1 panel for a core with only `scan.discover`, and a plain note for a
// core with neither. The v1 panel (`./scan`) is left exactly as it is.
import { Match, Switch, type Component } from 'solid-js';
import { useApp } from '~/state/context';
import { Scan } from './scan/Scan';
import { Scanner } from './scanner/Scanner';
import { scanStore } from './scanner/store';
import css from './scanner/scanner.module.css';

export const ScanPanel: Component = () => {
  const offered = scanStore(useApp()).offered;
  return (
    <Switch>
      <Match when={offered() === 'v2'}>
        <Scanner />
      </Match>
      <Match when={offered() === 'legacy'}>
        <Scan />
      </Match>
      <Match when={offered() === 'none'}>
        <section class={css.root} aria-label="Scanner">
          <div class={css.empty} role="status">
            The scanner is not offered by this core.
          </div>
        </section>
      </Match>
    </Switch>
  );
};
