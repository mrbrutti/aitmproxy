// Panel state that outlives the component: the selected run and local YAML edits. The panel
// unmounts whenever the inspector takes the lower region, so this lives per app store instead of
// per mount (and a fresh store — a test, a reconnect — starts clean).

import { createRoot, createSignal, type Accessor, type Setter } from 'solid-js';
import type { AppStore } from '~/state/app';

export interface FindingsState {
  selectedId: Accessor<string | null>;
  setSelectedId: Setter<string | null>;
  localYaml: Accessor<ReadonlyMap<string, string>>;
  setLocalYaml: Setter<ReadonlyMap<string, string>>;
  /** PoC paths whose source was already requested through `poc.get` (asked once per session). */
  yamlRequested: Set<string>;
}

const states = new WeakMap<AppStore, FindingsState>();

export function findingsState(app: AppStore): FindingsState {
  let s = states.get(app);
  if (!s) {
    s = createRoot(() => {
      const [selectedId, setSelectedId] = createSignal<string | null>(null);
      const [localYaml, setLocalYaml] = createSignal<ReadonlyMap<string, string>>(new Map());
      return { selectedId, setSelectedId, localYaml, setLocalYaml, yamlRequested: new Set<string>() };
    });
    states.set(app, s);
  }
  return s;
}
