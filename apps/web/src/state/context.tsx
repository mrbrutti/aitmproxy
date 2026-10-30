import { createContext, onCleanup, onMount, useContext, type ParentComponent } from 'solid-js';
import type { AppStore } from './app';
import { createL4Store, type L4Store } from '~/panels/l4/store';

const AppContext = createContext<AppStore>();
const L4Context = createContext<L4Store>();

/** How often the lifted L4 store re-reads `l4.flow.list` (L4 has no push today — it is polled). */
const L4_POLL_MS = 1500;

export const AppProvider: ParentComponent<{ store: AppStore }> = (props) => {
  // One L4 store for the page, lifted so the unified flow list, the lower-region L4 inspector and
  // the capture bar all share one selection and one refreshed session set.
  const l4 = createL4Store(props.store);
  onMount(() => {
    void l4.refresh();
    const t = setInterval(() => void l4.refresh(), L4_POLL_MS);
    onCleanup(() => clearInterval(t));
  });
  return (
    <AppContext.Provider value={props.store}>
      <L4Context.Provider value={l4}>{props.children}</L4Context.Provider>
    </AppContext.Provider>
  );
};

export function useApp(): AppStore {
  const s = useContext(AppContext);
  if (!s) throw new Error('useApp outside AppProvider');
  return s;
}

/** The lifted L4 store, or `null` when there is no provider (unit tests that mount a bare list). */
export function useL4(): L4Store | null {
  return useContext(L4Context) ?? null;
}
