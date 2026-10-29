import { createContext, useContext, type ParentComponent } from 'solid-js';
import type { AppStore } from './app';

const AppContext = createContext<AppStore>();

export const AppProvider: ParentComponent<{ store: AppStore }> = (props) => (
  <AppContext.Provider value={props.store}>{props.children}</AppContext.Provider>
);

export function useApp(): AppStore {
  const s = useContext(AppContext);
  if (!s) throw new Error('useApp outside AppProvider');
  return s;
}
