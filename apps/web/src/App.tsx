import { createRoot, type Component } from 'solid-js';
import { createBus } from '~/bus';
import { createAppStore } from '~/state/app';
import { AppProvider } from '~/state/context';
import { Shell } from '~/shell/Shell';

const App: Component = () => {
  // The bus and store live for the page: own them in a root so their signals are not orphaned.
  const store = createRoot(() => createAppStore(createBus()));
  return (
    <AppProvider store={store}>
      <Shell />
    </AppProvider>
  );
};

export default App;
