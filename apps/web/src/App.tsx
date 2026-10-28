import type { Component } from 'solid-js';
import { createBus } from '~/bus';
import { createAppStore } from '~/state/app';
import { AppProvider } from '~/state/context';
import { Shell } from '~/shell/Shell';

const App: Component = () => {
  const store = createAppStore(createBus());
  return (
    <AppProvider store={store}>
      <Shell />
    </AppProvider>
  );
};

export default App;
