// Placeholder until the shell lands; keeps the scaffold compiling.
import type { Component } from 'solid-js';
import { useApp } from '~/state/context';

export const Shell: Component = () => {
  const app = useApp();
  return (
    <div style={{ padding: '16px', 'font-family': 'var(--font-ui)' }}>
      aitmproxy — {app.total()} flows · bus {app.bus.address} ({app.bus.state()})
    </div>
  );
};
