// Slot: the Request | Response inspector (foundation §2.7 "Inspector"). Owned by the inspector
// builder; the shell mounts it in the lower region and nothing else imports from here.
import type { Component } from 'solid-js';
import { useApp } from '~/state/context';

export const Inspector: Component = () => {
  const app = useApp();
  return (
    <div style={{ padding: '12px', color: 'var(--color-text-tertiary)' }}>
      {app.selected() ? `inspector: ${app.selected()!.flow.method} ${app.selected()!.flow.path}` : 'Select a flow'}
    </div>
  );
};
