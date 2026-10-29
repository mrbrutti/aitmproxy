import { afterEach, describe, expect, it } from 'vitest';
import { createMockBus } from '~/bus/mock';
import { createAppStore } from './app';

function store() {
  const bus = createMockBus({ initial: 0, agentActive: false });
  return createAppStore(bus);
}

afterEach(() => {
  /* each test builds its own root-owned store */
});

describe('app store — L4 selection routing', () => {
  it('routes a registered L4 id to the L4 inspector without the HTTP detail path', () => {
    const app = store();
    app.setL4Ids(['l4-cap-1', 'l4-craft-1']);
    expect(app.selectedIsL4()).toBe(false);

    app.select('l4-cap-1');
    expect(app.selectedId()).toBe('l4-cap-1');
    expect(app.selectedIsL4()).toBe(true);
    // Selecting a flow always returns the lower region to the inspector (the shell picks L4 by kind).
    expect(app.ui.panel).toBe('inspector');
    // Single-select only for L4 (no HTTP range/additive semantics).
    expect([...app.selectedIds()]).toEqual(['l4-cap-1']);
  });

  it('clears the L4 flag when the selection is not an L4 id', () => {
    const app = store();
    app.setL4Ids(['l4-cap-1']);
    app.select('l4-cap-1');
    expect(app.selectedIsL4()).toBe(true);
    app.setL4Ids([]); // the store refreshed and the session went away
    expect(app.selectedIsL4()).toBe(false);
  });

  it('treats the L4 sidebar item as a filter, not a panel (lower region stays the inspector)', () => {
    const app = store();
    app.setSidebar({ kind: 'l4' });
    expect(app.ui.sidebar).toEqual({ kind: 'l4' });
    expect(app.ui.panel).toBe('inspector');
  });
});
