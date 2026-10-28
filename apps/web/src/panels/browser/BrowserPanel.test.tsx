import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { createStore } from 'solid-js/store';
import { AppProvider } from '~/state/context';
import type { AppStore } from '~/state/app';
import type { ToolDef } from '~/bus/types';
import { BrowserPanel } from '../BrowserPanel';
import { browserState } from './state';

const tool = (name: string): ToolDef => ({ name, description: '', inputSchema: { type: 'object' } });

/** A stub app store: reactive `proxy.tools` / `ui.panel`, a recording `call`, a recording `notice`. */
function stubApp(tools: string[], panel = 'browser') {
  const [proxy, setProxy] = createStore({ tools: tools.map(tool) });
  const [ui, setUi] = createStore({ panel });
  const calls: { tool: string; args: Record<string, unknown> | undefined }[] = [];
  const app = {
    proxy,
    ui,
    call: vi.fn(async (t: string, args?: Record<string, unknown>) => {
      calls.push({ tool: t, args });
      switch (t) {
        case 'browser.tabs':
          return [{ id: 'tab_1', url: 'https://shop-staging.test/', title: 'Shop (staging)', active: true }];
        case 'browser.navigate':
          return { url: args!.url, title: 'Landed' };
        case 'browser.screenshot':
          return ''; // jsdom has no canvas; an empty frame is "nothing yet"
        default:
          return null;
      }
    }),
    notice: vi.fn(),
    setSidebar: vi.fn(),
    setPanel: vi.fn(),
  };
  return { app: app as unknown as AppStore, calls, setProxy, setUi };
}

const tick = () => new Promise((r) => setTimeout(r, 20));
const mount = (app: AppStore) =>
  render(() => (
    <AppProvider store={app}>
      <BrowserPanel />
    </AppProvider>
  ));

afterEach(() => cleanup());

describe('BrowserPanel availability', () => {
  it('says there is no embedded browser when tools lack browser.navigate, and disables the chrome', async () => {
    const { app, calls } = stubApp(['flow.list', 'flow.get']);
    const r = mount(app);
    await tick();
    expect(r.container.textContent).toContain('No embedded browser on this server — start aitm with browser.engine: obscura.');
    expect(r.getByLabelText<HTMLInputElement>('Address').disabled).toBe(true);
    expect(calls.filter((c) => c.tool.startsWith('browser.'))).toHaveLength(0);
    // the frame is kept: strip, toolbar, note
    expect(r.container.textContent).toContain('Clicks are relayed by CSS selector until the screencast lands (F14).');
    expect(r.container.textContent).toContain('Untitled');
  });

  it('shows nothing while tools/list has not answered yet', () => {
    const { app } = stubApp([]);
    const r = mount(app);
    expect(r.container.textContent).not.toContain('No embedded browser');
    expect(r.container.querySelector('[role="progressbar"]')).toBeNull();
  });

  it('shows a single untitled tab when browser.tabs is absent, then the page title after navigating', async () => {
    const { app, calls } = stubApp(['browser.navigate', 'browser.screenshot']);
    const r = mount(app);
    await tick();
    const tabs = r.container.querySelectorAll('[aria-label="Open tabs"] > li[aria-current]');
    expect(tabs).toHaveLength(1);
    expect(tabs[0]!.textContent).toContain('Untitled');
    expect(calls.some((c) => c.tool === 'browser.tabs')).toBe(false);

    const s = browserState(app);
    await s.navigate('shop-staging.test/login');
    expect(calls.find((c) => c.tool === 'browser.navigate')?.args).toEqual({ url: 'https://shop-staging.test/login' });
    expect(r.container.querySelector('[aria-label="Open tabs"] > li[aria-current]')!.textContent).toContain('Landed');
    expect(r.getByLabelText<HTMLInputElement>('Address').value).toBe('https://shop-staging.test/login');
  });

  it('lists the server tabs and seeds the address from the active one', async () => {
    const { app } = stubApp(['browser.navigate', 'browser.tabs', 'browser.screenshot']);
    const r = mount(app);
    await tick();
    expect(r.container.querySelector('[aria-label="Open tabs"] > li[aria-current]')!.textContent).toContain('Shop (staging)');
    expect(r.getByLabelText<HTMLInputElement>('Address').value).toBe('https://shop-staging.test/');
    expect(r.container.querySelector('[role="progressbar"]')).not.toBeNull(); // first frame pending
  });

  it('shows "needs F14" on the tab controls that have no bus command yet', async () => {
    const { app } = stubApp(['browser.navigate']);
    const r = mount(app);
    expect(r.getByLabelText<HTMLButtonElement>('New tab').disabled).toBe(true);
    expect(r.getByLabelText('New tab').getAttribute('title')).toContain('needs F14');
    expect(r.getByLabelText<HTMLButtonElement>('Close tab').disabled).toBe(true);
  });
});

describe('BrowserPanel live polling', () => {
  it('polls browser.screenshot only while the panel is the visible one and live is on', async () => {
    vi.useFakeTimers();
    try {
      const { app, calls, setUi } = stubApp(['browser.navigate', 'browser.screenshot'], 'inspector');
      mount(app);
      const shots = () => calls.filter((c) => c.tool === 'browser.screenshot').length;
      await vi.advanceTimersByTimeAsync(2000);
      expect(shots()).toBe(0);
      setUi('panel', 'browser');
      await vi.advanceTimersByTimeAsync(0);
      expect(shots()).toBe(1);
      await vi.advanceTimersByTimeAsync(1600);
      expect(shots()).toBe(3);
      const s = browserState(app);
      s.setLive(false);
      await vi.advanceTimersByTimeAsync(3000);
      expect(shots()).toBe(3);
      expect(s.polling()).toBe(false);
      s.setLive(true);
      await vi.advanceTimersByTimeAsync(0);
      expect(shots()).toBe(4);
      expect(s.polling()).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('Flows › filters the list to the obscura app and shows the inspector', async () => {
    const { app } = stubApp(['browser.navigate']);
    const r = mount(app);
    r.getByText('Flows').click();
    expect(app.setSidebar).toHaveBeenCalledWith({ kind: 'app', key: 'obscura' });
    expect(app.setPanel).toHaveBeenCalledWith('inspector');
  });
});
