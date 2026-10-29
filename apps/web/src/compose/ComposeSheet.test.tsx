import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import { AppProvider } from '~/state/context';
import type { AppStore } from '~/state/app';
import type { FlowDetail } from '~/model/flow';
import { ComposeSheet } from './ComposeSheet';
import { onPrefillEvent } from './prefill';

function stubApp(scope: string[]) {
  const [version] = createSignal(0);
  const [ui, setUi] = createStore({ composeOpen: true });
  const compose = vi.fn(async () => 'f9');
  const app = {
    ui,
    proxy: { scope: scope.map((host) => ({ host })), tools: [] },
    version,
    entries: [],
    byId: new Map(),
    details: {},
    loadDetail: vi.fn(async (): Promise<FlowDetail | null> => null),
    openCompose: vi.fn((open: boolean) => setUi('composeOpen', open)),
    compose,
    replay: vi.fn(async () => 'f10'),
    select: vi.fn(),
    notice: vi.fn(),
    addScope: vi.fn(async () => {}),
  };
  return app as unknown as AppStore & typeof app;
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const mount = async (app: AppStore) => {
  render(() => <AppProvider store={app}><ComposeSheet /></AppProvider>);
  await tick(); // Portal content lands after the first render
  return screen; // render() binds its queries to the container; portals land in document.body
};

// This jsdom has no localStorage; the sheet persists its history through it.
const mem = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k), clear: () => mem.clear() },
});

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe('ComposeSheet scope pre-check', () => {
  it('disables Send and explains until the URL host is in scope; Add to scope calls the store', async () => {
    const app = stubApp(['api.shop-staging.test', 'localhost:8443', '*.corp.test']);
    const { getByLabelText, getByText } = await mount(app);
    const url = getByLabelText('URL') as HTMLInputElement;
    const send = () => getByText('Send').closest('button')!;

    expect(send().disabled).toBe(true);
    expect(getByText(/Enter a URL/)).toBeTruthy();

    fireEvent.input(url, { target: { value: 'https://evil.test/x' } });
    await tick();
    expect(send().disabled).toBe(true);
    expect(getByText(/Out of scope/).textContent).toContain('add evil.test to scope to send');
    fireEvent.click(getByText('Add to scope'));
    expect(app.addScope).toHaveBeenCalledWith('evil.test');

    fireEvent.input(url, { target: { value: 'https://api.shop-staging.test/v1?a=1' } });
    await tick();
    expect(send().disabled).toBe(false);
    expect(getByText(/in scope/)).toBeTruthy();

    fireEvent.input(url, { target: { value: 'https://localhost/x' } });
    await tick();
    expect(send().disabled).toBe(true);
    fireEvent.input(url, { target: { value: 'https://localhost:8443/x' } });
    await tick();
    expect(send().disabled).toBe(false);
    fireEvent.input(url, { target: { value: 'https://auth.corp.test/x' } });
    await tick();
    expect(send().disabled).toBe(false);
  });

  it('sends with ⌘⏎, selects the new flow, notices and records history', async () => {
    const app = stubApp(['api.shop-staging.test']);
    const { getByLabelText, getByRole } = await mount(app);
    fireEvent.input(getByLabelText('URL'), { target: { value: 'https://api.shop-staging.test/v1?q=1' } });
    await tick();
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter', metaKey: true });
    await tick();
    await tick();
    expect(app.compose).toHaveBeenCalledWith({ method: 'GET', url: 'https://api.shop-staging.test/v1?q=1', headers: {}, body: '' });
    expect(app.select).toHaveBeenCalledWith('f9');
    expect(app.notice).toHaveBeenCalledWith('Sent');
    const history = JSON.parse(localStorage.getItem('aitm.compose.history')!);
    expect(history).toHaveLength(1);
    expect(history[0].draft.url).toBe('https://api.shop-staging.test/v1?q=1');
  });

  it('keeps query rows and the URL in sync both ways', async () => {
    const app = stubApp(['x.test']);
    const { getByLabelText } = await mount(app);
    const url = getByLabelText('URL') as HTMLInputElement;
    fireEvent.input(url, { target: { value: 'https://x.test/p?a=1&b=two' } });
    await tick();
    expect((getByLabelText('Query parameter name 1') as HTMLInputElement).value).toBe('a');
    expect((getByLabelText('Query parameter value 2') as HTMLInputElement).value).toBe('two');
    fireEvent.input(getByLabelText('Query parameter value 2'), { target: { value: 'three' } });
    await tick();
    expect(url.value).toBe('https://x.test/p?a=1&b=three');
    fireEvent.input(getByLabelText('Query parameter name 3'), { target: { value: 'c' } });
    await tick();
    expect(url.value).toBe('https://x.test/p?a=1&b=three&c');
  });

  it('adds the content-type automatically for a JSON body and flags invalid JSON', async () => {
    const app = stubApp(['x.test']);
    const { getByLabelText, getByText, getByRole } = await mount(app);
    fireEvent.input(getByLabelText('URL'), { target: { value: 'https://x.test/p' } });
    fireEvent.click(getByText('JSON'));
    await tick();
    const body = getByLabelText('Request body') as HTMLTextAreaElement;
    fireEvent.input(body, { target: { value: '{"a":' } });
    await tick();
    expect(getByRole('alert').textContent).toMatch(/Invalid JSON/);
    expect((getByText('Send').closest('button') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(body, { target: { value: '{"a":1}' } });
    await tick();
    expect(getByLabelText('Content-Type value (automatic; edit to override)')).toHaveProperty('value', 'application/json');
    fireEvent.keyDown(getByRole('dialog'), { key: 'Enter', metaKey: true });
    await tick();
    await tick();
    expect(app.compose).toHaveBeenCalledWith(expect.objectContaining({ method: 'GET', headers: { 'Content-Type': 'application/json' }, body: '{"a":1}' }));
  });

  it('prefills from a pending aitm:compose-prefill event and offers Send unchanged', async () => {
    const app = stubApp(['auth.shop-staging.test']);
    app.loadDetail = vi.fn(async () => ({
      id: 'f3',
      seq: 3,
      kind: 'http' as const,
      method: 'POST',
      scheme: 'https' as const,
      authority: 'auth.shop-staging.test',
      path: '/login',
      query: null,
      status: 200,
      statusText: 'OK',
      startedAt: 0,
      durationMs: 1,
      reqSize: 1,
      resSize: 1,
      client: { id: 'c', name: 'c' },
      tls: 'mitm' as const,
      httpVersion: 'HTTP/2' as const,
      intercept: 'none' as const,
      edited: false,
      isReplay: false,
      origin: 'client' as const,
      inScope: true,
      contentType: 'application/json',
      mark: null,
      comment: null,
      request: { headers: [{ name: 'content-type', value: 'application/json' }], body: { text: '{"u":1}', contentType: 'application/json', size: 7, truncated: false } },
      response: null,
      conn: {},
      timing: null,
    }));
    onPrefillEvent(new CustomEvent('aitm:compose-prefill', { detail: { id: 'f3' } }));
    const { getByLabelText, getByText } = await mount(app);
    await tick();
    await tick();
    expect((getByLabelText('URL') as HTMLInputElement).value).toBe('https://auth.shop-staging.test/login');
    expect((getByLabelText('Method') as HTMLSelectElement).value).toBe('POST');
    expect((getByLabelText('Request body') as HTMLTextAreaElement).value).toBe('{"u":1}');
    fireEvent.click(getByText('Send unchanged'));
    await tick();
    await tick();
    expect(app.replay).toHaveBeenCalledWith('f3');
    expect(app.select).toHaveBeenCalledWith('f10');
  });

  it('Esc closes', async () => {
    const app = stubApp([]);
    const { getByRole } = await mount(app);
    fireEvent.keyDown(getByRole('dialog'), { key: 'Escape' });
    expect(app.openCompose).toHaveBeenCalledWith(false);
  });
});
