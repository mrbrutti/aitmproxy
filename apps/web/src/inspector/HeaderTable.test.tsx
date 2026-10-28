import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'solid-js';
import { createStore } from 'solid-js/store';
import { cleanup, fireEvent, render, screen } from '@solidjs/testing-library';
import type { FlowDetail } from '~/model/flow';
import { createEditState } from './edit';
import { HeaderTable } from './HeaderTable';

const headers = [
  { name: 'Host', value: 'api.shop-staging.test' },
  { name: 'Authorization', value: 'Bearer ' + 'x'.repeat(120) },
];

afterEach(() => cleanup());

describe('HeaderTable', () => {
  it('renders lowercase names and full values in rows', () => {
    render(() => <HeaderTable headers={headers} />);
    const rows = screen.getAllByRole('row');
    expect(rows).toHaveLength(2);
    expect(rows[0]!.textContent).toContain('host');
    expect(rows[0]!.textContent).not.toContain('Host');
    expect(rows[1]!.textContent).toContain('x'.repeat(120));
    expect(screen.getByRole('button', { name: 'Copy Host' })).toBeTruthy();
  });

  it('says so when there are none', () => {
    render(() => <HeaderTable headers={[]} />);
    expect(screen.getByText('No headers')).toBeTruthy();
  });

  it('edits, adds and removes rows in edit mode and marks changed rows', () => {
    const onChange = vi.fn();
    render(() => <HeaderTable headers={headers} editable original={headers} onChange={onChange} />);
    const value = screen.getByLabelText('Header 1 value') as HTMLInputElement;
    fireEvent.input(value, { target: { value: 'evil.test' } });
    expect(onChange).toHaveBeenLastCalledWith([{ name: 'Host', value: 'evil.test' }, headers[1]]);

    fireEvent.click(screen.getByRole('button', { name: 'Add header' }));
    expect(onChange).toHaveBeenLastCalledWith([...headers, { name: '', value: '' }]);

    fireEvent.click(screen.getByRole('button', { name: 'Remove Authorization' }));
    expect(onChange).toHaveBeenLastCalledWith([headers[0]]);
  });

  // Two wirings: the draft patched by path (what the inspector does) and a parent that replaces
  // the whole array with new objects on every keystroke (what used to rebuild every row).
  for (const byPath of [true, false]) {
    it(`keeps focus in the input while typing a header name, one keystroke at a time (${byPath ? 'patched by path' : 'array replaced'})`, () => {
      const [draft, setDraft] = createStore({ headers: [{ name: '', value: '' }, { name: 'Host', value: 'a.test' }] });
      const onEdit = byPath
        ? (i: number, p: { name?: string; value?: string }) => {
            if (p.name !== undefined) setDraft('headers', i, 'name', p.name);
            if (p.value !== undefined) setDraft('headers', i, 'value', p.value);
          }
        : undefined;
      render(() => <HeaderTable headers={draft.headers} editable original={[]} onChange={(h) => setDraft('headers', h.map((x) => ({ ...x })))} onEdit={onEdit} />);
      const name = screen.getByLabelText('Header 1 name') as HTMLInputElement;
      name.focus();
      expect(document.activeElement).toBe(name);
      for (const typed of ['x', 'x-', 'x-c']) {
        fireEvent.input(name, { target: { value: typed } });
        expect(document.activeElement).toBe(name);
      }
      expect(draft.headers[0]!.name).toBe('x-c');
      expect(name.value).toBe('x-c');
      // The other row's input is untouched by the edits.
      expect((screen.getByLabelText('Header 2 value') as HTMLInputElement).value).toBe('a.test');

      // Adding a row replaces the array but keeps the focused input alive.
      fireEvent.click(screen.getByRole('button', { name: 'Add header' }));
      expect(document.activeElement).toBe(name);
      expect(screen.getAllByRole('row')).toHaveLength(3);
      expect(screen.getByLabelText('Header 1 name') as HTMLInputElement).toBe(name);
    });
  }

  it('wires the edit state: setHeader patches one cell and re-serialises the raw document', () => {
    const detail = {
      id: 'f1',
      method: 'GET',
      path: '/api/me',
      query: null,
      httpVersion: 'HTTP/1.1',
      request: { headers: [{ name: 'host', value: 'a.test' }], body: { text: '', contentType: null, size: 0, truncated: false } },
    } as unknown as FlowDetail;
    // The draft is reset from the detail by an effect, which runs once the root's own batch ends.
    const { edit, dispose } = createRoot((dispose) => ({ edit: createEditState(() => detail), dispose }));
    expect(edit.draft.headers).toEqual([{ name: 'host', value: 'a.test' }]);
    edit.setHeaders([...edit.draft.headers, { name: '', value: '' }]);
    const row = edit.draft.headers[1];
    edit.setHeader(1, { name: 'x' });
    edit.setHeader(1, { name: 'x-cua' });
    edit.setHeader(1, { value: 'yes' });
    expect(edit.draft.headers[1]).toBe(row); // same store node: the row's inputs survive
    expect(edit.draft.headers[1]).toEqual({ name: 'x-cua', value: 'yes' });
    expect(edit.rawText()).toBe('GET /api/me HTTP/1.1\nhost: a.test\nx-cua: yes\n\n');
    expect(edit.editCount()).toBe(1);
    dispose();
  });

  it('flags rows that differ from the original', () => {
    const { container } = render(() => <HeaderTable headers={[{ name: 'x-forwarded-for', value: '127.0.0.1' }, headers[0]!]} editable original={headers} onChange={() => {}} />);
    const rows = container.querySelectorAll('[role="row"]');
    expect(rows[0]!.className).toMatch(/rowEdited/);
    expect(rows[1]!.className).not.toMatch(/rowEdited/);
  });
});
