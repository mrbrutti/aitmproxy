import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@solidjs/testing-library';
import { HeaderTable } from './HeaderTable';

const headers = [
  { name: 'Host', value: 'api.shop-staging.test' },
  { name: 'Authorization', value: 'Bearer ' + 'x'.repeat(120) },
];

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

  it('flags rows that differ from the original', () => {
    const { container } = render(() => <HeaderTable headers={[{ name: 'x-forwarded-for', value: '127.0.0.1' }, headers[0]!]} editable original={headers} onChange={() => {}} />);
    const rows = container.querySelectorAll('[role="row"]');
    expect(rows[0]!.className).toMatch(/rowEdited/);
    expect(rows[1]!.className).not.toMatch(/rowEdited/);
  });
});
