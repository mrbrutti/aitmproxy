// T8 task 3 (D-T8.6, W-9 dialog half): ConfirmInject gains an optional `confirmLabel` so the scanner
// can reuse the same operator confirm-over-the-wire dialog with its own primary-button wording while
// everything else — the prompt surfaced verbatim, cancel/confirm wiring — is unchanged.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { ConfirmInject } from './ConfirmInject';

afterEach(cleanup);

const SCAN_PROMPT = 'This scan sends malformed traffic to http://t and may disrupt the target. Continue?';

describe('ConfirmInject confirmLabel', () => {
  it('default_label_unchanged: the primary button is "Send to wire" when no confirmLabel is given', () => {
    const r = render(() => <ConfirmInject prompt="p" onConfirm={() => {}} onCancel={() => {}} />);
    expect(r.getByText('Send to wire')).toBeTruthy();
  });

  it('custom_label: confirmLabel renders in place of the default and the default is gone', () => {
    const r = render(() => (
      <ConfirmInject prompt="p" confirmLabel="Start scan" onConfirm={() => {}} onCancel={() => {}} />
    ));
    expect(r.getByText('Start scan')).toBeTruthy();
    expect(r.queryByText('Send to wire')).toBeNull();
  });

  it('prompt_verbatim: the prompt text node equals the given string exactly', () => {
    const r = render(() => (
      <ConfirmInject prompt={SCAN_PROMPT} confirmLabel="Start scan" onConfirm={() => {}} onCancel={() => {}} />
    ));
    expect(r.getByText(SCAN_PROMPT).textContent).toBe(SCAN_PROMPT);
  });

  it('cancel_calls_onCancel_not_onConfirm', () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const r = render(() => (
      <ConfirmInject prompt="p" confirmLabel="Start scan" onConfirm={onConfirm} onCancel={onCancel} />
    ));
    fireEvent.click(r.getByText('Cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
