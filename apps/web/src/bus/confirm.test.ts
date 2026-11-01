import { describe, expect, it } from 'vitest';
import { isMalformedConfirm, isNeedsConfirm } from './confirm';

describe('bus confirm envelope (spec D4)', () => {
  it('detects the needs_confirmation result and ignores a plain success', () => {
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 'Confirm…', confirm_token: 'abc' })).toBe(true);
    expect(isNeedsConfirm({ flow_id: 'f', sent: 1 })).toBe(false);
    expect(isNeedsConfirm(null)).toBe(false);
  });

  it('is not an ask without a string confirm_token', () => {
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 'Confirm…' })).toBe(false);
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 'Confirm…', confirm_token: 42 })).toBe(false);
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 'Confirm…', confirm_token: null })).toBe(false);
  });

  it('is not an ask without a string prompt: the server always sends one, so a prompt-less envelope is an ordinary reply', () => {
    expect(isNeedsConfirm({ status: 'needs_confirmation', confirm_token: 'abc' })).toBe(false);
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 7, confirm_token: 'abc' })).toBe(false);
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: null, confirm_token: 'abc' })).toBe(false);
  });

  it('rejects non-objects and arrays', () => {
    expect(isNeedsConfirm(undefined)).toBe(false);
    expect(isNeedsConfirm('needs_confirmation')).toBe(false);
    expect(isNeedsConfirm(['needs_confirmation'])).toBe(false);
    expect(isNeedsConfirm({ status: 'ok', prompt: 'Confirm…', confirm_token: 'abc' })).toBe(false);
  });

  it('isMalformedConfirm: a status-only envelope is malformed; a valid envelope and a non-envelope are not', () => {
    expect(isMalformedConfirm({ status: 'needs_confirmation' })).toBe(true);
    expect(isMalformedConfirm({ status: 'needs_confirmation', prompt: 'Confirm…' })).toBe(true);
    expect(isMalformedConfirm({ status: 'needs_confirmation', confirm_token: 'abc' })).toBe(true);
    expect(isMalformedConfirm({ status: 'needs_confirmation', prompt: 'Confirm…', confirm_token: 'abc' })).toBe(false);
    expect(isMalformedConfirm({ flow_id: 'f', sent: 1 })).toBe(false);
    expect(isMalformedConfirm({ status: 'ok' })).toBe(false);
    expect(isMalformedConfirm(null)).toBe(false);
    expect(isMalformedConfirm('needs_confirmation')).toBe(false);
  });
});
