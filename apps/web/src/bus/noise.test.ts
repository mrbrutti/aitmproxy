// The flood rule (push spec D7, as amended after the security review): a line is this UI's own
// background read, and dropped, only when it succeeded, names one of the reads the UI issues on
// timers, and is unlabelled from our own origin. The bridge labels no connection, and a label is the
// caller's self-declared `clientInfo.name`, so a labelled line is never ours, whatever the label says.

import { describe, expect, it } from 'vitest';
import { UI_BACKGROUND_READS, isUiPollNoise, ownOriginOf } from './noise';

describe('isUiPollNoise / ownOriginOf', () => {
  const own = { origin: 'operator' } as const;
  const ownRead = { origin: 'operator', clientLabel: null, command: 'flow.list', result: 'ok' } as const;

  it('isUiPollNoise matrix', () => {
    // (1) our origin, unlabelled, a successful background read: noise.
    expect(isUiPollNoise(ownRead, own)).toBe(true);
    // (2) the label absent rather than null is the same thing.
    expect(isUiPollNoise({ origin: 'operator', command: 'flow.list', result: 'ok' }, own)).toBe(true);
    // (3) a line labelled `aitm-web` is NOT ours: no bridge line carries a label, and a label is
    //     whatever the caller put in `initialize.clientInfo.name`.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: 'aitm-web', command: 'flow.detail', result: 'ok' }, own)).toBe(false);
    // (3b) …not even from our own origin: an agent on the same token that names itself `aitm-web`
    //      to hide its reads from the operator's log keeps them visible.
    expect(isUiPollNoise({ ...ownRead, clientLabel: 'aitm-web' }, own)).toBe(false);
    // (4) an action from our origin is what the panel exists to show.
    expect(isUiPollNoise({ ...ownRead, command: 'flow.kill' }, own)).toBe(false);
    // (5) a failing poll is signal.
    expect(isUiPollNoise({ ...ownRead, result: 'error' }, own)).toBe(false);
    // (6) a real agent labels itself; never ours.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: 'claude-code', command: 'flow.list', result: 'ok' }, own)).toBe(false);
    // (7) an unlabelled read from another origin is somebody else's.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: null, command: 'flow.list', result: 'ok' }, own)).toBe(false);
    // (8) an unknown own origin matches nothing by origin.
    expect(isUiPollNoise(ownRead, { origin: null })).toBe(false);
    // (9) …but when we run on the agent token, our origin is `mcp`.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: null, command: 'flow.list', result: 'ok' }, { origin: 'mcp' })).toBe(true);
    // (10) another frontend's polling is that frontend's activity.
    expect(isUiPollNoise({ ...ownRead, clientLabel: 'aitm-mac' }, own)).toBe(false);
    // (11) an empty string is still a label, not the bridge's null.
    expect(isUiPollNoise({ ...ownRead, clientLabel: '' }, own)).toBe(false);
    // The other reads the UI makes on its own count the same as `flow.list`; a navigation is an action.
    expect(isUiPollNoise({ ...ownRead, command: 'agent.activity' }, own)).toBe(true);
    expect(isUiPollNoise({ ...ownRead, command: 'l4.intercept.list' }, own)).toBe(true);
    expect(isUiPollNoise({ ...ownRead, command: 'browser.screenshot' }, own)).toBe(true);
    expect(isUiPollNoise({ ...ownRead, command: 'browser.navigate' }, own)).toBe(false);
  });

  it('UI_BACKGROUND_READS is exactly the reads the UI issues on timers or in bulk refreshes', () => {
    expect([...UI_BACKGROUND_READS].sort()).toEqual(
      [
        'flow.list',
        'flow.get',
        'flow.detail',
        'proxy.status',
        'agent.status',
        'agent.activity',
        'scope.list',
        'poc.list',
        'l4.flow.list',
        'l4.flow.get',
        'l4.scope.list',
        'l4.capture.status',
        'l4.agent.status',
        'l4.intercept.status',
        'l4.intercept.list',
        'browser.tabs',
        'browser.screenshot',
      ].sort(),
    );
  });

  it('ownOriginOf maps roles', () => {
    expect(ownOriginOf('operator')).toBe('operator');
    expect(ownOriginOf('agent')).toBe('mcp');
    expect(ownOriginOf(null)).toBeNull();
  });
});
