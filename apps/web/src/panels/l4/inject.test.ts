import { describe, expect, it, vi } from 'vitest';
import { beginInject, confirmInject, type InjectArgs } from './inject';

const args: InjectArgs = {
  spec: { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: [112] }] },
  dst: '127.0.0.1',
  interface: 'lo0',
  port: 9,
  count: 1,
};

// The real wire summary the core builds (crates/aitm-proto-l4 wire_confirm_summary): it carries the
// destination, the packet layers + length, the count, the matched scope entry and the permit budget.
const PROMPT =
  'Confirm l4.inject: 1× [IPv4/UDP/Raw] (29 bytes) → 127.0.0.1:9 on lo0 (outbound). ' +
  'Matched scope 127.0.0.1/32  ports 0-65535  rate 100pps/100burst; permit budget 100 packets/call. ' +
  'Re-issue with `_confirm` to send.';

describe('inject_shows_confirm', () => {
  it('surfaces the needs_confirmation prompt (target + summary + scope + budget) without hitting the wire', async () => {
    const call = vi.fn().mockResolvedValue({ status: 'needs_confirmation', prompt: PROMPT, confirm_token: 'tok-123' });
    const outcome = await beginInject(call, args);

    expect(call).toHaveBeenCalledWith('l4.inject', { spec: args.spec, dst: '127.0.0.1', interface: 'lo0', port: 9, count: 1 });
    // The first call carries NO _confirm — nothing reaches the wire yet.
    expect(call.mock.calls[0]![1]).not.toHaveProperty('_confirm');
    expect(outcome.kind).toBe('confirm');
    if (outcome.kind === 'confirm') {
      expect(outcome.token).toBe('tok-123');
      expect(outcome.prompt).toContain('127.0.0.1:9'); // destination
      expect(outcome.prompt).toContain('[IPv4/UDP/Raw]'); // packet summary
      expect(outcome.prompt).toContain('Matched scope 127.0.0.1/32'); // matched scope entry
      expect(outcome.prompt).toContain('permit budget 100'); // permit budget
    }
  });

  it('re-issues the identical call with the _confirm token to reach the wire', async () => {
    const call = vi.fn().mockResolvedValue({ flow_id: 'l4-7', sent: 1 });
    const outcome = await confirmInject(call, args, 'tok-123');
    expect(call).toHaveBeenCalledWith('l4.inject', { spec: args.spec, dst: '127.0.0.1', interface: 'lo0', port: 9, count: 1, _confirm: 'tok-123' });
    expect(outcome).toEqual({ kind: 'sent', flowId: 'l4-7', sent: 1 });
  });

  it('surfaces a guard refusal verbatim and shows no dialog', async () => {
    const call = vi.fn().mockRejectedValue(new Error('OutOfL4Scope: 8.8.8.8'));
    const outcome = await beginInject(call, { ...args, dst: '8.8.8.8' });
    expect(outcome).toEqual({ kind: 'refused', message: 'OutOfL4Scope: 8.8.8.8' });
  });

  it('reports a stale/reused token as refused, not sent', async () => {
    const call = vi.fn().mockResolvedValue({ status: 'needs_confirmation', prompt: PROMPT, confirm_token: 'fresh' });
    const outcome = await confirmInject(call, args, 'stale');
    expect(outcome.kind).toBe('refused');
  });
});
