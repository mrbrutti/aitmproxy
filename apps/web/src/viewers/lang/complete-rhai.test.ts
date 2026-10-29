import { describe, expect, it } from 'vitest';
import { rhaiCompletionFixtures as fixtures } from './conformance.gen';
import { rhaiCompletions } from './complete-rhai';

const sorted = (a: string[]) => [...a].sort();

describe('rhai completion source — conformance fixtures', () => {
  for (const f of fixtures) {
    it(f.name, () => {
      const got = rhaiCompletions(f.context, f.caret).map((c) => c.label);
      expect(sorted(got)).toEqual(sorted(f.expected_candidates));
    });
  }

  it('carries catalog detail/info on a member candidate', () => {
    const cands = rhaiCompletions('fn on_request(flow) {\n    flow.request.', 39);
    const headers = cands.find((c) => c.label === 'headers');
    expect(headers?.info).toContain('headers');
  });
});
