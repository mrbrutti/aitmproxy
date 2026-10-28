import { describe, expect, it } from 'vitest';
import { pocCompletionFixtures as fixtures } from './conformance.gen';
import { pocYamlCompletions, pocYamlContext } from './complete-yaml';

const sorted = (a: string[]) => [...a].sort();

describe('poc-yaml completion source — conformance fixtures', () => {
  for (const f of fixtures) {
    it(`${f.name} — resolves path + kind`, () => {
      const ctx = pocYamlContext(f.context, f.caret);
      expect(ctx.kind).toBe(f.kind);
      expect(ctx.path).toBe(f.path);
    });

    it(`${f.name} — offers the expected candidates`, () => {
      const got = pocYamlCompletions(f.context, f.caret).map((c) => c.label);
      expect(sorted(got)).toEqual(sorted(f.expected_candidates));
    });
  }

  it('tolerates a half-written document without throwing (Review Focus)', () => {
    expect(() => pocYamlCompletions('steps:\n  - http:\n      metho', 27)).not.toThrow();
  });
});
