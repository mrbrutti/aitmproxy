import { describe, expect, it } from 'vitest';
import { allContainerPaths, filterTree, flatten, jsonPath, parentPath, preview } from './json-tree-model';

const doc = {
  items: [
    { id: 1, name: 'Aurora Lamp', price: 129.5, tags: ['home'] },
    { id: 2, name: 'Vela Chair', price: 0, tags: [] },
    { id: 3, name: 'Tidal Mug', price: 9.9, 'odd key': { "it's": true } },
  ],
  total: 3,
  ok: true,
  none: null,
};

describe('jsonPath', () => {
  it('uses dot for identifiers, brackets for indexes and odd keys', () => {
    expect(jsonPath('$', 'items')).toBe('$.items');
    expect(jsonPath('$.items', 3)).toBe('$.items[3]');
    expect(jsonPath('$.items[3]', 'price')).toBe('$.items[3].price');
    expect(jsonPath('$.items[2]', 'odd key')).toBe("$.items[2]['odd key']");
    expect(jsonPath("$.items[2]['odd key']", "it's")).toBe("$.items[2]['odd key']['it\\'s']");
  });
  it('parentPath walks back up', () => {
    expect(parentPath('$.items[3].price')).toBe('$.items[3]');
    expect(parentPath('$.items[3]')).toBe('$.items');
    expect(parentPath('$.items')).toBe('$');
    expect(parentPath('$')).toBeNull();
  });
});

describe('flatten', () => {
  it('shows only the root when nothing is expanded', () => {
    const { rows } = flatten(doc, new Set(), { sortKeys: false });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ path: '$', kind: 'object', expandable: true, expanded: false, count: 4 });
  });
  it('emits nested rows for expanded containers with paths and commas', () => {
    const { rows } = flatten(doc, new Set(['$', '$.items', '$.items[2]']), { sortKeys: false });
    const paths = rows.map((r) => r.path);
    expect(paths).toEqual([
      '$',
      '$.items',
      '$.items[0]',
      '$.items[1]',
      '$.items[2]',
      '$.items[2].id',
      '$.items[2].name',
      '$.items[2].price',
      "$.items[2]['odd key']",
      '$.total',
      '$.ok',
      '$.none',
    ]);
    const price = rows.find((r) => r.path === '$.items[2].price')!;
    expect(price).toMatchObject({ kind: 'number', value: 9.9, depth: 3, comma: true });
    expect(rows.find((r) => r.path === '$.none')).toMatchObject({ kind: 'null', comma: false });
  });
  it('sorts object keys when asked', () => {
    const { rows } = flatten(doc, new Set(['$']), { sortKeys: true });
    expect(rows.slice(1).map((r) => r.key)).toEqual(['items', 'none', 'ok', 'total']);
  });
  it('previews collapsed containers', () => {
    expect(preview(doc.items)).toBe('3 items');
    expect(preview(doc)).toBe('4 keys');
    expect(preview([])).toBe('empty');
  });
});

describe('filterTree', () => {
  it('matches keys and values and reveals ancestors', () => {
    const f = filterTree(doc, 'mug')!;
    expect([...f.matches]).toEqual(['$.items[2].name']);
    expect([...f.reveal].sort()).toEqual(['$', '$.items', '$.items[2]']);
    const { rows } = flatten(doc, new Set(), { sortKeys: false, filter: f });
    expect(rows.map((r) => r.path)).toEqual(['$', '$.items', '$.items[2]', '$.items[2].name']);
  });
  it('matches on key names too', () => {
    const f = filterTree(doc, 'odd')!;
    expect(f.matches.has("$.items[2]['odd key']")).toBe(true);
  });
  it('is null for an empty query', () => {
    expect(filterTree(doc, '  ')).toBeNull();
  });
});

describe('allContainerPaths', () => {
  it('lists every non-empty container', () => {
    const { paths } = allContainerPaths(doc);
    expect([...paths].sort()).toEqual(['$', '$.items', '$.items[0]', '$.items[0].tags', '$.items[1]', '$.items[2]', "$.items[2]['odd key']"].sort());
  });
});
