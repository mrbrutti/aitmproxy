import { describe, expect, it } from 'vitest';
import { createRoot } from 'solid-js';
import { createFormState, inferField, inferFields, validate } from './infer';
import type { JsonSchema } from '~/bus/types';

const schema: JsonSchema = {
  type: 'object',
  properties: {
    id: { type: 'string', 'x-aitm': 'FlowId', description: 'Flow id' },
    flow_id: { type: 'string' },
    url: { type: 'string' },
    name: { type: 'string' },
    script: { type: 'string' },
    mode: { type: 'string', enum: ['reset', '429', '503'] },
    enabled: { type: 'boolean' },
    count: { type: 'integer' },
    ratio: { type: 'number' },
    edits: { type: 'object', description: 'method, path, headers, body' },
    hosts: { type: 'array', items: { type: 'string' } },
    ports: { type: 'array', items: { type: 'integer' } },
    pem: { type: 'string', 'x-aitm': 'Bytes' },
    maybe: { type: ['string', 'null'] },
  },
  required: ['id', 'url', 'count'],
};

describe('inferFields', () => {
  const byName = Object.fromEntries(inferFields(schema).map((f) => [f.name, f]));

  it('picks the flow picker from the x-aitm hint or an id-like name', () => {
    expect(byName.id!.kind).toBe('flow');
    expect(byName.flow_id!.kind).toBe('flow');
  });
  it('uses mono inputs for data-like names and text areas for script-like names', () => {
    expect(byName.url!.kind).toBe('mono');
    expect(byName.name!.kind).toBe('string');
    expect(byName.script!.kind).toBe('text');
  });
  it('maps enum, boolean, number, object, array and bytes', () => {
    expect(byName.mode!.kind).toBe('enum');
    expect(byName.mode!.options).toEqual(['reset', '429', '503']);
    expect(byName.enabled!.kind).toBe('boolean');
    expect(byName.count).toMatchObject({ kind: 'number', integer: true });
    expect(byName.ratio).toMatchObject({ kind: 'number', integer: false });
    expect(byName.edits!.kind).toBe('object');
    expect(byName.hosts).toMatchObject({ kind: 'array', itemKind: 'string' });
    expect(byName.ports).toMatchObject({ kind: 'array', itemKind: 'number' });
    expect(byName.pem!.kind).toBe('bytes');
  });
  it('takes the non-null member of a type union and carries description/required', () => {
    expect(byName.maybe!.kind).toBe('string');
    expect(byName.id).toMatchObject({ required: true, description: 'Flow id' });
    expect(byName.name!.required).toBe(false);
  });
  it('returns no fields for a schema without properties', () => {
    expect(inferFields({ type: 'object' })).toEqual([]);
    expect(inferFields(undefined)).toEqual([]);
  });
  it('humanises labels', () => {
    expect(inferField('poc_path', { type: 'string' }, true).label).toBe('poc path');
  });
});

describe('validate', () => {
  const fields = inferFields(schema);

  it('reports missing required fields and omits blank optional ones', () => {
    const r = validate(fields, { name: '' });
    expect(r.valid).toBe(false);
    expect(r.errors).toEqual({ id: 'Required', url: 'Required', count: 'Required' });
    expect(r.args).toEqual({});
  });
  it('coerces numbers, booleans, objects and arrays', () => {
    const r = validate(fields, {
      id: 'f1',
      url: 'https://x.test',
      count: '3',
      ratio: '0.5',
      enabled: true,
      edits: '{"method":"POST"}',
      hosts: 'a.test\n\nb.test\n',
      ports: '80\n443',
      mode: '429',
    });
    expect(r.valid).toBe(true);
    expect(r.args).toEqual({
      id: 'f1',
      url: 'https://x.test',
      count: 3,
      ratio: 0.5,
      enabled: true,
      edits: { method: 'POST' },
      hosts: ['a.test', 'b.test'],
      ports: [80, 443],
      mode: '429',
    });
  });
  it('rejects a non-integer, a JSON array for an object field and bad numbers in an array', () => {
    const r = validate(fields, { id: 'f1', url: 'u', count: '1.5', edits: '[1]', ports: '80\nx' });
    expect(r.errors.count).toBe('Must be a whole number');
    expect(r.errors.edits).toBe('Must be a JSON object');
    expect(r.errors.ports).toBe('Line 2 is not a number');
  });
  it('explains a JSON syntax error without the engine text', () => {
    const r = validate(fields, { id: 'f1', url: 'u', count: '1', edits: '{"a":' });
    expect(r.errors.edits).toMatch(/^Invalid JSON/);
  });
  it('passes base64 for bytes and keeps a false boolean only when required', () => {
    const r = validate(fields, { id: 'f1', url: 'u', count: '1', pem: { name: 'ca.pem', size: 3, base64: 'QUJD' } });
    expect(r.args.pem).toBe('QUJD');
    expect('enabled' in r.args).toBe(false);
  });
});

describe('createFormState', () => {
  it('tracks values and touched, validating live', () =>
    createRoot((dispose) => {
      const form = createFormState({ inputSchema: schema });
      expect(form.result().valid).toBe(false);
      form.setValue('id', 'f9');
      form.setValue('url', 'https://x.test/');
      form.setValue('count', '2');
      expect(form.result().valid).toBe(true);
      form.touch('id');
      expect(form.touched().has('id')).toBe(true);
      form.touchAll();
      expect(form.touched().size).toBe(form.fields.length);
      form.reset();
      expect(form.result().valid).toBe(false);
      expect(form.touched().size).toBe(0);
      dispose();
    }));
});
