// Schema → form (foundation §4.2 step 3): fields are inferred from a tool's `inputSchema`, never
// hard-coded per command. `required` drives validation; `x-aitm` hints pick the richer controls
// (FlowId → flow picker, Bytes → file). Pure; the components live next door.

import { createMemo, createSignal, type Accessor } from 'solid-js';
import { createStore, type SetStoreFunction } from 'solid-js/store';
import type { JsonSchema, JsonValue, ToolDef } from '~/bus/types';

export type FieldKind =
  | 'string'
  | 'mono' // a string that is data: ids, paths, urls, selectors
  | 'text' // multi-line string (scripts, bodies)
  | 'flow'
  | 'enum'
  | 'boolean'
  | 'number'
  | 'object'
  | 'array'
  | 'bytes';

export interface FieldSpec {
  name: string;
  label: string;
  kind: FieldKind;
  required: boolean;
  description: string | null;
  options: JsonValue[];
  integer: boolean;
  /** Item schema for arrays, when the items are not plain strings. */
  itemKind: 'string' | 'number' | 'json';
  /** Schema default, when given. */
  default: JsonValue | undefined;
}

const MONO_NAME = /(^|_)(id|ids|path|url|uri|host|hosts|selector|target|hash|token|key|fingerprint|address|addr)(_|$)|^(url|path)/i;
const TEXT_NAME = /(^|_)(script|body|text|yaml|pem|source|code|content|message)(_|$)/i;
const FLOW_NAME = /(^|_)flow_?id$|^id$/i;

function primaryType(schema: JsonSchema): string | undefined {
  const t = schema.type;
  if (Array.isArray(t)) return t.find((x) => x !== 'null') ?? t[0];
  return t;
}

export function inferField(name: string, schema: JsonSchema, required: boolean): FieldSpec {
  const type = primaryType(schema);
  const hint = schema['x-aitm'];
  const base: FieldSpec = {
    name,
    label: name.replace(/_/g, ' '),
    kind: 'string',
    required,
    description: schema.description ?? null,
    options: schema.enum ?? [],
    integer: type === 'integer',
    itemKind: 'string',
    default: (schema as { default?: JsonValue }).default,
  };
  if (hint === 'FlowId' || ((type === 'string' || type == null) && FLOW_NAME.test(name))) return { ...base, kind: 'flow' };
  if (hint === 'Bytes' || schema.format === 'byte' || schema.format === 'binary') return { ...base, kind: 'bytes' };
  if (schema.enum && schema.enum.length) return { ...base, kind: 'enum' };
  switch (type) {
    case 'boolean':
      return { ...base, kind: 'boolean' };
    case 'number':
    case 'integer':
      return { ...base, kind: 'number' };
    case 'object':
      return { ...base, kind: 'object' };
    case 'array': {
      const it = schema.items ? primaryType(schema.items) : 'string';
      return { ...base, kind: 'array', itemKind: it === 'number' || it === 'integer' ? 'number' : it === 'object' || it === 'array' ? 'json' : 'string' };
    }
    default:
      if (TEXT_NAME.test(name)) return { ...base, kind: 'text' };
      if (MONO_NAME.test(name) || schema.format === 'uri' || schema.format === 'url') return { ...base, kind: 'mono' };
      return base;
  }
}

/** Fields of a tool, in schema order, required first only when the schema lists them first. */
export function inferFields(schema: JsonSchema | undefined): FieldSpec[] {
  if (!schema?.properties) return [];
  const required = new Set(schema.required ?? []);
  return Object.entries(schema.properties).map(([name, s]) => inferField(name, s, required.has(name)));
}

export const hasParameters = (tool: Pick<ToolDef, 'inputSchema'>): boolean => inferFields(tool.inputSchema).length > 0;

/** Raw form values are strings/booleans/files; `buildArgs` coerces them per field. */
export type RawValue = string | boolean | { name: string; size: number; base64: string } | null | undefined;
export type RawValues = Record<string, RawValue>;

export interface ValidationResult {
  args: Record<string, unknown>;
  errors: Record<string, string>;
  valid: boolean;
}

const isBlank = (v: RawValue) => v == null || v === '' || v === false;

export function validate(fields: FieldSpec[], values: RawValues): ValidationResult {
  const args: Record<string, unknown> = {};
  const errors: Record<string, string> = {};
  for (const f of fields) {
    const v = values[f.name];
    if (f.kind === 'boolean') {
      if (v === true) args[f.name] = true;
      else if (f.required) args[f.name] = false;
      continue;
    }
    if (isBlank(v)) {
      if (f.required) errors[f.name] = 'Required';
      continue;
    }
    switch (f.kind) {
      case 'number': {
        const n = Number(String(v).trim());
        if (!Number.isFinite(n)) errors[f.name] = 'Must be a number';
        else if (f.integer && !Number.isInteger(n)) errors[f.name] = 'Must be a whole number';
        else args[f.name] = n;
        break;
      }
      case 'object': {
        try {
          const parsed: unknown = JSON.parse(String(v));
          if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) errors[f.name] = 'Must be a JSON object';
          else args[f.name] = parsed;
        } catch (e) {
          errors[f.name] = jsonError(e);
        }
        break;
      }
      case 'array': {
        const lines = String(v)
          .split('\n')
          .map((l) => l.trim())
          .filter(Boolean);
        if (!lines.length) {
          if (f.required) errors[f.name] = 'Required';
          break;
        }
        if (f.itemKind === 'number') {
          const nums = lines.map(Number);
          const bad = nums.findIndex((n) => !Number.isFinite(n));
          if (bad >= 0) errors[f.name] = `Line ${bad + 1} is not a number`;
          else args[f.name] = nums;
        } else if (f.itemKind === 'json') {
          try {
            args[f.name] = lines.map((l) => JSON.parse(l) as unknown);
          } catch (e) {
            errors[f.name] = jsonError(e);
          }
        } else args[f.name] = lines;
        break;
      }
      case 'bytes': {
        if (typeof v === 'object' && v && 'base64' in v) args[f.name] = v.base64;
        else errors[f.name] = 'Choose a file';
        break;
      }
      case 'enum': {
        const match = f.options.find((o) => String(o) === String(v));
        if (match === undefined) errors[f.name] = 'Not one of the options';
        else args[f.name] = match;
        break;
      }
      default:
        args[f.name] = String(v);
    }
  }
  return { args, errors, valid: Object.keys(errors).length === 0 };
}

export function jsonError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  // V8: "Unexpected token } in JSON at position 12" / newer: "… (line 2 column 3)"
  const pos = /position (\d+)/.exec(msg);
  const lc = /line (\d+) column (\d+)/.exec(msg);
  if (lc) return `Invalid JSON at line ${lc[1]}, column ${lc[2]}`;
  if (pos) return `Invalid JSON at offset ${pos[1]}`;
  return 'Invalid JSON';
}

export interface FormState {
  fields: FieldSpec[];
  values: RawValues;
  setValue: (name: string, v: RawValue) => void;
  touched: Accessor<ReadonlySet<string>>;
  touch: (name: string) => void;
  touchAll: () => void;
  result: Accessor<ValidationResult>;
  reset: () => void;
}

/** Reactive form state for one tool: values, touched set, live validation. */
export function createFormState(tool: Pick<ToolDef, 'inputSchema'>, initial: RawValues = {}): FormState {
  const fields = inferFields(tool.inputSchema);
  const defaults = (): RawValues => {
    const out: RawValues = {};
    for (const f of fields) {
      const d = f.default;
      if (d === undefined) continue;
      if (f.kind === 'boolean') out[f.name] = d === true;
      else if (f.kind === 'object' || f.kind === 'array') out[f.name] = f.kind === 'array' && Array.isArray(d) ? d.map(String).join('\n') : JSON.stringify(d, null, 2);
      else out[f.name] = String(d);
    }
    return out;
  };
  const [values, setValues] = createStore<RawValues>({ ...defaults(), ...initial });
  const [touched, setTouched] = createSignal<ReadonlySet<string>>(new Set<string>());
  const result = createMemo(() => validate(fields, values));
  const set: SetStoreFunction<RawValues> = setValues;
  return {
    fields,
    values,
    setValue: (name, v) => set(name, v),
    touched,
    touch: (name) => setTouched((s) => (s.has(name) ? s : new Set([...s, name]))),
    touchAll: () => setTouched(new Set(fields.map((f) => f.name))),
    result,
    reset: () => {
      for (const f of fields) set(f.name, undefined);
      const d = defaults();
      for (const k of Object.keys(d)) set(k, d[k]);
      setTouched(new Set<string>());
    },
  };
}
