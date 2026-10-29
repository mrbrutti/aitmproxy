// Renders the fields of a FormState (see infer.ts). Descriptions sit under each field as 12px
// help; errors show once a field was touched (or after `touchAll` on submit).
import { For, Match, Show, Switch, type Component } from 'solid-js';
import { Icon } from '~/components/Icon';
import { FlowPicker } from './FlowPicker';
import type { FieldSpec, FormState, RawValue } from './infer';
import css from './schema-form.module.css';

export interface SchemaFormProps {
  form: FormState;
  /** Prefix for element ids so several forms can coexist. */
  idPrefix: string;
  /** Focus the first field on mount. */
  autofocus?: boolean | undefined;
  /** Called on ⌘⏎ inside any control. */
  onSubmit?: (() => void) | undefined;
  class?: string | undefined;
}

const SHORT_ENUM = (opts: unknown[]) => opts.length <= 4 && opts.every((o) => String(o).length <= 10);

async function fileToBase64(file: File): Promise<string> {
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(bin);
}

export const SchemaForm: Component<SchemaFormProps> = (props) => {
  const f = () => props.form;
  const err = (name: string) => (f().touched().has(name) ? f().result().errors[name] : undefined);
  const id = (name: string, suffix = '') => `${props.idPrefix}-${name}${suffix}`;
  const str = (v: RawValue) => (typeof v === 'string' ? v : '');
  const fileInputs: Record<string, HTMLInputElement | undefined> = {};

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey) && props.onSubmit) {
      e.preventDefault();
      props.onSubmit();
    }
  };

  const Help: Component<{ field: FieldSpec }> = (p) => (
    <>
      <Show when={err(p.field.name)}>
        <span id={id(p.field.name, '-err')} class={css.error} role="alert">
          {err(p.field.name)}
        </span>
      </Show>
      <Show when={p.field.description}>
        <span id={id(p.field.name, '-help')} class={css.help}>
          {p.field.description}
        </span>
      </Show>
    </>
  );

  const describedBy = (field: FieldSpec) => [field.description ? id(field.name, '-help') : null, err(field.name) ? id(field.name, '-err') : null].filter(Boolean).join(' ') || undefined;

  return (
    <div class={`${css.form}${props.class ? ` ${props.class}` : ''}`} onKeyDown={onKey}>
      <For each={f().fields}>
        {(field, i) => {
          const first = () => props.autofocus === true && i() === 0;
          const set = (v: RawValue) => f().setValue(field.name, v);
          const touch = () => f().touch(field.name);
          const invalid = () => !!err(field.name);
          const label = (
            <span class={css.labelRow}>
              <label class={css.label} for={field.kind === 'boolean' ? undefined : id(field.name)} id={id(field.name, '-label')}>
                {field.label}
              </label>
              <Show when={!field.required}>
                <span class={css.optional}>optional</span>
              </Show>
            </span>
          );
          return (
            <Switch>
              <Match when={field.kind === 'boolean'}>
                <div class={css.field} data-inline="true">
                  <span class={css.labelRow} style={{ 'flex-direction': 'column', 'align-items': 'flex-start', gap: '4px' }}>
                    {label}
                    <Help field={field} />
                  </span>
                  <button
                    type="button"
                    role="switch"
                    class={css.switch}
                    aria-checked={f().values[field.name] === true}
                    aria-labelledby={id(field.name, '-label')}
                    ref={(n) => first() && queueMicrotask(() => n.focus())}
                    onClick={() => {
                      set(f().values[field.name] !== true);
                      touch();
                    }}
                  />
                </div>
              </Match>
              <Match when={field.kind === 'flow'}>
                <div class={css.field}>
                  {label}
                  <FlowPicker id={id(field.name)} value={str(f().values[field.name])} onChange={(v) => set(v)} onBlur={touch} invalid={invalid()} autofocus={first()} describedBy={describedBy(field)} />
                  <Help field={field} />
                </div>
              </Match>
              <Match when={field.kind === 'enum' && SHORT_ENUM(field.options)}>
                <div class={css.field}>
                  {label}
                  <div class={css.seg} role="radiogroup" aria-labelledby={id(field.name, '-label')} aria-describedby={describedBy(field)}>
                    <For each={field.options}>
                      {(opt, oi) => (
                        <button
                          type="button"
                          role="radio"
                          aria-checked={String(f().values[field.name] ?? '') === String(opt)}
                          data-mono={/^\d/.test(String(opt)) ? 'true' : undefined}
                          ref={(n) => first() && oi() === 0 && queueMicrotask(() => n.focus())}
                          onClick={() => {
                            set(String(opt));
                            touch();
                          }}
                        >
                          {String(opt)}
                        </button>
                      )}
                    </For>
                  </div>
                  <Help field={field} />
                </div>
              </Match>
              <Match when={field.kind === 'enum'}>
                <div class={css.field}>
                  {label}
                  <span class={css.selectWrap}>
                    <select
                      id={id(field.name)}
                      class={css.select}
                      value={str(f().values[field.name])}
                      aria-invalid={invalid() ? 'true' : undefined}
                      aria-describedby={describedBy(field)}
                      ref={(n) => first() && queueMicrotask(() => n.focus())}
                      onChange={(e) => {
                        set(e.currentTarget.value);
                        touch();
                      }}
                    >
                      <option value="">{field.required ? 'Choose…' : '—'}</option>
                      <For each={field.options}>{(opt) => <option value={String(opt)}>{String(opt)}</option>}</For>
                    </select>
                    <Icon name="chevron-down" size={12} />
                  </span>
                  <Help field={field} />
                </div>
              </Match>
              <Match when={field.kind === 'number'}>
                <div class={css.field}>
                  {label}
                  <input
                    id={id(field.name)}
                    class={`${css.input} ${css.mono} ${css.number}`}
                    type="text"
                    inputmode={field.integer ? 'numeric' : 'decimal'}
                    value={str(f().values[field.name])}
                    aria-invalid={invalid() ? 'true' : undefined}
                    aria-describedby={describedBy(field)}
                    ref={(n) => first() && queueMicrotask(() => n.focus())}
                    onInput={(e) => set(e.currentTarget.value)}
                    onBlur={touch}
                  />
                  <Help field={field} />
                </div>
              </Match>
              <Match when={field.kind === 'object' || field.kind === 'array' || field.kind === 'text'}>
                <div class={css.field}>
                  {label}
                  <textarea
                    id={id(field.name)}
                    class={`${css.textarea} ${css.mono}`}
                    rows={field.kind === 'array' ? 3 : 4}
                    placeholder={field.kind === 'object' ? '{ }' : field.kind === 'array' ? 'one per line' : undefined}
                    value={str(f().values[field.name])}
                    aria-invalid={invalid() ? 'true' : undefined}
                    aria-describedby={describedBy(field)}
                    spellcheck={false}
                    ref={(n) => first() && queueMicrotask(() => n.focus())}
                    onInput={(e) => set(e.currentTarget.value)}
                    onBlur={touch}
                  />
                  <Help field={field} />
                </div>
              </Match>
              <Match when={field.kind === 'bytes'}>
                <div class={css.field}>
                  {label}
                  <div class={css.file}>
                    <input
                      ref={(n) => (fileInputs[field.name] = n)}
                      id={id(field.name)}
                      type="file"
                      tabIndex={-1}
                      aria-describedby={describedBy(field)}
                      onChange={async (e) => {
                        const file = e.currentTarget.files?.[0];
                        if (!file) return set(null);
                        set({ name: file.name, size: file.size, base64: await fileToBase64(file) });
                        touch();
                      }}
                    />
                    <button type="button" class={css.fileBtn} ref={(n) => first() && queueMicrotask(() => n.focus())} onClick={() => fileInputs[field.name]?.click()}>
                      Choose file…
                    </button>
                    <span class={css.fileName}>
                      {(() => {
                        const v = f().values[field.name];
                        return v && typeof v === 'object' ? `${v.name} · ${v.size} B` : 'No file chosen';
                      })()}
                    </span>
                  </div>
                  <Help field={field} />
                </div>
              </Match>
              <Match when={true}>
                <div class={css.field}>
                  {label}
                  <input
                    id={id(field.name)}
                    class={`${css.input}${field.kind === 'mono' ? ` ${css.mono}` : ''}`}
                    type="text"
                    value={str(f().values[field.name])}
                    aria-invalid={invalid() ? 'true' : undefined}
                    aria-describedby={describedBy(field)}
                    autocomplete="off"
                    spellcheck={false}
                    ref={(n) => first() && queueMicrotask(() => n.focus())}
                    onInput={(e) => set(e.currentTarget.value)}
                    onBlur={touch}
                  />
                  <Help field={field} />
                </div>
              </Match>
            </Switch>
          );
        }}
      </For>
    </div>
  );
};

