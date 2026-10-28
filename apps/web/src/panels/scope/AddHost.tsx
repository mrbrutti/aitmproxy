// The Add host line: a 28px mono input validated per the three forms (host, host:port,
// *.wildcard), an inline 12px error, Enter / ⌘⏎ or the `Add ⌘⏎` button to submit.
import { createSignal, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { validateHost } from './scope';
import css from './ScopePanel.module.css';

export const AddHost: Component<{
  existing: readonly string[];
  onAdd: (host: string) => void | Promise<unknown>;
}> = (props) => {
  const [value, setValue] = createSignal('');
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  let input: HTMLInputElement | undefined;

  const submit = async () => {
    const v = validateHost(value());
    if (!v.ok) {
      setError(v.error);
      return;
    }
    if (props.existing.includes(v.host)) {
      setError(`${v.host} is already in scope.`);
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await props.onAdd(v.host);
      setValue('');
    } finally {
      setBusy(false);
      input?.focus({ preventScroll: true });
    }
  };

  return (
    <div class={css.add}>
      <div class={css.field}>
        <input
          ref={input}
          class={css.input}
          type="text"
          value={value()}
          placeholder="host, host:port or *.wildcard"
          aria-label="Add host to scope"
          aria-invalid={error() ? 'true' : undefined}
          aria-describedby={error() ? 'scope-add-error' : undefined}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
          onInput={(e) => {
            setValue(e.currentTarget.value);
            if (error()) setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              void submit();
            }
          }}
        />
        <Show when={error()}>
          <div id="scope-add-error" class={css.error} role="alert">
            {error()}
          </div>
        </Show>
      </div>
      <Button variant="outline" kbd="⌘⏎" disabled={!value().trim() || busy()} onClick={() => void submit()}>
        Add
      </Button>
    </div>
  );
};
