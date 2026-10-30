// The new-script editor: a name (checked against the core's `[A-Za-z0-9_-]+` rule before any call), a
// plain monospace textarea for the source (no editor dependency), Validate (`script.validate`, a read)
// and Save (`script.save` with `enable: true`). The result region shows the validate summary, the save
// result with its `restart_required` verdict, or the core's error text verbatim — compile errors are
// positioned, multi-line text, so it is rendered pre-wrapped and untouched.
import { Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { isScriptName, type ScriptReport } from './model';
import { AGENT_REASON, type ScriptsStore } from './store';
import css from './ScriptsPanel.module.css';

const SKELETON = 'const NAME = "my-script";\nconst API = "1";\n\nfn on_request(flow) {\n  // inspect or change the request here\n}\n';

const list = (items: readonly string[]) => (items.length ? items.join(', ') : '—');

const Report: Component<{ kind: 'valid' | 'saved'; report: ScriptReport }> = (props) => (
  <>
    <div class={css.verdict}>{props.kind === 'saved' ? `Saved ${props.report.name}` : 'Valid'}</div>
    <dl class={css.fields}>
      <dt>Name</dt>
      <dd data-field="name">{props.report.name}</dd>
      <Show when={props.report.path}>
        {(path) => (
          <>
            <dt>Path</dt>
            <dd data-field="path">{path()}</dd>
          </>
        )}
      </Show>
      <dt>API</dt>
      <dd data-field="api">{props.report.api}</dd>
      <dt>Hooks</dt>
      <dd data-field="hooks" data-none={props.report.hooks.length === 0 ? '' : undefined}>
        {list(props.report.hooks)}
      </dd>
      <dt>Commands</dt>
      <dd data-field="commands" data-none={props.report.registers.commands.length === 0 ? '' : undefined}>
        {list(props.report.registers.commands)}
      </dd>
      <dt>Options</dt>
      <dd data-field="options" data-none={props.report.registers.options.length === 0 ? '' : undefined}>
        {list(props.report.registers.options)}
      </dd>
    </dl>
    <Show when={props.report.restartRequired !== null}>
      <p class={css.restart} data-required={props.report.restartRequired ? 'true' : 'false'}>
        {props.report.restartRequired
          ? 'Restart required — the commands and options it registers appear after the core restarts; its hooks already run.'
          : 'No restart needed — its hooks run on the next event.'}
      </p>
    </Show>
  </>
);

export const ScriptEditor: Component<{ store: ScriptsStore }> = (props) => {
  const s = props.store;
  const hasSource = () => s.source().trim() !== '';
  const canValidate = () => s.canValidate() && !s.busy() && hasSource();
  const canSave = () => s.canSave() && !s.busy() && hasSource() && isScriptName(s.name());

  const error = () => {
    const o = s.outcome();
    return o?.kind === 'error' ? o.text : null;
  };
  const report = () => {
    const o = s.outcome();
    return o?.kind === 'valid' || o?.kind === 'saved' ? o : null;
  };

  return (
    <section class={css.editor} aria-label="New script">
      <h3 class={css.heading}>New script</h3>

      <div class={css.field}>
        <label class={css.label} for="script-name">
          Script name
        </label>
        <input
          id="script-name"
          class={css.input}
          type="text"
          value={s.name()}
          placeholder="my-script"
          spellcheck={false}
          autocomplete="off"
          aria-invalid={s.nameError() ? 'true' : undefined}
          aria-describedby={s.nameError() ? 'script-name-error' : undefined}
          onInput={(e) => s.setName(e.currentTarget.value)}
        />
        <Show when={s.nameError()}>
          {(message) => (
            <p class={css.fieldError} id="script-name-error">
              {message()}
            </p>
          )}
        </Show>
      </div>

      <div class={css.field}>
        <label class={css.label} for="script-source">
          Script source
        </label>
        <textarea
          id="script-source"
          class={css.source}
          value={s.source()}
          placeholder={SKELETON}
          spellcheck={false}
          autocomplete="off"
          autocapitalize="off"
          onInput={(e) => s.setSource(e.currentTarget.value)}
        />
      </div>

      <div class={css.actions}>
        <Button variant="outline" disabled={!canValidate()} title={s.canValidate() ? 'Compile it without saving' : 'script.validate is not offered by this core'} onClick={() => void s.validate()}>
          Validate
        </Button>
        <Button
          variant="primary"
          disabled={!canSave()}
          title={s.agent() ? AGENT_REASON : s.canSave() ? 'Write it to the scripts directory and enable it' : 'script.save is not offered by this core'}
          onClick={() => void s.save()}
        >
          Save
        </Button>
      </div>

      <section class={css.result} aria-label="Result" aria-live="polite" data-empty={s.outcome() ? undefined : 'true'}>
        <Show when={error()}>
          {(text) => (
            <pre class={css.pre} role="alert">
              {text()}
            </pre>
          )}
        </Show>
        <Show when={report()}>{(r) => <Report kind={r().kind} report={r().report} />}</Show>
      </section>
    </section>
  );
};
