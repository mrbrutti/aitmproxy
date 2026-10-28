// Cookies (request `cookie`) and Set-Cookie (response) parsed into name · value · attributes.

import { createMemo, For, Show, type Component } from 'solid-js';
import type { Header } from '~/model/flow';
import { requestCookies, responseCookies, type SetCookie } from './cookies';
import { Centered } from './ui';
import css from './inspector.module.css';

export const CookieTable: Component<{ headers: Header[]; mode: 'cookie' | 'set-cookie' }> = (props) => {
  const rows = createMemo<SetCookie[]>(() =>
    props.mode === 'cookie' ? requestCookies(props.headers).map((c) => ({ ...c, attributes: [] })) : responseCookies(props.headers),
  );
  const showAttrs = () => props.mode === 'set-cookie';

  return (
    <Show when={rows().length} fallback={<Centered>{props.mode === 'cookie' ? 'No cookies sent' : 'No cookies set'}</Centered>}>
      <div class={css.table} classList={{ [css.tableThree!]: showAttrs() }} role="table" aria-label={props.mode === 'cookie' ? 'Cookies' : 'Set-Cookie'}>
        <div class={`${css.row} ${css.rowHead}`} role="row">
          <span role="columnheader">name</span>
          <span role="columnheader">value</span>
          <Show when={showAttrs()}>
            <span role="columnheader">attributes</span>
          </Show>
        </div>
        <For each={rows()}>
          {(c) => (
            <div class={css.row} role="row">
              <span class={css.cellKey} role="cell">
                {c.name}
              </span>
              <span class={css.cellVal} role="cell">
                {c.value || <span class={css.dash}>—</span>}
              </span>
              <Show when={showAttrs()}>
                <span class={`${css.cellVal} ${css.cellAttrs}`} role="cell">
                  <Show when={c.attributes.length} fallback={<span class={css.dash}>—</span>}>
                    <For each={c.attributes}>
                      {(a, i) => (
                        <>
                          <Show when={i() > 0}>
                            <span class={css.attrSep}>·</span>
                          </Show>
                          <span>
                            {a.name}
                            {a.value != null ? `=${a.value}` : ''}
                          </span>
                        </>
                      )}
                    </For>
                  </Show>
                </span>
              </Show>
            </div>
          )}
        </For>
      </div>
    </Show>
  );
};
