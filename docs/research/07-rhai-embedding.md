# Rhai embedding — reference for the M3 scripting tier

Sources: the Rhai Book (rhai.rs/book — safety/sandbox/progress, engine/call-fn,
rust/custom-types + getters-setters, start/features) and the `rhai` crate API
(docs.rs/rhai, **v1.27.0**). mitmproxy addon/`@concurrent` model from
`01-mitmproxy.md`.

> **Provenance:** AI-generated research summary produced on 2026-10-27 while
> designing Milestone 3 (the Rhai scripting plugin tier). Signatures below were
> read from the rhai 1.27.0 docs where quoted; a few setter names relied on the
> stable public API and are marked **(verify at build)**. Verify specifics
> against upstream before relying on them in code (per this folder's policy).

## 1. Why Rhai fits (recap — decision already LOCKED)

Rhai is a pure-Rust, embeddable scripting language with **no ambient authority**:
the language core has **no filesystem, network, process, env, or clock access**.
The Book states a script "can never read from outside its own environment," and
an `Engine` created non-`mut` "cannot mutate any state, including itself." The
only capabilities a script gets are the Rust functions the host explicitly
registers. This is exactly the trust posture an operator-authored,
sandboxed plugin/PoC tier needs. (Engine selection is settled — see the
plugin-system spec; this note is embedding mechanics, not a re-litigation.)

## 2. Embedding mechanics (compile once, call many)

- **Compile once, reuse the AST.** `Engine::compile(script: impl AsRef<str>) ->
  Result<AST, ParseError>`. `AST` is `Clone`; with the `sync` feature it is
  `Send + Sync`. Compile each `.rhai` file once at load and keep the `AST`.
- **Call a named function (a hook).** `Engine::call_fn::<T>(&self, scope: &mut
  Scope, ast: &AST, name: &str, args: impl FuncArgs) -> Result<T, Box<EvalAltResult>>`.
  Args are a tuple (`("abc", 123_i64)`; one arg needs a trailing comma;
  no args is `()`). Rhai does **no implicit type conversion** — arg types must
  match the registered function exactly or the engine reports "function not
  found."
- **Inject per-call variables via `Scope`.** `Scope::new()` + `scope.push(name,
  value)`. This is how the PoC `script` step exposes `vars`, and how a hook can
  be handed request-scoped context. `call_fn` **rewinds the scope** after the
  call (new vars discarded) unless overridden with `CallFnOptions::new()
  .rewind_scope(false)` + `call_fn_with_options(...)`.
- **Run a bare body (no function).** `run_ast_with_scope(&self, scope, ast)` /
  `eval_ast_with_scope::<T>(&self, scope, ast)` — used for the PoC `script` step,
  whose body is a top-level block rather than a named hook.
- **Capture output.** `Engine::on_print(Fn(&str))` and `on_debug(Fn(&str, Option<&str>, Position))`
  route the script's `print`/`debug` (and our `log.*`) to the host logger; there
  is no stdout access otherwise.

## 3. Type marshalling (Rust ⇄ Rhai)

- **`Dynamic`** is Rhai's any-type. Built-in mappings: `i64` (INT), `f64`
  (FLOAT), `bool`, `rhai::ImmutableString` (string, cheap-clone), `rhai::Array`
  = `Vec<Dynamic>`, `rhai::Map` = `BTreeMap<SmartString, Dynamic>`, `rhai::Blob`
  = `Vec<u8>` (**the natural carrier for request/response bodies as bytes**).
- **Custom Rust types** need only `Clone` (`+ Send + Sync` under `sync`). Expose
  one with `register_type_with_name::<T>(name)`, then:
  - **getters/setters:** `register_get(name, Fn(&mut T) -> V)`,
    `register_set(name, Fn(&mut T, V))`, or `register_get_set(...)`.
  - **methods:** `register_fn(name, func)`; a method whose **first parameter is
    `&mut T` mutates in place and the change is visible to the script** (e.g.
    `a.xyz = "42"` then reading `a.xyz` yields `42`). This is the mechanism for
    in-place flow mutation from a script.
  - **indexers** (`m[k]`): `register_indexer_get/_set/_get_set` — natural fit for
    a header map's `headers["X"]` access.
  - `#[derive(CustomType)]` + `TypeBuilder` can generate the above for types we
    own; manual registration is for foreign types (orphan rule).
- Custom types are stored as a `dyn Variant` trait object → one extra level of
  indirection, so they run **slower than built-ins** (fine for a flexibility
  tier, not a hot path).
- **Design consequence (marshalling-by-handle, Architect's call).** Rather than
  deep-copy a whole `Flow` into Rhai per event, expose a thin **handle** custom
  type (e.g. `ScriptFlow`) wrapping a mutable borrow/`Arc` into the real `Flow`,
  with getters/setters that read/write the underlying Rust fields on demand.
  Bodies cross as `Blob`/string only when a script touches `.body`.

## 4. Sandboxing & resource limits (the capability model)

Default-deny is the starting point (§1). On top, bound every runaway vector:

| Control | Engine setter | Purpose |
|---|---|---|
| CPU / op count | `set_max_operations(u64)` (0 = unlimited) | abort looping/busy scripts |
| Recursion/stack | `set_max_call_levels(usize)` | cap call depth |
| Parser/AST depth | `set_max_expr_depths(max_expr: usize, max_fn_expr: usize)` | cap nesting at compile |
| String growth | `set_max_string_size(usize)` **(verify at build)** | cap memory |
| Array growth | `set_max_array_size(usize)` **(verify at build)** | cap memory |
| Map growth | `set_max_map_size(usize)` **(verify at build)** | cap memory |
| Module imports | `set_max_modules(usize)` (set 0 to forbid) | block `import` |
| Keyword/op ban | `disable_symbol(&str)` | remove e.g. `eval`, operators |

- **Operation callback + wall-clock timeout:** `Engine::on_progress(Fn(operations:
  u64) -> Option<Dynamic>)` fires once per operation. Return `None` to continue;
  return `Some(token)` to **terminate immediately** — the run then fails with
  `EvalAltResult::ErrorTerminated(token, position)`. The Book's own timeout
  example records a start `Instant` and returns `Some(Dynamic::UNIT)` once
  elapsed exceeds a limit. **This is the only wall-clock mechanism** (Rhai has no
  built-in timer) and it is how a per-hook time budget is enforced in addition to
  `max_operations`.
- **`eval` string-eval:** disable with `disable_symbol("eval")` (or Rhai's
  `Engine::disable_doc_comments`/`set_allow_*` toggles) so scripts cannot build
  code at runtime.
- **`unchecked` feature must NOT be enabled** — it turns off the operation,
  stack, module, and data-size limits ("a bad script may panic the entire
  system"). The `internals` feature must also stay off (exposes AST internals,
  "may enable external attack vectors").

## 5. The synchronous/async bridge (the key structural fact)

**Rhai is entirely synchronous.** A hook/host function runs to completion on the
calling thread; there is no `async fn` surface and `call_fn` returns a value, not
a future. But aitmproxy's guarded capabilities are async: the proxy client
(`ProxyClient::send -> BoxFuture`), the browser (`BrowserDriver::* -> BoxFuture`),
and `ModuleCtx::emit`. So:

- **Host functions that touch async core services bridge inside the call** with
  `tokio::runtime::Handle::current().block_on(fut)` (or a stored `Handle`). From
  Rhai's view `http.send(...)` / `browser.navigate(...)` are ordinary blocking
  calls that return a value; underneath they drive the async guarded future to
  completion.
- **Because a hook blocks, it must not run on a proxy I/O worker** — that would
  stall the flow (mitmproxy's exact pain point). Hooks run on
  `tokio::task::spawn_blocking` (or a dedicated script threadpool), mirroring
  mitmproxy's `@concurrent`. This also means the hosting `Engine` must be built
  with the **`sync` feature** (`Engine`/`Scope`/`AST` become `Send + Sync`) so it
  can be shared across those blocking tasks.
- The per-hook **wall-clock timeout (§4)** is what rescues a hook that blocks too
  long; combined with the blocking-thread isolation, a runaway script cannot
  wedge the proxy — it is aborted and surfaces as an `Error` event.

## 6. Hot-reload (optional nicety, not required for M3 gate)

`AST` is a plain owned value, so reload = recompile the file and atomically swap
the stored `AST` behind the lock the host plugin already holds. A file watcher
(`notify` crate) can trigger it. Compilation errors on reload keep the previous
good `AST`. (The plugin-system spec marks hot-reload a "later nicety" — treat as
roadmap, design the swap-point but don't require it for the exit gate.)

## 6a. JS-like authoring ergonomics (what Rhai gives for free)

Rhai's own syntax is already C/JavaScript/Rust-like, and two features make a
curated surface read like a small, friendly JS DSL without any transpilation:

- **Template literals.** Backtick strings with `${...}` interpolation, exactly
  like JavaScript: `` `${base}/search?q=${url_encode(payload)}` ``. (Escape
  sequences are not processed inside backtick strings.) This alone removes most
  of the `+ "..." +` concatenation noise that makes embedded scripts ugly.
- **`in`, indexing, ranges.** `"secret" in body`, `headers["X-Api"]`,
  `record[4..8]` — all read naturally.

So the "easy JS-like DSL" Matt wants is achievable as **Rhai + a curated
domain-verb host API + a small bundled prelude**, not a separate DSL compiler.
Object maps (`#{ ... }`) are the natural argument shape for `http.send(#{...})`
and `finding(#{...})`. (The RustProxy project cited as a DSL precedent,
`BarisSenel/RustProxy`, is in fact a reverse-SOCKS5 tunneler with CLI-flag config
and no scripting layer — the DSL inspiration to mine is nuclei's matcher/DSL
vocabulary, already captured in `02-nuclei.md`, expressed through Rhai's
JS-like syntax.)

## 7. Design takeaways for aitmproxy M3

1. One shared `Engine` (built with `sync`, default-deny, all limits set,
   `on_progress` op+time budget, `on_print`/`on_debug` → host log), created once
   by the host plugin.
2. Per script: compile to `AST` once at load; keep `(name, AST, metadata)`.
3. Dispatch an `Event` → `call_fn::<Verdict-ish>(&mut scope, &ast, hook_name,
   args)` on a blocking task; map the return to `Verdict::Continue|Halt`.
4. Expose flow/request/response/ws-message as **handle custom types** with
   getters/setters/indexers; bodies as `Blob`/string on demand.
5. Register host-function namespaces (`log`, `http`, `browser`, `store`, `scope`
   + DSL helpers) as Rust closures capturing `Arc` handles; the network/browser
   ones `block_on` their guarded async future so **every capability still passes
   the scope/rate/SSRF guards** — no guard bypass is reachable from a script.
6. The PoC `script` step reuses the identical engine + host surface, body form
   via `run_ast_with_scope`, with `vars` injected through the `Scope`.
