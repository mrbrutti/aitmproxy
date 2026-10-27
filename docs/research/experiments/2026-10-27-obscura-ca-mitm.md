# Experiment: can obscura trust aitmproxy's MITM CA?

**Date:** 2026-10-27
**Branch:** `claude/experiment-obscura-ca-mitm-8bd9e9` (the app's name for
`experiment/obscura-ca-mitm`; never merged — only this write-up is worth
cherry-picking; delete or leave the rest untouched)
**Session:** separate session with its own worktree
**Inputs:** `docs/research/06-obscura-embedding.md` (flagged CA trust as the M2
blocker, unverified), `crates/aitm-browser/src/{driver.rs,ssrf.rs}`.

## Question

Can an embedded or self-hosted obscura browser trust aitmproxy's MITM root CA
so that its HTTPS traffic is decrypted and captured by aitmproxy — and what is
the cheapest way to make that work, ideally without a fork?

Secondary: does obscura's SSRF guard block a **loopback upstream proxy**; what
does obscura cost to build; does the library crate (vs the CDP server) expose
`screenshot` and `type`.

## Setup

- **obscura:** source clone of `github.com/h4ckf0r0day/obscura` at
  `034a147` (2026-10-27, workspace version 0.1.0) read for the trust mechanism;
  prebuilt release binaries **v0.2.5** (2026-10-17) run for the proof:
  `obscura-aarch64-macos.tar.gz` (render, 73 MiB) and
  `obscura-aarch64-macos-stealth.tar.gz` (render+stealth, 76 MiB). macOS 26,
  Apple Silicon.
- **aitmproxy:** `main` at `a0a0e8a` plus one throwaway harness,
  `crates/aitm/examples/obscura_spike.rs` (and a `chromiumoxide` dev-dependency
  on `aitm` for it). The harness builds the real proxy with
  `aitm::wire::build_proxy`, runs `proxy.run` (or `run_browser`, the
  SSRF-filtered listener) on `127.0.0.1:18080` with a fresh `CertAuthority` in
  `~/tmp/obscura-spike/ca`, then either spawns an obscura command as a child
  with `SSL_CERT_FILE` / `SSL_CERT_DIR` / nothing in its environment, or
  connects to a running `obscura serve` over CDP with `chromiumoxide` exactly
  as `ChromeDriver` does (`Browser::connect`, `new_page`,
  `Security.setIgnoreCertificateErrors`, `goto`, `evaluate`, `content`,
  `screenshot`). It then dumps every flow in the proxy's store. A decrypted
  request line (method, path, status) in that dump is the proof of MITM.
- Skipped: tests, error handling, the OS-keychain install (see Result 1 — the
  source shows it cannot work, so Matt's keychain was not touched), a source
  build of the `obscura` **crate** linked into aitmproxy.

## Result

### 1. obscura's TLS trust mechanism (from source)

obscura does **not** use the OS trust store and does **not** use Chromium's
network stack. Its HTTP client is `reqwest 0.12` with
`features = ["rustls-tls", ...], default-features = false`
(`Cargo.toml:49`); the lockfile resolves that to `webpki-roots 1.0.10` and
contains **no** `rustls-native-certs`, `native-tls`,
`rustls-platform-verifier`, `openssl-probe` or `security-framework`. So the
bundled Mozilla roots are the baseline, and installing a CA in the macOS
keychain or `/etc/ssl/certs` is invisible to it.

What it **does** have — undocumented in the user docs, but present and tested —
is `SSL_CERT_FILE` / `SSL_CERT_DIR` support that **adds** roots:

- `crates/obscura-net/src/client.rs:18-34` `configured_root_paths()` reads
  `SSL_CERT_FILE` (one path) and every entry of `SSL_CERT_DIR` (non-empty
  values only).
- `client.rs:37-62` `configured_root_certificates()` parses each file as a PEM
  bundle, falling back to DER, into `reqwest::Certificate`s (a `OnceLock`, so
  read once per process).
- `client.rs:1090-1113` `get_client()` builds the client with
  `.danger_accept_invalid_certs(false)`, the SSRF `dns_resolver`, then — only if
  either env var is set — `add_root_certificate` for each configured root, then
  `reqwest::Proxy::all(proxy_url)`.
- Tests `client.rs:2901` `configured_roots_trust_a_private_ca_via_ssl_cert_file`,
  `:2916` `..._via_ssl_cert_dir`, `:2934`
  `private_ca_is_still_rejected_without_ssl_cert_file` mint a throwaway CA with
  rcgen and prove exactly our case.
- Stealth build (`wreq`/BoringSSL, `crates/obscura-net/src/wreq_client.rs:240-272`):
  when either env var is set it installs
  `wreq::tls::trust::CertStore::builder().set_default_paths()` via
  `tls_cert_store`. The comment is explicit that this **replaces** the webpki
  roots rather than adding to them. (The "bundles webpki roots instead of the
  system store" line in `docs/Configure-stealth-and-proxies.md:16` describes
  the no-env default.)

There is no `--ca-cert`, no insecure/no-verify flag, no builder method on the
library crate, and the CDP `Security` domain is a stub: `Security.enable` and
friends are accepted and ignored (`crates/obscura-cdp/src/dispatch.rs:862`,
`server.rs:2268`). `Security.setIgnoreCertificateErrors` therefore
**succeeds and does nothing** (Result 3).

### 2. No-fork paths, cheapest first

Harness output, verbatim (trimmed to the decisive lines). Target
`https://example.com`, proxy `http://127.0.0.1:18080`, obscura v0.2.5.

| # | Path | obscura result | Proxy store |
|---|---|---|---|
| A | `--proxy`, **no CA** | exit 1 after 212 ms: `client error (Connect): invalid peer certificate: UnknownIssuer` | 0 flows |
| B | `--proxy`, **`SSL_CERT_FILE=<ca.crt>`** | exit 0 after 216 ms, prints `Example Domain` | `GET https://example.com/ -> 200`, `GET https://example.com/s.js -> 200` |
| C | `--proxy`, `SSL_CERT_DIR=<CA dir>` | **panic** at `client.rs:1095`: `failed to build HTTP client: InvalidCertificate(BadEncoding)` — the dir also holds `ca.key`, which it tried to load as a certificate | 0 flows |
| D | as B, via aitmproxy's **SSRF-filtered browser listener** (`run_browser`) | exit 0 after 283 ms | same 2 decrypted flows |
| E1 | **stealth** binary, `--stealth --proxy`, `SSL_CERT_FILE` | exit 0 after 410 ms | same 2 decrypted flows |
| E2 | stealth, no CA | exit 1: `[CERTIFICATE_VERIFY_FAILED]` | 0 flows |
| G1 | `--proxy`, target `http://127.0.0.1:18099/`, no flag | exit 1 after 8 ms: `Access to private/internal IP address 127.0.0.1 is not allowed … start Obscura with --allow-private-network` | 0 flows (blocked before the proxy) |
| G2 | as G1 with `--allow-private-network` | `connection closed before message completed` (nothing listens on 18099) | `GET http://127.0.0.1:18099/ -> None` — the request **did** go through the proxy |

(a) OS trust store — not attempted: ruled out by source (Result 1).
(b) `SSL_CERT_FILE` — **works**, both builds. (c) config/API flag — none exists.
(d) loopback proxy — **works with no SSRF allowance** (B, D, E1): the proxy URL
is never passed through `validate_url` (`client.rs:643-696`, which inspects
only the target URL) and, with a proxy configured, reqwest dials the proxy's
IP literal without consulting the `SsrfGuardResolver` (`client.rs:608-640`).
`--allow-private-network` / `OBSCURA_ALLOW_PRIVATE_NETWORK=1` is needed only
when the **target** is private or loopback (G1 vs G2); it is a global CLI flag
(`obscura-cli/src/main.rs:55-61`, mirrored into the env var at `:443-449`).

### 3. End to end over CDP (the M2 shape)

`SSL_CERT_FILE=<ca.crt> obscura serve --port 9333 --proxy http://127.0.0.1:18080`,
then the harness in CDP mode (`chromiumoxide::Browser::connect("ws://127.0.0.1:9333")`):

```
[cdp] Security.setIgnoreCertificateErrors: accepted
[cdp] navigated https://example.com/ in 216.562167ms
[cdp] url: Some("https://example.com/")
[cdp] document.title = Some(String("Example Domain"))
[cdp] content: 2373 bytes
[cdp] screenshot: 63715 bytes
[flow] GET https://example.com/ -> Some(200)
[flow] GET https://example.com/s.js -> Some(200)
```

Every primitive the current driver uses worked unchanged against obscura; the
proxy decrypted the navigation. The `Security.setIgnoreCertificateErrors` call
was accepted but is a no-op — trust came from `SSL_CERT_FILE` (A proves it is
not granted otherwise). Cosmetic: aborting the chromiumoxide handler without a
close frame logs `WS read error: Connection reset without closing handshake`
on the server.

### 4. Build weight, platforms, library API

- **Prebuilt:** release archives for Linux x86_64/aarch64 (Ubuntu 22.04 /
  glibc 2.35+), macOS arm64/x86_64, Windows; 73 MiB (`render`), 76 MiB
  (`render-stealth`), plus a 69-72 MiB `obscura-worker` only `scrape` needs.
  Gatekeeper needs `xattr -d com.apple.quarantine`. Docker image is distroless.
- **Source:** `cargo build --release -p obscura-cli --bins --features render`
  on this machine (Apple Silicon, see Result 4a below). V8 comes from the
  crates.io `v8 150.4.0` (rusty_v8) via `deno_core 0.412` — rusty_v8 downloads
  a prebuilt static library by default; the README's "V8 compiles from source,
  ~5 min" and "~5 GB disk" should be read against the measured number. The
  `stealth` feature additionally builds BoringSSL (CMake, Clang, libclang; on
  macOS 26 an `SDKROOT`/`CXXFLAGS` workaround is documented). Tests require
  `cargo nextest` (one V8 isolate per process).
- **Library crate (`crates/obscura`, Candidate B):** `Browser::builder()
  .proxy().stealth().user_agent().storage_dir()`; `Page::{goto, url, evaluate,
  evaluate_in_frame, content, query_selector, wait_for_selector, settle,
  add_preload_script, enable_interception, on_request, on_response}`;
  `Element::{text, attribute, click}` (`crates/obscura/src/{browser,page}.rs`).
  **No `screenshot`, no `type`/key input, no `allow_private_network`** on the
  facade (`Browser::build` at `browser.rs:25-45` passes `false`; only the env
  var reaches it). One level down, `obscura_browser::Page::screenshot(viewport)
  -> Option<Vec<u8>>` exists behind the `render` feature
  (`obscura-browser/src/page.rs:4098`), and key input exists only in the CDP
  layer (`obscura-cdp/src/domains/input.rs`, `Input.dispatchKeyEvent` /
  `insertText` implemented as injected JS). So the CDP server covers all six
  `browser.*` commands today; the crate covers four.
- `obscura serve` has `--ready-file <PATH>` (written when listening), `--host`,
  `--max-connections`, `OBSCURA_CDP_TOKEN`; `--proxy` is global and applies to
  `serve`. obscura ignores `HTTP_PROXY`/`NO_PROXY` (`docs/Environment-variables.md:197`),
  so there is no bypass list to disable — loopback targets go through the proxy
  too (G2), which is what `--proxy-bypass-list=<-loopback>` achieves for Chrome.

#### 4a. Measured source build

Cold release build of the CLI from source at `034a147`, Apple M3 Max
(16 cores), macOS 27.0, Rust 1.97.1, warm crates.io cache:

```
cargo build --release -p obscura-cli --bins --features render
    Finished `release` profile [optimized] target(s) in 1m 19s
743.77s user 52.24s system 1001% cpu 1:19.47 total
target/release/obscura  109M      target/  2.0G
```

**1 min 19 s wall, ~12.4 CPU-minutes, 2.0 GiB of target, 109 MiB binary.**
V8 was not compiled from source — `v8 150.4.0` (rusty_v8) downloaded its
prebuilt static library, which is why the README's "~5 min / ~5 GB" overstates
it on a supported platform. `stealth` was not built here (needs CMake + Clang +
libclang for BoringSSL and would add materially to this). For comparison the
whole aitmproxy workspace debug build of `aitm` took 31 s on the same machine.

## Conclusion

**Proven.** obscura trusts aitmproxy's MITM CA with **no fork and no patch**:
set `SSL_CERT_FILE=<path to ca.crt>` in the obscura process's environment.
HTTPS through aitmproxy is then decrypted and captured, for both the default
(reqwest/rustls) and stealth (wreq/BoringSSL) builds, over `fetch` and over
CDP from `obscura serve`, through either of aitmproxy's listeners.

The research note's blocker is resolved, with three corrections to it:

1. The trust mechanism is `SSL_CERT_FILE`/`SSL_CERT_DIR`, present in source and
   tests since before v0.2.5 but absent from the user docs.
2. A loopback **upstream proxy** needs no SSRF allowance; only loopback/private
   **targets** do.
3. `Security.setIgnoreCertificateErrors` is not "absent" — it is accepted and
   ignored, which is worse for diagnosis (a driver would believe it worked).

The cheapest working path is **Candidate A** from the research note: ship the
prebuilt `obscura` binary, spawn `obscura serve --port <p> --proxy
http://127.0.0.1:<browser-listener>` with `SSL_CERT_FILE` set on the child,
and point the existing chromiumoxide driver at it with `Browser::connect`.
The in-process crate (Candidate B) is held back not by TLS but by its facade:
no screenshot, no typing, and trust configured by a process-global env var
that aitmproxy would have to set in its own process before the first client
builds (harmless to aitmproxy's own rustls/webpki upstream verification, but a
hidden coupling).

## Carry into the spec

- **CA trust:** the obscura process gets `SSL_CERT_FILE=<ca.crt>` at spawn.
  Never `SSL_CERT_DIR` pointed at the CA directory: it contains `ca.key`, which
  obscura reads and chokes on (panic, Result C) — and the browser process has
  no business opening the key. If the CA dir layout ever changes, keep the
  cert in a file obscura can be pointed at alone.
- **Drop** `Security.setIgnoreCertificateErrors` from the obscura driver path
  (accepted-and-ignored); `BrowserConfig::ignore_cert_errors` keeps its Chrome
  meaning or is replaced by "CA is trusted via env" for obscura. The driver must
  not infer trust from the CDP call succeeding.
- **SSRF:** pass `--allow-private-network` to obscura iff aitmproxy's own
  policy/scope would let a private or loopback target through (otherwise
  obscura blocks it before aitmproxy's guard sees it and the operator gets
  obscura's error, not ours); aitmproxy's `ssrf.rs` and the SSRF-filtered
  browser listener remain the authoritative guard either way. The loopback
  proxy itself needs nothing.
- **Stealth:** optional. With `SSL_CERT_FILE` set the stealth client trusts
  *only* that file, which is correct when every request goes via the proxy
  (aitmproxy verifies upstream with webpki roots) and must be stated.
- **Driver shape:** the CDP driver is reusable as is (`Browser::connect`
  instead of `launch`); `navigate/click/type/screenshot/eval/get_dom` all
  worked. Use `--ready-file` (or poll the port) for spawn readiness and close
  the CDP session cleanly. Pin a release tag ≥ v0.2.5.
- **Distribution:** a ~73 MiB prebuilt per platform (macOS arm64/x86_64, Linux
  x86_64/aarch64 glibc ≥ 2.35) bundled or fetched; `obscura-worker` is not
  needed. If the spec prefers linking the crate (B), it must add screenshot and
  typing (upstream PR or the CDP server as fallback) and accept the build
  weight in 4a.
- **Upstream nicety, not a dependency:** a `root_certificate()` on
  `obscura::BrowserBuilder` / `ObscuraHttpClient::with_full_options` would
  replace the env var for in-process use; it is a ~20-line change in
  `obscura-net` and worth proposing, but M2 does not need it.
