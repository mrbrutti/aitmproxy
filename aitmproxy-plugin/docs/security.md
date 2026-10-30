# Security — streamable-HTTP transport threat model

This covers the **streamable-HTTP MCP transport** (spec §F, workstream W1). stdio
(bare `aitm`) is the default and is not affected by anything here; read this only
if you enable the HTTP listener.

> **Authorized engagements only.** aitmproxy is a man-in-the-middle proxy. Run it,
> and expose its control plane, solely against targets covered by a written
> engagement you are authorized to test.

## What is exposed

The streamable-HTTP endpoint exposes aitmproxy's **control plane over a network
socket**: reading captured traffic, replaying and mutating requests, adjusting
scope, and running PoCs. Anyone who can both reach the socket and present the
Bearer token can drive the proxy. That is the blast radius — treat the token and
the bind address as credentials to the MITM itself.

## Defenses

### Bearer token — the only authentication

- Every request must carry `Authorization: Bearer <token>` equal to the
  configured token, compared in **constant time**.
- The token is **required and non-empty** in config. A request with a missing,
  empty, or wrong token is **never dispatched** — it gets `401` with no body that
  echoes the token.
- The token is **never logged** and never appears in the startup line. The
  stderr startup line says only `MCP streamable HTTP listening on <addr><path>`.

### Loopback-default bind

- Default bind is `127.0.0.1:8084`. There is **no "bind all" default** and no code
  path that widens the bind implicitly.
- Binding any non-loopback interface is an **explicit operator decision** made by
  setting `bind` in config/CLI. Doing so widens the blast radius above to every
  host that can reach that interface — make that choice deliberately and state it.

### Origin allowlist + Host / DNS-rebinding guards

These are the **only** DNS-rebinding defense. Guards run **before any dispatch**,
fail-closed, in this fixed order:

1. **Auth** — Bearer token (above). Fail → `401`.
2. **Origin allowlist** — if an `Origin` header is present it must be in
   `allowed_origins` (exact match); otherwise `403`. The default allowlist is
   **empty**, so any present `Origin` is rejected (same-origin / no-Origin tools
   still work).
3. **Host check** — the `Host` header must be a loopback literal
   (`127.0.0.1[:port]`, `[::1][:port]`, `localhost[:port]`) or an explicitly
   allowlisted host; otherwise `403`. This blocks a rebound DNS name that resolves
   to loopback.
4. **Method / path** — anything but `POST` / `GET` on the configured `path` →
   `405` / `404`.

### No in-process TLS

The transport ships **no TLS**. For any non-loopback use the operator **must**
front it with a tunnel or an HTTPS reverse proxy that terminates TLS and forwards
to the loopback listener. Do not send the Bearer token over a plaintext network
hop.

## v1 limitation — GET SSE lane is structural-only

The `GET` endpoint opens a `text/event-stream` lane so the Streamable-HTTP shape
is complete, but in v1 it is **structural only**: `POST` and `GET` are
**uncorrelated** — there is no cross-request subscription delivery, so
server→client notifications are not pushed to a specific client session over this
channel. Do not rely on it for live `notifications/aitm/*` delivery in v1.

## Operator sign-off (MV6)

A **security reviewer must sign off before any non-loopback use** of this
endpoint. Loopback-only development needs no sign-off; the moment `bind` leaves
loopback, the review — covering the token handling, the fronting TLS/tunnel, and
the exposure of the MITM control plane — is required.
