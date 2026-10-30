# tests/e2e/ne — macOS Network Extension (L4 capture)

End-to-end checks for the macOS Network Extension capture path. Run with:

    python3 tests/e2e/run.py ne            # AUTO suites only
    python3 tests/e2e/run.py ne --manual   # also the live 2-click gate

## AUTO (no human, no signed build needed)
- `ne_rust_handoff.sh` — the provider↔core handoff, loop-avoidance and capability
  seam (`crates/aitm/tests/macos_capture_*`). Binds Unix domain sockets, so it runs
  here (unsandboxed), not in CI's restricted sandbox. SKIPs off macOS / without cargo.
- `ne_swift_capability.sh` — the capability state machine, `TunnelReconcilePolicy`
  and the `TunnelFailure` classifier (`AitmproxyKitTests/CaptureCapabilityTests`).
  SKIPs off macOS / without swift.
- `ne_signing.sh` — entitlements, codesign, spctl, the notarization staple, and the
  sysex `CFBundleVersion` / activation state on a SIGNED build. SKIPs loudly until a
  signed NE build is installed in `/Applications` (`build.sh` runs at Task 18).

## MANUAL (`--manual`)
- `test_live_capture.py` — the live gate: the two System Settings approval clicks,
  then the in-scope capture shown in all three UIs (macOS app, `aitm web`, `aitm tui`).
  `tier=manual`. SKIPs until a signed build is installed; the cross-UI capture
  assertions are wired when the core-side rendezvous writer + scope-spec emitter land.

A SKIP (exit 77) is loud and stays green — it never reads as a pass. Each suite goes
green on its own as its dependency lands; the live gate is the Task-18 milestone.
