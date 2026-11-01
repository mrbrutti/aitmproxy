# Proxyman screen index

Status 2026-10-31: **Proxyman has not been run by this session.** Its
"Auto Override System Proxy Settings at Launch" default routed every new
Claude session through 127.0.0.1:9090 earlier tonight, so the clone pass
(bama `clone`: every screen, menu and dialog, shot with
`apps/mac/tools/winshot.swift`) waits for a run **Matt starts himself with
that checkbox off**. Nothing below was captured from a live Proxyman window.

What is here instead:

| Folder | Source | Files |
|---|---|---|
| `shots/demo-video/` | frames of `capture-http-https-demo-2026.mp4` (scaled to 1762 px) | `f001-main-window.png` (sidebar, chip bar, list, inspector Header tabs, status bar), `f008-custom-previewer.png` (the `Custom Previewer Tab` sheet), `f011-json-path.png` (JSON tab with JSON Path field) |
| `shots/aitmproxy-live-2026-10-31/` | our own app, live dev bundle, real curl traffic (see [DELTA.md](DELTA.md)) | `0-landing` (Apps page, empty), `1-after-traffic`, `2-row-selected`, `3-domains`, `5-status`, `6-ca`, `7-scope`, `8-overview`, `9-connection-log`, `10b-front` (Settings ▸ General) |

## Screens to capture when Proxyman is open (checklist for the clone pass)

Main window
- [ ] main window, empty session (first second after launch)
- [ ] main window with traffic, Apps expanded (real icons), one app expanded to its domains
- [ ] Domains expanded, a host with a path disclosure
- [ ] a `CONNECT` row selected: Response pane with `Enable only this domain (⌥⏎)` / `Enable all domains from "<app>"`
- [ ] a decrypted row selected: Header / Body / Raw / Treeview; `+` → Custom Previewer Tab sheet
- [ ] chip bar overflow (`‹` / `›`), a saved-filter chip
- [ ] status bar with `Proxy Overridden` and `Breakpoint` badges
- [ ] row context menu; sidebar app row context menu (`Enable SSL Proxying`, `Pin to Favorites`)
- [ ] `⌘K` command palette
- [ ] layout glyphs: inspector right / bottom / hidden

Sheets and dialogs
- [ ] `Install Proxy Helper Tool / Version 1.7.0` sheet (do **not** click Install)
- [ ] `No HTTP Traffic?` alert (appears on its own after a silent start)
- [ ] `SSL Proxying List…` (⌘⌥P), Include / Exclude tabs
- [ ] Certificate ▸ `Install Certificate on this Mac…`, Automatic and Manual tabs (do **not** click Install & Trust)
- [ ] Compose window; Breakpoint rule editor; Map Local editor

Settings (⌘,)
- [ ] App ▸ General (`Port Number`, `Auto Override System Proxy Settings at Launch`, `Auto Start Recording Traffic at Launch`, `Use HTTP/2`, `Advanced Proxy Setting…`, `Proxyman CA` block)
- [ ] App ▸ Appearance (`Menu Bar: Show Proxyman Icon on Menu Bar`, `Status Bar`)
- [ ] App ▸ Privacy
- [ ] Integrations ▸ MCP (`Enable MCP Server`, `Redact Sensitive Data…`), GitHub, Tools
- [ ] Advanced ▸ Network Extension BETA (`Enable Network Extension`, do **not** click Install and Enable), Advanced (`Proxy Helper Tool:` row)
- [ ] Proxyman ▸ Workspace, Products

Menus
- [ ] every menu-bar menu dropped down (File, Edit, View, Tools, Certificate, Window, Help …)
- [ ] the menu-bar extra, if `Show Proxyman Icon on Menu Bar` is on

Rules for the pass: read-only. Never change a persistent Proxyman setting,
never install the helper, the CA or the extension, never leave Proxyman
running with the override on when done. One shot per state, ≤ 2 MB, named
`NN-<screen>-<state>.png` under `shots/proxyman/`.
