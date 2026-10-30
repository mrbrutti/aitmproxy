# Linux packaging of obscura — payload shape and runtime dependencies

**Purpose.** Authoritative input for Task 1 of the cross-platform packaging plan
(`docs/superpowers/plans/2026-10-29-aitmproxy-distribution-packaging-plan.md`),
satisfying AC3/AC4: what the Linux obscura artifact actually contains and what
shared libraries it needs, so the `.deb`/`.rpm` `Depends`/`Requires` are derived
from the binary, not guessed.

**Provenance.** Commands run 2026-10-29 against the `mrbrutti/obscura@aitm-v1`
Linux release assets, on macOS (no `ldd`/`readelf` available, so `DT_NEEDED` was
read directly from the ELF `.dynamic` section with a self-contained parser). The
one check that genuinely needs a Linux host — launching obscura and confirming no
`dlopen` failure — is called out below as a CI/Linux-host step.

## 1. Payload shape — a single self-contained binary

Both Linux assets extract to exactly one file, `obscura`, with no sibling `.so`,
resource `.pak`, locale, or sandbox-helper files:

```
$ tar -xzf obscura-x86_64-unknown-linux-gnu.tar.gz -C e64 && find e64
e64
e64/obscura
$ du -sh e64   # 117M   (compressed asset ~46 MB)
$ file e64/obscura
e64/obscura: ELF 64-bit LSB pie executable, x86-64, ... dynamically linked,
  interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, ... not stripped
$ file ea/obscura
ea/obscura: ELF 64-bit LSB pie executable, ARM aarch64, ... dynamically linked,
  interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, ... not stripped
```

So the package payload per arch is just the one `obscura` binary (plus `aitm` and
`aitm-tui` from this repo). No companion files to lay down.

## 2. Direct dynamic dependencies (`DT_NEEDED`)

`DT_NEEDED` is the authoritative direct-dependency list — what `ldd` resolves at
load time. Read from the `.dynamic` section of each binary:

```
=== x86_64 NEEDED ===            === aarch64 NEEDED ===
libgcc_s.so.1                    libgcc_s.so.1
libm.so.6                        libm.so.6
libc.so.6                        libc.so.6
ld-linux-x86-64.so.2             ld-linux-aarch64.so.1
```

obscura is **near-fully statically linked**: it needs only glibc (`libc.so.6`,
`libm.so.6`), `libgcc_s.so.1`, and the dynamic loader — all present on every
glibc-based Linux. It does **not** directly link GTK, X11, NSS, GBM, ALSA, or the
rest of a typical desktop-Chromium stack (consistent with it being driven headless
over CDP by `aitm`).

### Derived package dependencies

| Format | Field | Value | Why |
|---|---|---|---|
| Debian/Ubuntu `.deb` | `Depends` | `libc6, libgcc-s1` | `libc.so.6`+`libm.so.6` ⇒ `libc6`; `libgcc_s.so.1` ⇒ `libgcc-s1` (named `libgcc1` on pre-2022 releases). |
| Fedora/RHEL `.rpm` | `Requires` | `glibc, libgcc` | `libc.so.6`/`libm.so.6` ⇒ `glibc`; `libgcc_s.so.1` ⇒ `libgcc`. |

These are the values Task 3's `nfpm.yaml` sets explicitly (nfpm does not auto-scan
ELF deps the way `dpkg-shlibdeps`/`rpmbuild` do).

### Caveat — `dlopen` is not visible in `DT_NEEDED`

`DT_NEEDED` lists libraries resolved at load time, not libraries a program
`dlopen`s at runtime. A Chromium-derived engine *can* pull extra libraries lazily
(e.g. a GPU/EGL path). The single-binary payload and glibc-only `NEEDED` strongly
indicate obscura runs software-rendered headless with its stack statically linked,
but the definitive proof is a launch on a real Linux host. **CI/Linux-host check
(AC3):** on the release runner, after installing the `.deb`, run `ldd
/usr/lib/aitmproxy/obscura` (expect only glibc/libgcc/loader, all "found") and let
`aitm` probe + CDP-launch obscura once; if a `dlopen` of an absent library ever
surfaces, add that library's package to the `Depends`/`Requires` above. Until then,
keep the conservative glibc+libgcc list.

## 3. Discovery across the `/usr/bin` symlink

Install layout (spec §B): `/usr/lib/aitmproxy/{aitm,obscura,aitm-tui}` with
`/usr/bin/aitm` → `/usr/lib/aitmproxy/aitm`. obscura is found by discovery step 3
in `crates/aitm-browser/src/obscura.rs::discover_binary` — `obscura` next to the
*resolved* `aitm` executable. `aitm` computes that dir from
`std::env::current_exe()`, which on Linux reads `/proc/self/exe` (already
symlink-resolved by the kernel) and on macOS canonicalizes the path. So invoking
`/usr/bin/aitm` resolves to `/usr/lib/aitmproxy/aitm`, giving
`exe_dir = /usr/lib/aitmproxy`, where `obscura` sits beside it — no `PATH` entry,
`AITM_OBSCURA_BIN`, or config key needed. (`obscura` is intentionally **not**
symlinked into `/usr/bin`; it is not a user command.) The real-install probe is the
same AC3 Linux-host step above.
