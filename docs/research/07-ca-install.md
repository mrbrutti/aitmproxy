# Exporting, installing, uninstalling and checking the root CA in the OS trust store

> **Provenance:** Researcher engine, read on **2026-10-27**. Sources are cited
> per finding. Items marked **(observed)** were run on this machine (macOS 27.0,
> build 26A428, inside the Claude Bash sandbox, read-only commands only, no
> keychain or trust setting was modified). Items marked **(unverified)** were
> not seen in a source or run. Nothing here is a design decision.

## 1. Question

How should an intercepting proxy export, install, uninstall, and report the
status of its root CA in the OS trust store on macOS, Linux (Debian/Ubuntu,
Fedora/RHEL families) and Windows, by shelling out to platform tools, so the
operations are idempotent and the certificate is identified by SHA-256; and
what do mitmproxy, Burp Suite and mkcert expose?

## 2. Short answer

Every platform has a documented tool, but none keys on SHA-256 uniformly:
Windows `certutil` uses SHA-1 thumbprints, macOS 27.0 `security` accepts
SHA-256 or SHA-1 (observed; older releases SHA-1), Linux indexes by file only.
Idempotency must be built by the caller: hash the DER in Rust, detect, then
act, parsing stdout because exit codes are weak (macOS `find-certificate -a`
exits 0 on no match; Windows duplicate `-addstore` succeeds). Installs need
root/admin plus a GUI auth prompt on macOS and Windows-user. These commands
serve bring-your-own clients; embedded obscura ignores the OS store and uses
`SSL_CERT_FILE`.

## 3. Findings

### 3.0 Corrections to the brief (evidence contradicts the premise)

- **mkcert does not use `-r trustRoot` or `find-certificate -Z` on macOS, and
  does not use `certutil` on Windows.** Its current `master` source (read via
  raw.githubusercontent.com, 2026-10-27) is quoted in 3.5. The brief's
  recollection of `add-trusted-cert -d -r trustRoot -k System.keychain` is
  what malware and Jamf scripts use (3.1, 3.7), not mkcert.
- **macOS `-Z` prints SHA-256 as well as SHA-1** on this machine (observed) and
  `delete-certificate -Z` accepts either (help text, observed). The brief's
  "SHA-1 only" holds for older macOS (secondary sources only; the release that
  changed it is unverified).
- **Burp's documented URL is `http://burpsuite`**, not `http://burp/cert`
  (3.6). `http://burp/cert` is unverified.

### 3.1 macOS (`security`)

Paths. Login keychain `~/Library/Keychains/login.keychain-db` is the default
keychain; the System keychain is `/Library/Keychains/System.keychain`
(`security default-keychain`, `security list-keychains -d user|system`,
`ls -l`: observed). The System keychain is `-rw-r--r-- root:wheel`, so
`security find-certificate -a -Z /Library/Keychains/System.keychain` works
without sudo (observed; nearhost PR #264 says the same). The user's search list
here had three user keychains plus System, so a bare `delete-certificate`
or `find-certificate` walks all of them (observed): name the keychain.

Install. `security add-trusted-cert [-d] [-r resultType] [-p policy] [-k
keychain] [certFile]`; `-d` = "Add to admin cert store; default is user"; `-r`
default is `trustRoot`; `-p` repeatable policy constraint (ssl, basic, ...);
`-k` = keychain the cert is added to; certFile may be DER or PEM (`security
help add-trusted-cert`, observed; man page,
https://keith.github.io/xcode-man-pages/security.1.html, 2026-10-27). Man page:
"When modifying per-user Trust Settings, user authentication is required via an
authentication dialog."

Exact command lines found in the wild:

| Who | Command |
|---|---|
| mitmproxy docs | `sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem` |
| mkcert | `sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain <rootCA.pem>`, then export/patch/import of admin trust settings (3.5) |
| Ay MaMi malware (MITRE T1553.004), Jamf scripts | `add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>` |

Privilege and prompts.
- System keychain + `-d` needs root: every real-world invocation above is under
  `sudo`. (No source states the exact failure text for a non-root run:
  unverified.)
- A GUI authorization step is involved even for root: run from a PKG
  post-install script, daemon or `osascript ... with administrator privileges`
  it fails with `SecTrustSettingsSetTrustSettings: The authorization was denied
  since no user interaction was possible` while the cert still lands in the
  keychain untrusted (Apple Developer Forums thread 764689, warren PR #18,
  2026-10-27). Apple DTS answer on that thread: use MDM for managed fleets;
  "you shouldn't be installing trusted roots without their approval"
  otherwise. Warren PR #18's workaround (root adds the cert to System keychain,
  then the logged-in user runs `add-trusted-cert` to get the dialog) was
  verified by hand there (exit 0, `verify-cert` succeeded). I did not test any
  install here (it would modify the trust store).
- So a process without a GUI session (SSH, headless CI, an MCP server started
  as a daemon) cannot reliably complete the macOS trust step. A terminal
  session with sudo is the case mkcert and mitmproxy assume.

Detect (keychain presence).
`security find-certificate -a -Z [-c <name>] <keychain>` prints one block per
cert, starting with `SHA-256 hash: <64 hex upper>` then `SHA-1 hash: <40 hex
upper>` then `keychain: "<path>"` then attributes (observed, e.g.
`SHA-256 hash: 63343ABF...E9179`). `-c` is a substring name match, `-p` emits
PEM, no flag to filter by hash, so to match by fingerprint list with `-a -Z`
and compare the SHA-256 line. Exit codes (observed):
- no `-a`, no match: **exit 44**, stderr `security: SecKeychainSearchCopyNext:
  The specified item could not be found in the keychain.`
- **with `-a`, no match: exit 0, empty stdout and stderr** (both default list
  and explicit keychain). Exit code cannot distinguish "absent"; parse stdout.

Detect (trust, not just presence). Presence in a keychain is not trust.
- `security verify-cert -c <file> -l -L -p ssl` (`-l` needed because the
  leaf is a CA, `-L` = no network): in this sandbox it exited 1 for **both**
  an untrusted self-signed CA and a trusted Apple root, and with `-p basic` on
  the untrusted CA printed `Cert Verify Result: No error.` with exit 1
  (observed). Not usable as a signal here; may be a sandbox artefact
  (trustd access) or the CT message. **Unverified outside the sandbox.**
- `security dump-trust-settings [-d|-s]` ("Display Trust Settings";
  `-d` admin, default user): failed here with `SecTrustSettingsCopyCertificates:
  No keychain is available` (observed, sandbox). Output format unverified.
- `security trust-settings-export -d <file>` writes a plist; mkcert parses
  `trustVersion` and `trustList` entries keyed by cert with an `issuerName`
  field (truststore_darwin.go). Whether keys are SHA-1 hashes: unverified.
- mkcert's own check is not a `security` call at all (3.5).

Remove.
- `security delete-certificate -Z <hash> [-t] <keychain>`: `-Z` "Specify
  certificate to delete by its SHA-256 (or SHA-1) hash value", `-t` "Also
  delete user trust settings for this certificate" (help, observed). Deleting
  in System keychain needs sudo (Jamf answer, secondary).
- Absent cert: **exit 1**, stderr `Unable to delete certificate matching
  "<hash>"` for a SHA-256, a SHA-1 and a malformed hash alike (observed, using
  an all-zero hash against the default list; nothing could match, nothing was
  deleted). So "absent" and "bad argument" are the same exit code.
- `security remove-trusted-cert [-d] <certFile>` removes **trust settings
  only** and leaves the certificate in the keychain: nearhost PR #264 reports
  each trust/untrust cycle left another copy of the root (one machine had
  three) and added `find-certificate -a -Z` + `sudo delete-certificate -Z
  <sha1>`. The man text says only "Remove certificate ... from per-user or
  local Admin Trust Settings". Takes a file, not a hash, so the cert file (or
  a temp copy re-materialised from the DER) must be available.
- A full uninstall is therefore two steps: `remove-trusted-cert -d <file>`
  then `delete-certificate -Z <hash> /Library/Keychains/System.keychain`;
  nearhost orders trust removal first.

Idempotency of `add-trusted-cert` on an identical cert: **unverified**. No
source states it, and I did not run it. The nearhost "three copies" report is
about remove-then-re-add cycles and may involve regenerated CAs with the same
name; it does not settle it. The Apple forum shows `errSecDuplicateItem`
exists for certs with the same subject but different key/serial (SecItemAdd,
not this tool). Guard with a `find-certificate -a -Z` check first.

### 3.2 Linux

Detect the family. Two sources, neither authoritative alone:
- By tool/dir presence, which is what mkcert does (`init()` in
  truststore_linux.go, first match wins):

| Directory exists | Anchor file name template | Refresh command |
|---|---|---|
| `/etc/pki/ca-trust/source/anchors/` | `<name>.pem` | `update-ca-trust extract` |
| `/usr/local/share/ca-certificates/` | `<name>.crt` | `update-ca-certificates` |
| `/etc/ca-certificates/trust-source/anchors/` | `<name>.crt` | `trust extract-compat` |
| `/usr/share/pki/trust/anchors` | `<name>.pem` | `update-ca-certificates` |

  Last row is openSUSE; the mapping of rows to distros beyond Fedora/RHEL
  (row 1) and Debian/Ubuntu (row 2) is mkcert's, partly from search
  summaries (Arch via `trust`, Alpine via `update-ca-certificates`).
- By `/etc/os-release`: `ID=` and `ID_LIKE=` (space-separated, closest first;
  "scripts should check it when ID= is not recognized"; Ubuntu `ID_LIKE=debian`,
  CentOS `ID_LIKE="rhel fedora"`); `/etc/os-release` takes precedence over
  `/usr/lib/os-release` (freedesktop os-release(5),
  https://www.freedesktop.org/software/systemd/man/latest/os-release.html,
  2026-10-27). Does not tell you which tool is installed (a minimal container
  may lack `ca-certificates`).

Root is needed for all writes (files under `/usr/local/share` / `/etc/pki` are
root-owned; mkcert wraps every call in `sudo`, `tee` for the write, `rm -f` for
the delete; `commandWithSudo` skips sudo when uid is 0, else `sudo
--prompt=Sudo password: -- <cmd>`, or fails if `sudo` is not on PATH). No
source states a failure text for a non-root run (unverified).

Debian/Ubuntu/Alpine (`update-ca-certificates`).
- Man page (https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html,
  2026-10-27): "Certificates must be in PEM format and have a .crt extension in
  order to be included"; "one certificate per file"; local certs go in
  `/usr/local/share/ca-certificates`; bundle is
  `/etc/ssl/certs/ca-certificates.crt`; `--fresh`/`-f` "Remove symlinks in
  /etc/ssl/certs directory"; also `--verbose`, `--certsconf`, `--certsdir`,
  `--localcertsdir`, `--etccertsdir`. No EXIT STATUS section; no statement of
  idempotency.
- Script behaviour (salsa.debian.org `sbin/update-ca-certificates`, `master`,
  2026-10-27; summarised by the fetch tool, excerpts quoted there):
  `find -L "$LOCALCERTSDIR" -type f -name '*.crt' | sort` then `add`; `add`
  makes `/etc/ssl/certs/<basename, spaces->_ , ( ) -> =, comma -> _>.pem` via
  `ln -sf` only if missing or different; counts reported as `"<n> added, <n>
  removed; done."`; runs with `set -e`; **no root check and no explicit exit
  code**; a bundle `.new` is rebuilt from every cert and `mv -f`'d over
  `ca-certificates.crt`; `openssl rehash` and dangling-symlink cleanup run
  **only if ADDED_CNT or REMOVED_CNT > 0**. Consequences:
  - **Re-running with no change is idempotent** and prints `0 added, 0
    removed` (derived from the script).
  - **Removal**: delete the `.crt` then run it. The bundle is rebuilt without
    the cert (derived), but because the orphan cleanup is gated on non-zero
    counts, a plain run after deleting the file may leave a dangling
    `/etc/ssl/certs/<name>.pem` link and its hash link, whereas `--fresh`
    clears all managed links and re-adds, which sets the counts and runs
    cleanup (derived from script text; **not run**, treat as a candidate to
    verify). mkcert uses the plain command on uninstall (and `rm -f`).
  - `/etc/ca-certificates.conf` lists only system certs under
    `/usr/share/ca-certificates` (a `!` prefix deselects); locally installed
    certs are not listed there and need no edit.
- Alpine: same tool and directory (`apk add ca-certificates`, copy as `.crt`,
  run `update-ca-certificates`); secondary sources only (search summary
  2026-10-27; Alpine wiki returned 403).

Fedora/RHEL (`update-ca-trust`).
- `update-ca-trust [extract] [-o DIR]`; no argument = `extract`. Anchors go in
  `/etc/pki/ca-trust/source/anchors/` (or `/usr/share/pki/ca-trust-source/anchors/`)
  as DER or PEM; no file-extension rule is stated (man page via
  https://www.mankier.com/8/update-ca-trust, RHEL 9 doc
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/using-shared-system-certificates_securing-networks,
  both 2026-10-27). mkcert still uses `.pem`.
- Output under `/etc/pki/ca-trust/extracted/` (do not edit), notably
  `pem/tls-ca-bundle.pem` (TLS CAs, PEM) and `openssl/ca-bundle.trust.crt`.
- Removal: RHEL doc documents `trust anchor --remove <file|pkcs11 URI>`; the
  "delete the file, rerun `update-ca-trust extract`" form is stated by a
  secondary source (search summary) and used by mkcert (`rm -f` then the
  command). The command is silent on success (secondary).
- `trust list` lists anchors with PKCS#11 URI and label (RHEL doc). It does not
  advertise a hash (unverified).

Arch (`trust`/`p11-kit`). `trust anchor [--store] <file>` "stored as anchors,
unless they are already present" (man.archlinux.org/man/trust.1, 2026-10-27),
so re-running looks safe; `trust anchor --remove <file|pkcs11:id=...;type=cert>`;
"may need to be run as root". Manual route is a file in
`/etc/ca-certificates/trust-source/anchors/` then `update-ca-trust`
(search summary of man.archlinux.org/man/update-ca-trust.8). The ArchWiki
returned an anti-bot block page, so its text was not read.

Detect installed on Linux. No tool reports by fingerprint; options:
- anchor file exists at the known path **and** its DER SHA-256 equals ours
  (file read plus Rust hash);
- the cert is present in the consolidated bundle: Debian family
  `/etc/ssl/certs/ca-certificates.crt` (man page), Fedora family
  `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (man page). A bundle
  holds many PEM blocks, so hash each. `x509_parser::pem::Pem::iter_from_buffer`
  yields every block as `Pem { label, contents }` (x509-parser 0.18.1 source,
  `src/pem.rs`, read in `~/.cargo/registry`, 2026-10-27), no shell needed;
- the file check proves "we installed it", the bundle check proves "it is
  trusted" (catches a file that was dropped but never refreshed).
Do not append to the bundle by hand: it is regenerated and the edit is lost
(search summaries for Arch and Alpine).

### 3.3 Windows (`certutil`)

I could not run Windows tools. Everything here is documentation or secondary.

Commands (Microsoft certutil reference,
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil,
page `ms.date` 2025-05-01, read 2026-10-27):
- `certutil [options] -addstore CertificateStoreName InFile`; options
  `[-f] [-Enterprise] [-user] [-GroupPolicy] [-dc DCName]`.
- `certutil [options] -delstore CertificateStoreName certID`.
- `certutil [options] -store [CertificateStoreName [CertId [OutputFile]]]`
  ("Dumps the certificate store"); store names include `My, CA (default),
  Root`.
- `-user` "accesses a user store instead of a machine store" (so without it,
  LocalMachine); `-enterprise`, `-grouppolicy` other machine stores.
- `CertId` may be a "Serial number", "SHA-1 certificate [hash]", "Public key",
  "Certificate subject Common Name", numeric index, ..., "Many of these
  identifiers might result in multiple matches." Whether a SHA-256 hash is
  accepted as CertId is **not stated (unverified)**; the doc lists SHA-1.
- Performance note in the doc: with more than 10 certs, a CertId is matched
  against every id type; the doc recommends PowerShell for typed matching.
- Thumbprint is SHA-1 of the DER; it is not a certificate field (Windows
  Q&A / MS .NET docs via search summary). `-store` output shows `Cert
  Hash(sha1)`; a 2013 blog dump also shows a `Cert Hash(sha256)` line, so the
  display may include SHA-256 on some versions (secondary, exact current
  layout unverified).
- `certutil -hashfile InFile [HashAlgorithm]` supports `MD2 MD4 MD5 SHA1
  SHA256 SHA384 SHA512` (same doc).

Examples in use:
- mitmproxy docs: `certutil -addstore root mitmproxy-ca-cert.cer` (the
  mitmproxy table says the `.cer` is the "same file as .pem" yet certutil
  takes it, so certutil accepts a PEM file; mitmproxy docs 2026-10-27).
- MITRE T1553.004 / Sigma rule: `certutil -addstore -f -user ROOT <file>`.

Privilege and prompts.
- LocalMachine Root (no `-user`) needs an elevated process; an unelevated run
  is expected to fail with access denied `0x80070005` (inference from other
  certutil operations in search results, **not seen for `-addstore Root`**).
- CurrentUser Root (`-user`) needs no elevation but shows a "Security Warning"
  dialog asking to confirm installing a CA (Microsoft Learn VS troubleshooting
  page for `Import-Certificate -CertStoreLocation Cert:\CurrentUser\Root`, same
  store, "Click **Yes**"; PacketFence issue #11 confirms users get a warning
  with `certutil -addstore`, 2026-10-27). No documented silent switch. A
  headless run therefore blocks or fails; mkcert's Windows route avoids the
  dialog by calling crypt32 directly against `CertOpenSystemStoreW(0, "ROOT")`,
  which is the current-user store (3.5) (the CurrentUser dialog behaviour for
  that API is not stated in the source: unverified).

Idempotency and exit codes.
- Duplicate `-addstore`: prints "already in store" and ends "CertUtil: -addstore
  command completed successfully" (Experts Exchange and Microsoft Q&A threads
  via search summary, one for `Trusted Publishers`, not for Root: secondary).
  So exit code cannot tell "added" from "already present".
- Win32 level: `CertAddEncodedCertificateToStore` dispositions
  `ADD_ALWAYS` (duplicates), `ADD_NEW` (fails `CRYPT_E_EXISTS`),
  `ADD_REPLACE_EXISTING`, `ADD_USE_EXISTING` (no fail, no new context)
  (https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddencodedcertificatetostore,
  2026-10-27). Which disposition certutil uses is **not stated**.
- `-delstore` of an absent cert: CRYPT_E_NOT_FOUND `0x80092004` ("Cannot find
  object or property") is the code mkcert treats as end-of-enumeration; that
  `-delstore` returns it and a non-zero exit code is an inference
  (**unverified**).
- A match by CommonName can hit several certs; deleting by SHA-1 thumbprint
  is exact.

PowerShell alternative (candidate; not exercised): `Import-Certificate
-FilePath <f> -CertStoreLocation Cert:\CurrentUser\Root` is documented to
install into the CurrentUser Root store (same VS page). A `Cert:\...\Root`
delete by thumbprint and `Get-ChildItem` listing are **unverified** here.

### 3.4 Fingerprints and what is already in the build

| Platform | Key the tool uses | Source |
|---|---|---|
| macOS 27.0 | `-Z` prints SHA-256 + SHA-1; `delete-certificate -Z` takes either | observed |
| macOS older | SHA-1 (secondary: Jamf, nearhost PR #264 uses SHA-1) | secondary |
| Windows | SHA-1 thumbprint, serial, CN, index | MS certutil doc |
| Linux | none; file name | man pages |

In `Cargo.lock` (grepped and `cargo tree --offline`, 2026-10-27):
- `sha1 0.10.7`, only via `tungstenite 0.28.0` (reached from `aitm-browser`'s
  chromiumoxide and `aitm-proto-ws` dev-deps), not a direct dependency of
  anything in this workspace.
- **No `sha2`** in `Cargo.lock` (the crates.io source cache has `sha2 0.10.9`
  and `0.11.0` from other projects, but they are not resolved here).
- `ring 0.17.14` (via `rcgen 0.14.10` and `rustls 0.23.46`, and
  `aitm-proto-http` already selects the ring provider; not a direct dependency
  of `aitm-proto-http`). Source read in `~/.cargo/registry`: `ring::digest::SHA256`,
  `ring::digest::SHA1_FOR_LEGACY_USE_ONLY` (doc comment "Deprecated"),
  `pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest`,
  `impl AsRef<[u8]> for Digest` (`ring-0.17.14/src/digest.rs`).
- `x509-parser 0.18.1` (direct dependency of `aitm-proto-http`): `pem::parse_x509_pem`,
  `pem::Pem { label, contents }`, `Pem::iter_from_buffer`,
  `parse_x509_certificate` (source read).
- `rcgen 0.14.10`: `Certificate::der()` and, under feature `pem`,
  `Certificate::pem()`; `base64 0.22.1/0.23.1`, `pem 4.0.0`,
  `data-encoding 2.11.1` are also resolved (names/versions from the lock;
  APIs other than those above **not checked**).
- In the repo: `ca.crt` is PEM written by `rcgen` `cert.pem()`; `root_cert_pem()`
  returns it; subject CN `aitmproxy root CA`, O `aitmproxy`, validity ~10
  years (`crates/aitm-proto-http/src/ca.rs`); `CaConfig { dir, key_mode }`
  (`crates/aitm-core/src/config.rs`). The CA dir holds `ca.key` next to
  `ca.crt` (see 3.8).
- The workspace sets `unsafe_code = "forbid"` (root `Cargo.toml`), which rules
  out mkcert's Windows route (raw `crypt32.dll` FFI) unless a safe wrapper
  crate is added; shelling out has no such issue.

### 3.5 mkcert (best single reference; `master`, read 2026-10-27)

Files `truststore_darwin.go`, `truststore_linux.go`, `truststore_windows.go`,
`truststore_nss.go`, `main.go`, `cert.go` at
https://raw.githubusercontent.com/FiloSottile/mkcert/master/. The fetch tool
reproduced darwin and windows in full and gave excerpts for the rest.

- **Naming.** `rootName = "rootCA.pem"`, `rootKeyName = "rootCA-key.pem"`;
  `caUniqueName() = "mkcert development CA " + serial`; root subject O
  `mkcert development CA`, OU `<user@host>`, CN `mkcert <user@host>`;
  `CAROOT` env, else `LocalAppData` / `XDG_DATA_HOME` / `~/Library/Application
  Support` / `~/.local/share` + `mkcert`.
- **Install flow** (`install`): if `checkPlatform()` is true it logs "The local
  CA is already installed in the system trust store!" and skips (idempotent by
  check-first). `TRUST_STORES` env (`system`, `java`, `nss`, comma list; empty
  = all) selects stores. `uninstall` does **not** check first; it just runs.
- **`checkPlatform()`** (in `main.go`): `m.caCert.Verify(x509.VerifyOptions{})`,
  i.e. Go's x509 verification against the system pool, `err == nil`, with an
  `ignoreCheckFailure` bypass. No `security`, `certutil` or file test. The
  OS-independent check "does the platform trust it" is what it models.
- **macOS install.** `sudo security add-trusted-cert -d -k
  /Library/Keychains/System.keychain <CAROOT>/rootCA.pem`; then makes trust
  settings explicit (Go issue 24652, "older Go does not know the defaults"):
  `sudo security trust-settings-export -d <tmp.plist>`, edit the plist entry
  whose `issuerName` equals the root subject (ASN.1) to set `trustSettings` to
  two dicts (`sslServer` and `basicX509`, result `1`), then `sudo security
  trust-settings-import -d <tmp.plist>`. All via `CombinedOutput` and fatal on
  error. **Uninstall:** `sudo security remove-trusted-cert -d <rootCA.pem>`
  (trust only; per 3.1 the cert stays in the keychain).
- **Linux install.** Copy with `sudo tee <path>` (stdin = PEM), then `sudo
  <refresh>`. Name: `SystemTrustFilename` with `caUniqueName()` spaces to
  underscores. **Uninstall:** `sudo rm -f <path>`, also removes the legacy
  `.../mkcert-rootCA.<ext>` if it exists, then `sudo <refresh>`. If none of
  the four directories exists, `SystemTrustCommand` is nil: logs that system
  install is unsupported and returns false (NSS browsers still handled).
- **Windows.** Direct crypt32 calls, not `certutil`: PEM decode, then
  `CertOpenSystemStoreW(0, "ROOT")`, `CertAddEncodedCertificateToStore(...
  disposition 3 /*REPLACE_EXISTING*/)` (comment `TODO: ok to always
  overwrite?`); uninstall enumerates the store and `CertDeleteCertificateFromStore`
  every cert with the **same serial number** (`deleteCertsWithSerial`),
  failing with "no certs found" if none, ending enumeration on error
  `0x80092004`. Fixed by serial, not by hash.
- **NSS/Firefox** (out of scope for us): `truststore_nss.go` uses `certutil`
  against profile DBs; `installNSS` reports "no ... security databases found"
  and returns false if there are no profiles; `uninstallNSS` silently skips
  profiles that fail the check.
- mkcert README (https://github.com/FiloSottile/mkcert): "the `rootCA-key.pem`
  file ... gives complete power to intercept secure requests", do not share;
  Windows "try running `mkcert` as an Administrator".

### 3.6 mitmproxy and Burp Suite

mitmproxy (https://docs.mitmproxy.org/stable/concepts/certificates/,
2026-10-27):
- Magic domain `mitm.it`, reached through the proxy, offers per-platform
  download/install icons. Not a CLI.
- `~/.mitmproxy` (override `--set confdir=DIR`; it looks for
  `mitmproxy-ca.pem`, generates if missing):

  | File | Contents | Private key |
  |---|---|---|
  | `mitmproxy-ca.pem` | cert **and** key, PEM | yes |
  | `mitmproxy-ca-cert.pem` | cert, PEM, "most non-Windows platforms" | no |
  | `mitmproxy-ca-cert.p12` | cert, PKCS12, "for use on Windows" | no |
  | `mitmproxy-ca-cert.cer` | same as `.pem`, extension for Android | no |

- Docs give two "automated" one-liners (macOS and Windows, above), a Java
  `keytool -importcert ...`, and curl/wget `--cacert` examples; Linux, Android
  and Firefox/Chrome are links only; iOS is manual Settings steps. **No
  uninstall instructions on the page; no install subcommand** in the page
  (I did not search mitmproxy's source for one: treat as "documented: none").
  Mitmproxy's own `01-mitmproxy.md` covers the TLS design, not install UX.

Burp Suite (https://portswigger.net/burp/documentation/desktop/tools/proxy/manage-certificates
and `.../external-browser-config/certificate/ca-cert-chrome-macos`, 2026-10-27;
search summary of the rest):
- Download from `http://burpsuite` ("CA Certificate" button); the macOS page
  says drag it into Keychain Access, System keychain, then set Trust to
  "Always trust". Export in Proxy settings > "Import / export CA certificate"
  (DER by the dialog; the page notes "You should not disclose the private key
  for your certificate to any untrusted party").
- Regenerating the CA needs a Burp restart and a re-install in browsers;
  if you installed a previous Burp CA, remove it first (secondary).
- Burp's built-in browser needs no install (secondary). No CLI to install or
  uninstall into the OS store was found in the docs read.

### 3.7 Security notes

- A trusted proxy root CA can mint a certificate for any hostname that every
  client using that store will accept; compromise of `ca.key` means silent
  interception of all of that user's TLS, not just through the proxy. mkcert
  and Burp both say so in their docs (quoted above). MITRE T1553.004 treats
  "install root certificate" as an adversary technique and gives
  `certutil -addstore -f -user ROOT` and macOS `add-trusted-cert -d -r
  trustRoot -k System.keychain` as the observed command lines; Sigma rule
  "New Root Certificate Installed Via Certutil.EXE" flags any `certutil` with
  `-addstore` and `root` (https://attack.mitre.org/techniques/T1553/004/,
  https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_certutil_certificate_installation/).
  Expect EDR to alert on these exact invocations.
- Why uninstall matters: the CA is generated per installation with a 10-year
  validity here; a stale installed root outlives the test engagement and the
  key file. macOS `remove-trusted-cert` alone leaves the cert present
  (3.1); Debian-family removal without `--fresh` may leave dangling links
  (3.2, derived).
- The key must not leave the CA dir. Every command above takes `ca.crt` only
  (a certificate path). The CA dir holds `ca.key` (mode 0600, directory 0700);
  never point a directory-scanning option (`SSL_CERT_DIR`, `update-ca-*
  --localcertsdir`) at it. The obscura experiment already showed obscura reads
  every file in `SSL_CERT_DIR` and panics on `ca.key`
  (`docs/research/experiments/2026-10-27-obscura-ca-mitm.md`). Export must
  write the certificate only, never the key; mitmproxy's `mitmproxy-ca.pem`
  bundles both, which is a layout to avoid.
- Tool output: `security find-certificate -a -Z` prints subject/issuer blobs
  and hashes, nothing secret (observed); the install tools take a cert path
  and no passwords (`security create-keychain -p` is "insecure" by its own
  help, not needed here). `sudo` prompts for the user's password: pass no
  secrets via argv. `update-ca-certificates` and `update-ca-trust` print counts
  only (script excerpt; mankier). `certutil -store` dumps cert metadata only
  (not verified for key-bearing stores; `Root` holds no keys). mkcert pipes
  `CombinedOutput` into its fatal error message, which is safe for these tools
  but is a pattern to apply to captured output deliberately.
- Consent: Apple's DTS says a tool should not install a trusted root without
  the user's approval; the macOS auth dialog and the Windows CurrentUser
  Security Warning are that approval. A feature that hides those prompts
  (e.g. loosening `com.apple.trust-settings.admin` via `security
  authorizationdb write ... allow`, suggested in one Jamf thread) is a
  security regression, not a technique to adopt.
- Agent-driven install (MCP): the above prompts need a human GUI session; an
  agent running headless will hit `no user interaction was possible` on macOS
  and a blocking dialog or access denied on Windows. This is a fact for the
  gating decision, not a recommendation.

### 3.8 Scope note

These commands are for clients that read the **OS** trust store (curl with
system roots, system browsers, Python/Go/Java tools that honour it). The
embedded obscura browser uses `reqwest`+`webpki-roots` and ignores the OS store;
it trusts the CA through `SSL_CERT_FILE=<path to ca.crt>` set at spawn
(`docs/research/experiments/2026-10-27-obscura-ca-mitm.md`). Firefox/NSS and
Java keystores are out of scope; mkcert handles them separately (3.5) and
mitmproxy documents `keytool` for Java.

## 4. Candidate directions (not decisions)

**A. `TrustStore` trait, one impl per platform, each a pure function from
operation to a list of `Command` descriptions plus a parser for captured
output.** The Rust side computes SHA-256 (and SHA-1 where the tool needs it)
from the DER once, so `status`, `install`, `uninstall` share one
fingerprint. Detect-then-act per op; tests assert the command lines and parse
canned stdout without touching the OS.
- Pro: unit-testable without root (command lists and parsers are data);
  fits `unsafe_code = "forbid"`; each platform's quirks stay local (macOS
  empty-stdout-on-`-a`, Windows success-on-duplicate).
- Con: parsing human-readable output is brittle (`security` format, `certutil`
  localised output on non-English Windows: unverified); needs a real-OS
  smoke test per platform that the sandbox cannot give us.

**B. Same as A, but status uses a tool-independent check.** E.g. mkcert's
model: verify our CA against the platform verifier. In Rust, that means a
client-side check such as a platform-verifier chain (none is in this
repo's `Cargo.lock`: grep found no `rustls-native-certs`,
`rustls-platform-verifier`, `security-framework`, `schannel` or
`openssl-probe`, only `webpki-roots` 0.26.11 and 1.0.11) or running
`security verify-cert` (inconclusive in sandbox, 3.1).
- Pro: reports "is it actually trusted", not "is a file present", including
  macOS trust-settings and Windows store scope.
- Con: new dependency or a flaky `verify-cert`; harder to key by fingerprint.

**C. Shell-script bundle (`install.sh`/`install.ps1`) emitted by `ca export`
for the user to run.** Avoids the proxy ever calling `sudo` or touching the OS
store; the human runs it in their own session (satisfying the GUI-auth
requirement and the consent point in 3.7).
- Pro: no privilege handling in the Rust process; works headless over SSH
  with a copy-paste; same output for CLI and MCP.
- Con: no idempotent status/uninstall from the proxy; three scripts to
  maintain; not unit-testable the way A is.

**D. Hybrid: `export` and `status` run in-process (read-only, no privilege),
`install`/`uninstall` default to printing the exact commands (dry run) and
execute only with an explicit opt-in.** Maps to A's command lists.
- Pro: the safe path is the default; the exact command lines are visible for
  review; matches EDR expectations.
- Con: two modes to document and test.

**E. Windows: `certutil -user` (dialog, no elevation) vs `certutil` machine
store (elevation, no dialog per the MS doc silence; unverified), vs PowerShell
`Import-Certificate`.** Pick per scope; `certutil` sees SHA-1 thumbprints, so
the Rust side must show SHA-256 and convert only at the `-delstore` call.

**F. Linux naming.** Fixed file name (e.g. `aitmproxy-root-ca.crt`) means a
regenerated CA overwrites rather than accumulates (idempotent by path) but
cannot represent two CAs; a name with the fingerprint prefix (mkcert uses the
serial) is unique but needs a glob to clean up stale entries. Debian needs
`.crt`, mkcert uses `.pem` for the RHEL anchors dir.

**G. Linux family selection.** By anchor-directory existence (mkcert) vs by
`ID_LIKE` vs by binary on PATH. Directory existence is the check closest to
what the tool will do; `ID_LIKE` is cheap but misses derivatives and minimal
images.

## 5. Open questions (could not answer)

1. **macOS idempotency of `add-trusted-cert`** on an identical cert in the
   same keychain (duplicate item, error, or no-op; exit code). Needs a run on
   a disposable keychain/VM outside the sandbox.
2. **Whether `verify-cert -c <ca> -l -L -p ssl` and `dump-trust-settings`
   give a usable "trusted?" signal** outside the sandbox. In-sandbox both were
   uninformative (3.1).
3. **Which macOS release added SHA-256 to `find-certificate -Z` and
   `delete-certificate -Z`.** Only 27.0 observed. Older releases matter if
   the fleet is not on current macOS.
4. **Exact non-root failure output** (and exit code) for `security
   add-trusted-cert -d` into System, `update-ca-certificates`, `update-ca-trust`,
   `certutil -addstore Root`.
5. **Windows**: exit code and message of `certutil -delstore Root <sha1>` for
   an absent cert; whether `-delstore`/`-store` accept a SHA-256; whether
   `certutil` prints `Cert Hash(sha256)` on current Windows; whether
   `-addstore -f Root` on a duplicate is a replace or reuse; whether
   machine-store `-addstore` from an elevated shell shows any prompt; whether
   `-user` dialog can be avoided in a non-interactive session. All
   require a Windows machine.
6. **`update-ca-certificates` plain run vs `--fresh` after deleting a local
   `.crt`**: does the dangling `/etc/ssl/certs/<name>.pem` and hash link
   survive a plain run (script reading says it can). Needs a Debian container.
7. **Fedora anchor file extension rules** under p11-kit (man page states none;
   mkcert uses `.pem`), and Arch bundle location for the detect-by-bundle
   check.
8. **Fedora/RHEL, Arch, Alpine behaviour on a minimal container without
   `ca-certificates`/`p11-kit`**: tool-missing handling.
9. Whether `sha1` should be added as a direct dependency or `ring`'s
   `SHA1_FOR_LEGACY_USE_ONLY` used, is a design question; this note only
   records what is in `Cargo.lock` and in the `ring` source.
10. mitmproxy source was not searched for any hidden install helper; Burp's
    `http://burp/cert` was not found in official docs.

## 6. Sources

Repo (read 2026-10-27):
- `docs/superpowers/WORKFLOW.md`
- `docs/research/experiments/2026-10-27-obscura-ca-mitm.md`
- `docs/research/01-mitmproxy.md`
- `crates/aitm-proto-http/src/ca.rs`, `crates/aitm-proto-http/Cargo.toml`
- `crates/aitm-core/src/config.rs`
- `Cargo.toml`, `Cargo.lock`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/{ring-0.17.14/src/digest.rs, x509-parser-0.18.1/src/{lib,pem}.rs, rcgen-0.14.10/src/certificate.rs}`

Local runs (observed, macOS 27.0 build 26A428, Claude Bash sandbox, read-only):
`security help {find-certificate,delete-certificate,add-trusted-cert,remove-trusted-cert,verify-cert,dump-trust-settings,trust-settings-export,create-keychain}`,
`security find-certificate -a -Z` against SystemRootCertificates and System keychains,
`security find-certificate` with and without `-a` for an absent name,
`security delete-certificate -Z <zeros>`,
`security verify-cert -c ... -l -L -p ssl|basic`,
`security dump-trust-settings`, `security list-keychains`, `security default-keychain`.

Web (all read 2026-10-27):
- mkcert source: https://raw.githubusercontent.com/FiloSottile/mkcert/master/truststore_darwin.go, `truststore_linux.go`, `truststore_windows.go`, `truststore_nss.go`, `main.go`, `cert.go`; README https://github.com/FiloSottile/mkcert
- Apple `security(1)`: https://keith.github.io/xcode-man-pages/security.1.html
- Apple Developer Forums thread 764689: https://developer.apple.com/forums/thread/764689
- warren PR #18: https://github.com/kalahroudi/warren/pull/18
- nearhost PR #264: https://github.com/nearhost/nearhost/pull/264
- Debian `update-ca-certificates(8)`: https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html
- Debian script: https://salsa.debian.org/debian/ca-certificates/-/raw/master/sbin/update-ca-certificates
- `update-ca-trust(8)`: https://www.mankier.com/8/update-ca-trust
- RHEL 9 shared system certificates: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/using-shared-system-certificates_securing-networks
- Arch `trust(1)`: https://man.archlinux.org/man/trust.1 ; `update-ca-trust(8)`: https://man.archlinux.org/man/update-ca-trust.8 (search summary only)
- os-release(5): https://www.freedesktop.org/software/systemd/man/latest/os-release.html
- Microsoft certutil: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
- `CertAddEncodedCertificateToStore`: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddencodedcertificatetostore
- VS untrusted-certificate article (CurrentUser Root warning): https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/installation/warnings-untrusted-certificate
- PacketFence issue 11: https://github.com/inverse-inc/packetfence-windows-agent/issues/11
- mitmproxy certificates: https://docs.mitmproxy.org/stable/concepts/certificates/
- Burp: https://portswigger.net/burp/documentation/desktop/tools/proxy/manage-certificates ; https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate/ca-cert-chrome-macos
- MITRE T1553.004: https://attack.mitre.org/techniques/T1553/004/
- Sigma rule: https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_certutil_certificate_installation/

Secondary (search-result summaries, not a primary page read): Windows
duplicate `-addstore` behaviour (Experts Exchange, Microsoft Q&A), 0x80092004
meaning, Alpine steps, Arch `trust anchor --store` guide pages, `update-ca-trust`
"silent on success" and "delete file and rerun" removal, Burp "built-in browser
needs no install" and regenerate notes. Alpine wiki and ArchWiki fetches were
blocked (403 / anti-bot). Bash network egress to raw.githubusercontent.com
and salsa.debian.org was denied by the sandbox, so those pages were read
through the WebFetch tool instead.
