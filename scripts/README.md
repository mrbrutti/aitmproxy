# scripts

`package.sh` builds `aitm` in release mode, downloads the matching
`obscura-<target>.tar.gz` for the host from the obscura fork's GitHub Release
(`mrbrutti/obscura`, tag `OBSCURA_TAG`, default `aitm-v1`), verifies it against
the release's `SHA256SUMS`, strips macOS quarantine, and writes
`dist/aitm-<version>-<target>.tar.gz` containing exactly two files: `aitm` and
`obscura`. Extract that tarball anywhere and run `./aitm`: the browser engine
discovers `obscura` next to the `aitm` executable automatically, so no `PATH`
entry, config key, or `AITM_OBSCURA_BIN` is needed.
