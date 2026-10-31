#!/bin/zsh
# Preflight for a Network Extension build (build.sh --ne): both Developer ID
# provisioning profiles must exist, and the signing identity must be one of the
# certificates they authorise. Prints the identity's SHA-1 on stdout; everything
# else goes to stderr. Exit 1 when the build could not activate.
#
# Usage: tools/ne-preflight.sh <host profile> <sysex profile>
#   NE_SIGN_IDENTITY=<sha1>  pick this identity (still checked against both profiles);
#                            otherwise the first keychain identity both profiles list.
#
# Why: a team can hold several "Developer ID Application" certificates, and
# `security find-identity | awk ... exit` picks the first one in the keychain. A
# system extension signed with a certificate that is not in its embedded profile's
# DeveloperCertificates is rejected at activation. On 2026-10-31 the keychain held
# two (1D24F95F… and 296308E6…); both happened to be in the profiles, which is luck,
# not a guarantee, so the pick is verified here.
set -u
host_profile=${1:?host profile path}
sysex_profile=${2:?sysex profile path}

# SHA-1 fingerprints of a profile's DeveloperCertificates, uppercase hex, one per line.
profile_cert_shas() {
  local plist der i=0
  plist=$(security cms -D -i "$1" 2>/dev/null) || return 1
  while der=$(print -r -- "$plist" | plutil -extract "DeveloperCertificates.$i" raw -o - - 2>/dev/null); do
    print -r -- "$der" | base64 -d | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
      | sed -e 's/^.*=//' -e 's/://g' | tr '[:lower:]' '[:upper:]'
    (( i++ ))
  done
}

for p in "$host_profile" "$sysex_profile"; do
  [[ -f "$p" ]] || { echo "ne-preflight: missing provisioning profile $p" >&2; exit 1; }
done
host_shas=("${(@f)$(profile_cert_shas "$host_profile")}")
sysex_shas=("${(@f)$(profile_cert_shas "$sysex_profile")}")
(( ${#host_shas} && ${#sysex_shas} )) || { echo "ne-preflight: could not read DeveloperCertificates from the profiles (security cms / plutil / openssl)" >&2; exit 1; }

candidates=("${(@f)$(security find-identity -v -p codesigning 2>/dev/null | awk '/Developer ID Application/ {print $2}')}")
candidates=(${candidates:#})
if [[ -n ${NE_SIGN_IDENTITY:-} ]]; then
  identity=${NE_SIGN_IDENTITY:u}
  [[ $identity =~ ^[0-9A-F]{40}$ ]] || { echo "ne-preflight: NE_SIGN_IDENTITY must be the identity's SHA-1 (as security find-identity prints it)" >&2; exit 1; }
else
  matching=()
  for c in $candidates; do (( ${host_shas[(Ie)$c]} )) && matching+=("$c"); done
  case ${#matching} in
    0) echo "ne-preflight: none of the Developer ID Application identities in the keychain (${candidates:-none}) is in the host profile's DeveloperCertificates (${host_shas}); set NE_SIGN_IDENTITY" >&2; exit 1 ;;
    1) identity=$matching[1] ;;
    *) identity=$matching[1]; echo "ne-preflight: several keychain identities are in the host profile (${matching}); using the first, set NE_SIGN_IDENTITY to choose" >&2 ;;
  esac
fi
(( ${host_shas[(Ie)$identity]} )) || { echo "ne-preflight: identity $identity is not in the host profile's DeveloperCertificates (${host_shas})" >&2; exit 1; }
(( ${sysex_shas[(Ie)$identity]} )) || { echo "ne-preflight: identity $identity is not in the sysex profile's DeveloperCertificates (${sysex_shas})" >&2; exit 1; }
(( ${candidates[(Ie)$identity]} )) || { echo "ne-preflight: identity $identity is in the profiles but not in the keychain (security find-identity -v -p codesigning)" >&2; exit 1; }
echo "ne-preflight: signing with Developer ID $identity (in both profiles)" >&2
print -r -- "$identity"
