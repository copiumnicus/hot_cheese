#!/usr/bin/env bash
#
# Code-sign the hot_cheese release binary with the Secure Enclave entitlements.
#
# The Secure Enclave KEK only works on a *signed* binary: creating an SE P-256 key
# (`kSecAttrTokenIDSecureEnclave` + biometric access control) and reading its
# data-protection keychain items requires the `keychain-access-groups` entitlement,
# which is meaningless on an unsigned/ad-hoc binary.
#
# Identity tiers:
#   * A free Apple-ID "personal team" **Apple Development** identity is enough to
#     validate the SE path locally (the OS honors the entitlements for a locally-signed
#     dev build). These signatures are not distributable and expire.
#   * A **Developer ID Application** certificate (paid Apple Developer Program) is
#     needed for a stable, notarizable, distributable signature.
#
# Find your signing identities (the SHA-1 or the quoted common name both work as
# $IDENTITY):
#
#     security find-identity -v -p codesigning
#
# Then sign, passing the identity by env var or as the first argument:
#
#     IDENTITY="Apple Development: you@example.com (TEAMID1234)" scripts/sign.sh
#     scripts/sign.sh "Developer ID Application: Your Org (TEAMID1234)"
#
# Remember to edit hotcheese.entitlements first and replace the __TEAM_ID__ token with
# your Apple Team ID.

set -euo pipefail

# Resolve repo root from this script's location so it can be run from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BINARY="${BINARY:-${REPO_ROOT}/target/release/hot_cheese}"
ENTITLEMENTS="${ENTITLEMENTS:-${REPO_ROOT}/hotcheese.entitlements}"

# Identity from $1 or $IDENTITY.
IDENTITY="${1:-${IDENTITY:-}}"
if [[ -z "${IDENTITY}" ]]; then
	echo "error: no signing identity provided." >&2
	echo "       pass it as the first argument or via the IDENTITY env var, e.g.:" >&2
	echo "       IDENTITY=\"Apple Development: you@example.com (TEAMID1234)\" $0" >&2
	echo >&2
	echo "available code-signing identities:" >&2
	security find-identity -v -p codesigning >&2 || true
	exit 1
fi

if [[ ! -f "${BINARY}" ]]; then
	echo "error: binary not found at ${BINARY}" >&2
	echo "       build it first: cargo build --release" >&2
	exit 1
fi

if [[ ! -f "${ENTITLEMENTS}" ]]; then
	echo "error: entitlements not found at ${ENTITLEMENTS}" >&2
	exit 1
fi

if grep -q "__TEAM_ID__" "${ENTITLEMENTS}"; then
	echo "error: ${ENTITLEMENTS} still contains the __TEAM_ID__ placeholder." >&2
	echo "       replace it with your 10-character Apple Team ID before signing." >&2
	exit 1
fi

echo "signing ${BINARY}"
echo "  with entitlements ${ENTITLEMENTS}"
echo "  as identity       ${IDENTITY}"

# --options runtime enables the Hardened Runtime (required for notarization and a
# stricter, more representative environment for the SE path).
# --force re-signs if a previous signature exists.
# --timestamp requests a secure timestamp (needed for Developer ID / notarization).
codesign \
	--force \
	--options runtime \
	--timestamp \
	--entitlements "${ENTITLEMENTS}" \
	--sign "${IDENTITY}" \
	"${BINARY}"

echo
echo "verifying signature + entitlements:"
codesign --verify --strict --verbose=2 "${BINARY}"
codesign --display --entitlements - "${BINARY}"

echo
echo "done. the binary can now create/use its Secure Enclave key."
