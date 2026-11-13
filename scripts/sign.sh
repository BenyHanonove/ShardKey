#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Sign the Symbolon kernel and release manifest (docs/SIGNING.md §4.2):
#   1. sbsign out/bzImage.unsigned -> out/bzImage
#   2. Verify sbattach --remove restores out/bzImage.unsigned bit-for-bit
#   3. Build out/symbolon.img containing signed out/bzImage
#   4. Write out/SHA256SUMS (bzImage, bzImage.unsigned, symbolon.img, initramfs.cpio.gz)
#   5. Sign out/SHA256SUMS -> out/SHA256SUMS.sig
#
# Usage:
#   scripts/sign.sh /path/to/symbolon-signing.key
#   make sign KEY=/media/keyusb/symbolon-signing.key

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/versions.env
source "${ROOT_DIR}/config/versions.env"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
KEYS_DIR="${SYMBOLON_KEYS_DIR:-${ROOT_DIR}/keys}"
CERT="${KEYS_DIR}/symbolon-signing.crt"
UNSIGNED_KERNEL="${OUT_DIR}/bzImage.unsigned"
SIGNED_KERNEL="${OUT_DIR}/bzImage"
INITRAMFS_IMG="${OUT_DIR}/initramfs.cpio.gz"
USB_IMG="${OUT_DIR}/symbolon.img"
SUMS_FILE="${OUT_DIR}/SHA256SUMS"
SIG_FILE="${OUT_DIR}/SHA256SUMS.sig"

log() {
    printf '[sign] %s\n' "$*"
}

die() {
    printf '[sign] ERROR: %s\n' "$*" >&2
    exit 1
}

KEY_PATH="${1:-${KEY:-}}"
if [[ -z "${KEY_PATH}" ]]; then
    die "private key path is required (e.g. make sign KEY=/media/keyusb/symbolon-signing.key)"
fi
[[ -r "${KEY_PATH}" ]] || die "private key not readable: ${KEY_PATH}"
[[ -r "${CERT}" ]] || die "public certificate not found: ${CERT} (run scripts/gen-signing-key.sh first)"
[[ -f "${UNSIGNED_KERNEL}" ]] || die "unsigned kernel missing: ${UNSIGNED_KERNEL} (run 'make' first)"
[[ -f "${INITRAMFS_IMG}" ]] || die "initramfs missing: ${INITRAMFS_IMG} (run 'make' first)"

for cmd in sbsign sbverify sbattach openssl sha256sum cmp; do
    command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/symbolon-sign.XXXXXX")"
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

TMP_SIGNED="${WORK_DIR}/bzImage.signed"
TMP_STRIPPED="${WORK_DIR}/bzImage.stripped"

log "Signing ${UNSIGNED_KERNEL} with sbsign..."
sbsign --key "${KEY_PATH}" --cert "${CERT}" --output "${TMP_SIGNED}" "${UNSIGNED_KERNEL}"

log "Verifying embedded Secure Boot signature..."
sbverify --cert "${CERT}" "${TMP_SIGNED}" >/dev/null

cp -f "${TMP_SIGNED}" "${TMP_STRIPPED}"
sbattach --remove "${TMP_STRIPPED}" >/dev/null
if ! cmp -s "${UNSIGNED_KERNEL}" "${TMP_STRIPPED}"; then
    die "sbattach --remove on signed kernel did not match ${UNSIGNED_KERNEL}!"
fi

mv -f "${TMP_SIGNED}" "${SIGNED_KERNEL}"

log "Building bootable disk image ${USB_IMG} from signed kernel..."
"${ROOT_DIR}/scripts/build-image.sh"
[[ -f "${USB_IMG}" ]] || die "failed to build ${USB_IMG}"

log "Writing ${SUMS_FILE}..."
(
    cd "${OUT_DIR}"
    sha256sum bzImage bzImage.unsigned symbolon.img initramfs.cpio.gz >SHA256SUMS
)

log "Signing ${SUMS_FILE} -> ${SIG_FILE}..."
openssl dgst -sha256 -sign "${KEY_PATH}" -out "${SIG_FILE}" "${SUMS_FILE}"

log "Signing complete."
log "Next: unplug your key USB drive, then run 'make verify'."
