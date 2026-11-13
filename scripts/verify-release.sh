#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify a signed Symbolon release in out/ against the public certificate in keys/
# (docs/SIGNING.md §4.3 & §5, docs/PLAN.md §4 Phase 7):
#   1. Confirm keys/{symbolon-signing.crt,symbolon-signing.cer,FINGERPRINT.txt} consistency
#   2. Verify out/SHA256SUMS.sig using keys/symbolon-signing.crt
#   3. Run sha256sum -c out/SHA256SUMS and ensure all 4 expected release artifacts are listed
#   4. Run sbverify --cert keys/symbolon-signing.crt out/bzImage
#   5. Verify sbattach --remove on out/bzImage matches out/bzImage.unsigned bit-for-bit
#   6. Verify out/symbolon.img contains /EFI/BOOT/BOOTX64.EFI & /symbolon/bzImage == out/bzImage
#   7. Print certificate SHA-256 fingerprint for out-of-band confirmation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/versions.env
source "${ROOT_DIR}/config/versions.env"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
KEYS_DIR="${SYMBOLON_KEYS_DIR:-${ROOT_DIR}/keys}"
CERT="${KEYS_DIR}/symbolon-signing.crt"
CER="${KEYS_DIR}/symbolon-signing.cer"
FP_FILE="${KEYS_DIR}/FINGERPRINT.txt"

SIGNED_KERNEL="${OUT_DIR}/bzImage"
UNSIGNED_KERNEL="${OUT_DIR}/bzImage.unsigned"
INITRAMFS_IMG="${OUT_DIR}/initramfs.cpio.gz"
USB_IMG="${OUT_DIR}/symbolon.img"
SUMS_FILE="${OUT_DIR}/SHA256SUMS"
SIG_FILE="${OUT_DIR}/SHA256SUMS.sig"

log() {
    printf '[verify] %s\n' "$*"
}

die() {
    printf '[verify] ERROR: %s\n' "$*" >&2
    exit 1
}

for cmd in openssl sha256sum sbverify sbattach mcopy cmp awk python3; do
    command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

for f in "${CERT}" "${CER}" "${FP_FILE}" "${SIGNED_KERNEL}" "${UNSIGNED_KERNEL}" "${INITRAMFS_IMG}" "${USB_IMG}" "${SUMS_FILE}" "${SIG_FILE}"; do
    [[ -r "${f}" ]] || die "missing required file: ${f}"
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/symbolon-verify.XXXXXX")"
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# 1. Verify .crt/.cer/.FINGERPRINT.txt consistency
openssl x509 -in "${CERT}" -outform DER -out "${WORK_DIR}/cert.der"
if ! cmp -s "${CER}" "${WORK_DIR}/cert.der"; then
    die "public DER certificate ${CER} does not match ${CERT}"
fi

ACTUAL_FP="$(openssl x509 -in "${CERT}" -noout -fingerprint -sha256)"
if ! grep -Fxq "${ACTUAL_FP}" "${FP_FILE}"; then
    die "certificate fingerprint (${ACTUAL_FP}) does not match ${FP_FILE}"
fi

# 2. Verify SHA256SUMS.sig
log "Checking detached signature ${SIG_FILE}..."
openssl dgst -sha256 \
    -verify <(openssl x509 -in "${CERT}" -pubkey -noout) \
    -signature "${SIG_FILE}" \
    "${SUMS_FILE}" >/dev/null || die "SHA256SUMS signature verification FAILED"

# 3. Verify SHA256SUMS contents and file hashes
for expected in bzImage bzImage.unsigned symbolon.img initramfs.cpio.gz; do
    grep -Eq "^[0-9a-f]{64}  ${expected}$" "${SUMS_FILE}" || \
        die "SHA256SUMS is missing expected entry: ${expected}"
done

log "Checking SHA-256 hashes of release artifacts..."
(
    cd "${OUT_DIR}"
    sha256sum -c SHA256SUMS
)

# 4. Verify Secure Boot PE signature on out/bzImage
log "Checking Secure Boot signature on ${SIGNED_KERNEL}..."
sbverify --cert "${CERT}" "${SIGNED_KERNEL}" >/dev/null || \
    die "sbverify FAILED on ${SIGNED_KERNEL}"

# 5. Verify stripping signature reproduces out/bzImage.unsigned bit-for-bit
cp -f "${SIGNED_KERNEL}" "${WORK_DIR}/bzImage.stripped"
sbattach --remove "${WORK_DIR}/bzImage.stripped" >/dev/null
if ! cmp -s "${UNSIGNED_KERNEL}" "${WORK_DIR}/bzImage.stripped"; then
    die "sbattach --remove did not reproduce ${UNSIGNED_KERNEL}"
fi

# 6. Verify out/symbolon.img contains the signed kernel cleanly
PART_OFFSET="$(python3 - "${USB_IMG}" <<'PY'
import struct, sys
with open(sys.argv[1], "rb") as f:
    mbr = f.read(512)
if len(mbr) != 512 or mbr[510:512] != b"\x55\xaa":
    raise SystemExit("invalid MBR signature")
entry = mbr[446:462]
status, ptype = entry[0], entry[4]
start_lba = struct.unpack("<I", entry[8:12])[0]
if status != 0x80 or ptype != 0x0C or start_lba == 0:
    raise SystemExit(f"unexpected MBR partition entry: status=0x{status:02x} type=0x{ptype:02x} lba={start_lba}")
print(start_lba * 512)
PY
)" || die "invalid MBR partition layout in ${USB_IMG}"

export MTOOLS_SKIP_CHECK=1
mcopy -n -i "${USB_IMG}@@${PART_OFFSET}" ::/EFI/BOOT/BOOTX64.EFI "${WORK_DIR}/img_bootx64.efi"
mcopy -n -i "${USB_IMG}@@${PART_OFFSET}" ::/symbolon/bzImage "${WORK_DIR}/img_bzImage"
cmp -s "${SIGNED_KERNEL}" "${WORK_DIR}/img_bootx64.efi" || \
    die "${USB_IMG} ::/EFI/BOOT/BOOTX64.EFI does not match ${SIGNED_KERNEL}"
cmp -s "${SIGNED_KERNEL}" "${WORK_DIR}/img_bzImage" || \
    die "${USB_IMG} ::/symbolon/bzImage does not match ${SIGNED_KERNEL}"

# 7. Print certificate fingerprint for manual verification
log "ALL CHECKS PASSED."
log "Certificate fingerprint (compare with your paper record):"
printf '    %s\n' "${ACTUAL_FP}"
