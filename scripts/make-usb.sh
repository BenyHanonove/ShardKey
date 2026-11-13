#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Write a verified Symbolon release onto a physical USB boot stick (/dev/sdX),
# install Syslinux for BIOS boot and /EFI/BOOT/BOOTX64.EFI for UEFI Secure Boot,
# copy SHA256SUMS + SHA256SUMS.sig, then flush buffers, re-mount read-only,
# and verify every signature and hash read back from the stick.
#
# Reference: docs/PLAN.md (§4 Phase 7) and docs/SIGNING.md (§4.3).
#
# Usage:
#   sudo scripts/make-usb.sh /dev/sdX
#   sudo make usb DEV=/dev/sdX

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/versions.env
source "${ROOT_DIR}/config/versions.env"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
KEYS_DIR="${SYMBOLON_KEYS_DIR:-${ROOT_DIR}/keys}"
CERT="${KEYS_DIR}/symbolon-signing.crt"
SIGNED_KERNEL="${OUT_DIR}/bzImage"
SUMS_FILE="${OUT_DIR}/SHA256SUMS"
SIG_FILE="${OUT_DIR}/SHA256SUMS.sig"
SYSLINUX_MBR="/usr/lib/syslinux/mbr/mbr.bin"

log() {
    printf '[make-usb] %s\n' "$*"
}

die() {
    printf '[make-usb] ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 1 ]] || [[ -z "${1:-}" ]]; then
    die "usage: $0 /dev/sdX"
fi
DEV="$1"

# 1. Refuse to proceed unless release verification passes first
log "Verifying release artifacts before touching ${DEV}..."
"${ROOT_DIR}/scripts/verify-release.sh" || die "release verification failed; refusing to write ${DEV}"

[[ "$(id -u)" -eq 0 ]] || die "root privileges are required to partition and format ${DEV} (use sudo)"
[[ -r "${SYSLINUX_MBR}" ]] || die "missing syslinux MBR binary: ${SYSLINUX_MBR}"

for cmd in dd sfdisk blockdev mkfs.vfat syslinux mount umount sha256sum sbverify openssl sync awk cmp; do
    command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

# 2. Strict USB whole-disk safety checks
case "${DEV}" in
    /dev/sd*) ;;
    *) die "refusing unsupported or non-sd device path: ${DEV}" ;;
esac

DEV_NAME="${DEV#/dev/}"
case "${DEV_NAME}" in
    sd[a-z]|sd[a-z][a-z]) ;;
    *) die "expected whole-disk device like /dev/sdb, got: ${DEV}" ;;
esac

[[ -b "${DEV}" ]] || die "block device does not exist: ${DEV}"
SYS_BLK="/sys/block/${DEV_NAME}"
[[ -e "${SYS_BLK}" ]] || die "sysfs entry not found: ${SYS_BLK}"
[[ ! -e "${SYS_BLK}/partition" ]] || die "refusing partition device: ${DEV}"

REAL_BLK="$(cd -P "${SYS_BLK}" 2>/dev/null && pwd)" || die "cannot resolve sysfs path: ${SYS_BLK}"
case "${REAL_BLK}" in
    */usb/*|*/usb[0-9]*/*) ;;
    *) die "refusing non-USB device ${DEV} (${REAL_BLK})" ;;
esac

if [[ -r /proc/mounts ]]; then
    while read -r mdev _mp _rest; do
        case "${mdev}" in
            "${DEV}"|"${DEV}"[0-9]*)
                die "refusing currently mounted device: ${mdev}"
                ;;
        esac
    done < /proc/mounts
fi

SECTORS="$(cat "${SYS_BLK}/size")"
SIZE_BYTES=$((SECTORS * 512))
SIZE_GIB="$(awk -v b="${SIZE_BYTES}" 'BEGIN { printf "%.2f GiB", b / (1024*1024*1024) }')"
SIZE_MIB="$(awk -v b="${SIZE_BYTES}" 'BEGIN { printf "%.1f MiB", b / (1024*1024) }')"
VENDOR="$(cat "${SYS_BLK}/device/vendor" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//' || echo "Unknown")"
MODEL="$(cat "${SYS_BLK}/device/model" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//' || echo "USB Drive")"

printf '\nWARNING: ALL DATA ON %s WILL BE PERMANENTLY DESTROYED!\n' "${DEV}"
printf '  Device: %s (%s / %s)\n' "${DEV}" "${SIZE_GIB}" "${SIZE_MIB}"
printf '  Vendor: %s\n' "${VENDOR:-Unknown}"
printf '  Model:  %s\n\n' "${MODEL:-USB Drive}"
printf 'Type YES to erase %s: ' "${DEV}"
IFS= read -r CONFIRM
if [[ "${CONFIRM}" != "YES" ]]; then
    die "aborted by operator (did not type YES)"
fi

MNT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/symbolon-usb-mnt.XXXXXX")"
CFG_TMP="$(mktemp "${TMPDIR:-/tmp}/symbolon-syslinux.XXXXXX.cfg")"
cleanup() {
    if mountpoint -q "${MNT_DIR}" >/dev/null 2>&1; then
        umount "${MNT_DIR}" >/dev/null 2>&1 || true
    fi
    rmdir "${MNT_DIR}" >/dev/null 2>&1 || true
    rm -f "${CFG_TMP}"
}
trap cleanup EXIT

cat >"${CFG_TMP}" <<'EOF'
DEFAULT symbolon
PROMPT 0
TIMEOUT 0

LABEL symbolon
    LINUX /symbolon/bzImage
EOF

# 3. Partition (MBR active 0x0c) + install Syslinux MBR + format FAT32
log "Wiping partition table and writing MBR onto ${DEV}..."
dd if=/dev/zero of="${DEV}" bs=1048576 count=2 conv=fsync status=none
printf 'label: dos\nunit: sectors\n\n2048,,c,*\n' | sfdisk -q "${DEV}" >/dev/null
dd if="${SYSLINUX_MBR}" of="${DEV}" bs=440 count=1 conv=fsync status=none
sync
blockdev --rereadpt "${DEV}" >/dev/null 2>&1 || true

PART="${DEV}1"
tries=0
while [[ ! -b "${PART}" ]] && [[ "${tries}" -lt 10 ]]; do
    sleep 1
    tries=$((tries + 1))
done
[[ -b "${PART}" ]] || die "partition node did not appear: ${PART}"

log "Formatting ${PART} as FAT32 (label SYMBOLON) and installing Syslinux..."
mkfs.vfat -F 32 -n SYMBOLON "${PART}" >/dev/null
syslinux --install -d /syslinux "${PART}"

# 4. Copy release files onto the stick
mount -t vfat -o rw,umask=0022 "${PART}" "${MNT_DIR}"
mkdir -p "${MNT_DIR}/EFI/BOOT" "${MNT_DIR}/symbolon" "${MNT_DIR}/syslinux"
cp -f "${SIGNED_KERNEL}" "${MNT_DIR}/EFI/BOOT/BOOTX64.EFI"
cp -f "${SIGNED_KERNEL}" "${MNT_DIR}/symbolon/bzImage"
cp -f "${CFG_TMP}" "${MNT_DIR}/syslinux/syslinux.cfg"
cp -f "${SUMS_FILE}" "${MNT_DIR}/SHA256SUMS"
cp -f "${SIG_FILE}" "${MNT_DIR}/SHA256SUMS.sig"
sync
umount "${MNT_DIR}"

# Flush block device buffers and drop page cache before read-back verification
blockdev --flushbufs "${PART}" "${DEV}" >/dev/null 2>&1 || true
if [[ -w /proc/sys/vm/drop_caches ]]; then
    echo 3 >/proc/sys/vm/drop_caches 2>/dev/null || true
fi

# 5. Read everything back from the stick and verify hashes & signatures
log "Reading stick back read-only and verifying all files, hashes, and signatures..."
mount -t vfat -o ro "${PART}" "${MNT_DIR}"

openssl dgst -sha256 \
    -verify <(openssl x509 -in "${CERT}" -pubkey -noout) \
    -signature "${MNT_DIR}/SHA256SUMS.sig" \
    "${MNT_DIR}/SHA256SUMS" >/dev/null || die "stick SHA256SUMS.sig verification FAILED"

cmp -s "${SUMS_FILE}" "${MNT_DIR}/SHA256SUMS" || die "stick SHA256SUMS differs from ${SUMS_FILE}"
cmp -s "${CFG_TMP}" "${MNT_DIR}/syslinux/syslinux.cfg" || die "stick syslinux.cfg read-back mismatch"

EXPECTED_KERNEL_HASH="$(awk '$2 == "bzImage" { print $1 }' "${MNT_DIR}/SHA256SUMS")"
[[ -n "${EXPECTED_KERNEL_HASH}" ]] || die "bzImage entry missing in stick SHA256SUMS"

EFI_HASH="$(sha256sum "${MNT_DIR}/EFI/BOOT/BOOTX64.EFI" | awk '{print $1}')"
BIOS_HASH="$(sha256sum "${MNT_DIR}/symbolon/bzImage" | awk '{print $1}')"

[[ "${EFI_HASH}" == "${EXPECTED_KERNEL_HASH}" ]] || \
    die "stick /EFI/BOOT/BOOTX64.EFI hash (${EFI_HASH}) != SHA256SUMS (${EXPECTED_KERNEL_HASH})"
[[ "${BIOS_HASH}" == "${EXPECTED_KERNEL_HASH}" ]] || \
    die "stick /symbolon/bzImage hash (${BIOS_HASH}) != SHA256SUMS (${EXPECTED_KERNEL_HASH})"

sbverify --cert "${CERT}" "${MNT_DIR}/EFI/BOOT/BOOTX64.EFI" >/dev/null || \
    die "sbverify FAILED on stick /EFI/BOOT/BOOTX64.EFI"
sbverify --cert "${CERT}" "${MNT_DIR}/symbolon/bzImage" >/dev/null || \
    die "sbverify FAILED on stick /symbolon/bzImage"

umount "${MNT_DIR}"
blockdev --flushbufs "${PART}" "${DEV}" >/dev/null 2>&1 || true

log "SUCCESS: ${DEV} is ready and verified for both UEFI (Secure Boot) and BIOS boot."
