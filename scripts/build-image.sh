#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build a hybrid BIOS (Syslinux) + UEFI (EFI_STUB) bootable disk image in out/.
# If a signed kernel exists at out/bzImage, produces out/shardkey.img using the
# signed kernel (as required by docs/PLAN.md §4 Phase 7 & docs/SIGNING.md).
# If only out/bzImage.unsigned exists (prior to `make sign`), skips writing
# out/shardkey.img so an unsigned image is never mistaken for a signed release.
#
# Usage:
#   scripts/build-image.sh [--force-unsigned <out-img-path>]

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/versions.env
source "${ROOT_DIR}/config/versions.env"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"

SIGNED_KERNEL="${OUT_DIR}/bzImage"
UNSIGNED_KERNEL="${OUT_DIR}/bzImage.unsigned"
SYSLINUX_MBR="/usr/lib/syslinux/mbr/mbr.bin"

log() {
    printf '[build-image] %s\n' "$*"
}

die() {
    printf '[build-image] ERROR: %s\n' "$*" >&2
    exit 1
}

FORCE_UNSIGNED_OUT=""
if [[ "${1:-}" == "--force-unsigned" ]]; then
    [[ $# -eq 2 ]] || die "--force-unsigned requires an output path"
    FORCE_UNSIGNED_OUT="$2"
    shift 2
fi
[[ $# -eq 0 ]] || die "unexpected argument: $1"

if [[ -n "${FORCE_UNSIGNED_OUT}" ]]; then
    KERNEL_SRC="${UNSIGNED_KERNEL}"
    IMG_OUT="${FORCE_UNSIGNED_OUT}"
elif [[ -f "${SIGNED_KERNEL}" ]]; then
    KERNEL_SRC="${SIGNED_KERNEL}"
    IMG_OUT="${OUT_DIR}/shardkey.img"
elif [[ -f "${UNSIGNED_KERNEL}" ]]; then
    log "Unsigned kernel ready at ${UNSIGNED_KERNEL}."
    log "Skipping out/shardkey.img until kernel is signed (run 'make sign KEY=/path/to/shardkey-signing.key')."
    exit 0
else
    die "neither ${SIGNED_KERNEL} nor ${UNSIGNED_KERNEL} exists; run 'make kernel' first."
fi

[[ -f "${KERNEL_SRC}" ]] || die "missing kernel: ${KERNEL_SRC}"
[[ -r "${SYSLINUX_MBR}" ]] || die "missing syslinux MBR binary: ${SYSLINUX_MBR}"

for cmd in truncate sfdisk dd mkfs.vfat syslinux mmd mcopy sha256sum touch; do
    command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

mkdir -p "$(dirname "${IMG_OUT}")"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shardkey-image.XXXXXX")"
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

TMP_IMG="${WORK_DIR}/disk.img"
PART_IMG="${WORK_DIR}/part.img"
CFG_FILE="${WORK_DIR}/syslinux.cfg"
KERNEL_COPY="${WORK_DIR}/bzImage"

DISK_MB=72
START_SECTOR=2048
PART_SECTORS=$((DISK_MB * 1024 * 2 - START_SECTOR))
PART_BLOCKS=$((PART_SECTORS / 2))
PART_OFFSET=$((START_SECTOR * 512))

truncate -s "${DISK_MB}M" "${TMP_IMG}"
printf 'label: dos\nlabel-id: 0x53485244\nunit: sectors\n\n%u,,c,*\n' "${START_SECTOR}" | \
    sfdisk -q "${TMP_IMG}" >/dev/null
dd if="${SYSLINUX_MBR}" of="${TMP_IMG}" bs=440 count=1 conv=notrunc status=none

mkfs.vfat -F 32 -n SHARDKEY -i 53484152 --invariant -C "${PART_IMG}" "${PART_BLOCKS}" >/dev/null
dd if="${PART_IMG}" of="${TMP_IMG}" bs=512 seek="${START_SECTOR}" conv=notrunc status=none
rm -f "${PART_IMG}"

cat >"${CFG_FILE}" <<'EOF'
DEFAULT shardkey
PROMPT 0
TIMEOUT 0

LABEL shardkey
    LINUX /shardkey/bzImage
EOF

cp -f "${KERNEL_SRC}" "${KERNEL_COPY}"
touch -h -d "@${SOURCE_DATE_EPOCH}" "${CFG_FILE}" "${KERNEL_COPY}"

MTOOLS_IMG="${TMP_IMG}@@${PART_OFFSET}"
export MTOOLS_SKIP_CHECK=1

mmd -i "${MTOOLS_IMG}" ::/EFI ::/EFI/BOOT ::/shardkey ::/syslinux
syslinux --offset "${PART_OFFSET}" -d /syslinux -i "${TMP_IMG}"
mcopy -m -i "${MTOOLS_IMG}" "${KERNEL_COPY}" ::/EFI/BOOT/BOOTX64.EFI
mcopy -m -i "${MTOOLS_IMG}" "${KERNEL_COPY}" ::/shardkey/bzImage
mcopy -m -i "${MTOOLS_IMG}" "${CFG_FILE}" ::/syslinux/syslinux.cfg

mv -f "${TMP_IMG}" "${IMG_OUT}"
img_hash="$(sha256sum "${IMG_OUT}" | awk '{print $1}')"
log "Built hybrid BIOS/UEFI boot image: ${IMG_OUT} (sha256=${img_hash})"
