#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify the Phase 4 rootfs tree, initramfs.list, and out/initramfs.cpio.gz archive:
#   1. BusyBox ash syntax checks on /init and /lib/shardkey/prep-drive.sh
#   2. Static musl ELF checks on /bin/shardkey and /bin/busybox
#   3. gzip -n header check (zero MTIME and FNAME flags)
#   4. cpio contents check: 0:0 ownership, exact mtimes, /dev/console (c 5 1),
#      /dev/null (c 1 3), empty mountpoint dirs, and all BusyBox applet symlinks.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/config/versions.env}"

die() {
    echo "[verify-rootfs] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[verify-rootfs] $*"
}

if [[ ! -f "${VERSIONS_FILE}" ]]; then
    die "Versions file not found: ${VERSIONS_FILE}"
fi

_OVR_SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}"
# shellcheck source=../config/versions.env
. "${VERSIONS_FILE}"
[[ -n "${_OVR_SOURCE_DATE_EPOCH}" ]] && SOURCE_DATE_EPOCH="${_OVR_SOURCE_DATE_EPOCH}"

export LC_ALL=C
export TZ=UTC

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"

ROOTFS_DIR="${1:-${BUILD_DIR}/rootfs}"
INITRAMFS_LIST="${2:-${BUILD_DIR}/initramfs.list}"
OUT_ARCHIVE="${3:-${OUT_DIR}/initramfs.cpio.gz}"
BUSYBOX_BIN="${4:-${BUILD_DIR}/busybox/busybox}"

[[ -d "${ROOTFS_DIR}" ]] || die "Rootfs directory not found: ${ROOTFS_DIR}"
[[ -f "${INITRAMFS_LIST}" ]] || die "initramfs.list not found: ${INITRAMFS_LIST}"
[[ -f "${OUT_ARCHIVE}" ]] || die "initramfs archive not found: ${OUT_ARCHIVE}"
[[ -x "${BUSYBOX_BIN}" ]] || die "BusyBox binary not found: ${BUSYBOX_BIN}"

# ─────────────────────────────────────────────────────────────
# 1. Validate scripts and static ELF binaries in staged tree
# ─────────────────────────────────────────────────────────────
for script in "${ROOTFS_DIR}/init" "${ROOTFS_DIR}/lib/shardkey/prep-drive.sh"; do
    [[ -x "${script}" ]] || die "Script is missing or not executable: ${script}"
    "${BUSYBOX_BIN}" sh -n "${script}" || die "ash syntax check failed: ${script}"
done

for bin in "${ROOTFS_DIR}/bin/busybox" "${ROOTFS_DIR}/bin/shardkey"; do
    [[ -x "${bin}" ]] || die "Binary missing or not executable: ${bin}"
    finfo="$(file -b "${bin}")"
    if [[ "${finfo}" != *"ELF 64-bit LSB executable"* || "${finfo}" != *"statically linked"* ]]; then
        die "${bin} is not a statically linked x86-64 ELF binary: ${finfo}"
    fi
    if [[ "${finfo}" == *"for GNU/Linux"* ]]; then
        die "${bin} must not be linked against glibc: ${finfo}"
    fi
done

for dir in proc sys dev mnt bin lib lib/shardkey; do
    [[ -d "${ROOTFS_DIR}/${dir}" ]] || die "Missing directory in staged rootfs: ${ROOTFS_DIR}/${dir}"
done

for empty_dir in proc sys dev mnt; do
    if [[ -n "$(ls -A "${ROOTFS_DIR}/${empty_dir}")" ]]; then
        die "Staged mount directory ${ROOTFS_DIR}/${empty_dir} must be empty"
    fi
done

# Verify gen_init_cpio list declares /dev/console and /dev/null with 0:0 ownership
grep -qxF 'nod /dev/console 0600 0 0 c 5 1' "${INITRAMFS_LIST}" || \
    die "Missing 'nod /dev/console 0600 0 0 c 5 1' in ${INITRAMFS_LIST}"
grep -qxF 'nod /dev/null 0666 0 0 c 1 3' "${INITRAMFS_LIST}" || \
    die "Missing 'nod /dev/null 0666 0 0 c 1 3' in ${INITRAMFS_LIST}"

info "Staged tree and initramfs.list checks OK."

# ─────────────────────────────────────────────────────────────
# 2. Verify deterministic gzip header (no filename or mtime)
# ─────────────────────────────────────────────────────────────
gz_hdr="$(od -An -tx1 -N8 "${OUT_ARCHIVE}" | tr -s ' ' | sed 's/^ //; s/ $//')"
if [[ "${gz_hdr}" != "1f 8b 08 00 00 00 00 00" ]]; then
    die "Non-deterministic gzip header in ${OUT_ARCHIVE}: '${gz_hdr}' (expected '1f 8b 08 00 00 00 00 00')"
fi

# ─────────────────────────────────────────────────────────────
# 3. Verify compressed cpio archive contents, device nodes, and ownership
# ─────────────────────────────────────────────────────────────
listing="$(gzip -dc "${OUT_ARCHIVE}" | cpio -tv --numeric-uid-gid 2>/dev/null)" || \
    die "Failed to list cpio archive: ${OUT_ARCHIVE}"
paths_only="$(gzip -dc "${OUT_ARCHIVE}" | cpio -t 2>/dev/null)" || \
    die "Failed to list cpio archive paths: ${OUT_ARCHIVE}"

expected_year="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y')"
expected_mon_day="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%b %e')"
expected_hh_mm="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%H:%M')"

# Every archive entry must belong to uid=0 gid=0 and carry the SOURCE_DATE_EPOCH timestamp
while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    uid_val="$(printf '%s\n' "${line}" | awk '{print $3}')"
    gid_val="$(printf '%s\n' "${line}" | awk '{print $4}')"
    if [[ "${uid_val}" != "0" || "${gid_val}" != "0" ]]; then
        die "Archive entry does not have 0:0 ownership: ${line}"
    fi
    if [[ "${line}" != *"${expected_mon_day}  ${expected_year}"* && \
          "${line}" != *"${expected_mon_day} ${expected_hh_mm}"* ]]; then
        die "Archive entry does not match SOURCE_DATE_EPOCH (${expected_mon_day} ${expected_year}/${expected_hh_mm}): ${line}"
    fi
done <<< "${listing}"

# Required device nodes
if ! printf '%s\n' "${listing}" | grep -qE '^crw-------[[:space:]]+1[[:space:]]+0[[:space:]]+0[[:space:]]+5,[[:space:]]+1[[:space:]].* dev/console$'; then
    die "Missing or malformed dev/console device node in ${OUT_ARCHIVE}"
fi
if ! printf '%s\n' "${listing}" | grep -qE '^crw-rw-rw-[[:space:]]+1[[:space:]]+0[[:space:]]+0[[:space:]]+1,[[:space:]]+3[[:space:]].* dev/null$'; then
    die "Missing or malformed dev/null device node in ${OUT_ARCHIVE}"
fi

# Required regular executable files
for req_file in init bin/busybox bin/shardkey lib/shardkey/prep-drive.sh; do
    if ! printf '%s\n' "${listing}" | grep -qE "^-rwxr-xr-x[[:space:]]+1[[:space:]]+0[[:space:]]+0[[:space:]]+[0-9]+.* ${req_file}$"; then
        die "Missing or non-0755 executable '${req_file}' in ${OUT_ARCHIVE}"
    fi
done

# Required empty directories (proc, sys, mnt must have zero children; dev has only console & null)
for req_dir in proc sys dev mnt bin lib lib/shardkey; do
    if ! printf '%s\n' "${listing}" | grep -qE "^drwxr-xr-x[[:space:]]+2[[:space:]]+0[[:space:]]+0[[:space:]]+0.* ${req_dir}$"; then
        die "Missing directory '${req_dir}' in ${OUT_ARCHIVE}"
    fi
done

for empty_dir in proc sys mnt; do
    if printf '%s\n' "${paths_only}" | grep -qE "^${empty_dir}/.+$"; then
        die "Directory '${empty_dir}' must be empty in ${OUT_ARCHIVE}"
    fi
done

unexpected_dev="$(printf '%s\n' "${paths_only}" | grep '^dev/' | grep -vE '^dev/(console|null)$' || true)"
if [[ -n "${unexpected_dev}" ]]; then
    die "Unexpected /dev entries in ${OUT_ARCHIVE}: ${unexpected_dev}"
fi

# Verify every BusyBox applet symlink points to 'busybox'
mapfile -t applets < <("${BUSYBOX_BIN}" --list | LC_ALL=C sort)
[[ "${#applets[@]}" -gt 0 ]] || die "BusyBox --list returned no applets"

for applet in "${applets[@]}"; do
    [[ "${applet}" == "busybox" ]] && continue
    if ! printf '%s\n' "${listing}" | grep -qE "^lrwxrwxrwx[[:space:]]+1[[:space:]]+0[[:space:]]+0[[:space:]]+[0-9]+.* bin/${applet} -> busybox$"; then
        die "Missing applet symlink bin/${applet} -> busybox in ${OUT_ARCHIVE}"
    fi
done

info "Archive check OK: ${OUT_ARCHIVE} (0/0 owner, ${#applets[@]} applets, dev nodes verified)."
