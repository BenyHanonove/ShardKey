#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Assemble the Symbolon initramfs tree in build/rootfs/, generate the kernel
# gen_init_cpio file list (with /dev/console and /dev/null without requiring
# root), and build a deterministic out/initramfs.cpio.gz archive.
#
# Reference: docs/PLAN.md (§4 Phase 4) and docs/DECISIONS.md (D-001, D-006).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/config/versions.env}"

die() {
    echo "[build-rootfs] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[build-rootfs] $*"
}

if [[ ! -f "${VERSIONS_FILE}" ]]; then
    die "Versions file not found: ${VERSIONS_FILE}"
fi

_OVR_KERNEL_SHA256="${KERNEL_SHA256:-}"
_OVR_SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}"

# shellcheck source=../config/versions.env
. "${VERSIONS_FILE}"

[[ -n "${_OVR_KERNEL_SHA256}" ]] && KERNEL_SHA256="${_OVR_KERNEL_SHA256}"
[[ -n "${_OVR_SOURCE_DATE_EPOCH}" ]] && SOURCE_DATE_EPOCH="${_OVR_SOURCE_DATE_EPOCH}"

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
SRC_DIR="${SRC_DIR:-${BUILD_DIR}/src}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
ROOTFS_DIR="${ROOTFS_DIR:-${BUILD_DIR}/rootfs}"
TOOL_BIN="${TOOL_BIN:-${BUILD_DIR}/tool/symbolon}"
BUSYBOX_BIN="${BUSYBOX_BIN:-${BUILD_DIR}/busybox/busybox}"
INIT_SRC="${INIT_SRC:-${ROOT_DIR}/rootfs/init}"
PREP_SRC="${PREP_SRC:-${ROOT_DIR}/rootfs/lib/symbolon/prep-drive.sh}"
INITRAMFS_LIST="${INITRAMFS_LIST:-${BUILD_DIR}/initramfs.list}"
GEN_INIT_CPIO_BIN="${GEN_INIT_CPIO_BIN:-${BUILD_DIR}/gen_init_cpio}"
OUT_ARCHIVE="${OUT_ARCHIVE:-${OUT_DIR}/initramfs.cpio.gz}"
KERNEL_ARCHIVE="${SRC_DIR}/${KERNEL_TARBALL}"

for tool in gcc tar xz gzip cpio sha256sum find sort readlink install; do
    command -v "${tool}" >/dev/null 2>&1 || die "Required host tool not found: ${tool}"
done

[[ "${ROOTFS_DIR}" != *[[:space:]]* ]] || die "ROOTFS_DIR must not contain whitespace: ${ROOTFS_DIR}"
[[ -x "${TOOL_BIN}" ]] || die "Built symbolon binary not found or not executable: ${TOOL_BIN} (run 'make tool')"
[[ -x "${BUSYBOX_BIN}" ]] || die "Built BusyBox binary not found or not executable: ${BUSYBOX_BIN} (run 'make busybox')"
[[ -f "${INIT_SRC}" ]] || die "Missing rootfs init script: ${INIT_SRC}"
[[ -f "${PREP_SRC}" ]] || die "Missing rootfs prep-drive script: ${PREP_SRC}"
[[ -f "${KERNEL_ARCHIVE}" ]] || die "Kernel source tarball not found: ${KERNEL_ARCHIVE} (run 'make fetch')"

# Verify guest shell scripts parse cleanly with the built BusyBox ash shell
"${BUSYBOX_BIN}" sh -n "${INIT_SRC}" || die "BusyBox ash syntax check failed for ${INIT_SRC}"
"${BUSYBOX_BIN}" sh -n "${PREP_SRC}" || die "BusyBox ash syntax check failed for ${PREP_SRC}"

verify_sha256() {
    local file="$1"
    local expected="$2"
    local name actual
    name="$(basename "${file}")"

    expected="$(echo "${expected}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
        die "Malformed expected SHA-256 for ${name}: '${expected}'"
    fi

    actual="$(sha256sum "${file}" | awk '{print tolower($1)}')"
    if [[ "${actual}" != "${expected}" ]]; then
        die "SHA-256 mismatch for ${name}: expected ${expected}, got ${actual}"
    fi
}

verify_sha256 "${KERNEL_ARCHIVE}" "${KERNEL_SHA256}"

# ─────────────────────────────────────────────────────────────
# 1. Build kernel gen_init_cpio tool from verified kernel tarball
# ─────────────────────────────────────────────────────────────
mkdir -p "${BUILD_DIR}" "${OUT_DIR}"
GEN_INIT_CPIO_STAMP="${GEN_INIT_CPIO_BIN}.sha256"
GEN_INIT_CPIO_SRC="${BUILD_DIR}/gen_init_cpio.c"

if [[ ! -x "${GEN_INIT_CPIO_BIN}" ]] || [[ ! -f "${GEN_INIT_CPIO_STAMP}" ]] || \
   [[ "$(cat "${GEN_INIT_CPIO_STAMP}")" != "${KERNEL_SHA256}" ]]; then
    info "Building gen_init_cpio from linux-${KERNEL_VERSION}/usr/gen_init_cpio.c ..."
    tar -xJf "${KERNEL_ARCHIVE}" -O "linux-${KERNEL_VERSION}/usr/gen_init_cpio.c" > "${GEN_INIT_CPIO_SRC}.tmp"
    mv -f "${GEN_INIT_CPIO_SRC}.tmp" "${GEN_INIT_CPIO_SRC}"
    gcc -O2 -Wall -Werror=implicit-function-declaration \
        -o "${GEN_INIT_CPIO_BIN}.tmp" "${GEN_INIT_CPIO_SRC}"
    mv -f "${GEN_INIT_CPIO_BIN}.tmp" "${GEN_INIT_CPIO_BIN}"
    printf '%s\n' "${KERNEL_SHA256}" > "${GEN_INIT_CPIO_STAMP}"
fi

# ─────────────────────────────────────────────────────────────
# 2. Populate deterministic rootfs staging tree
# ─────────────────────────────────────────────────────────────
info "Staging rootfs tree in ${ROOTFS_DIR} ..."
rm -rf "${ROOTFS_DIR}"
install -d -m 0755 \
    "${ROOTFS_DIR}/bin" \
    "${ROOTFS_DIR}/dev" \
    "${ROOTFS_DIR}/lib" \
    "${ROOTFS_DIR}/lib/symbolon" \
    "${ROOTFS_DIR}/mnt" \
    "${ROOTFS_DIR}/proc" \
    "${ROOTFS_DIR}/sys"

install -m 0755 "${INIT_SRC}" "${ROOTFS_DIR}/init"
install -m 0755 "${BUSYBOX_BIN}" "${ROOTFS_DIR}/bin/busybox"
install -m 0755 "${TOOL_BIN}" "${ROOTFS_DIR}/bin/symbolon"
install -m 0755 "${PREP_SRC}" "${ROOTFS_DIR}/lib/symbolon/prep-drive.sh"

mapfile -t applets < <("${BUSYBOX_BIN}" --list | LC_ALL=C sort)
[[ "${#applets[@]}" -gt 0 ]] || die "BusyBox --list returned zero applets"

for applet in "${applets[@]}"; do
    [[ -n "${applet}" ]] || continue
    [[ "${applet}" != "busybox" ]] || continue
    [[ "${applet}" != *"/"* ]] || die "Unexpected slash in applet name: ${applet}"
    ln -s busybox "${ROOTFS_DIR}/bin/${applet}"
done

# Normalize timestamps on staged tree as well
find "${ROOTFS_DIR}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ─────────────────────────────────────────────────────────────
# 3. Generate sorted gen_init_cpio list (no root needed for /dev nodes)
# ─────────────────────────────────────────────────────────────
info "Generating ${INITRAMFS_LIST} ..."
tmp_unsorted="${INITRAMFS_LIST}.unsorted.tmp"
tmp_list="${INITRAMFS_LIST}.tmp"
rm -f "${tmp_unsorted}" "${tmp_list}"

while IFS= read -r -d '' path; do
    rel="${path#"${ROOTFS_DIR}"}"
    [[ -n "${rel}" ]] || continue
    [[ "${rel}" != *[[:space:]]* ]] || die "Unsupported whitespace in rootfs path: ${rel}"

    if [[ -L "${path}" ]]; then
        target="$(readlink "${path}")"
        [[ -n "${target}" && "${target}" != *[[:space:]]* ]] || die "Invalid symlink target for ${rel}: '${target}'"
        printf '%s\tslink %s %s 0777 0 0\n' "${rel}" "${rel}" "${target}" >> "${tmp_unsorted}"
    elif [[ -d "${path}" ]]; then
        printf '%s\tdir %s 0755 0 0\n' "${rel}" "${rel}" >> "${tmp_unsorted}"
    elif [[ -f "${path}" ]]; then
        if [[ -x "${path}" ]]; then
            mode="0755"
        else
            mode="0644"
        fi
        printf '%s\tfile %s %s %s 0 0\n' "${rel}" "${rel}" "${path}" "${mode}" >> "${tmp_unsorted}"
    else
        die "Unsupported file type in staged rootfs: ${path}"
    fi
done < <(find "${ROOTFS_DIR}" -mindepth 1 -print0)

# Declare device nodes needed by PID 1 and Linux kernel console before devtmpfs mounts
printf '/dev/console\tnod /dev/console 0600 0 0 c 5 1\n' >> "${tmp_unsorted}"
printf '/dev/null\tnod /dev/null 0666 0 0 c 1 3\n' >> "${tmp_unsorted}"

{
    printf '# SPDX-License-Identifier: GPL-2.0-only\n'
    printf '# Auto-generated by scripts/build-rootfs.sh (LC_ALL=C sorted)\n'
    LC_ALL=C sort -t $'\t' -k1,1 "${tmp_unsorted}" | cut -f2-
} > "${tmp_list}"

rm -f "${tmp_unsorted}"
mv -f "${tmp_list}" "${INITRAMFS_LIST}"

# ─────────────────────────────────────────────────────────────
# 4. Build reproducible compressed initramfs archive
# ─────────────────────────────────────────────────────────────
info "Building reproducible ${OUT_ARCHIVE} (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}) ..."
tmp_cpio="${OUT_ARCHIVE}.cpio.tmp"
tmp_gz="${OUT_ARCHIVE}.gz.tmp"
rm -f "${tmp_cpio}" "${tmp_gz}"

"${GEN_INIT_CPIO_BIN}" -t "${SOURCE_DATE_EPOCH}" -o "${tmp_cpio}" "${INITRAMFS_LIST}"
gzip -n -9 -c "${tmp_cpio}" > "${tmp_gz}"
rm -f "${tmp_cpio}"
chmod 0644 "${tmp_gz}"
touch -d "@${SOURCE_DATE_EPOCH}" "${tmp_gz}"
mv -f "${tmp_gz}" "${OUT_ARCHIVE}"

# ─────────────────────────────────────────────────────────────
# 5. Verify staged rootfs and generated archive
# ─────────────────────────────────────────────────────────────
"${SCRIPT_DIR}/verify-rootfs.sh" "${ROOTFS_DIR}" "${INITRAMFS_LIST}" "${OUT_ARCHIVE}" "${BUSYBOX_BIN}"

info "Rootfs build complete: ${OUT_ARCHIVE} ($(sha256sum "${OUT_ARCHIVE}" | awk '{print $1}'))"
