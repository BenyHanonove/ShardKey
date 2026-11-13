#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Configure, verify, and compile the Symbolon Linux LTS kernel with embedded
# initramfs and locked command line.
#
# Modes:
#   scripts/build-kernel.sh           -> release build -> out/bzImage.unsigned
#   scripts/build-kernel.sh --debug   -> QEMU serial debug build -> out/debug/bzImage
#
# Reference: docs/PLAN.md (§4 Phase 5), docs/KERNEL_CONFIG.md, docs/SIGNING.md.

set -euo pipefail

DEBUG_MODE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG_MODE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--debug]"
            exit 0
            ;;
        *)
            echo "[build-kernel] ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/config/versions.env}"

die() {
    echo "[build-kernel] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[build-kernel] $*"
}

[[ -f "${VERSIONS_FILE}" ]] || die "Versions file not found: ${VERSIONS_FILE}"

_OVR_KERNEL_SHA256="${KERNEL_SHA256:-}"
_OVR_SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}"
_OVR_KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-}"

# shellcheck source=../config/versions.env
. "${VERSIONS_FILE}"

[[ -n "${_OVR_KERNEL_SHA256}" ]] && KERNEL_SHA256="${_OVR_KERNEL_SHA256}"
[[ -n "${_OVR_SOURCE_DATE_EPOCH}" ]] && SOURCE_DATE_EPOCH="${_OVR_SOURCE_DATE_EPOCH}"
[[ -n "${_OVR_KBUILD_BUILD_TIMESTAMP}" ]] && KBUILD_BUILD_TIMESTAMP="${_OVR_KBUILD_BUILD_TIMESTAMP}"

# Reproducible Kbuild environment
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH
export KCONFIG_NOTIMESTAMP=1
export KBUILD_BUILD_TIMESTAMP
export KBUILD_BUILD_USER
export KBUILD_BUILD_HOST
export KBUILD_BUILD_VERSION="1"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
SRC_DIR="${SRC_DIR:-${BUILD_DIR}/src}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
KERNEL_ARCHIVE="${SRC_DIR}/${KERNEL_TARBALL}"
INITRAMFS_LIST="${INITRAMFS_LIST:-${BUILD_DIR}/initramfs.list}"
RELEASE_FRAGMENT="${RELEASE_FRAGMENT:-${ROOT_DIR}/config/kernel/symbolon.config}"
DEBUG_FRAGMENT="${DEBUG_FRAGMENT:-${ROOT_DIR}/config/kernel/debug-serial.config}"

if [[ "${DEBUG_MODE}" -eq 1 ]]; then
    KBUILD_SUBDIR="${KERNEL_DEBUG_BUILD_DIR:-${BUILD_DIR}/kernel-debug}"
    OUT_IMAGE="${OUT_DIR}/debug/bzImage"
    MODE_LABEL="debug"
else
    KBUILD_SUBDIR="${KERNEL_BUILD_DIR:-${BUILD_DIR}/kernel}"
    OUT_IMAGE="${OUT_DIR}/bzImage.unsigned"
    MODE_LABEL="release"
fi

KERNEL_SRC_DIR="${KERNEL_SRC_DIR:-${BUILD_DIR}/kernel-src/linux-${KERNEL_VERSION}}"
KERNEL_SRC_STAMP="${BUILD_DIR}/kernel-src/.stamp"

for tool in make gcc ld flex bison bc sha256sum tar xz; do
    command -v "${tool}" >/dev/null 2>&1 || die "Required host tool not found: ${tool}"
done

[[ -f "${KERNEL_ARCHIVE}" ]] || die "Kernel tarball not found: ${KERNEL_ARCHIVE} (run 'make fetch')"
[[ -f "${RELEASE_FRAGMENT}" ]] || die "Kernel config fragment not found: ${RELEASE_FRAGMENT}"
[[ -f "${INITRAMFS_LIST}" ]] || die "Initramfs list not found: ${INITRAMFS_LIST} (run 'make rootfs')"
[[ "${INITRAMFS_LIST}" != *[[:space:]]* ]] || die "INITRAMFS_LIST path must not contain whitespace: ${INITRAMFS_LIST}"
if [[ "${DEBUG_MODE}" -eq 1 ]]; then
    [[ -f "${DEBUG_FRAGMENT}" ]] || die "Debug config fragment not found: ${DEBUG_FRAGMENT}"
fi

verify_sha256() {
    local file="$1"
    local expected="$2"
    local name actual
    name="$(basename "${file}")"

    expected="$(echo "${expected}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || die "Malformed expected SHA-256 for ${name}: '${expected}'"

    actual="$(sha256sum "${file}" | awk '{print tolower($1)}')"
    if [[ "${actual}" != "${expected}" ]]; then
        die "SHA-256 mismatch for ${name}: expected ${expected}, got ${actual}"
    fi
}

verify_sha256 "${KERNEL_ARCHIVE}" "${KERNEL_SHA256}"

# ─────────────────────────────────────────────────────────────
# 1. Extract verified kernel source cleanly (cached by version+hash)
# ─────────────────────────────────────────────────────────────
EXPECTED_SRC_STAMP="${KERNEL_VERSION}:${KERNEL_SHA256}"
if [[ ! -d "${KERNEL_SRC_DIR}" ]] || [[ ! -f "${KERNEL_SRC_STAMP}" ]] || \
   [[ "$(cat "${KERNEL_SRC_STAMP}")" != "${EXPECTED_SRC_STAMP}" ]]; then
    info "Extracting ${KERNEL_TARBALL} into ${BUILD_DIR}/kernel-src ..."
    rm -rf "${BUILD_DIR}/kernel-src"
    mkdir -p "${BUILD_DIR}/kernel-src"
    tar -xJf "${KERNEL_ARCHIVE}" -C "${BUILD_DIR}/kernel-src"
    [[ -d "${KERNEL_SRC_DIR}" ]] || die "Expected directory missing after extract: ${KERNEL_SRC_DIR}"
    printf '%s\n' "${EXPECTED_SRC_STAMP}" > "${KERNEL_SRC_STAMP}"
fi

# ─────────────────────────────────────────────────────────────
# 2. Configure with allnoconfig + KCONFIG_ALLCONFIG + olddefconfig
# ─────────────────────────────────────────────────────────────
rm -rf "${KBUILD_SUBDIR}"
mkdir -p "${KBUILD_SUBDIR}" "$(dirname "${OUT_IMAGE}")"

RESOLVED_FRAGMENT="${KBUILD_SUBDIR}/symbolon.allconfig"
sed "s|__INITRAMFS_SOURCE__|${INITRAMFS_LIST}|g" "${RELEASE_FRAGMENT}" > "${RESOLVED_FRAGMENT}"
if [[ "${DEBUG_MODE}" -eq 1 ]]; then
    printf '\n' >> "${RESOLVED_FRAGMENT}"
    cat "${DEBUG_FRAGMENT}" >> "${RESOLVED_FRAGMENT}"
fi

info "Configuring Linux ${KERNEL_VERSION} (${MODE_LABEL}) via allnoconfig + KCONFIG_ALLCONFIG ..."
make -C "${KERNEL_SRC_DIR}" \
    O="${KBUILD_SUBDIR}" \
    ARCH=x86_64 \
    allnoconfig \
    KCONFIG_ALLCONFIG="${RESOLVED_FRAGMENT}" >/dev/null

make -C "${KERNEL_SRC_DIR}" \
    O="${KBUILD_SUBDIR}" \
    ARCH=x86_64 \
    olddefconfig >/dev/null

# ─────────────────────────────────────────────────────────────
# 3. Verify final .config before compiling
# ─────────────────────────────────────────────────────────────
if [[ "${DEBUG_MODE}" -eq 1 ]]; then
    "${SCRIPT_DIR}/verify-kconfig.sh" --debug "${KBUILD_SUBDIR}/.config"
else
    "${SCRIPT_DIR}/verify-kconfig.sh" "${KBUILD_SUBDIR}/.config"
fi

# Save a copy of the verified .config next to debug/release metadata if useful,
# then compile bzImage deterministically.
info "Compiling bzImage (${MODE_LABEL}) with $(nproc) job(s) ..."
make -C "${KERNEL_SRC_DIR}" \
    O="${KBUILD_SUBDIR}" \
    ARCH=x86_64 \
    -j"$(nproc)" \
    bzImage

BUILT_BZIMAGE="${KBUILD_SUBDIR}/arch/x86/boot/bzImage"
[[ -f "${BUILT_BZIMAGE}" ]] || die "Kernel build succeeded but bzImage not found: ${BUILT_BZIMAGE}"

install -m 0644 "${BUILT_BZIMAGE}" "${OUT_IMAGE}.tmp"
touch -d "@${SOURCE_DATE_EPOCH}" "${OUT_IMAGE}.tmp"
mv -f "${OUT_IMAGE}.tmp" "${OUT_IMAGE}"

info "Kernel build complete (${MODE_LABEL}): ${OUT_IMAGE} ($(stat -c '%s' "${OUT_IMAGE}") bytes, sha256=$(sha256sum "${OUT_IMAGE}" | awk '{print $1}'))"
