#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build static BusyBox with musl-gcc and sanitized kernel headers from our
# pinned LTS kernel, configured from 'make allnoconfig' + config/busybox/symbolon.config.
# Outputs:
#   build/busybox/busybox   (statically linked x86_64 binary)
#   build/busybox/.config   (resolved BusyBox configuration)
#
# Reference: docs/PLAN.md (§4 Phase 3) and docs/DECISIONS.md (D-001, D-004).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/config/versions.env}"

die() {
    echo "[build-busybox] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[build-busybox] $*"
}

if [[ ! -f "${VERSIONS_FILE}" ]]; then
    die "Versions file not found: ${VERSIONS_FILE}"
fi

# Preserve optional environment overrides before sourcing versions.env
_OVR_KERNEL_SHA256="${KERNEL_SHA256:-}"
_OVR_BUSYBOX_SHA256="${BUSYBOX_SHA256:-}"

# shellcheck source=../config/versions.env
. "${VERSIONS_FILE}"

[[ -n "${_OVR_KERNEL_SHA256}" ]] && KERNEL_SHA256="${_OVR_KERNEL_SHA256}"
[[ -n "${_OVR_BUSYBOX_SHA256}" ]] && BUSYBOX_SHA256="${_OVR_BUSYBOX_SHA256}"

# Export reproducible build environment
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH
export KCONFIG_NOTIMESTAMP=1
export KBUILD_BUILD_TIMESTAMP
export KBUILD_BUILD_USER
export KBUILD_BUILD_HOST

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
SRC_DIR="${SRC_DIR:-${BUILD_DIR}/src}"
BUSYBOX_BUILD_DIR="${BUSYBOX_BUILD_DIR:-${BUILD_DIR}/busybox}"
BUSYBOX_CONFIG_FRAGMENT="${BUSYBOX_CONFIG_FRAGMENT:-${ROOT_DIR}/config/busybox/symbolon.config}"

if [[ ! -f "${BUSYBOX_CONFIG_FRAGMENT}" ]]; then
    die "BusyBox config fragment not found: ${BUSYBOX_CONFIG_FRAGMENT}"
fi

KERNEL_ARCHIVE="${SRC_DIR}/${KERNEL_TARBALL}"
BUSYBOX_ARCHIVE="${SRC_DIR}/${BUSYBOX_TARBALL}"

if [[ ! -f "${KERNEL_ARCHIVE}" ]]; then
    die "Kernel archive not found: ${KERNEL_ARCHIVE} (run 'make fetch' first)"
fi
if [[ ! -f "${BUSYBOX_ARCHIVE}" ]]; then
    die "BusyBox archive not found: ${BUSYBOX_ARCHIVE} (run 'make fetch' first)"
fi

verify_sha256() {
    local file="$1"
    local expected="$2"
    local name
    name="$(basename "${file}")"

    expected="$(echo "${expected}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
        die "Malformed expected SHA-256 for ${name}: '${expected}'"
    fi

    local actual
    actual="$(sha256sum "${file}" | awk '{print tolower($1)}')"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "[build-busybox] ERROR: SHA-256 mismatch for ${name}!" >&2
        echo "  Expected: ${expected}" >&2
        echo "  Actual:   ${actual}" >&2
        exit 1
    fi
}

verify_sha256 "${KERNEL_ARCHIVE}" "${KERNEL_SHA256}"
verify_sha256 "${BUSYBOX_ARCHIVE}" "${BUSYBOX_SHA256}"

mkdir -p "${BUSYBOX_BUILD_DIR}"

# ─────────────────────────────────────────────────────────────
# 1. Resolve musl-gcc compiler
# ─────────────────────────────────────────────────────────────
CC_REQ="${CC:-musl-gcc}"
CC_BIN=""
MUSL_SYSROOT="${BUSYBOX_BUILD_DIR}/musl-sysroot"
MUSL_SYSROOT_STAMP="${MUSL_SYSROOT}/.stamp"

if command -v "${CC_REQ}" >/dev/null 2>&1; then
    CC_BIN="$(command -v "${CC_REQ}")"
elif [[ "${CC_REQ}" == "musl-gcc" ]]; then
    if [[ ! -x "${MUSL_SYSROOT}/usr/bin/musl-gcc" || \
          ! -f "${MUSL_SYSROOT_STAMP}" || \
          "$(cat "${MUSL_SYSROOT_STAMP}")" != "${MUSL_SYSROOT}" ]]; then
        if compgen -G "/var/cache/apt/archives/musl-tools_*.deb" >/dev/null && \
           compgen -G "/var/cache/apt/archives/musl-dev_*.deb" >/dev/null && \
           compgen -G "/var/cache/apt/archives/musl_*.deb" >/dev/null; then
            info "Extracting cached musl toolchain into ${MUSL_SYSROOT} ..."
            rm -rf "${MUSL_SYSROOT}"
            mkdir -p "${MUSL_SYSROOT}"
            deb_musl="$(ls -v /var/cache/apt/archives/musl_*.deb | tail -n 1)"
            deb_musl_dev="$(ls -v /var/cache/apt/archives/musl-dev_*.deb | tail -n 1)"
            deb_musl_tools="$(ls -v /var/cache/apt/archives/musl-tools_*.deb | tail -n 1)"
            for deb in "${deb_musl}" "${deb_musl_dev}" "${deb_musl_tools}"; do
                dpkg-deb -x "${deb}" "${MUSL_SYSROOT}"
            done
            sed -i \
                -e "s|/usr/include/x86_64-linux-musl|${MUSL_SYSROOT}/usr/include/x86_64-linux-musl|g" \
                -e "s|/usr/lib/x86_64-linux-musl|${MUSL_SYSROOT}/usr/lib/x86_64-linux-musl|g" \
                -e "s|/lib/ld-musl|${MUSL_SYSROOT}/lib/ld-musl|g" \
                "${MUSL_SYSROOT}/usr/lib/x86_64-linux-musl/musl-gcc.specs"
            sed -i \
                -e "s|/usr/lib/x86_64-linux-musl/musl-gcc.specs|${MUSL_SYSROOT}/usr/lib/x86_64-linux-musl/musl-gcc.specs|g" \
                "${MUSL_SYSROOT}/usr/bin/musl-gcc"
            printf '%s\n' "${MUSL_SYSROOT}" > "${MUSL_SYSROOT_STAMP}"
        fi
    fi
    if [[ -x "${MUSL_SYSROOT}/usr/bin/musl-gcc" ]]; then
        CC_BIN="${MUSL_SYSROOT}/usr/bin/musl-gcc"
    fi
fi

if [[ -z "${CC_BIN}" ]]; then
    die "Compiler '${CC_REQ}' not found (install 'musl-tools')."
fi

cc_defs="$(printf '#include <features.h>\n' | "${CC_BIN}" -dM -E - 2>/dev/null)" \
    || die "Compiler '${CC_BIN}' failed preprocessor sanity check."
if grep -qE '^#define __GLIBC__\b' <<< "${cc_defs}"; then
    die "Compiler '${CC_BIN}' targets glibc (__GLIBC__ is defined); musl-gcc is required (D-004)."
fi

info "Using musl compiler: ${CC_BIN}"

# ─────────────────────────────────────────────────────────────
# 2. Install sanitized kernel headers from pinned LTS kernel
# ─────────────────────────────────────────────────────────────
KHEADERS_DIR="${BUSYBOX_BUILD_DIR}/kheaders"
KHEADERS_INC="${KHEADERS_DIR}/include"
KHEADERS_STAMP="${KHEADERS_DIR}/.stamp"
EXPECTED_KHEADERS_STAMP="${KERNEL_VERSION}:${KERNEL_SHA256}"

if [[ ! -f "${KHEADERS_STAMP}" || \
      "$(cat "${KHEADERS_STAMP}")" != "${EXPECTED_KHEADERS_STAMP}" || \
      ! -f "${KHEADERS_INC}/linux/version.h" || \
      ! -f "${KHEADERS_INC}/linux/fs.h" || \
      ! -f "${KHEADERS_INC}/linux/hdreg.h" ]]; then
    info "Installing sanitized kernel headers from ${KERNEL_TARBALL} into ${KHEADERS_DIR} ..."
    rm -rf "${KHEADERS_DIR}"
    KERNEL_HDR_SRC="${BUSYBOX_BUILD_DIR}/linux-${KERNEL_VERSION}"
    rm -rf "${KERNEL_HDR_SRC}"

    tar -xJf "${KERNEL_ARCHIVE}" -C "${BUSYBOX_BUILD_DIR}" \
        "linux-${KERNEL_VERSION}/Makefile" \
        "linux-${KERNEL_VERSION}/Kbuild" \
        "linux-${KERNEL_VERSION}/Kconfig" \
        "linux-${KERNEL_VERSION}/scripts" \
        "linux-${KERNEL_VERSION}/include" \
        "linux-${KERNEL_VERSION}/arch/x86"

    make -C "${KERNEL_HDR_SRC}" \
        ARCH=x86_64 \
        INSTALL_HDR_PATH="${KHEADERS_DIR}" \
        headers_install >/dev/null

    rm -rf "${KERNEL_HDR_SRC}"
    printf '%s\n' "${EXPECTED_KHEADERS_STAMP}" > "${KHEADERS_STAMP}"
fi

if [[ ! -f "${KHEADERS_INC}/linux/version.h" || \
      ! -f "${KHEADERS_INC}/linux/fs.h" || \
      ! -f "${KHEADERS_INC}/linux/hdreg.h" ]]; then
    die "Sanitized kernel headers missing under ${KHEADERS_INC}"
fi

info "Sanitized kernel headers ready at ${KHEADERS_INC}"

# ─────────────────────────────────────────────────────────────
# 3. Extract BusyBox and apply allnoconfig + symbolon.config
# ─────────────────────────────────────────────────────────────
BB_SRC_DIR="${BUSYBOX_BUILD_DIR}/busybox-${BUSYBOX_VERSION}"
rm -rf "${BB_SRC_DIR}"

info "Extracting ${BUSYBOX_TARBALL} ..."
tar -xjf "${BUSYBOX_ARCHIVE}" -C "${BUSYBOX_BUILD_DIR}"

HOSTCFLAGS_BB="-O2 -Wno-unused-result"

info "Running 'make allnoconfig' ..."
make -C "${BB_SRC_DIR}" ARCH=x86_64 HOSTCFLAGS="${HOSTCFLAGS_BB}" allnoconfig >/dev/null

info "Applying config fragment ${BUSYBOX_CONFIG_FRAGMENT} ..."
while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
    line="${raw_line%$'\r'}"
    # Skip blank lines
    if [[ "${line}" =~ ^[[:space:]]*$ ]]; then
        continue
    fi
    # Handle '# CONFIG_FOO is not set'
    if [[ "${line}" =~ ^#[[:space:]]+(CONFIG_[A-Za-z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set[[:space:]]*$ ]]; then
        sym="${BASH_REMATCH[1]}"
        sed -i -e "/^${sym}=/d" -e "/^# ${sym} is not set$/d" "${BB_SRC_DIR}/.config"
        echo "# ${sym} is not set" >> "${BB_SRC_DIR}/.config"
        continue
    fi
    # Skip ordinary comment lines
    if [[ "${line}" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    # Handle 'CONFIG_FOO=value'
    if [[ "${line}" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
        sym="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        sed -i -e "/^${sym}=/d" -e "/^# ${sym} is not set$/d" "${BB_SRC_DIR}/.config"
        echo "${sym}=${val}" >> "${BB_SRC_DIR}/.config"
        continue
    fi
    die "Malformed line in ${BUSYBOX_CONFIG_FRAGMENT}: '${line}'"
done < "${BUSYBOX_CONFIG_FRAGMENT}"

# Resolve Kconfig dependencies non-interactively; any unmentioned new sub-options default to 'n'
set +o pipefail
yes n | make -C "${BB_SRC_DIR}" ARCH=x86_64 HOSTCFLAGS="${HOSTCFLAGS_BB}" oldconfig >/dev/null
set -o pipefail

# Generate include/autoconf.h and include/config/* deterministically before parallel build
make -C "${BB_SRC_DIR}" ARCH=x86_64 HOSTCFLAGS="${HOSTCFLAGS_BB}" silentoldconfig >/dev/null

# ─────────────────────────────────────────────────────────────
# 4. Build static BusyBox with musl-gcc and kernel headers
# ─────────────────────────────────────────────────────────────
EXTRA_CFLAGS="-isystem ${KHEADERS_INC} -O2 -fstack-protector-strong -ffile-prefix-map=${BB_SRC_DIR}=. -ffile-prefix-map=${KHEADERS_INC}=/usr/include -ffile-prefix-map=${MUSL_SYSROOT}="

info "Compiling static BusyBox ${BUSYBOX_VERSION} with ${CC_BIN} ..."
make -C "${BB_SRC_DIR}" -j"$(nproc)" \
    ARCH=x86_64 \
    CC="${CC_BIN}" \
    HOSTCFLAGS="${HOSTCFLAGS_BB}" \
    EXTRA_CFLAGS="${EXTRA_CFLAGS}" \
    SKIP_STRIP=n \
    busybox >/dev/null

cp -f "${BB_SRC_DIR}/busybox" "${BUSYBOX_BUILD_DIR}/busybox"
cp -f "${BB_SRC_DIR}/.config" "${BUSYBOX_BUILD_DIR}/.config"

# ─────────────────────────────────────────────────────────────
# 5. Verify built binary, applet list, and configuration
# ─────────────────────────────────────────────────────────────
"${SCRIPT_DIR}/verify-busybox.sh" "${BUSYBOX_BUILD_DIR}/busybox" "${BUSYBOX_BUILD_DIR}/.config"

info "BusyBox build complete: ${BUSYBOX_BUILD_DIR}/busybox ($(sha256sum "${BUSYBOX_BUILD_DIR}/busybox" | awk '{print $1}'))"
