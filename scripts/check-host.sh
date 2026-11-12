#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify that the build machine has the required Debian packages installed.
# Usage:
#   scripts/check-host.sh             # check all packages needed for a full build
#   scripts/check-host.sh --fetch     # check only packages needed for 'make fetch'
#   scripts/check-host.sh --tool      # check only packages needed for 'make tool'
#   scripts/check-host.sh --busybox   # check only packages needed for 'make busybox'
#   scripts/check-host.sh --kernel    # check only packages needed for 'make kernel'

set -euo pipefail

MODE="all"
if [[ $# -gt 0 ]]; then
    case "$1" in
        --fetch)
            MODE="fetch"
            ;;
        --tool)
            MODE="tool"
            ;;
        --busybox)
            MODE="busybox"
            ;;
        --kernel)
            MODE="kernel"
            ;;
        --all)
            MODE="all"
            ;;
        *)
            echo "[check-host] ERROR: unknown argument: $1" >&2
            echo "Usage: $0 [--all | --fetch | --tool | --busybox | --kernel]" >&2
            exit 2
            ;;
    esac
fi

# 1. Verify x86_64 architecture
ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
    echo "[check-host] ERROR: host architecture is '${ARCH}', expected 'x86_64'." >&2
    exit 1
fi

# 2. Check OS release (informational note if not Debian 13)
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "13" ]]; then
        echo "[check-host] Note: host OS is '${PRETTY_NAME:-unknown}' (target reference is Debian 13 x86_64)."
    fi
fi

# 3. Require dpkg-query (Debian/Ubuntu package database)
if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "[check-host] ERROR: 'dpkg-query' not found; a Debian-based host is required." >&2
    exit 1
fi

FETCH_PACKAGES=(
    ca-certificates
    curl
    gnupg
    xz-utils
    bzip2
)

TOOL_PACKAGES=(
    build-essential
    musl-tools
)

BUSYBOX_PACKAGES=(
    build-essential
    musl-tools
    bzip2
    xz-utils
)

KERNEL_PACKAGES=(
    build-essential
    bc
    bison
    flex
    libelf-dev
    cpio
    xz-utils
)

ALL_PACKAGES=(
    build-essential
    bc
    bison
    flex
    libelf-dev
    musl-tools
    cpio
    xz-utils
    bzip2
    syslinux
    syslinux-common
    mtools
    dosfstools
    gnupg
    sbsigntool
    openssl
    qemu-system-x86
    ovmf
    curl
    ca-certificates
)

if [[ "${MODE}" == "fetch" ]]; then
    PACKAGES=("${FETCH_PACKAGES[@]}")
elif [[ "${MODE}" == "tool" ]]; then
    PACKAGES=("${TOOL_PACKAGES[@]}")
elif [[ "${MODE}" == "busybox" ]]; then
    PACKAGES=("${BUSYBOX_PACKAGES[@]}")
elif [[ "${MODE}" == "kernel" ]]; then
    PACKAGES=("${KERNEL_PACKAGES[@]}")
else
    PACKAGES=("${ALL_PACKAGES[@]}")
fi

is_musl_cc() {
    local cc_cmd="$1"
    command -v "${cc_cmd}" >/dev/null 2>&1 || return 1
    local defs
    defs="$(printf '#include <features.h>\n' | "${cc_cmd}" -dM -E - 2>/dev/null)" || return 1
    if grep -qE '^#define __GLIBC__\b' <<< "${defs}"; then
        return 1
    fi
    return 0
}

if [[ ( "${MODE}" == "tool" || "${MODE}" == "busybox" ) && -n "${CC:-}" ]]; then
    if command -v "${CC}" >/dev/null 2>&1 && ! is_musl_cc "${CC}"; then
        echo "[check-host] ERROR: CC='${CC}' targets glibc; musl-gcc is required (D-004)." >&2
        exit 1
    fi
fi

MISSING=()
for pkg in "${PACKAGES[@]}"; do
    status="$(dpkg-query -W -f='${Status}\n' "${pkg}" 2>/dev/null || true)"
    if [[ "${status}" != "install ok installed" ]]; then
        if [[ ( "${MODE}" == "tool" || "${MODE}" == "busybox" ) && "${pkg}" == "musl-tools" ]]; then
            if is_musl_cc "${CC:-musl-gcc}"; then
                echo "[check-host] Note: '${pkg}' not installed via dpkg, using musl compiler '${CC:-musl-gcc}'."
                continue
            fi
            if [[ -z "${CC:-}" || "${CC}" == "musl-gcc" ]] && \
               compgen -G "/var/cache/apt/archives/musl-tools_*.deb" >/dev/null && \
               compgen -G "/var/cache/apt/archives/musl-dev_*.deb" >/dev/null && \
               compgen -G "/var/cache/apt/archives/musl_*.deb" >/dev/null; then
                echo "[check-host] Note: '${pkg}' not installed via dpkg, using cached .deb archives in /var/cache/apt/archives/."
                continue
            fi
        fi
        MISSING+=("${pkg}")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[check-host] ERROR: missing required Debian package(s) (${MODE} mode):" >&2
    for pkg in "${MISSING[@]}"; do
        echo "  - ${pkg}" >&2
    done
    echo "" >&2
    echo "Install them with:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y ${MISSING[*]}" >&2
    exit 1
fi

echo "[check-host] OK (${MODE}): all ${#PACKAGES[@]} required packages are satisfied."
