#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify that the build machine has the required Debian packages installed.
# Usage:
#   scripts/check-host.sh           # check all packages needed for a full build
#   scripts/check-host.sh --fetch   # check only packages needed for 'make fetch'

set -euo pipefail

MODE="all"
if [[ $# -gt 0 ]]; then
    case "$1" in
        --fetch)
            MODE="fetch"
            ;;
        --all)
            MODE="all"
            ;;
        *)
            echo "[check-host] ERROR: unknown argument: $1" >&2
            echo "Usage: $0 [--all | --fetch]" >&2
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
else
    PACKAGES=("${ALL_PACKAGES[@]}")
fi

MISSING=()
for pkg in "${PACKAGES[@]}"; do
    status="$(dpkg-query -W -f='${Status}\n' "${pkg}" 2>/dev/null || true)"
    if [[ "${status}" != "install ok installed" ]]; then
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

echo "[check-host] OK (${MODE}): all ${#PACKAGES[@]} required packages are installed."
