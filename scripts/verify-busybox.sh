#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify the built BusyBox binary and its configuration against Phase 3 requirements:
#   1. ELF 64-bit x86-64 static binary with no dynamic section and no PT_INTERP
#   2. Exact applet list from 'busybox --list' (no missing or unexpected applets)
#   3. Required Kconfig options enabled (CONFIG_STATIC=y, CONFIG_FEATURE_SH_STANDALONE=y, ...)
#   4. Forbidden Kconfig options (networking, mdev, telnetd, wget, halt, reboot, ...) unset
#   5. Standalone shell smoke check with empty PATH
#
# Usage:
#   scripts/verify-busybox.sh [path/to/busybox] [path/to/.config]
#
# Reference: docs/PLAN.md (§4 Phase 3) and docs/DECISIONS.md (D-001, D-004, D-013).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"

BUSYBOX_BIN="${1:-${BUILD_DIR}/busybox/busybox}"
BUSYBOX_CONFIG="${2:-${BUILD_DIR}/busybox/.config}"

die() {
    echo "[verify-busybox] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[verify-busybox] $*"
}

if [[ ! -f "${BUSYBOX_BIN}" ]]; then
    die "BusyBox binary not found: ${BUSYBOX_BIN}"
fi
if [[ ! -x "${BUSYBOX_BIN}" ]]; then
    die "BusyBox binary is not executable: ${BUSYBOX_BIN}"
fi
if [[ ! -f "${BUSYBOX_CONFIG}" ]]; then
    die "BusyBox .config file not found: ${BUSYBOX_CONFIG}"
fi

# ─────────────────────────────────────────────────────────────
# 1. Verify static ELF binary properties
# ─────────────────────────────────────────────────────────────
file_out="$(file -b "${BUSYBOX_BIN}")"
if [[ "${file_out}" != *"ELF 64-bit LSB executable"* || "${file_out}" != *"x86-64"* ]]; then
    die "${BUSYBOX_BIN} is not an x86-64 ELF 64-bit executable: ${file_out}"
fi
if [[ "${file_out}" != *"statically linked"* ]]; then
    die "${BUSYBOX_BIN} is not statically linked: ${file_out}"
fi
if [[ "${file_out}" == *"for GNU/Linux"* ]]; then
    die "${BUSYBOX_BIN} has a glibc GNU/Linux ABI note (must be statically linked with musl-gcc): ${file_out}"
fi

readelf_dyn="$(readelf -d "${BUSYBOX_BIN}" 2>&1)"
if [[ "${readelf_dyn}" != *"There is no dynamic section in this file"* ]]; then
    echo "${readelf_dyn}" >&2
    die "${BUSYBOX_BIN} has a dynamic section!"
fi

readelf_prog="$(readelf -l "${BUSYBOX_BIN}" 2>&1)"
if echo "${readelf_prog}" | grep -qE '^\s*INTERP\b'; then
    echo "${readelf_prog}" >&2
    die "${BUSYBOX_BIN} contains a PT_INTERP program interpreter segment!"
fi

readelf_sec="$(readelf -S "${BUSYBOX_BIN}" 2>&1)"
if echo "${readelf_sec}" | grep -qF '.note.ABI-tag'; then
    die "${BUSYBOX_BIN} contains a glibc .note.ABI-tag section (must be built with musl-gcc)!"
fi
if strings "${BUSYBOX_BIN}" | grep -qF 'GNU C Library'; then
    die "${BUSYBOX_BIN} contains GNU C Library (glibc) strings (must be built with musl-gcc)!"
fi

info "ELF check OK: statically linked musl x86-64 binary with no dynamic section."

# ─────────────────────────────────────────────────────────────
# 2. Verify exact applet list from 'busybox --list'
# ─────────────────────────────────────────────────────────────
# docs/PLAN.md §4 Phase 3:
#   ash (as sh), mount, umount, mkdir, cat, echo, sleep, dd, fdisk,
#   mkfs.vfat, sync, poweroff, blockdev, stty, clear, ls (debug)
EXPECTED_APPLETS=(
    ash
    blockdev
    cat
    clear
    dd
    echo
    fdisk
    ls
    mkdir
    mkfs.vfat
    mount
    poweroff
    sh
    sleep
    stty
    sync
    umount
)

actual_list_raw="$("${BUSYBOX_BIN}" --list)" || die "Failed to run '${BUSYBOX_BIN} --list'"
if [[ -z "${actual_list_raw}" ]]; then
    die "'${BUSYBOX_BIN} --list' produced empty output!"
fi

expected_sorted="$(printf '%s\n' "${EXPECTED_APPLETS[@]}" | LC_ALL=C sort)"
actual_sorted="$(printf '%s\n' "${actual_list_raw}" | LC_ALL=C sort)"

if [[ "${actual_sorted}" != "${expected_sorted}" ]]; then
    missing="$(comm -23 <(printf '%s\n' "${expected_sorted}") <(printf '%s\n' "${actual_sorted}") || true)"
    extra="$(comm -13 <(printf '%s\n' "${expected_sorted}") <(printf '%s\n' "${actual_sorted}") || true)"
    echo "[verify-busybox] ERROR: BusyBox applet list mismatch!" >&2
    if [[ -n "${missing}" ]]; then
        echo "  Missing expected applet(s):" >&2
        while IFS= read -r app; do
            [[ -n "${app}" ]] && echo "    - ${app}" >&2
        done <<< "${missing}"
    fi
    if [[ -n "${extra}" ]]; then
        echo "  Unexpected / forbidden applet(s):" >&2
        while IFS= read -r app; do
            [[ -n "${app}" ]] && echo "    + ${app}" >&2
        done <<< "${extra}"
    fi
    exit 1
fi

info "Applet list OK: exactly ${#EXPECTED_APPLETS[@]} entries (${EXPECTED_APPLETS[*]})."

# ─────────────────────────────────────────────────────────────
# 3. Verify .config required and forbidden symbols
# ─────────────────────────────────────────────────────────────
REQUIRED_CONFIG_Y=(
    CONFIG_STATIC
    CONFIG_BUSYBOX
    CONFIG_ASH
    CONFIG_SH_IS_ASH
    CONFIG_SHELL_ASH
    CONFIG_FEATURE_SH_STANDALONE
    CONFIG_ASH_INTERNAL_GLOB
    CONFIG_MOUNT
    CONFIG_FEATURE_MOUNT_FLAGS
    CONFIG_UMOUNT
    CONFIG_MKDIR
    CONFIG_CAT
    CONFIG_ECHO
    CONFIG_SLEEP
    CONFIG_DD
    CONFIG_FDISK
    CONFIG_FEATURE_FDISK_WRITABLE
    CONFIG_MKFS_VFAT
    CONFIG_SYNC
    CONFIG_POWEROFF
    CONFIG_BLOCKDEV
    CONFIG_STTY
    CONFIG_CLEAR
    CONFIG_LS
)

for sym in "${REQUIRED_CONFIG_Y[@]}"; do
    if ! grep -qx "${sym}=y" "${BUSYBOX_CONFIG}"; then
        die "Required BusyBox option '${sym}=y' is missing in ${BUSYBOX_CONFIG}"
    fi
done

FORBIDDEN_CONFIG=(
    CONFIG_PIE
    CONFIG_BUILD_LIBBUSYBOX
    CONFIG_FEATURE_INSTALLER
    CONFIG_FEATURE_SUID
    CONFIG_HUSH
    CONFIG_SHELL_HUSH
    CONFIG_SH_IS_HUSH
    CONFIG_BASH_IS_ASH
    CONFIG_BASH_IS_HUSH
    CONFIG_HALT
    CONFIG_REBOOT
    CONFIG_MKDOSFS
    CONFIG_FSYNC
    CONFIG_MDEV
    CONFIG_FEATURE_MOUNT_NFS
    CONFIG_FEATURE_MOUNT_CIFS
    CONFIG_FEATURE_MOUNT_HELPERS
    CONFIG_FEATURE_IPV6
    CONFIG_FEATURE_UNIX_LOCAL
    CONFIG_ARP
    CONFIG_ARPING
    CONFIG_BRCTL
    CONFIG_DNSD
    CONFIG_ETHER_WAKE
    CONFIG_FTPD
    CONFIG_FTPGET
    CONFIG_FTPPUT
    CONFIG_HOSTNAME
    CONFIG_DNSDOMAINNAME
    CONFIG_HTTPD
    CONFIG_IFCONFIG
    CONFIG_IFENSLAVE
    CONFIG_IFPLUGD
    CONFIG_IFUP
    CONFIG_IFDOWN
    CONFIG_INETD
    CONFIG_IP
    CONFIG_IPADDR
    CONFIG_IPLINK
    CONFIG_IPROUTE
    CONFIG_IPTUNNEL
    CONFIG_IPRULE
    CONFIG_IPNEIGH
    CONFIG_IPCALC
    CONFIG_FAKEIDENTD
    CONFIG_NAMEIF
    CONFIG_NBDCLIENT
    CONFIG_NC
    CONFIG_NETCAT
    CONFIG_NETSTAT
    CONFIG_NSLOOKUP
    CONFIG_NTPD
    CONFIG_PING
    CONFIG_PING6
    CONFIG_PSCAN
    CONFIG_ROUTE
    CONFIG_SLATTACH
    CONFIG_SSL_CLIENT
    CONFIG_TC
    CONFIG_TCPSVD
    CONFIG_UDPSVD
    CONFIG_TELNET
    CONFIG_TELNETD
    CONFIG_TFTP
    CONFIG_TFTPD
    CONFIG_TRACEROUTE
    CONFIG_TRACEROUTE6
    CONFIG_TUNCTL
    CONFIG_VCONFIG
    CONFIG_WGET
    CONFIG_WHOIS
    CONFIG_ZCIP
    CONFIG_UDHCPD
    CONFIG_DUMPLEASES
    CONFIG_DHCPRELAY
    CONFIG_UDHCPC
    CONFIG_UDHCPC6
)

for sym in "${FORBIDDEN_CONFIG[@]}"; do
    if grep -qE "^${sym}=[ym]" "${BUSYBOX_CONFIG}"; then
        die "Forbidden BusyBox option '${sym}' is enabled in ${BUSYBOX_CONFIG}"
    fi
done

info "Config check OK: all ${#REQUIRED_CONFIG_Y[@]} required options enabled and ${#FORBIDDEN_CONFIG[@]} forbidden options unset."

# ─────────────────────────────────────────────────────────────
# 4. Functional smoke check (ash, sh, and standalone mode)
# ─────────────────────────────────────────────────────────────
sh_out="$("${BUSYBOX_BIN}" sh -c 'echo shardkey-sh-ok')" || die "Failed to execute 'busybox sh'"
if [[ "${sh_out}" != "shardkey-sh-ok" ]]; then
    die "Unexpected output from 'busybox sh': '${sh_out}'"
fi

ash_out="$("${BUSYBOX_BIN}" ash -c 'echo shardkey-ash-ok')" || die "Failed to execute 'busybox ash'"
if [[ "${ash_out}" != "shardkey-ash-ok" ]]; then
    die "Unexpected output from 'busybox ash': '${ash_out}'"
fi

standalone_out="$(PATH="" "${BUSYBOX_BIN}" sh -c 'echo standalone-pipeline-ok | cat')" \
    || die "Standalone shell execution with empty PATH failed"
if [[ "${standalone_out}" != "standalone-pipeline-ok" ]]; then
    die "Unexpected standalone shell output: '${standalone_out}'"
fi

info "Smoke check OK: ash, sh, and standalone applet execution verified."
