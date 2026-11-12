#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Verify a resolved kernel .config against docs/KERNEL_CONFIG.md §2–§5:
#   - Strictly enforces all §3 Keep symbols (=y / exact string/int values)
#   - Strictly rejects all §4 Forbidden symbols (=y or =m)
#   - Rejects any loadable modules (=m) anywhere in .config
#   - Requires SERIAL_8250 / SERIAL_8250_CONSOLE / console=ttyS0 to be OFF in
#     release mode and ON in --debug mode.
#
# Usage:
#   scripts/verify-kconfig.sh [--debug] <path/to/.config>

set -euo pipefail

DEBUG_MODE=0
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG_MODE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--debug] <path/to/.config>"
            exit 0
            ;;
        *)
            if [[ -n "${CONFIG_FILE}" ]]; then
                echo "[verify-kconfig] ERROR: unexpected extra argument: $1" >&2
                exit 2
            fi
            CONFIG_FILE="$1"
            shift
            ;;
    esac
done

CONFIG_FILE="${CONFIG_FILE:-build/kernel/.config}"

die() {
    echo "[verify-kconfig] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[verify-kconfig] $*"
}

if [[ ! -f "${CONFIG_FILE}" ]]; then
    die "Kernel .config not found: ${CONFIG_FILE}"
fi

# Extract exact value for a CONFIG_* symbol (returns "" if unset/missing)
get_sym() {
    local sym="$1"
    local line
    line="$(grep -E "^CONFIG_${sym}=" "${CONFIG_FILE}" || true)"
    if [[ -n "${line}" ]]; then
        printf '%s' "${line#CONFIG_${sym}=}"
    fi
}

FAILURES=0

require_y() {
    local sym="$1"
    if [[ "$(get_sym "${sym}")" != "y" ]]; then
        echo "[verify-kconfig] FAIL: expected CONFIG_${sym}=y (got '$(get_sym "${sym}")')" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

require_val() {
    local sym="$1"
    local expected="$2"
    local actual
    actual="$(get_sym "${sym}")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "[verify-kconfig] FAIL: expected CONFIG_${sym}=${expected} (got '${actual}')" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

forbid_sym() {
    local sym="$1"
    local actual
    actual="$(get_sym "${sym}")"
    if [[ "${actual}" == "y" || "${actual}" == "m" ]]; then
        echo "[verify-kconfig] FAIL: forbidden symbol CONFIG_${sym}=${actual} is enabled" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

# ─────────────────────────────────────────────────────────────
# 1. Core Keep List (docs/KERNEL_CONFIG.md §3)
# ─────────────────────────────────────────────────────────────
KEEP_Y=(
    # Core
    64BIT
    PRINTK
    BINFMT_ELF
    BINFMT_SCRIPT
    FUTEX
    PROC_FS
    SYSFS
    DEVTMPFS
    DEVTMPFS_MOUNT
    BLK_DEV_INITRD
    RD_GZIP
    INITRAMFS_COMPRESSION_GZIP
    ACPI
    PCI
    PCI_MSI
    # Boot
    EFI
    EFI_STUB
    RELOCATABLE
    RANDOMIZE_BASE
    # Console & Keyboard
    TTY
    VT
    VT_CONSOLE
    VGA_CONSOLE
    FRAMEBUFFER_CONSOLE
    FONT_8x16
    INPUT
    INPUT_KEYBOARD
    SERIO
    SERIO_I8042
    KEYBOARD_ATKBD
    HID_SUPPORT
    HID
    HID_GENERIC
    USB_HID
    # USB & Flash drives
    USB_SUPPORT
    USB
    USB_PCI
    USB_XHCI_HCD
    USB_XHCI_PCI
    USB_EHCI_HCD
    USB_EHCI_PCI
    USB_OHCI_HCD
    USB_OHCI_HCD_PCI
    USB_UHCI_HCD
    USB_STORAGE
    USB_UAS
    BLOCK
    SCSI
    BLK_DEV_SD
    MSDOS_PARTITION
    # Filesystem
    FAT_FS
    VFAT_FS
    NLS
    NLS_CODEPAGE_437
    NLS_ISO8859_1
    # Hardening
    INIT_ON_ALLOC_DEFAULT_ON
    INIT_ON_FREE_DEFAULT_ON
    STACKPROTECTOR
    STACKPROTECTOR_STRONG
    STRICT_KERNEL_RWX
    HARDENED_USERCOPY
    SLAB_FREELIST_RANDOM
    SLAB_FREELIST_HARDENED
    SECURITY_DMESG_RESTRICT
    BUG_ON_DATA_CORRUPTION
    PANIC_ON_OOPS
    # Locked Command Line
    CMDLINE_BOOL
    CMDLINE_OVERRIDE
)

for sym in "${KEEP_Y[@]}"; do
    require_y "${sym}"
done

# Framebuffer strategy: primary FB + FB_EFI, or simpledrm fallback (KERNEL_CONFIG.md §3)
FB_MODE=""
if [[ "$(get_sym FB)" == "y" && "$(get_sym FB_EFI)" == "y" ]]; then
    FB_MODE="fb_efi"
    forbid_sym DRM
elif [[ "$(get_sym DRM)" == "y" && "$(get_sym DRM_SIMPLEDRM)" == "y" && \
        "$(get_sym SYSFB_SIMPLEFB)" == "y" && "$(get_sym DRM_FBDEV_EMULATION)" == "y" ]]; then
    FB_MODE="simpledrm"
else
    echo "[verify-kconfig] FAIL: neither (FB+FB_EFI) nor (DRM+DRM_SIMPLEDRM+SYSFB_SIMPLEFB+DRM_FBDEV_EMULATION) is configured" >&2
    FAILURES=$((FAILURES + 1))
fi

# Exact non-boolean required values
require_val FAT_DEFAULT_CODEPAGE '437'
require_val FAT_DEFAULT_IOCHARSET '"iso8859-1"'

initramfs_src="$(get_sym INITRAMFS_SOURCE)"
if [[ -z "${initramfs_src}" || "${initramfs_src}" == '""' || "${initramfs_src}" == *"__INITRAMFS_SOURCE__"* ]]; then
    echo "[verify-kconfig] FAIL: CONFIG_INITRAMFS_SOURCE must reference the generated initramfs list (got '${initramfs_src}')" >&2
    FAILURES=$((FAILURES + 1))
fi

# ─────────────────────────────────────────────────────────────
# 2. Built-in command line & debug serial policy (§2, §5)
# ─────────────────────────────────────────────────────────────
RELEASE_CMDLINE='"console=tty0 loglevel=3 init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 efi=noruntime panic=0"'
DEBUG_CMDLINE='"console=tty0 console=ttyS0 loglevel=3 init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 efi=noruntime panic=0"'

if [[ "${DEBUG_MODE}" -eq 1 ]]; then
    require_y SERIAL_8250
    require_y SERIAL_8250_CONSOLE
    require_val CMDLINE "${DEBUG_CMDLINE}"
else
    forbid_sym SERIAL_8250
    forbid_sym SERIAL_8250_CONSOLE
    require_val CMDLINE "${RELEASE_CMDLINE}"
fi

# ─────────────────────────────────────────────────────────────
# 3. Forbidden List (§4) & no loadable modules
# ─────────────────────────────────────────────────────────────
FORBIDDEN_SYMS=(
    NET
    WIRELESS
    CFG80211
    BT
    INET
    UNIX
    PACKET
    MODULES
    MODULE_UNLOAD
    SWAP
    HIBERNATION
    SUSPEND
    COREDUMP
    KEXEC
    KEXEC_CORE
    KEXEC_FILE
    CRASH_DUMP
    MAGIC_SYSRQ
    ATA
    SATA_AHCI
    BLK_DEV_NVME
    NVME_CORE
    MMC
    FIREWIRE
    THUNDERBOLT
    USB4
    PCMCIA
    USB_GADGET
    USB_NET_DRIVERS
    USB_SERIAL
    SOUND
    MEDIA_SUPPORT
    WLAN
    BLK_DEV_LOOP
    MD
    BLK_DEV_DM
    EXT4_FS
    BTRFS_FS
    XFS_FS
    NTFS3_FS
    ISO9660_FS
    FUSE_FS
    EFIVAR_FS
    EFI_VARS
    DEVMEM
    DEVPORT
    DEBUG_FS
    KPROBES
    UPROBES
    FTRACE
    FUNCTION_TRACER
    BPF_SYSCALL
    PROFILING
    DEBUG_PERF_USE_VMALLOC
    IO_URING
    USERFAULTFD
    IA32_EMULATION
    X86_X32_ABI
    IKCONFIG
    IKCONFIG_PROC
    MICROCODE_LATE_LOADING
    MICROCODE_DBG
)

for sym in "${FORBIDDEN_SYMS[@]}"; do
    forbid_sym "${sym}"
done

# Assert zero '=m' entries anywhere
mod_lines="$(grep -E '^CONFIG_[A-Za-z0-9_]+=m$' "${CONFIG_FILE}" || true)"
if [[ -n "${mod_lines}" ]]; then
    echo "[verify-kconfig] FAIL: unexpected =m module entries found:" >&2
    echo "${mod_lines}" >&2
    FAILURES=$((FAILURES + 1))
fi

if [[ "${FAILURES}" -gt 0 ]]; then
    die "Kconfig verification failed with ${FAILURES} violation(s)."
fi

info "OK (${CONFIG_FILE}, mode=$([[ ${DEBUG_MODE} -eq 1 ]] && echo debug || echo release), fb=${FB_MODE}): all required symbols enabled and all forbidden symbols unset."
