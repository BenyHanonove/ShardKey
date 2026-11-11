#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Prepare a target USB drive for a ShardKey share:
#   - Refuse non-USB block devices (verify /sys/block/<dev> resolves under /usb)
#   - Zero the first 1 MiB of the device
#   - Write an MBR partition table with one primary FAT32 LBA (0x0c) partition
#   - Format that partition with FAT32 and volume label 'SHARDKEY'
#
# Usage:
#   /lib/shardkey/prep-drive.sh <dev_node>   (e.g. /dev/sda)

set -eu

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

die() {
    echo "prep-drive.sh: ERROR: $*" >&2
    exit 1
}

if [ "$#" -ne 1 ] || [ -z "${1:-}" ]; then
    die "usage: $0 <whole-disk-device>"
fi

DEV="$1"

case "${DEV}" in
    /dev/sd*) ;;
    *) die "refusing unsupported or non-sd device path: ${DEV}" ;;
esac

DEV_NAME="${DEV#/dev/}"
case "${DEV_NAME}" in
    sd[a-z]|sd[a-z][a-z]) ;;
    *) die "expected whole-disk device like /dev/sda, got: ${DEV}" ;;
esac

[ -b "${DEV}" ] || die "block device does not exist: ${DEV}"

SYS_BLK="/sys/block/${DEV_NAME}"
[ -e "${SYS_BLK}" ] || die "sysfs entry not found: ${SYS_BLK}"
[ ! -e "${SYS_BLK}/partition" ] || die "refusing partition device: ${DEV}"

real_blk="$(cd -P "${SYS_BLK}" 2>/dev/null && pwd)" || die "cannot resolve sysfs path: ${SYS_BLK}"
case "${real_blk}" in
    */usb/*|*/usb[0-9]*/*) ;;
    *) die "refusing non-USB device ${DEV} (${real_blk})" ;;
esac

if [ -r /proc/mounts ]; then
    while read -r mdev _mp _rest; do
        case "${mdev}" in
            "${DEV}"|"${DEV}"[0-9]*)
                die "refusing mounted device: ${mdev}"
                ;;
        esac
    done < /proc/mounts
fi

# Clear first 1 MiB and flush any stale kernel partition mappings
if ! dd_out="$(dd if=/dev/zero of="${DEV}" bs=1048576 count=1 2>&1)"; then
    die "failed to zero first 1 MiB of ${DEV}: ${dd_out}"
fi
sync
blockdev --rereadpt "${DEV}" >/dev/null 2>&1 || true

# Create fresh DOS MBR with partition 1 primary FAT32 LBA (0x0c).
# BusyBox fdisk 't' auto-selects partition 1 when it is the only partition.
if ! fdisk_out="$(printf 'o\nn\np\n1\n\n\nt\nc\nw\n' | fdisk -u "${DEV}" 2>&1)"; then
    sync
    sleep 1
    if ! blockdev --rereadpt "${DEV}" >/dev/null 2>&1; then
        die "fdisk failed on ${DEV}: ${fdisk_out}"
    fi
fi

sync
blockdev --rereadpt "${DEV}" >/dev/null 2>&1 || true

PART="${DEV}1"
tries=0
while [ ! -b "${PART}" ] && [ "${tries}" -lt 5 ]; do
    sleep 1
    tries=$((tries + 1))
done
[ -b "${PART}" ] || die "partition node did not appear after fdisk: ${PART}"

if ! mkfs_out="$(mkfs.vfat -F 32 -n SHARDKEY "${PART}" 2>&1)"; then
    die "mkfs.vfat failed on ${PART}: ${mkfs_out}"
fi

sync
blockdev --flushbufs "${PART}" >/dev/null 2>&1 || true
blockdev --flushbufs "${DEV}" >/dev/null 2>&1 || true

exit 0
