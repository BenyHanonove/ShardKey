/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_DRIVE_H
#define SHARDKEY_DRIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DRIVE_DEFAULT_SYS_BLOCK  "/sys/block"
#define DRIVE_DEFAULT_DEV_DIR    "/dev"
#define DRIVE_DEFAULT_MOUNT_DIR  "/mnt"
#define DRIVE_PREP_SCRIPT_PATH   "/lib/shardkey/prep-drive.sh"

struct drive_info {
	char     name[32];      /* e.g. "sda" */
	char     dev_node[64];  /* e.g. "/dev/sda" */
	char     part_node[64]; /* e.g. "/dev/sda1" */
	char     vendor[64];    /* e.g. "SanDisk" */
	char     model[64];     /* e.g. "Ultra" */
	uint64_t size_bytes;    /* Total capacity in bytes */
};

/*
 * Check if a block device name (e.g. "sda") under sys_block_dir is a USB disk.
 * Returns true if the device is a valid SCSI disk ("sd*") whose sysfs path or
 * device symlink resolves under a USB controller ("/usb").
 */
bool drive_is_usb_block(const char *sys_block_dir, const char *dev_name);

/*
 * Populate out_info for dev_name from sys_block_dir and dev_dir.
 * Returns 0 on success, -1 on error.
 */
int drive_read_info(const char *sys_block_dir,
                    const char *dev_dir,
                    const char *dev_name,
                    struct drive_info *out_info);

/*
 * Enumerate all currently attached USB block devices under sys_block_dir.
 * Results are sorted lexicographically by device name for determinism.
 * Returns 0 on success, -1 on error.
 */
int drive_scan_usb(const char *sys_block_dir,
                   const char *dev_dir,
                   struct drive_info *out_list,
                   size_t max_devs,
                   size_t *out_count);

/* Format byte size into human-readable string (e.g. "14.9 GiB", "512.0 MiB") */
void drive_format_size(uint64_t size_bytes, char *out_str, size_t cap);

/* Poll sys_block_dir until no USB block devices are present */
int drive_wait_all_removed(const char *sys_block_dir,
                           const char *dev_dir,
                           unsigned int poll_ms);

/* Poll sys_block_dir until a USB block device is present (and has non-zero size) */
int drive_wait_inserted(const char *sys_block_dir,
                        const char *dev_dir,
                        unsigned int poll_ms,
                        struct drive_info *out_info);

/* Poll sys_block_dir until the specific device dev_name is removed */
int drive_wait_removed_name(const char *sys_block_dir,
                            const char *dev_name,
                            unsigned int poll_ms);

/*
 * Run prep_script (typically /lib/shardkey/prep-drive.sh) on dev_node via fork+execv.
 * Returns 0 if the script exits with status 0, -1 otherwise.
 */
int drive_run_prep_script(const char *prep_script, const char *dev_node);

/* Mount part_node (vfat) at mount_dir (read-only if read_only is true) */
int drive_mount_vfat(const char *part_node, const char *mount_dir, bool read_only);

/* Unmount mount_dir and sync filesystems */
int drive_umount_sync(const char *mount_dir);

/*
 * Write the encoded share file and holder README.txt into an already-mounted
 * directory (mount_dir), fsyncing both files and the directory itself.
 */
int drive_write_files_in_dir(const char *mount_dir,
                             uint8_t index,
                             uint8_t shares,
                             const char *share_content,
                             size_t share_len,
                             const char *readme_content,
                             size_t readme_len);

#include "secmem.h"

enum drive_existing_status {
	DRIVE_EXISTING_NONE          = 0,
	DRIVE_EXISTING_BOOT_STICK    = 1,
	DRIVE_EXISTING_EARLIER_SHARE = 2
};

/*
 * Read back the share file from mount_dir into verify_buf, compare it
 * byte-for-byte with expected_content in constant time, verify its
 * format and SHA-256 check field via share_fmt_parse, and confirm README.txt exists.
 * Always wipes verify_buf before returning.
 */
int drive_verify_files_in_dir(const char *mount_dir,
                              uint8_t index,
                              uint8_t shares,
                              const char *expected_content,
                              size_t expected_len,
                              char *verify_buf,
                              size_t verify_cap);

/*
 * Inspect an already-mounted drive directory (mount_dir) before erasing:
 *   - returns DRIVE_EXISTING_BOOT_STICK if ShardKey boot stick markers are present
 *   - returns DRIVE_EXISTING_EARLIER_SHARE if a valid share 1..(current_idx-1)
 *     from the current ceremony (matching set_id) is present
 *   - returns DRIVE_EXISTING_NONE otherwise
 */
enum drive_existing_status drive_inspect_existing_dir(
	const char *mount_dir,
	uint8_t current_idx,
	uint8_t total_shares,
	const uint8_t set_id[SHARDKEY_SET_ID_LEN]);

#endif /* SHARDKEY_DRIVE_H */
