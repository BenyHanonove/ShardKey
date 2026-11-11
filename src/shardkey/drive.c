/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "drive.h"
#include "secmem.h"
#include "share_fmt.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static bool valid_sd_name(const char *name)
{
	if (name == NULL || name[0] != 's' || name[1] != 'd' || name[2] == '\0') {
		return false;
	}
	size_t len = strlen(name);
	if (len >= 32u) {
		return false;
	}
	for (size_t i = 2u; i < len; i++) {
		if (name[i] < 'a' || name[i] > 'z') {
			return false;
		}
	}
	return true;
}

static bool path_has_usb_component(const char *p)
{
	if (p == NULL) {
		return false;
	}
	return (strstr(p, "/usb") != NULL);
}

bool drive_is_usb_block(const char *sys_block_dir, const char *dev_name)
{
	if (sys_block_dir == NULL || !valid_sd_name(dev_name)) {
		return false;
	}

	char path[PATH_MAX];
	char resolved[PATH_MAX];
	char link_target[PATH_MAX];

	int n = snprintf(path, sizeof(path), "%s/%s", sys_block_dir, dev_name);
	if (n <= 0 || (size_t)n >= sizeof(path)) {
		return false;
	}

	if (realpath(path, resolved) != NULL && path_has_usb_component(resolved)) {
		return true;
	}

	ssize_t llen = readlink(path, link_target, sizeof(link_target) - 1u);
	if (llen > 0) {
		link_target[llen] = '\0';
		if (path_has_usb_component(link_target)) {
			return true;
		}
	}

	n = snprintf(path, sizeof(path), "%s/%s/device", sys_block_dir, dev_name);
	if (n <= 0 || (size_t)n >= sizeof(path)) {
		return false;
	}

	if (realpath(path, resolved) != NULL && path_has_usb_component(resolved)) {
		return true;
	}

	llen = readlink(path, link_target, sizeof(link_target) - 1u);
	if (llen > 0) {
		link_target[llen] = '\0';
		if (path_has_usb_component(link_target)) {
			return true;
		}
	}

	return false;
}

static void read_sysfs_trimmed(const char *path, char *out, size_t cap, const char *fallback)
{
	if (cap == 0u) {
		return;
	}

	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(out, cap, "%s", fallback);
		return;
	}

	ssize_t r = read(fd, out, cap - 1u);
	close(fd);
	if (r <= 0) {
		snprintf(out, cap, "%s", fallback);
		return;
	}
	out[r] = '\0';

	/* Strip leading and trailing whitespace / control characters */
	size_t start = 0u;
	size_t end = (size_t)r;
	while (start < end && ((unsigned char)out[start] <= 0x20u || (unsigned char)out[start] >= 0x7fu)) {
		start++;
	}
	while (end > start && ((unsigned char)out[end - 1u] <= 0x20u || (unsigned char)out[end - 1u] >= 0x7fu)) {
		end--;
	}

	if (end <= start) {
		snprintf(out, cap, "%s", fallback);
		return;
	}

	size_t trimmed_len = end - start;
	if (start > 0u) {
		memmove(out, out + start, trimmed_len);
	}
	out[trimmed_len] = '\0';
	for (size_t i = 0u; i < trimmed_len; i++) {
		if ((unsigned char)out[i] < 0x20u || (unsigned char)out[i] >= 0x7fu) {
			out[i] = ' ';
		}
	}
}

static int read_sysfs_u64(const char *path, uint64_t *out_val)
{
	char buf[64];
	read_sysfs_trimmed(path, buf, sizeof(buf), "");
	if (buf[0] == '\0') {
		return -1;
	}
	uint64_t val = 0u;
	for (size_t i = 0u; buf[i] != '\0'; i++) {
		if (buf[i] < '0' || buf[i] > '9') {
			return -1;
		}
		uint64_t digit = (uint64_t)(buf[i] - '0');
		if (val > (UINT64_MAX - digit) / 10u) {
			return -1;
		}
		val = val * 10u + digit;
	}
	*out_val = val;
	return 0;
}

int drive_read_info(const char *sys_block_dir,
                    const char *dev_dir,
                    const char *dev_name,
                    struct drive_info *out_info)
{
	if (sys_block_dir == NULL || dev_dir == NULL ||
	    dev_name == NULL || out_info == NULL) {
		return -1;
	}
	if (!drive_is_usb_block(sys_block_dir, dev_name)) {
		return -1;
	}

	memset(out_info, 0, sizeof(*out_info));
	snprintf(out_info->name, sizeof(out_info->name), "%s", dev_name);
	snprintf(out_info->dev_node, sizeof(out_info->dev_node), "%s/%s", dev_dir, dev_name);
	snprintf(out_info->part_node, sizeof(out_info->part_node), "%s/%s1", dev_dir, dev_name);

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s/device/vendor", sys_block_dir, dev_name);
	read_sysfs_trimmed(path, out_info->vendor, sizeof(out_info->vendor), "Unknown");

	snprintf(path, sizeof(path), "%s/%s/device/model", sys_block_dir, dev_name);
	read_sysfs_trimmed(path, out_info->model, sizeof(out_info->model), "USB Drive");

	snprintf(path, sizeof(path), "%s/%s/size", sys_block_dir, dev_name);
	uint64_t sectors = 0u;
	if (read_sysfs_u64(path, &sectors) != 0) {
		return -1;
	}
	out_info->size_bytes = sectors * 512u;

	return 0;
}

static int cmp_drive_info(const void *a, const void *b)
{
	const struct drive_info *da = (const struct drive_info *)a;
	const struct drive_info *db = (const struct drive_info *)b;
	return strcmp(da->name, db->name);
}

int drive_scan_usb(const char *sys_block_dir,
                   const char *dev_dir,
                   struct drive_info *out_list,
                   size_t max_devs,
                   size_t *out_count)
{
	if (sys_block_dir == NULL || dev_dir == NULL || out_count == NULL) {
		return -1;
	}
	if (max_devs > 0u && out_list == NULL) {
		return -1;
	}

	DIR *dir = opendir(sys_block_dir);
	if (dir == NULL) {
		return -1;
	}

	size_t count = 0u;
	struct dirent *de;
	while ((de = readdir(dir)) != NULL) {
		if (!valid_sd_name(de->d_name)) {
			continue;
		}
		if (!drive_is_usb_block(sys_block_dir, de->d_name)) {
			continue;
		}
		struct drive_info info;
		if (drive_read_info(sys_block_dir, dev_dir, de->d_name, &info) != 0) {
			continue;
		}
		if (out_list != NULL && count < max_devs) {
			out_list[count] = info;
		}
		count++;
	}
	closedir(dir);

	size_t stored = (count < max_devs) ? count : max_devs;
	if (out_list != NULL && stored > 1u) {
		qsort(out_list, stored, sizeof(struct drive_info), cmp_drive_info);
	}

	*out_count = count;
	return 0;
}

void drive_format_size(uint64_t size_bytes, char *out_str, size_t cap)
{
	if (out_str == NULL || cap == 0u) {
		return;
	}

	const uint64_t gib = 1024ULL * 1024ULL * 1024ULL;
	const uint64_t mib = 1024ULL * 1024ULL;
	const uint64_t kib = 1024ULL;

	if (size_bytes >= gib) {
		uint64_t whole = size_bytes / gib;
		uint64_t tenth = ((size_bytes % gib) * 10ULL) / gib;
		snprintf(out_str, cap, "%llu.%llu GiB",
		         (unsigned long long)whole, (unsigned long long)tenth);
	} else if (size_bytes >= mib) {
		uint64_t whole = size_bytes / mib;
		uint64_t tenth = ((size_bytes % mib) * 10ULL) / mib;
		snprintf(out_str, cap, "%llu.%llu MiB",
		         (unsigned long long)whole, (unsigned long long)tenth);
	} else if (size_bytes >= kib) {
		uint64_t whole = size_bytes / kib;
		snprintf(out_str, cap, "%llu KiB", (unsigned long long)whole);
	} else {
		snprintf(out_str, cap, "%llu B", (unsigned long long)size_bytes);
	}
}

static void sleep_ms(unsigned int ms)
{
	struct timespec ts;
	ts.tv_sec = (time_t)(ms / 1000u);
	ts.tv_nsec = (long)((ms % 1000u) * 1000000L);
	nanosleep(&ts, NULL);
}

int drive_wait_all_removed(const char *sys_block_dir,
                           const char *dev_dir,
                           unsigned int poll_ms)
{
	for (;;) {
		if (secmem_interrupted()) {
			return -1;
		}
		size_t count = 0u;
		if (drive_scan_usb(sys_block_dir, dev_dir, NULL, 0u, &count) != 0) {
			return -1;
		}
		if (count == 0u) {
			return 0;
		}
		sleep_ms(poll_ms);
	}
}

int drive_wait_inserted(const char *sys_block_dir,
                        const char *dev_dir,
                        unsigned int poll_ms,
                        struct drive_info *out_info)
{
	if (out_info == NULL) {
		return -1;
	}
	for (;;) {
		if (secmem_interrupted()) {
			return -1;
		}
		struct drive_info list[4];
		size_t count = 0u;
		if (drive_scan_usb(sys_block_dir, dev_dir, list, 4u, &count) != 0) {
			return -1;
		}
		if (count == 1u && list[0].size_bytes > 0u) {
			/* Brief settle delay for devtmpfs node readiness */
			if (poll_ms > 0u) {
				sleep_ms(poll_ms);
			}
			if (drive_read_info(sys_block_dir, dev_dir, list[0].name, out_info) == 0 &&
			    out_info->size_bytes > 0u) {
				return 0;
			}
		}
		sleep_ms(poll_ms);
	}
}

int drive_wait_removed_name(const char *sys_block_dir,
                            const char *dev_name,
                            unsigned int poll_ms)
{
	if (sys_block_dir == NULL || dev_name == NULL) {
		return -1;
	}
	for (;;) {
		if (secmem_interrupted()) {
			return -1;
		}
		if (!drive_is_usb_block(sys_block_dir, dev_name)) {
			return 0;
		}
		sleep_ms(poll_ms);
	}
}

static int exec_wait(const char *prog, char *const argv[])
{
	if (secmem_interrupted()) {
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		char *envp[] = {
			"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
			"LC_ALL=C",
			NULL
		};
		execve(prog, argv, envp);
		_exit(127);
	}

	int status = 0;
	for (;;) {
		pid_t w = waitpid(pid, &status, 0);
		if (w < 0) {
			if (errno == EINTR) {
				if (secmem_interrupted()) {
					return -1;
				}
				continue;
			}
			return -1;
		}
		break;
	}

	if (secmem_interrupted() || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		return -1;
	}
	return 0;
}

int drive_run_prep_script(const char *prep_script, const char *dev_node)
{
	if (prep_script == NULL || dev_node == NULL) {
		return -1;
	}
	char *argv[] = {
		(char *)prep_script,
		(char *)dev_node,
		NULL
	};
	return exec_wait(prep_script, argv);
}

int drive_mount_vfat(const char *part_node, const char *mount_dir, bool read_only)
{
	if (part_node == NULL || mount_dir == NULL || secmem_interrupted()) {
		return -1;
	}

	/* Wait briefly for devtmpfs partition node (/dev/sdX1) to settle after hotplug/fdisk */
	for (int attempt = 0; attempt < 10; attempt++) {
		if (secmem_interrupted()) {
			return -1;
		}
		if (access(part_node, F_OK) == 0) {
			break;
		}
		sleep_ms(50u);
	}

	unsigned long flags = MS_NOEXEC | MS_NOSUID | MS_NODEV;
	if (read_only) {
		flags |= MS_RDONLY;
	}
	if (mount(part_node, mount_dir, "vfat", flags, "fmask=0177,dmask=0077") == 0) {
		return 0;
	}

	/* Fallback to /bin/mount (BusyBox) */
	char *argv[] = {
		"/bin/mount",
		"-t",
		"vfat",
		"-o",
		read_only ? "ro,noexec,nosuid,nodev" : "rw,noexec,nosuid,nodev",
		(char *)part_node,
		(char *)mount_dir,
		NULL
	};
	return exec_wait("/bin/mount", argv);
}

int drive_umount_sync(const char *mount_dir)
{
	if (mount_dir == NULL) {
		return -1;
	}
	sync();
	if (umount2(mount_dir, 0) == 0) {
		sync();
		return 0;
	}

	char *argv[] = {
		"/bin/umount",
		(char *)mount_dir,
		NULL
	};
	int rc = exec_wait("/bin/umount", argv);
	if (rc != 0) {
		/* Detach stale mount point if the drive was pulled mid-operation */
		(void)umount2(mount_dir, MNT_DETACH);
	}
	sync();
	return rc;
}

static int write_full_sync(const char *filepath, const char *data, size_t len)
{
	if (secmem_interrupted()) {
		return -1;
	}
	int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		return -1;
	}

	size_t off = 0u;
	while (off < len) {
		if (secmem_interrupted()) {
			close(fd);
			return -1;
		}
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR) {
				continue;
			}
			close(fd);
			return -1;
		}
		off += (size_t)w;
	}

	if (fsync(fd) != 0) {
		close(fd);
		return -1;
	}
	if (close(fd) != 0) {
		return -1;
	}
	return 0;
}

int drive_write_files_in_dir(const char *mount_dir,
                             uint8_t index,
                             uint8_t shares,
                             const char *share_content,
                             size_t share_len,
                             const char *readme_content,
                             size_t readme_len)
{
	if (mount_dir == NULL || share_content == NULL || share_len == 0u ||
	    readme_content == NULL || readme_len == 0u || secmem_interrupted()) {
		return -1;
	}

	char share_name[64];
	if (share_fmt_filename(index, shares, share_name, sizeof(share_name)) != SHARE_FMT_OK) {
		return -1;
	}

	char share_path[PATH_MAX];
	char readme_path[PATH_MAX];

	int n1 = snprintf(share_path, sizeof(share_path), "%s/%s", mount_dir, share_name);
	int n2 = snprintf(readme_path, sizeof(readme_path), "%s/README.txt", mount_dir);
	if (n1 <= 0 || (size_t)n1 >= sizeof(share_path) ||
	    n2 <= 0 || (size_t)n2 >= sizeof(readme_path)) {
		return -1;
	}

	if (write_full_sync(share_path, share_content, share_len) != 0) {
		return -1;
	}
	if (write_full_sync(readme_path, readme_content, readme_len) != 0) {
		return -1;
	}

	int dir_fd = open(mount_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd >= 0) {
		(void)fsync(dir_fd);
		close(dir_fd);
	}
	sync();
	return 0;
}

int drive_verify_files_in_dir(const char *mount_dir,
                              uint8_t index,
                              uint8_t shares,
                              const char *expected_content,
                              size_t expected_len,
                              char *verify_buf,
                              size_t verify_cap)
{
	if (mount_dir == NULL || expected_content == NULL || expected_len == 0u ||
	    verify_buf == NULL || verify_cap <= expected_len || secmem_interrupted()) {
		return -1;
	}

	secmem_zero(verify_buf, verify_cap);

	char share_name[64];
	if (share_fmt_filename(index, shares, share_name, sizeof(share_name)) != SHARE_FMT_OK) {
		return -1;
	}

	char share_path[PATH_MAX];
	char readme_path[PATH_MAX];
	int n = snprintf(share_path, sizeof(share_path), "%s/%s", mount_dir, share_name);
	int nr = snprintf(readme_path, sizeof(readme_path), "%s/README.txt", mount_dir);
	if (n <= 0 || (size_t)n >= sizeof(share_path) ||
	    nr <= 0 || (size_t)nr >= sizeof(readme_path)) {
		return -1;
	}

	struct stat st;
	if (stat(readme_path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		return -1;
	}

	int fd = open(share_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	size_t off = 0u;
	while (off < verify_cap) {
		if (secmem_interrupted()) {
			close(fd);
			secmem_zero(verify_buf, verify_cap);
			return -1;
		}
		ssize_t r = read(fd, verify_buf + off, verify_cap - off);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			close(fd);
			secmem_zero(verify_buf, verify_cap);
			return -1;
		}
		if (r == 0) {
			break;
		}
		off += (size_t)r;
	}
	close(fd);

	if (off != expected_len) {
		secmem_zero(verify_buf, verify_cap);
		return -1;
	}

	/* Constant-time byte-for-byte check against RAM copy */
	int eq = secmem_ct_equal(verify_buf, expected_content, expected_len);

	/* Also parse and verify structure + SHA-256 check field */
	struct shardkey_share_record parsed;
	int prc = share_fmt_parse(verify_buf, off, &parsed);
	bool meta_ok = (prc == SHARE_FMT_OK &&
	                parsed.index == index &&
	                parsed.shares == shares);

	secmem_zero(&parsed, sizeof(parsed));
	secmem_zero(verify_buf, verify_cap);

	if (!eq || !meta_ok) {
		return -1;
	}
	return 0;
}

enum drive_existing_status drive_inspect_existing_dir(
	const char *mount_dir,
	uint8_t current_idx,
	uint8_t total_shares,
	const uint8_t set_id[SHARDKEY_SET_ID_LEN])
{
	if (mount_dir == NULL) {
		return DRIVE_EXISTING_NONE;
	}

	/* 1. Check for ShardKey boot stick files (docs/PLAN.md §4 Phase 7) */
	static const char *const boot_markers[] = {
		"shardkey/bzImage",
		"syslinux.cfg",
		"syslinux/syslinux.cfg",
		"SHA256SUMS.sig",
		"EFI/BOOT/BOOTX64.EFI"
	};

	for (size_t i = 0u; i < sizeof(boot_markers) / sizeof(boot_markers[0]); i++) {
		char mpath[PATH_MAX];
		int n = snprintf(mpath, sizeof(mpath), "%s/%s", mount_dir, boot_markers[i]);
		if (n > 0 && (size_t)n < sizeof(mpath) && access(mpath, F_OK) == 0) {
			return DRIVE_EXISTING_BOOT_STICK;
		}
	}

	/* 2. Check for an already-written earlier share 1..(current_idx-1) from this ceremony */
	if (current_idx <= 1u || set_id == NULL) {
		return DRIVE_EXISTING_NONE;
	}

	struct shardkey_secpool *pool = secmem_pool();
	char *buf = pool->verify_file_buf;
	size_t cap = sizeof(pool->verify_file_buf);
	bool found_earlier = false;

	for (uint8_t j = 1u; j < current_idx; j++) {
		char fname[64];
		char fpath[PATH_MAX];
		if (share_fmt_filename(j, total_shares, fname, sizeof(fname)) != SHARE_FMT_OK) {
			continue;
		}
		int n = snprintf(fpath, sizeof(fpath), "%s/%s", mount_dir, fname);
		if (n <= 0 || (size_t)n >= sizeof(fpath)) {
			continue;
		}
		int fd = open(fpath, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			continue;
		}
		size_t off = 0u;
		while (off < cap - 1u) {
			ssize_t r = read(fd, buf + off, (cap - 1u) - off);
			if (r < 0) {
				if (errno == EINTR && !secmem_interrupted()) {
					continue;
				}
				break;
			}
			if (r == 0) {
				break;
			}
			off += (size_t)r;
		}
		close(fd);
		if (off > 0u) {
			struct shardkey_share_record rec;
			if (share_fmt_parse(buf, off, &rec) == SHARE_FMT_OK) {
				if (secmem_ct_equal(rec.set_id, set_id, SHARDKEY_SET_ID_LEN)) {
					found_earlier = true;
				}
			}
			secmem_zero(&rec, sizeof(rec));
		}
		secmem_zero(buf, cap);
		if (found_earlier) {
			return DRIVE_EXISTING_EARLIER_SHARE;
		}
	}

	return DRIVE_EXISTING_NONE;
}
