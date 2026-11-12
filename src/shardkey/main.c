/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "drive.h"
#include "entropy.h"
#include "policy.h"
#include "secmem.h"
#include "sha256.h"
#include "shamir.h"
#include "share_fmt.h"
#include "ui.h"

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define POLL_INTERVAL_MS 200u

static void notify_event(const struct shardkey_ceremony_cfg *cfg,
                         const char *event,
                         uint8_t share_idx)
{
	if (cfg != NULL && cfg->on_drive_event != NULL) {
		cfg->on_drive_event(event, share_idx, cfg->user_data);
	}
}

/*
 * Check if an inserted drive is the ShardKey boot stick or already holds
 * a completed earlier share (1 .. current_idx - 1) from the current ceremony.
 */
static enum drive_existing_status inspect_inserted_drive(
	const struct shardkey_ceremony_cfg *cfg,
	const struct drive_info *drv,
	uint8_t current_idx,
	uint8_t total_shares,
	const uint8_t set_id[SHARDKEY_SET_ID_LEN])
{
	if (!cfg->skip_mount_syscalls) {
		if (access(drv->part_node, R_OK) != 0) {
			return DRIVE_EXISTING_NONE;
		}
		if (drive_mount_vfat(drv->part_node, cfg->mount_dir, true) != 0) {
			return DRIVE_EXISTING_NONE;
		}
	}

	enum drive_existing_status st = drive_inspect_existing_dir(
		cfg->mount_dir, current_idx, total_shares, set_id);

	if (!cfg->skip_mount_syscalls) {
		(void)drive_umount_sync(cfg->mount_dir);
	}
	return st;
}

static int write_and_verify_one_share(struct shardkey_secpool *pool,
                                      uint8_t idx,
                                      uint8_t k,
                                      uint8_t n,
                                      const struct shardkey_ceremony_cfg *cfg)
{
	struct shardkey_share_record rec;
	memset(&rec, 0, sizeof(rec));
	rec.threshold = k;
	rec.shares = n;
	rec.index = idx;
	memcpy(rec.set_id, pool->set_id, SHARDKEY_SET_ID_LEN);
	memcpy(rec.fingerprint, pool->fingerprint, SHARDKEY_FINGERPRINT_LEN);
	memcpy(rec.data, pool->shares[idx - 1u], SHARDKEY_SECRET_LEN);

	size_t share_len = 0u;
	if (share_fmt_encode(&rec, pool->share_file_buf,
	                     sizeof(pool->share_file_buf), &share_len) != SHARE_FMT_OK) {
		secmem_zero(&rec, sizeof(rec));
		return -1;
	}
	secmem_zero(&rec, sizeof(rec));

	char readme_buf[1024];
	size_t readme_len = 0u;
	if (share_fmt_readme(idx, k, n, pool->set_id, pool->fingerprint,
	                     readme_buf, sizeof(readme_buf), &readme_len) != SHARE_FMT_OK) {
		secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
		return -1;
	}

	for (;;) {
		if (secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}

		/* Ensure no USB drives are plugged in before asking for share drive */
		size_t present = 0u;
		if (drive_scan_usb(cfg->sys_block_dir, cfg->dev_dir, NULL, 0u, &present) == 0 &&
		    present > 0u) {
			fprintf(cfg->out, "Waiting for all USB drives to be unplugged...\n");
			fflush(cfg->out);
			notify_event(cfg, "wait_all_removed", idx);
			if (drive_wait_all_removed(cfg->sys_block_dir, cfg->dev_dir,
			                           cfg->poll_ms) != 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
		}

		fprintf(cfg->out, "Insert blank drive for share %u/%u...\n",
		        (unsigned int)idx, (unsigned int)n);
		fflush(cfg->out);

		notify_event(cfg, "wait_inserted_write", idx);
		struct drive_info drv;
		if (drive_wait_inserted(cfg->sys_block_dir, cfg->dev_dir,
		                        cfg->poll_ms, &drv) != 0 ||
		    secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}

		/* Refuse if this drive is the boot stick or already holds an earlier share */
		enum drive_existing_status ex = inspect_inserted_drive(
			cfg, &drv, idx, n, pool->set_id);
		if (secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}
		if (ex == DRIVE_EXISTING_BOOT_STICK) {
			if (ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
			        "this drive appears to be the ShardKey boot stick") < 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}
		if (ex == DRIVE_EXISTING_EARLIER_SHARE) {
			if (ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
			        "this drive already contains an earlier share from this ceremony") < 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}

		int confirm = ui_confirm_erase_drive(cfg->in, cfg->out, idx, n, &drv);
		if (confirm < 0 || secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}
		if (confirm == 0) {
			fprintf(cfg->out,
			        "Drive not confirmed. Please unplug it to select another drive.\n");
			fflush(cfg->out);
			notify_event(cfg, "wait_removed_declined", idx);
			if (drive_wait_removed_name(cfg->sys_block_dir, drv.name,
			                            cfg->poll_ms) != 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}

		fprintf(cfg->out, "Formatting and partitioning %s...\n", drv.dev_node);
		fflush(cfg->out);
		if (drive_run_prep_script(cfg->prep_script, drv.dev_node) != 0) {
			if (secmem_interrupted() ||
			    ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
			        "failed to partition and format USB drive") < 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}

		if (!cfg->skip_mount_syscalls) {
			if (drive_mount_vfat(drv.part_node, cfg->mount_dir, false) != 0) {
				if (secmem_interrupted() ||
				    ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
				        "failed to mount FAT32 partition for writing") < 0) {
					secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
					return -1;
				}
				continue;
			}
		}

		int wrc = drive_write_files_in_dir(cfg->mount_dir, idx, n,
		                                   pool->share_file_buf, share_len,
		                                   readme_buf, readme_len);
		int urc = cfg->skip_mount_syscalls ? 0 : drive_umount_sync(cfg->mount_dir);
		if (secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}
		if (wrc != 0 || urc != 0) {
			if (ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
			        "failed to write and sync share file to USB drive") < 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}

		/* D-012: Unplug and re-insert to force read-back from physical flash */
		fprintf(cfg->out, "Unplug the drive, then plug it back in to verify...\n");
		fflush(cfg->out);
		notify_event(cfg, "wait_removed_reinsert", idx);
		if (drive_wait_removed_name(cfg->sys_block_dir, drv.name, cfg->poll_ms) != 0) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}

		notify_event(cfg, "wait_inserted_verify", idx);
		struct drive_info reinserted;
		if (drive_wait_inserted(cfg->sys_block_dir, cfg->dev_dir,
		                        cfg->poll_ms, &reinserted) != 0 ||
		    secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}

		if (!cfg->skip_mount_syscalls) {
			if (drive_mount_vfat(reinserted.part_node, cfg->mount_dir, true) != 0) {
				if (secmem_interrupted() ||
				    ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
				        "failed to mount drive read-only for verification") < 0) {
					secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
					return -1;
				}
				continue;
			}
		}

		int vrc = drive_verify_files_in_dir(cfg->mount_dir, idx, n,
		                                    pool->share_file_buf, share_len,
		                                    pool->verify_file_buf,
		                                    sizeof(pool->verify_file_buf));
		int vurc = cfg->skip_mount_syscalls ? 0 : drive_umount_sync(cfg->mount_dir);
		if (secmem_interrupted()) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}
		if (vrc != 0 || vurc != 0) {
			if (ui_prompt_retry_share(cfg->in, cfg->out, idx, n,
			        "read-back verification failed (contents did not match RAM copy)") < 0) {
				secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
				return -1;
			}
			continue;
		}

		char short_id[5];
		ui_short_set_id(pool->set_id, short_id);
		fprintf(cfg->out,
		        "Share %u/%u OK. Unplug and label it 'Share %u of %u, set %s'.\n",
		        (unsigned int)idx, (unsigned int)n,
		        (unsigned int)idx, (unsigned int)n,
		        short_id);
		fflush(cfg->out);

		notify_event(cfg, "wait_removed_done", idx);
		if (drive_wait_removed_name(cfg->sys_block_dir, reinserted.name,
		                            cfg->poll_ms) != 0) {
			secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
			return -1;
		}

		break;
	}

	secmem_zero(pool->share_file_buf, sizeof(pool->share_file_buf));
	secmem_zero(pool->verify_file_buf, sizeof(pool->verify_file_buf));
	return 0;
}

int shardkey_ceremony_run(const struct shardkey_ceremony_cfg *user_cfg)
{
	struct shardkey_ceremony_cfg cfg;
	if (user_cfg != NULL) {
		cfg = *user_cfg;
	} else {
		memset(&cfg, 0, sizeof(cfg));
		cfg.poll_ms = POLL_INTERVAL_MS;
		cfg.require_mlock = true;
	}
	if (cfg.in == NULL) {
		cfg.in = stdin;
	}
	if (cfg.out == NULL) {
		cfg.out = stdout;
	}
	if (cfg.err == NULL) {
		cfg.err = stderr;
	}
	if (cfg.sys_block_dir == NULL) {
		cfg.sys_block_dir = DRIVE_DEFAULT_SYS_BLOCK;
	}
	if (cfg.dev_dir == NULL) {
		cfg.dev_dir = DRIVE_DEFAULT_DEV_DIR;
	}
	if (cfg.mount_dir == NULL) {
		cfg.mount_dir = DRIVE_DEFAULT_MOUNT_DIR;
	}
	if (cfg.prep_script == NULL) {
		cfg.prep_script = DRIVE_PREP_SCRIPT_PATH;
	}

	if (secmem_lockdown(cfg.require_mlock) != 0) {
		fprintf(cfg.err,
		        "[shardkey] FATAL: failed to lock process memory (mlockall/prctl/rlimit).\n");
		secmem_wipe_all();
		return 1;
	}

	struct shardkey_secpool *pool = secmem_pool();

	ui_print_banner(cfg.out);

	/* 1. Require boot stick and all other USB drives to be removed */
	if (ui_prompt_remove_usb(cfg.in, cfg.out) != 0 || secmem_interrupted()) {
		secmem_wipe_all();
		return 1;
	}
	size_t usb_count = 0u;
	if (drive_scan_usb(cfg.sys_block_dir, cfg.dev_dir, NULL, 0u, &usb_count) != 0) {
		fprintf(cfg.err, "[shardkey] FATAL: cannot inspect %s.\n", cfg.sys_block_dir);
		secmem_wipe_all();
		return 1;
	}
	if (usb_count > 0u) {
		fprintf(cfg.out, "Waiting until all USB drives are removed...\n");
		fflush(cfg.out);
		notify_event(&cfg, "wait_boot_removed", 0u);
		if (drive_wait_all_removed(cfg.sys_block_dir, cfg.dev_dir, cfg.poll_ms) != 0) {
			secmem_wipe_all();
			return 1;
		}
	}

	/* 2. Choose n (2..16) and k (majority..n) */
	uint8_t n = 0u;
	uint8_t k = 0u;
	if (ui_prompt_policy(cfg.in, cfg.out, &n, &k) != 0 || secmem_interrupted()) {
		secmem_wipe_all();
		return 1;
	}

	/* 3. Collect >= 100 operator dice rolls */
	if (ui_collect_dice(cfg.in, cfg.out, pool->dice_rolls,
	                    SHARDKEY_MAX_DICE_ROLLS, &pool->dice_len) != 0 ||
	    secmem_interrupted()) {
		secmem_wipe_all();
		return 1;
	}

	/* 4. Gather 64 bytes from kernel getrandom(..., 0) and mix with dice rolls */
	if (entropy_get_kernel_random(pool->kernel_rnd, SHARDKEY_KERNEL_RND_LEN) != 0 ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: getrandom() failed.\n");
		secmem_wipe_all();
		return 1;
	}
	if (entropy_mix_seed(pool->kernel_rnd, pool->dice_rolls,
	                     pool->dice_len, pool->seed) != 0 ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: entropy mixing failed.\n");
		secmem_wipe_all();
		return 1;
	}
	/* Wipe raw entropy inputs immediately after mixing */
	secmem_zero(pool->dice_rolls, sizeof(pool->dice_rolls));
	pool->dice_len = 0u;
	secmem_zero(pool->kernel_rnd, sizeof(pool->kernel_rnd));

	/* 5. Expand secret, polynomial coefficients, and set ID from mixed seed */
	if (entropy_derive_ceremony(pool->seed, k, pool->secret,
	                            pool->coeffs, pool->set_id) != 0 ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: key derivation failed.\n");
		secmem_wipe_all();
		return 1;
	}
	secmem_zero(pool->seed, sizeof(pool->seed));

	if (share_fmt_fingerprint(pool->secret, pool->fingerprint) != SHARE_FMT_OK ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: fingerprint computation failed.\n");
		secmem_wipe_all();
		return 1;
	}

	/* 6. Split secret into n shares and wipe polynomial coefficients */
	if (shamir_split(pool->secret, pool->coeffs, k, n, pool->shares) != 0 ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: Shamir split failed.\n");
		secmem_wipe_all();
		return 1;
	}
	secmem_zero(pool->coeffs, sizeof(pool->coeffs));

	/* 7. Verify in RAM that EVERY k-subset reconstructs the exact secret */
	if (shamir_verify_all_subsets(pool->secret,
	                              (const uint8_t (*)[SHARDKEY_SECRET_LEN])pool->shares,
	                              k, n) != 0 ||
	    secmem_interrupted()) {
		fprintf(cfg.err, "[shardkey] FATAL: Shamir k-subset self-test failed.\n");
		secmem_wipe_all();
		return 1;
	}
	/* Master secret is no longer needed in RAM once all shares and self-tests pass */
	secmem_zero(pool->secret, sizeof(pool->secret));

	ui_print_ceremony_info(cfg.out, k, n, pool->set_id, pool->fingerprint);

	/* 8. Write, unplug/re-insert, and verify each share 1..n */
	for (uint8_t idx = 1u; idx <= n; idx++) {
		if (write_and_verify_one_share(pool, idx, k, n, &cfg) != 0) {
			fprintf(cfg.err,
			        "[shardkey] Ceremony aborted while processing share %u/%u.\n",
			        (unsigned int)idx, (unsigned int)n);
			secmem_wipe_all();
			return 1;
		}
		/* Wipe share idx from RAM as soon as it is verified on its USB drive */
		secmem_zero(pool->shares[idx - 1u], SHARDKEY_SECRET_LEN);
	}

	fprintf(cfg.out, "\nAll %u shares written and verified. Wiping memory...\n",
	        (unsigned int)n);
	fflush(cfg.out);

	secmem_wipe_all();
	return 0;
}

#ifndef SHARDKEY_TEST_BUILD
static void attach_console_ctty(void)
{
	if (tcgetpgrp(STDIN_FILENO) >= 0) {
		return;
	}
	FILE *f = fopen("/sys/class/tty/console/active", "re");
	if (f == NULL) {
		return;
	}
	char buf[256];
	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		return;
	}
	fclose(f);

	/* /sys/class/tty/console/active lists space-separated names; last is primary */
	char *tok = NULL;
	char *p = buf;
	while (*p != '\0') {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
			p++;
		}
		if (*p == '\0') {
			break;
		}
		tok = p;
		while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
			p++;
		}
		if (*p != '\0') {
			*p++ = '\0';
		}
	}
	if (tok == NULL || strcmp(tok, "console") == 0) {
		return;
	}
	if (strcmp(tok, "tty0") == 0) {
		tok = "tty1";
	}

	char dev_path[64];
	if (snprintf(dev_path, sizeof(dev_path), "/dev/%s", tok) >= (int)sizeof(dev_path)) {
		return;
	}

	int fd = open(dev_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		return;
	}
	if (getsid(0) != getpid()) {
		(void)setsid();
	}
	if (ioctl(fd, TIOCSCTTY, 0) == 0) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
	}
	if (fd > STDERR_FILENO) {
		close(fd);
	}
}

int main(void)
{
	attach_console_ctty();
	return shardkey_ceremony_run(NULL);
}
#endif /* !SHARDKEY_TEST_BUILD */
