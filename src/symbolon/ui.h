/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SYMBOLON_UI_H
#define SYMBOLON_UI_H

#include "drive.h"
#include "secmem.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Print ceremony startup banner */
void ui_print_banner(FILE *out);

/* Prompt operator to remove boot stick and all USB drives, then wait for Enter */
int ui_prompt_remove_usb(FILE *in, FILE *out);

/*
 * Interactive prompt for n (2..16), k (M for majority or majority..n),
 * unanimous-threshold warning when k == n, and final YES confirmation.
 * Returns 0 on success, -1 on EOF or interrupt.
 */
int ui_prompt_policy(FILE *in, FILE *out, uint8_t *out_n, uint8_t *out_k);

/*
 * Interactive dice roll collection:
 *   - disables terminal echo and canonical mode if 'in' is a tty
 *   - collects digits '1'..'6' into dice_buf (capacity max_rolls)
 *   - shows only a counter on 'out', never echoing the digits
 *   - finishes when Enter is pressed after >= 100 rolls
 * Returns 0 on success, -1 on EOF or interrupt.
 */
int ui_collect_dice(FILE *in,
                    FILE *out,
                    uint8_t *dice_buf,
                    size_t max_rolls,
                    size_t *out_len);

/*
 * Print non-secret ceremony identifiers:
 *   "<k>-of-<n>, set ID <16-hex>, secret fingerprint <16-hex>"
 * Never prints the secret or any share bytes.
 */
void ui_print_ceremony_info(FILE *out,
                            uint8_t k,
                            uint8_t n,
                            const uint8_t set_id[SYMBOLON_SET_ID_LEN],
                            const uint8_t fingerprint[SYMBOLON_FINGERPRINT_LEN]);

/*
 * Show detected USB drive details (device, size, vendor, model) for share i/n
 * and require typing YES to erase it.
 * Returns 1 if confirmed ("YES"), 0 if declined, -1 on EOF/interrupt.
 */
int ui_confirm_erase_drive(FILE *in,
                           FILE *out,
                           uint8_t share_idx,
                           uint8_t total_shares,
                           const struct drive_info *drv);

/*
 * Format the 4-character uppercase hex short set ID (first 2 bytes of set_id)
 * used on physical drive labels (e.g. "7F3A").
 */
void ui_short_set_id(const uint8_t set_id[SYMBOLON_SET_ID_LEN], char out_short[5]);

/*
 * Offer to retry the current share after a drive error, or abort the ceremony.
 * Returns 1 to retry, -1 on ABORT/EOF/interrupt.
 */
int ui_prompt_retry_share(FILE *in,
                          FILE *out,
                          uint8_t share_idx,
                          uint8_t total_shares,
                          const char *reason);

/*
 * Ceremony runtime configuration (NULL uses production defaults:
 * stdin/stdout/stderr, /sys/block, /dev, /mnt, /lib/symbolon/prep-drive.sh).
 */
struct symbolon_ceremony_cfg {
	FILE        *in;
	FILE        *out;
	FILE        *err;
	const char  *sys_block_dir;
	const char  *dev_dir;
	const char  *mount_dir;
	const char  *prep_script;
	unsigned int poll_ms;
	bool         require_mlock;
	bool         skip_mount_syscalls;
	void       (*on_drive_event)(const char *event, uint8_t share_idx, void *user_data);
	void        *user_data;
};

/* Run the full Symbolon ceremony state machine (returns 0 on success, 1 on failure) */
int symbolon_ceremony_run(const struct symbolon_ceremony_cfg *cfg);

#endif /* SYMBOLON_UI_H */
