/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "ui.h"
#include "entropy.h"
#include "policy.h"
#include "share_fmt.h"

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int read_line_safe(FILE *in, char *buf, size_t cap)
{
	if (in == NULL || buf == NULL || cap < 2u) {
		return -1;
	}
	if (secmem_interrupted()) {
		return -1;
	}
	if (fgets(buf, (int)cap, in) == NULL) {
		return -1;
	}
	if (secmem_interrupted()) {
		secmem_zero(buf, cap);
		return -1;
	}
	/* If the line was longer than cap - 1 and had no newline, drain remainder */
	size_t len = strlen(buf);
	if (len > 0u && buf[len - 1u] != '\n') {
		int ch;
		while ((ch = fgetc(in)) != EOF && ch != '\n') {
			if (secmem_interrupted()) {
				secmem_zero(buf, cap);
				return -1;
			}
		}
	}
	return 0;
}

void ui_print_banner(FILE *out)
{
	if (out == NULL) {
		return;
	}
	fprintf(out,
		"\n"
		"============================================================\n"
		"  ShardKey — Air-Gapped Shamir Secret Sharing Ceremony (v1)\n"
		"============================================================\n\n");
	fflush(out);
}

int ui_prompt_remove_usb(FILE *in, FILE *out)
{
	char line[64];
	fprintf(out, "Remove the boot stick and all other USB drives. Press Enter.");
	fflush(out);
	if (read_line_safe(in, line, sizeof(line)) != 0) {
		secmem_zero(line, sizeof(line));
		return -1;
	}
	secmem_zero(line, sizeof(line));
	return 0;
}

int ui_prompt_policy(FILE *in, FILE *out, uint8_t *out_n, uint8_t *out_k)
{
	if (in == NULL || out == NULL || out_n == NULL || out_k == NULL) {
		return -1;
	}

	char line[128];

	for (;;) {
		uint8_t n = 0u;
		uint8_t k = 0u;

		/* Step 1: Read n (2..16) */
		for (;;) {
			fprintf(out, "How many shares (n)? [2-16]: ");
			fflush(out);
			if (read_line_safe(in, line, sizeof(line)) != 0) {
				secmem_zero(line, sizeof(line));
				return -1;
			}
			enum policy_result r = policy_parse_n(line, &n);
			if (r == POLICY_OK) {
				break;
			}
			fprintf(out, "Invalid share count. Please enter a number from 2 to 16.\n");
		}

		/* Step 2: Read k (M for majority, or majority..n) */
		uint8_t maj = policy_majority(n);
		enum policy_result kr = POLICY_ERR_PARSE;
		for (;;) {
			fprintf(out,
			        "Threshold (k): press M for majority (%u), or type a number from %u to %u: ",
			        (unsigned int)maj, (unsigned int)maj, (unsigned int)n);
			fflush(out);
			if (read_line_safe(in, line, sizeof(line)) != 0) {
				secmem_zero(line, sizeof(line));
				return -1;
			}
			kr = policy_parse_k(line, n, &k);
			if (kr == POLICY_OK || kr == POLICY_OK_NEEDS_WARNING) {
				break;
			}
			if (kr == POLICY_ERR_K_BELOW_MAJ) {
				fprintf(out,
				        "Refused: threshold k cannot be below a majority (%u of %u).\n",
				        (unsigned int)maj, (unsigned int)n);
			} else if (kr == POLICY_ERR_K_ABOVE_N) {
				fprintf(out,
				        "Refused: threshold k cannot exceed total shares (%u).\n",
				        (unsigned int)n);
			} else {
				fprintf(out,
				        "Invalid threshold. Press M for majority (%u) or type %u..%u.\n",
				        (unsigned int)maj, (unsigned int)maj, (unsigned int)n);
			}
		}

		/* Step 3: Warning if k == n */
		if (kr == POLICY_OK_NEEDS_WARNING) {
			fprintf(out,
			        "WARNING: k = n (%u of %u) means losing ANY one drive loses the secret forever.\n"
			        "Type YES to accept k = n: ",
			        (unsigned int)k, (unsigned int)n);
			fflush(out);
			if (read_line_safe(in, line, sizeof(line)) != 0) {
				secmem_zero(line, sizeof(line));
				return -1;
			}
			if (!policy_is_yes(line)) {
				fprintf(out, "k = n not accepted. Restarting policy selection.\n\n");
				continue;
			}
		}

		/* Step 4: Final confirmation */
		fprintf(out, "Create %u-of-%u shares? Type YES: ",
		        (unsigned int)k, (unsigned int)n);
		fflush(out);
		if (read_line_safe(in, line, sizeof(line)) != 0) {
			secmem_zero(line, sizeof(line));
			return -1;
		}
		if (policy_is_yes(line)) {
			secmem_zero(line, sizeof(line));
			*out_n = n;
			*out_k = k;
			return 0;
		}

		fprintf(out, "Policy not confirmed. Restarting policy selection.\n\n");
	}
}

int ui_collect_dice(FILE *in,
                    FILE *out,
                    uint8_t *dice_buf,
                    size_t max_rolls,
                    size_t *out_len)
{
	if (in == NULL || out == NULL || dice_buf == NULL || out_len == NULL) {
		return -1;
	}

	struct dice_collector dc;
	if (entropy_dice_init(&dc, dice_buf, max_rolls) != 0) {
		return -1;
	}

	int fd = fileno(in);
	struct termios orig_term;
	bool have_tty = false;

	if (fd >= 0 && isatty(fd)) {
		if (tcgetattr(fd, &orig_term) == 0) {
			struct termios raw = orig_term;
			raw.c_iflag |= (tcflag_t)ICRNL;
			raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			secmem_register_tty(fd, &orig_term);
			if (tcsetattr(fd, TCSANOW, &raw) == 0) {
				have_tty = true;
			} else {
				secmem_unregister_tty();
			}
		}
	}

	fprintf(out,
	        "Roll a die and type the results (digits 1-6). At least %u rolls.\n"
	        "Rolls: 0/%u",
	        SHARDKEY_MIN_DICE_ROLLS, SHARDKEY_MIN_DICE_ROLLS);
	fflush(out);

	int rc = -1;
	for (;;) {
		if (secmem_interrupted()) {
			break;
		}
		int ch = fgetc(in);
		if (secmem_interrupted() || ch == EOF) {
			break;
		}

		enum dice_feed_result res = entropy_dice_feed_char(&dc, (char)ch);
		if (res == DICE_ACCEPTED) {
			if (dc.count >= SHARDKEY_MIN_DICE_ROLLS) {
				fprintf(out, "\rRolls: %zu/%u (press Enter to finish)   ",
				        dc.count, SHARDKEY_MIN_DICE_ROLLS);
			} else {
				fprintf(out, "\rRolls: %zu/%u                           ",
				        dc.count, SHARDKEY_MIN_DICE_ROLLS);
			}
			fflush(out);
		} else if (res == DICE_FULL) {
			fprintf(out, "\rRolls: %zu/%u (max reached; press Enter)",
			        dc.count, SHARDKEY_MIN_DICE_ROLLS);
			fflush(out);
		} else if (res == DICE_NEED_MORE) {
			if (!have_tty && ch == '\r') {
				int next = fgetc(in);
				if (next != '\n' && next != EOF) {
					(void)ungetc(next, in);
				}
			}
			fprintf(out, "\rRolls: %zu/%u (need at least %u rolls)  ",
			        dc.count, SHARDKEY_MIN_DICE_ROLLS, SHARDKEY_MIN_DICE_ROLLS);
			fflush(out);
		} else if (res == DICE_DONE) {
			if (!have_tty && ch == '\r') {
				int next = fgetc(in);
				if (next != '\n' && next != EOF) {
					(void)ungetc(next, in);
				}
			}
			fprintf(out, "\rRolls: %zu/%u (complete)                \n",
			        dc.count, SHARDKEY_MIN_DICE_ROLLS);
			fflush(out);
			*out_len = dc.count;
			rc = 0;
			break;
		}
	}

	if (have_tty) {
		(void)tcsetattr(fd, TCSANOW, &orig_term);
		secmem_unregister_tty();
	}

	if (rc != 0) {
		secmem_zero(dice_buf, max_rolls);
		*out_len = 0u;
	}
	return rc;
}

void ui_short_set_id(const uint8_t set_id[SHARDKEY_SET_ID_LEN], char out_short[5])
{
	static const char uhex[16] = "0123456789ABCDEF";
	out_short[0] = uhex[(set_id[0] >> 4u) & 0x0fu];
	out_short[1] = uhex[set_id[0] & 0x0fu];
	out_short[2] = uhex[(set_id[1] >> 4u) & 0x0fu];
	out_short[3] = uhex[set_id[1] & 0x0fu];
	out_short[4] = '\0';
}

void ui_print_ceremony_info(FILE *out,
                            uint8_t k,
                            uint8_t n,
                            const uint8_t set_id[SHARDKEY_SET_ID_LEN],
                            const uint8_t fingerprint[SHARDKEY_FINGERPRINT_LEN])
{
	if (out == NULL || set_id == NULL || fingerprint == NULL) {
		return;
	}

	char set_id_hex[SHARDKEY_SET_ID_LEN * 2u + 1u];
	char fp_hex[SHARDKEY_FINGERPRINT_LEN * 2u + 1u];

	share_fmt_hex_encode(set_id, SHARDKEY_SET_ID_LEN, set_id_hex);
	share_fmt_hex_encode(fingerprint, SHARDKEY_FINGERPRINT_LEN, fp_hex);

	fprintf(out,
	        "\nCeremony parameters ready:\n"
	        "  %u-of-%u, set ID %s, secret fingerprint %s\n\n",
	        (unsigned int)k, (unsigned int)n, set_id_hex, fp_hex);
	fflush(out);
}

int ui_confirm_erase_drive(FILE *in,
                           FILE *out,
                           uint8_t share_idx,
                           uint8_t total_shares,
                           const struct drive_info *drv)
{
	if (in == NULL || out == NULL || drv == NULL) {
		return -1;
	}

	char size_str[32];
	char line[64];
	drive_format_size(drv->size_bytes, size_str, sizeof(size_str));

	fprintf(out,
	        "Detected USB drive for share %u/%u:\n"
	        "  Device: %s (%s)\n"
	        "  Vendor: %s\n"
	        "  Model:  %s\n"
	        "Type YES to erase it: ",
	        (unsigned int)share_idx,
	        (unsigned int)total_shares,
	        drv->dev_node,
	        size_str,
	        drv->vendor,
	        drv->model);
	fflush(out);

	if (read_line_safe(in, line, sizeof(line)) != 0) {
		secmem_zero(line, sizeof(line));
		return -1;
	}
	bool ok = policy_is_yes(line);
	secmem_zero(line, sizeof(line));
	return ok ? 1 : 0;
}

int ui_prompt_retry_share(FILE *in,
                          FILE *out,
                          uint8_t share_idx,
                          uint8_t total_shares,
                          const char *reason)
{
	if (in == NULL || out == NULL) {
		return -1;
	}
	char line[64];
	fprintf(out,
	        "\nERROR on share %u/%u: %s\n"
	        "Unplug any drive if present, then press Enter to retry share %u/%u (or type ABORT to cancel): ",
	        (unsigned int)share_idx,
	        (unsigned int)total_shares,
	        reason != NULL ? reason : "operation failed",
	        (unsigned int)share_idx,
	        (unsigned int)total_shares);
	fflush(out);

	if (read_line_safe(in, line, sizeof(line)) != 0) {
		secmem_zero(line, sizeof(line));
		return -1;
	}
	if (policy_is_abort(line)) {
		secmem_zero(line, sizeof(line));
		return -1;
	}
	secmem_zero(line, sizeof(line));
	return 1;
}
