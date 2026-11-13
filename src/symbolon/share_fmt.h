/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SYMBOLON_SHARE_FMT_H
#define SYMBOLON_SHARE_FMT_H

#include "secmem.h"
#include <stddef.h>
#include <stdint.h>

struct symbolon_share_record {
	uint8_t threshold;
	uint8_t shares;
	uint8_t index;
	uint8_t set_id[SYMBOLON_SET_ID_LEN];
	uint8_t fingerprint[SYMBOLON_FINGERPRINT_LEN];
	uint8_t data[SYMBOLON_SECRET_LEN];
	uint8_t check[SYMBOLON_CHECK_LEN];
};

enum share_fmt_status {
	SHARE_FMT_OK                = 0,
	SHARE_FMT_ERR_ARG           = -1,
	SHARE_FMT_ERR_SYNTAX        = -2,
	SHARE_FMT_ERR_MAGIC         = -3,
	SHARE_FMT_ERR_SCHEME        = -4,
	SHARE_FMT_ERR_POLICY        = -5,
	SHARE_FMT_ERR_INDEX         = -6,
	SHARE_FMT_ERR_HEX           = -7,
	SHARE_FMT_ERR_CHECKSUM      = -8,
	SHARE_FMT_ERR_SET_MISMATCH  = -9,
	SHARE_FMT_ERR_DUPLICATE_IDX = -10,
	SHARE_FMT_ERR_TOO_FEW       = -11
};

/*
 * Compute the 8-byte secret fingerprint:
 *   first 8 bytes of SHA-256("SYMBOLON-FP-V1" || secret[32])
 */
int share_fmt_fingerprint(const uint8_t secret[SYMBOLON_SECRET_LEN],
                          uint8_t out_fp[SYMBOLON_FINGERPRINT_LEN]);

/* Format a byte array as lowercase hex (out_hex must hold 2 * len + 1 bytes) */
void share_fmt_hex_encode(const uint8_t *bytes, size_t len, char *out_hex);

/*
 * Encode a v1 share file into out_buf (NUL-terminated).
 * Also populates rec->check with the computed 8-byte checksum.
 * Returns SHARE_FMT_OK (0) on success, negative error code on failure.
 */
int share_fmt_encode(struct symbolon_share_record *rec,
                     char *out_buf,
                     size_t buf_cap,
                     size_t *out_len);

/*
 * Parse and validate a v1 share file from buf[0..len-1].
 * Enforces all format rules and verifies the 8-byte SHA-256 check field.
 * Returns SHARE_FMT_OK (0) on success, negative error code on failure.
 */
int share_fmt_parse(const char *buf,
                    size_t len,
                    struct symbolon_share_record *out_rec);

/*
 * Validate a set of parsed share records against SHARE_FORMAT.md §4 rules 3-5:
 * matching set-id, threshold, shares, fingerprint; distinct indices; count >= threshold.
 */
int share_fmt_validate_set(const struct symbolon_share_record *recs, size_t count);

/*
 * Format the canonical share filename "symbolon-share-<i>-of-<n>.txt".
 */
int share_fmt_filename(uint8_t index, uint8_t shares, char *out_name, size_t cap);

/*
 * Format the non-secret holder README.txt content for a share drive.
 */
int share_fmt_readme(uint8_t index,
                     uint8_t threshold,
                     uint8_t shares,
                     const uint8_t set_id[SYMBOLON_SET_ID_LEN],
                     const uint8_t fingerprint[SYMBOLON_FINGERPRINT_LEN],
                     char *out_buf,
                     size_t cap,
                     size_t *out_len);

#endif /* SYMBOLON_SHARE_FMT_H */
