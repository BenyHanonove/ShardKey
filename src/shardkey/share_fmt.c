/* SPDX-License-Identifier: GPL-2.0-only */
#include "share_fmt.h"
#include "policy.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

#define FP_DOMAIN_PREFIX "SHARDKEY-FP-V1"

void share_fmt_hex_encode(const uint8_t *bytes, size_t len, char *out_hex)
{
	static const char hex_tab[16] = "0123456789abcdef";
	for (size_t i = 0u; i < len; i++) {
		out_hex[i * 2u]      = hex_tab[(bytes[i] >> 4u) & 0x0fu];
		out_hex[i * 2u + 1u] = hex_tab[bytes[i] & 0x0fu];
	}
	out_hex[len * 2u] = '\0';
}

static int hex_nibble_lower(char c)
{
	if (c >= '0' && c <= '9') {
		return (int)(c - '0');
	}
	if (c >= 'a' && c <= 'f') {
		return (int)(c - 'a') + 10;
	}
	return -1;
}

static int hex_decode_lower(const char *s, size_t hex_len, uint8_t *out, size_t out_len)
{
	if (hex_len != out_len * 2u) {
		return -1;
	}
	for (size_t i = 0u; i < out_len; i++) {
		int hi = hex_nibble_lower(s[i * 2u]);
		int lo = hex_nibble_lower(s[i * 2u + 1u]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)(((unsigned int)hi << 4u) | (unsigned int)lo);
	}
	return 0;
}

static int validate_rec_params(uint8_t threshold, uint8_t shares, uint8_t index)
{
	enum policy_result pr = policy_validate((int)shares, (int)threshold);
	if (pr != POLICY_OK && pr != POLICY_OK_NEEDS_WARNING) {
		return SHARE_FMT_ERR_POLICY;
	}
	if (index < 1u || index > shares) {
		return SHARE_FMT_ERR_INDEX;
	}
	return SHARE_FMT_OK;
}

int share_fmt_fingerprint(const uint8_t secret[SHARDKEY_SECRET_LEN],
                          uint8_t out_fp[SHARDKEY_FINGERPRINT_LEN])
{
	if (secret == NULL || out_fp == NULL) {
		return SHARE_FMT_ERR_ARG;
	}

	struct sha256_ctx ctx;
	uint8_t digest[SHA256_DIGEST_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, FP_DOMAIN_PREFIX, strlen(FP_DOMAIN_PREFIX));
	sha256_update(&ctx, secret, SHARDKEY_SECRET_LEN);
	sha256_final(&ctx, digest);

	memcpy(out_fp, digest, SHARDKEY_FINGERPRINT_LEN);
	secmem_zero(digest, sizeof(digest));
	return SHARE_FMT_OK;
}

int share_fmt_encode(struct shardkey_share_record *rec,
                     char *out_buf,
                     size_t buf_cap,
                     size_t *out_len)
{
	if (rec == NULL || out_buf == NULL || buf_cap < 256u) {
		return SHARE_FMT_ERR_ARG;
	}

	int vrc = validate_rec_params(rec->threshold, rec->shares, rec->index);
	if (vrc != SHARE_FMT_OK) {
		return vrc;
	}

	char set_id_hex[SHARDKEY_SET_ID_LEN * 2u + 1u];
	char fp_hex[SHARDKEY_FINGERPRINT_LEN * 2u + 1u];
	char data_hex[SHARDKEY_SECRET_LEN * 2u + 1u];
	char check_hex[SHARDKEY_CHECK_LEN * 2u + 1u];

	share_fmt_hex_encode(rec->set_id, SHARDKEY_SET_ID_LEN, set_id_hex);
	share_fmt_hex_encode(rec->fingerprint, SHARDKEY_FINGERPRINT_LEN, fp_hex);
	share_fmt_hex_encode(rec->data, SHARDKEY_SECRET_LEN, data_hex);

	int body_len = snprintf(out_buf, buf_cap,
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: %u\n"
		"shares: %u\n"
		"index: %u\n"
		"set-id: %s\n"
		"fingerprint: %s\n"
		"data: %s\n",
		(unsigned int)rec->threshold,
		(unsigned int)rec->shares,
		(unsigned int)rec->index,
		set_id_hex,
		fp_hex,
		data_hex);

	secmem_zero(data_hex, sizeof(data_hex));

	if (body_len <= 0 || (size_t)body_len >= buf_cap) {
		return SHARE_FMT_ERR_ARG;
	}

	uint8_t digest[SHA256_DIGEST_SIZE];
	sha256_oneshot(out_buf, (size_t)body_len, digest);
	memcpy(rec->check, digest, SHARDKEY_CHECK_LEN);
	secmem_zero(digest, sizeof(digest));

	share_fmt_hex_encode(rec->check, SHARDKEY_CHECK_LEN, check_hex);

	int tail_len = snprintf(out_buf + body_len, buf_cap - (size_t)body_len,
		"check: %s\n", check_hex);
	if (tail_len <= 0 || (size_t)body_len + (size_t)tail_len >= buf_cap) {
		return SHARE_FMT_ERR_ARG;
	}

	if (out_len != NULL) {
		*out_len = (size_t)body_len + (size_t)tail_len;
	}
	return SHARE_FMT_OK;
}

static int parse_u8_strict(const char *s, size_t len, uint8_t *out)
{
	if (len == 0u || len > 2u) {
		return -1;
	}
	if (s[0] < '1' || s[0] > '9') {
		return -1;
	}
	unsigned int val = 0u;
	for (size_t i = 0u; i < len; i++) {
		if (s[i] < '0' || s[i] > '9') {
			return -1;
		}
		val = val * 10u + (unsigned int)(s[i] - '0');
	}
	if (val > 255u) {
		return -1;
	}
	*out = (uint8_t)val;
	return 0;
}

static bool next_lf_line(const char *buf, size_t total_len, size_t *pos,
                         const char **line_start, size_t *line_len)
{
	if (*pos >= total_len) {
		return false;
	}
	size_t start = *pos;
	size_t i = start;
	while (i < total_len && buf[i] != '\n') {
		if (buf[i] == '\r' || buf[i] == '\0') {
			return false;
		}
		i++;
	}
	if (i >= total_len || buf[i] != '\n') {
		return false;
	}
	*line_start = buf + start;
	*line_len = i - start;
	*pos = i + 1u;
	return true;
}

static bool strip_prefix(const char *line, size_t line_len,
                         const char *prefix,
                         const char **val_start, size_t *val_len)
{
	size_t plen = strlen(prefix);
	if (line_len <= plen) {
		return false;
	}
	if (memcmp(line, prefix, plen) != 0) {
		return false;
	}
	*val_start = line + plen;
	*val_len = line_len - plen;
	return true;
}

int share_fmt_parse(const char *buf,
                    size_t len,
                    struct shardkey_share_record *out_rec)
{
	if (buf == NULL || out_rec == NULL || len == 0u) {
		return SHARE_FMT_ERR_ARG;
	}

	struct shardkey_share_record tmp;
	memset(&tmp, 0, sizeof(tmp));

	size_t pos = 0u;
	const char *line = NULL;
	size_t line_len = 0u;
	const char *val = NULL;
	size_t val_len = 0u;

	/* Line 1: SHARDKEY-SHARE-V1 */
	if (!next_lf_line(buf, len, &pos, &line, &line_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (line_len != strlen("SHARDKEY-SHARE-V1") ||
	    memcmp(line, "SHARDKEY-SHARE-V1", line_len) != 0) {
		return SHARE_FMT_ERR_MAGIC;
	}

	/* Line 2: scheme: shamir-gf256 */
	if (!next_lf_line(buf, len, &pos, &line, &line_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (!strip_prefix(line, line_len, "scheme: ", &val, &val_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (val_len != strlen("shamir-gf256") ||
	    memcmp(val, "shamir-gf256", val_len) != 0) {
		return SHARE_FMT_ERR_SCHEME;
	}

	/* Line 3: threshold: <k> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "threshold: ", &val, &val_len) ||
	    parse_u8_strict(val, val_len, &tmp.threshold) != 0) {
		return SHARE_FMT_ERR_SYNTAX;
	}

	/* Line 4: shares: <n> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "shares: ", &val, &val_len) ||
	    parse_u8_strict(val, val_len, &tmp.shares) != 0) {
		return SHARE_FMT_ERR_SYNTAX;
	}

	/* Line 5: index: <i> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "index: ", &val, &val_len) ||
	    parse_u8_strict(val, val_len, &tmp.index) != 0) {
		return SHARE_FMT_ERR_SYNTAX;
	}

	int vrc = validate_rec_params(tmp.threshold, tmp.shares, tmp.index);
	if (vrc != SHARE_FMT_OK) {
		return vrc;
	}

	/* Line 6: set-id: <16 hex> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "set-id: ", &val, &val_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (hex_decode_lower(val, val_len, tmp.set_id, SHARDKEY_SET_ID_LEN) != 0) {
		return SHARE_FMT_ERR_HEX;
	}

	/* Line 7: fingerprint: <16 hex> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "fingerprint: ", &val, &val_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (hex_decode_lower(val, val_len, tmp.fingerprint, SHARDKEY_FINGERPRINT_LEN) != 0) {
		return SHARE_FMT_ERR_HEX;
	}

	/* Line 8: data: <64 hex> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "data: ", &val, &val_len)) {
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (hex_decode_lower(val, val_len, tmp.data, SHARDKEY_SECRET_LEN) != 0) {
		secmem_zero(&tmp, sizeof(tmp));
		return SHARE_FMT_ERR_HEX;
	}

	/* End of line 8 (including '\n') is the boundary for check SHA-256 */
	size_t check_span_len = pos;

	/* Line 9: check: <16 hex> */
	if (!next_lf_line(buf, len, &pos, &line, &line_len) ||
	    !strip_prefix(line, line_len, "check: ", &val, &val_len)) {
		secmem_zero(&tmp, sizeof(tmp));
		return SHARE_FMT_ERR_SYNTAX;
	}
	if (hex_decode_lower(val, val_len, tmp.check, SHARDKEY_CHECK_LEN) != 0) {
		secmem_zero(&tmp, sizeof(tmp));
		return SHARE_FMT_ERR_HEX;
	}

	/* Reject any extra trailing bytes/lines */
	if (pos != len) {
		secmem_zero(&tmp, sizeof(tmp));
		return SHARE_FMT_ERR_SYNTAX;
	}

	uint8_t digest[SHA256_DIGEST_SIZE];
	sha256_oneshot(buf, check_span_len, digest);
	int chk_ok = secmem_ct_equal(digest, tmp.check, SHARDKEY_CHECK_LEN);
	secmem_zero(digest, sizeof(digest));

	if (!chk_ok) {
		secmem_zero(&tmp, sizeof(tmp));
		return SHARE_FMT_ERR_CHECKSUM;
	}

	memcpy(out_rec, &tmp, sizeof(tmp));
	secmem_zero(&tmp, sizeof(tmp));
	return SHARE_FMT_OK;
}

int share_fmt_validate_set(const struct shardkey_share_record *recs, size_t count)
{
	if (recs == NULL || count == 0u) {
		return SHARE_FMT_ERR_ARG;
	}

	for (size_t i = 0u; i < count; i++) {
		int vrc = validate_rec_params(recs[i].threshold, recs[i].shares, recs[i].index);
		if (vrc != SHARE_FMT_OK) {
			return vrc;
		}
		if (i > 0u) {
			if (recs[i].threshold != recs[0].threshold ||
			    recs[i].shares != recs[0].shares ||
			    memcmp(recs[i].set_id, recs[0].set_id, SHARDKEY_SET_ID_LEN) != 0 ||
			    memcmp(recs[i].fingerprint, recs[0].fingerprint, SHARDKEY_FINGERPRINT_LEN) != 0) {
				return SHARE_FMT_ERR_SET_MISMATCH;
			}
		}
		for (size_t j = i + 1u; j < count; j++) {
			if (recs[i].index == recs[j].index) {
				return SHARE_FMT_ERR_DUPLICATE_IDX;
			}
		}
	}

	if (count < (size_t)recs[0].threshold) {
		return SHARE_FMT_ERR_TOO_FEW;
	}

	return SHARE_FMT_OK;
}

int share_fmt_filename(uint8_t index, uint8_t shares, char *out_name, size_t cap)
{
	if (out_name == NULL || cap < 32u || index < 1u || index > shares ||
	    shares < SHARDKEY_MIN_SHARES || shares > SHARDKEY_MAX_SHARES) {
		return SHARE_FMT_ERR_ARG;
	}
	int n = snprintf(out_name, cap, "shardkey-share-%u-of-%u.txt",
	                 (unsigned int)index, (unsigned int)shares);
	if (n <= 0 || (size_t)n >= cap) {
		return SHARE_FMT_ERR_ARG;
	}
	return SHARE_FMT_OK;
}

int share_fmt_readme(uint8_t index,
                     uint8_t threshold,
                     uint8_t shares,
                     const uint8_t set_id[SHARDKEY_SET_ID_LEN],
                     const uint8_t fingerprint[SHARDKEY_FINGERPRINT_LEN],
                     char *out_buf,
                     size_t cap,
                     size_t *out_len)
{
	if (set_id == NULL || fingerprint == NULL || out_buf == NULL || cap < 256u) {
		return SHARE_FMT_ERR_ARG;
	}
	int vrc = validate_rec_params(threshold, shares, index);
	if (vrc != SHARE_FMT_OK) {
		return vrc;
	}

	char set_id_hex[SHARDKEY_SET_ID_LEN * 2u + 1u];
	char fp_hex[SHARDKEY_FINGERPRINT_LEN * 2u + 1u];
	share_fmt_hex_encode(set_id, SHARDKEY_SET_ID_LEN, set_id_hex);
	share_fmt_hex_encode(fingerprint, SHARDKEY_FINGERPRINT_LEN, fp_hex);

	int n = snprintf(out_buf, cap,
		"ShardKey Secret Share Drive\n"
		"===========================\n"
		"\n"
		"This USB flash drive holds Share %u of %u (threshold: %u required).\n"
		"Set ID:             %s\n"
		"Secret fingerprint: %s\n"
		"Share file:         shardkey-share-%u-of-%u.txt\n"
		"\n"
		"IMPORTANT:\n"
		"- Keep this drive in a secure location separate from the other shares.\n"
		"- Any %u shares from set %s can reconstruct the secret.\n"
		"- Fewer than %u shares reveal no information about the secret.\n"
		"- Do not modify or rename shardkey-share-%u-of-%u.txt.\n",
		(unsigned int)index, (unsigned int)shares, (unsigned int)threshold,
		set_id_hex,
		fp_hex,
		(unsigned int)index, (unsigned int)shares,
		(unsigned int)threshold, set_id_hex,
		(unsigned int)threshold,
		(unsigned int)index, (unsigned int)shares);

	if (n <= 0 || (size_t)n >= cap) {
		return SHARE_FMT_ERR_ARG;
	}
	if (out_len != NULL) {
		*out_len = (size_t)n;
	}
	return SHARE_FMT_OK;
}
