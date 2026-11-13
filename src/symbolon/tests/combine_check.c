/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host-only test helper for QEMU E2E share verification.
 * Reads a complete set of n share files, parses and validates every share,
 * exhaustively runs shamir_combine() across all C(n, k) k-subsets, and confirms
 * every subset reconstructs the exact same 32-byte secret matching the
 * header fingerprint. Never compiled into the appliance binary or initramfs.
 */
#define _GNU_SOURCE
#include "secmem.h"
#include "shamir.h"
#include "share_fmt.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int read_share_file(const char *path, char *buf, size_t cap, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "combine_check: cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}
	size_t n = fread(buf, 1u, cap - 1u, f);
	int err = ferror(f);
	int extra = fgetc(f);
	fclose(f);
	if (err != 0 || extra != EOF || n == 0u) {
		fprintf(stderr, "combine_check: invalid size/read error on %s\n", path);
		return -1;
	}
	buf[n] = '\0';
	*out_len = n;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3 || (size_t)(argc - 1) > SYMBOLON_MAX_SHARES) {
		fprintf(stderr, "usage: %s <share-1> <share-2> [... up to %u shares]\n",
		        argc > 0 ? argv[0] : "combine_check", SYMBOLON_MAX_SHARES);
		return 2;
	}

	size_t count = (size_t)(argc - 1);
	struct symbolon_share_record recs[SYMBOLON_MAX_SHARES];
	char file_buf[4096];
	int rc = 1;

	memset(recs, 0, sizeof(recs));

	for (size_t i = 0u; i < count; i++) {
		size_t flen = 0u;
		if (read_share_file(argv[i + 1], file_buf, sizeof(file_buf), &flen) != 0) {
			goto out;
		}
		int pr = share_fmt_parse(file_buf, flen, &recs[i]);
		if (pr != SHARE_FMT_OK) {
			fprintf(stderr, "combine_check: parse failed for %s (err=%d)\n",
			        argv[i + 1], pr);
			goto out;
		}
	}

	int vr = share_fmt_validate_set(recs, count);
	if (vr != SHARE_FMT_OK) {
		fprintf(stderr, "combine_check: set validation failed (err=%d)\n", vr);
		goto out;
	}

	uint8_t k = recs[0].threshold;
	uint8_t n = recs[0].shares;
	if (count != (size_t)n) {
		fprintf(stderr, "combine_check: expected %u shares, got %zu\n",
		        (unsigned int)n, count);
		goto out;
	}

	/* Verify indices cover 1..n exactly once */
	bool seen[SYMBOLON_MAX_SHARES + 1u];
	memset(seen, 0, sizeof(seen));
	for (size_t i = 0u; i < count; i++) {
		if (recs[i].index < 1u || recs[i].index > n || seen[recs[i].index]) {
			fprintf(stderr, "combine_check: unexpected/duplicate index %u\n",
			        (unsigned int)recs[i].index);
			goto out;
		}
		seen[recs[i].index] = true;
	}

	/* Exhaustively combine all C(n, k) k-subsets */
	uint8_t comb[SYMBOLON_MAX_SHARES];
	uint8_t x_coords[SYMBOLON_MAX_SHARES];
	uint8_t y_shares[SYMBOLON_MAX_SHARES][SYMBOLON_SECRET_LEN];
	uint8_t ref_secret[SYMBOLON_SECRET_LEN];
	uint8_t recovered[SYMBOLON_SECRET_LEN];
	uint8_t fp[SYMBOLON_FINGERPRINT_LEN];

	for (uint8_t i = 0u; i < k; i++) {
		comb[i] = i;
	}

	size_t subsets = 0u;
	bool have_ref = false;

	for (;;) {
		for (uint8_t i = 0u; i < k; i++) {
			const struct symbolon_share_record *r = &recs[comb[i]];
			x_coords[i] = r->index;
			memcpy(y_shares[i], r->data, SYMBOLON_SECRET_LEN);
		}

		if (shamir_combine(x_coords, (const uint8_t (*)[SYMBOLON_SECRET_LEN])y_shares,
		                   k, recovered) != 0) {
			fprintf(stderr, "combine_check: shamir_combine failed on subset %zu\n", subsets);
			goto wipe_secrets;
		}
		if (share_fmt_fingerprint(recovered, fp) != 0 ||
		    secmem_ct_equal(fp, recs[0].fingerprint, SYMBOLON_FINGERPRINT_LEN) != 1) {
			fprintf(stderr, "combine_check: fingerprint mismatch on subset %zu\n", subsets);
			goto wipe_secrets;
		}
		if (!have_ref) {
			memcpy(ref_secret, recovered, SYMBOLON_SECRET_LEN);
			have_ref = true;
		} else if (secmem_ct_equal(recovered, ref_secret, SYMBOLON_SECRET_LEN) != 1) {
			fprintf(stderr, "combine_check: secret mismatch across subset %zu\n", subsets);
			goto wipe_secrets;
		}
		subsets++;

		int pos = (int)k - 1;
		while (pos >= 0 && comb[pos] == (uint8_t)((size_t)pos + (size_t)n - (size_t)k)) {
			pos--;
		}
		if (pos < 0) {
			break;
		}
		comb[pos]++;
		for (int j = pos + 1; j < (int)k; j++) {
			comb[j] = (uint8_t)(comb[j - 1] + 1u);
		}
	}

	char set_id_hex[SYMBOLON_SET_ID_LEN * 2u + 1u];
	char fp_hex[SYMBOLON_FINGERPRINT_LEN * 2u + 1u];
	share_fmt_hex_encode(recs[0].set_id, SYMBOLON_SET_ID_LEN, set_id_hex);
	share_fmt_hex_encode(recs[0].fingerprint, SYMBOLON_FINGERPRINT_LEN, fp_hex);

	printf("OK set_id=%s fingerprint=%s k=%u n=%u subsets=%zu\n",
	       set_id_hex, fp_hex, (unsigned int)k, (unsigned int)n, subsets);
	rc = 0;

wipe_secrets:
	secmem_zero(y_shares, sizeof(y_shares));
	secmem_zero(ref_secret, sizeof(ref_secret));
	secmem_zero(recovered, sizeof(recovered));
out:
	secmem_zero(recs, sizeof(recs));
	secmem_zero(file_buf, sizeof(file_buf));
	return rc;
}
