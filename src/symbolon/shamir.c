/* SPDX-License-Identifier: GPL-2.0-only */
#include "shamir.h"
#include "gf256.h"

#include <string.h>

static uint8_t poly_eval(uint8_t s0, const uint8_t *coeffs_j, uint8_t deg, uint8_t x)
{
	/*
	 * Horner's method:
	 * P(x) = s0 + c[0]*x + c[1]*x^2 + ... + c[deg-1]*x^deg
	 */
	uint8_t acc = 0u;
	for (int d = (int)deg - 1; d >= 0; d--) {
		acc = gf256_add(gf256_mul(acc, x), coeffs_j[d]);
	}
	acc = gf256_add(gf256_mul(acc, x), s0);
	return acc;
}

int shamir_split(const uint8_t secret[SYMBOLON_SECRET_LEN],
                 const uint8_t *coeffs,
                 uint8_t k,
                 uint8_t n,
                 uint8_t out_shares[][SYMBOLON_SECRET_LEN])
{
	if (secret == NULL || coeffs == NULL || out_shares == NULL) {
		return -1;
	}
	if (n < SYMBOLON_MIN_SHARES || n > SYMBOLON_MAX_SHARES) {
		return -1;
	}
	if (k < SYMBOLON_MIN_SHARES || k > n) {
		return -1;
	}

	uint8_t deg = (uint8_t)(k - 1u);

	for (uint8_t i = 0u; i < n; i++) {
		uint8_t x = (uint8_t)(i + 1u);
		for (size_t j = 0u; j < SYMBOLON_SECRET_LEN; j++) {
			const uint8_t *c_j = &coeffs[j * (size_t)deg];
			out_shares[i][j] = poly_eval(secret[j], c_j, deg, x);
		}
	}

	return 0;
}

int shamir_combine(const uint8_t *x_coords,
                   const uint8_t y_shares[][SYMBOLON_SECRET_LEN],
                   uint8_t k,
                   uint8_t out_secret[SYMBOLON_SECRET_LEN])
{
	if (x_coords == NULL || y_shares == NULL || out_secret == NULL) {
		return -1;
	}
	if (k < SYMBOLON_MIN_SHARES || k > SYMBOLON_MAX_SHARES) {
		return -1;
	}

	/* Verify x coordinates are non-zero and pairwise distinct */
	for (uint8_t m = 0u; m < k; m++) {
		if (x_coords[m] == 0u) {
			return -1;
		}
		for (uint8_t r = (uint8_t)(m + 1u); r < k; r++) {
			if (x_coords[m] == x_coords[r]) {
				return -1;
			}
		}
	}

	memset(out_secret, 0, SYMBOLON_SECRET_LEN);

	for (uint8_t m = 0u; m < k; m++) {
		uint8_t num = 1u;
		uint8_t den = 1u;

		for (uint8_t r = 0u; r < k; r++) {
			if (r == m) {
				continue;
			}
			num = gf256_mul(num, x_coords[r]);
			den = gf256_mul(den, gf256_sub(x_coords[m], x_coords[r]));
		}

		uint8_t basis = gf256_div(num, den);
		for (size_t j = 0u; j < SYMBOLON_SECRET_LEN; j++) {
			out_secret[j] = gf256_add(out_secret[j],
			                          gf256_mul(basis, y_shares[m][j]));
		}
	}

	return 0;
}

int shamir_verify_all_subsets(const uint8_t secret[SYMBOLON_SECRET_LEN],
                              const uint8_t shares[][SYMBOLON_SECRET_LEN],
                              uint8_t k,
                              uint8_t n)
{
	if (secret == NULL || shares == NULL) {
		return -1;
	}
	if (n < SYMBOLON_MIN_SHARES || n > SYMBOLON_MAX_SHARES) {
		return -1;
	}
	if (k < SYMBOLON_MIN_SHARES || k > n) {
		return -1;
	}

	struct symbolon_secpool *pool = secmem_pool();
	uint8_t *idx = pool->scratch_idx;
	uint8_t *x_sub = pool->scratch_x;
	uint8_t (*y_sub)[SYMBOLON_SECRET_LEN] = pool->scratch_shares;
	uint8_t *rebuilt = pool->scratch_secret;

	for (uint8_t m = 0u; m < k; m++) {
		idx[m] = m;
	}

	int rc = 0;
	for (;;) {
		if (secmem_interrupted()) {
			rc = -1;
			break;
		}
		for (uint8_t m = 0u; m < k; m++) {
			uint8_t s_idx = idx[m];
			x_sub[m] = (uint8_t)(s_idx + 1u);
			memcpy(y_sub[m], shares[s_idx], SYMBOLON_SECRET_LEN);
		}

		if (shamir_combine(x_sub, (const uint8_t (*)[SYMBOLON_SECRET_LEN])y_sub,
		                   k, rebuilt) != 0 ||
		    !secmem_ct_equal(rebuilt, secret, SYMBOLON_SECRET_LEN)) {
			rc = -1;
			break;
		}

		/* Advance to next lexicographic k-combination of 0..n-1 */
		int pos = (int)k - 1;
		while (pos >= 0 && idx[pos] == (uint8_t)(n - k + (uint8_t)pos)) {
			pos--;
		}
		if (pos < 0) {
			break;
		}
		idx[pos]++;
		for (uint8_t m = (uint8_t)(pos + 1); m < k; m++) {
			idx[m] = (uint8_t)(idx[m - 1u] + 1u);
		}
	}

	secmem_zero(pool->scratch_idx, sizeof(pool->scratch_idx));
	secmem_zero(pool->scratch_x, sizeof(pool->scratch_x));
	secmem_zero(pool->scratch_shares, sizeof(pool->scratch_shares));
	secmem_zero(pool->scratch_secret, sizeof(pool->scratch_secret));

	return rc;
}
