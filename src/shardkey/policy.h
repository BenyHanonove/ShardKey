/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_POLICY_H
#define SHARDKEY_POLICY_H

#include <stdbool.h>
#include <stdint.h>

enum policy_result {
	POLICY_OK                 = 0,  /* Valid: majority(n) <= k < n */
	POLICY_OK_NEEDS_WARNING   = 1,  /* Valid: k == n (requires unanimous-loss warning + YES) */
	POLICY_ERR_N_OUT_OF_RANGE = -1, /* n outside 2..16 */
	POLICY_ERR_K_BELOW_MAJ    = -2, /* k < majority(n) */
	POLICY_ERR_K_ABOVE_N      = -3, /* k > n */
	POLICY_ERR_PARSE          = -4  /* Unparseable input */
};

/* Compute majority(n) = floor(n / 2) + 1 for n in 2..16 (returns 0 if n invalid) */
uint8_t policy_majority(uint8_t n);

/* Validate (n, k) against the ceremony threshold policy */
enum policy_result policy_validate(int n, int k);

/* Parse share count n (2..16) from an input line */
enum policy_result policy_parse_n(const char *line, uint8_t *out_n);

/*
 * Parse threshold k from an input line given valid n (2..16):
 *   - "M" or "m" selects majority(n)
 *   - decimal integer selects k, validated against majority(n) .. n
 */
enum policy_result policy_parse_k(const char *line, uint8_t n, uint8_t *out_k);

/* Return true iff line (after trimming leading/trailing horizontal/vertical whitespace) is "YES" */
bool policy_is_yes(const char *line);

/* Return true iff line (after trimming leading/trailing whitespace) is "ABORT" or "abort" */
bool policy_is_abort(const char *line);

#endif /* SHARDKEY_POLICY_H */
