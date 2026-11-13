/* SPDX-License-Identifier: GPL-2.0-only */
#include "policy.h"
#include "secmem.h"

#include <stddef.h>
#include <string.h>

static bool is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void trim_span(const char *s, const char **start, size_t *len)
{
	while (*s != '\0' && is_ws(*s)) {
		s++;
	}
	const char *end = s + strlen(s);
	while (end > s && is_ws(*(end - 1))) {
		end--;
	}
	*start = s;
	*len = (size_t)(end - s);
}

static int parse_nonneg_int(const char *start, size_t len, int *out_val)
{
	if (len == 0u || len > 6u) {
		return -1;
	}
	/* Reject multi-digit leading zeros such as "03" or "00" */
	if (len > 1u && start[0] == '0') {
		return -1;
	}
	int acc = 0;
	for (size_t i = 0u; i < len; i++) {
		if (start[i] < '0' || start[i] > '9') {
			return -1;
		}
		acc = acc * 10 + (int)(start[i] - '0');
	}
	*out_val = acc;
	return 0;
}

uint8_t policy_majority(uint8_t n)
{
	if (n < SYMBOLON_MIN_SHARES || n > SYMBOLON_MAX_SHARES) {
		return 0u;
	}
	return (uint8_t)((n / 2u) + 1u);
}

enum policy_result policy_validate(int n, int k)
{
	if (n < (int)SYMBOLON_MIN_SHARES || n > (int)SYMBOLON_MAX_SHARES) {
		return POLICY_ERR_N_OUT_OF_RANGE;
	}
	uint8_t maj = policy_majority((uint8_t)n);
	if (k < (int)maj) {
		return POLICY_ERR_K_BELOW_MAJ;
	}
	if (k > n) {
		return POLICY_ERR_K_ABOVE_N;
	}
	if (k == n) {
		return POLICY_OK_NEEDS_WARNING;
	}
	return POLICY_OK;
}

enum policy_result policy_parse_n(const char *line, uint8_t *out_n)
{
	if (line == NULL || out_n == NULL) {
		return POLICY_ERR_PARSE;
	}

	const char *start = NULL;
	size_t len = 0u;
	trim_span(line, &start, &len);

	int val = 0;
	if (parse_nonneg_int(start, len, &val) != 0) {
		return POLICY_ERR_PARSE;
	}
	if (val < (int)SYMBOLON_MIN_SHARES || val > (int)SYMBOLON_MAX_SHARES) {
		return POLICY_ERR_N_OUT_OF_RANGE;
	}

	*out_n = (uint8_t)val;
	return POLICY_OK;
}

enum policy_result policy_parse_k(const char *line, uint8_t n, uint8_t *out_k)
{
	if (line == NULL || out_k == NULL) {
		return POLICY_ERR_PARSE;
	}
	if (n < SYMBOLON_MIN_SHARES || n > SYMBOLON_MAX_SHARES) {
		return POLICY_ERR_N_OUT_OF_RANGE;
	}

	const char *start = NULL;
	size_t len = 0u;
	trim_span(line, &start, &len);
	if (len == 0u) {
		return POLICY_ERR_PARSE;
	}

	int k_val = 0;
	if (len == 1u && (start[0] == 'M' || start[0] == 'm')) {
		k_val = (int)policy_majority(n);
	} else {
		if (parse_nonneg_int(start, len, &k_val) != 0) {
			return POLICY_ERR_PARSE;
		}
	}

	enum policy_result res = policy_validate((int)n, k_val);
	if (res == POLICY_OK || res == POLICY_OK_NEEDS_WARNING) {
		*out_k = (uint8_t)k_val;
	}
	return res;
}

bool policy_is_yes(const char *line)
{
	if (line == NULL) {
		return false;
	}
	const char *start = NULL;
	size_t len = 0u;
	trim_span(line, &start, &len);
	return (len == 3u && memcmp(start, "YES", 3u) == 0);
}

bool policy_is_abort(const char *line)
{
	if (line == NULL) {
		return false;
	}
	const char *start = NULL;
	size_t len = 0u;
	trim_span(line, &start, &len);
	return (len == 5u && (memcmp(start, "ABORT", 5u) == 0 ||
	                      memcmp(start, "abort", 5u) == 0));
}
