/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "entropy.h"
#include "sha256.h"

#include <errno.h>
#include <string.h>
#include <sys/random.h>

#define SEED_DOMAIN_PREFIX   "SHARDKEY-SEED-V1"
#define SECRET_INFO_LABEL    "SHARDKEY-SECRET-V1"
#define SETID_INFO_LABEL     "SHARDKEY-SETID-V1"
#define COEFFS_INFO_LABEL    "SHARDKEY-COEFFS-V1"

int entropy_get_kernel_random(uint8_t *buf, size_t len)
{
	if (buf == NULL || len == 0u) {
		return -1;
	}

	size_t off = 0u;
	while (off < len) {
		if (secmem_interrupted()) {
			secmem_zero(buf, len);
			return -1;
		}
		/* Flags must be 0: block until CRNG is ready, never GRND_NONBLOCK */
		ssize_t n = getrandom(buf + off, len - off, 0u);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			secmem_zero(buf, len);
			return -1;
		}
		if (n == 0) {
			secmem_zero(buf, len);
			return -1;
		}
		off += (size_t)n;
	}

	return 0;
}

int entropy_dice_init(struct dice_collector *dc, uint8_t *buf, size_t capacity)
{
	if (dc == NULL || buf == NULL || capacity < SHARDKEY_MIN_DICE_ROLLS) {
		return -1;
	}
	secmem_zero(buf, capacity);
	dc->buf = buf;
	dc->capacity = capacity;
	dc->count = 0u;
	return 0;
}

enum dice_feed_result entropy_dice_feed_char(struct dice_collector *dc, char c)
{
	if (dc == NULL || dc->buf == NULL) {
		return DICE_IGNORED;
	}

	if (c == '\n' || c == '\r') {
		if (dc->count >= SHARDKEY_MIN_DICE_ROLLS) {
			return DICE_DONE;
		}
		return DICE_NEED_MORE;
	}

	if (c >= '1' && c <= '6') {
		if (dc->count >= dc->capacity) {
			return DICE_FULL;
		}
		dc->buf[dc->count++] = (uint8_t)c;
		return DICE_ACCEPTED;
	}

	return DICE_IGNORED;
}

int entropy_mix_seed(const uint8_t kernel_rnd[SHARDKEY_KERNEL_RND_LEN],
                     const uint8_t *dice, size_t dice_len,
                     uint8_t out_seed[SHARDKEY_SEED_LEN])
{
	if (kernel_rnd == NULL || dice == NULL || out_seed == NULL) {
		return -1;
	}
	if (dice_len < SHARDKEY_MIN_DICE_ROLLS || dice_len > SHARDKEY_MAX_DICE_ROLLS) {
		return -1;
	}

	for (size_t i = 0u; i < dice_len; i++) {
		if (dice[i] < (uint8_t)'1' || dice[i] > (uint8_t)'6') {
			return -1;
		}
	}

	uint8_t len_be[8];
	uint64_t dlen = (uint64_t)dice_len;
	len_be[0] = (uint8_t)(dlen >> 56u);
	len_be[1] = (uint8_t)(dlen >> 48u);
	len_be[2] = (uint8_t)(dlen >> 40u);
	len_be[3] = (uint8_t)(dlen >> 32u);
	len_be[4] = (uint8_t)(dlen >> 24u);
	len_be[5] = (uint8_t)(dlen >> 16u);
	len_be[6] = (uint8_t)(dlen >> 8u);
	len_be[7] = (uint8_t)(dlen);

	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, SEED_DOMAIN_PREFIX, strlen(SEED_DOMAIN_PREFIX));
	sha256_update(&ctx, kernel_rnd, SHARDKEY_KERNEL_RND_LEN);
	sha256_update(&ctx, len_be, sizeof(len_be));
	sha256_update(&ctx, dice, dice_len);
	sha256_final(&ctx, out_seed);

	secmem_zero(len_be, sizeof(len_be));
	return 0;
}

int entropy_hkdf_expand(const uint8_t seed[SHARDKEY_SEED_LEN],
                        const void *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
	if (seed == NULL || out == NULL || out_len == 0u) {
		return -1;
	}
	if (info == NULL && info_len > 0u) {
		return -1;
	}
	/* Maximum output in HKDF-Expand is 255 * 32 = 8160 bytes */
	if (out_len > 255u * SHA256_DIGEST_SIZE) {
		return -1;
	}

	uint8_t prev[SHA256_DIGEST_SIZE];
	size_t prev_len = 0u;
	size_t generated = 0u;
	uint8_t counter = 1u;

	while (generated < out_len) {
		struct hmac_sha256_ctx hctx;
		uint8_t block[SHA256_DIGEST_SIZE];

		hmac_sha256_init(&hctx, seed, SHARDKEY_SEED_LEN);
		if (prev_len > 0u) {
			hmac_sha256_update(&hctx, prev, prev_len);
		}
		if (info_len > 0u) {
			hmac_sha256_update(&hctx, info, info_len);
		}
		hmac_sha256_update(&hctx, &counter, 1u);
		hmac_sha256_final(&hctx, block);

		size_t copy_len = out_len - generated;
		if (copy_len > SHA256_DIGEST_SIZE) {
			copy_len = SHA256_DIGEST_SIZE;
		}
		memcpy(out + generated, block, copy_len);
		memcpy(prev, block, SHA256_DIGEST_SIZE);
		prev_len = SHA256_DIGEST_SIZE;
		generated += copy_len;
		counter++;

		secmem_zero(block, sizeof(block));
	}

	secmem_zero(prev, sizeof(prev));
	return 0;
}

int entropy_derive_ceremony(const uint8_t seed[SHARDKEY_SEED_LEN],
                            uint8_t k,
                            uint8_t out_secret[SHARDKEY_SECRET_LEN],
                            uint8_t *out_coeffs,
                            uint8_t out_set_id[SHARDKEY_SET_ID_LEN])
{
	if (seed == NULL || out_secret == NULL || out_coeffs == NULL || out_set_id == NULL) {
		return -1;
	}
	if (k < SHARDKEY_MIN_SHARES || k > SHARDKEY_MAX_SHARES) {
		return -1;
	}

	size_t coeff_bytes = (size_t)SHARDKEY_SECRET_LEN * (size_t)(k - 1u);

	if (entropy_hkdf_expand(seed, SECRET_INFO_LABEL, strlen(SECRET_INFO_LABEL),
	                        out_secret, SHARDKEY_SECRET_LEN) != 0) {
		return -1;
	}
	if (entropy_hkdf_expand(seed, SETID_INFO_LABEL, strlen(SETID_INFO_LABEL),
	                        out_set_id, SHARDKEY_SET_ID_LEN) != 0) {
		secmem_zero(out_secret, SHARDKEY_SECRET_LEN);
		return -1;
	}
	if (entropy_hkdf_expand(seed, COEFFS_INFO_LABEL, strlen(COEFFS_INFO_LABEL),
	                        out_coeffs, coeff_bytes) != 0) {
		secmem_zero(out_secret, SHARDKEY_SECRET_LEN);
		secmem_zero(out_set_id, SHARDKEY_SET_ID_LEN);
		return -1;
	}

	return 0;
}
