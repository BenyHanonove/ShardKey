/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_ENTROPY_H
#define SHARDKEY_ENTROPY_H

#include "secmem.h"
#include <stddef.h>
#include <stdint.h>

enum dice_feed_result {
	DICE_ACCEPTED  = 0,  /* Valid roll '1'..'6' recorded */
	DICE_IGNORED   = 1,  /* Non-'1'..'6' character ignored */
	DICE_NEED_MORE = 2,  /* Enter pressed, but count < SHARDKEY_MIN_DICE_ROLLS */
	DICE_DONE      = 3,  /* Enter pressed and count >= SHARDKEY_MIN_DICE_ROLLS */
	DICE_FULL      = 4   /* Buffer at SHARDKEY_MAX_DICE_ROLLS capacity */
};

struct dice_collector {
	uint8_t *buf;
	size_t   capacity;
	size_t   count;
};

/*
 * Fill buf[0..len-1] from the Linux kernel CSPRNG via getrandom(buf, len, 0).
 * Loops on short reads and EINTR; never falls back to GRND_NONBLOCK.
 * Returns 0 on success, -1 on error.
 */
int entropy_get_kernel_random(uint8_t *buf, size_t len);

/* Initialize dice collector backed by a caller-supplied buffer (in secmem_pool) */
int entropy_dice_init(struct dice_collector *dc, uint8_t *buf, size_t capacity);

/* Feed a single input character into the dice collector */
enum dice_feed_result entropy_dice_feed_char(struct dice_collector *dc, char c);

/*
 * Mix kernel randomness (64 bytes) and dice rolls (>= 100 bytes in '1'..'6'):
 *   seed = SHA-256("SHARDKEY-SEED-V1" || kernel_rnd[64] || be64(dice_len) || dice)
 * Returns 0 on success, -1 if arguments or dice rolls are invalid.
 */
int entropy_mix_seed(const uint8_t kernel_rnd[SHARDKEY_KERNEL_RND_LEN],
                     const uint8_t *dice, size_t dice_len,
                     uint8_t out_seed[SHARDKEY_SEED_LEN]);

/*
 * HKDF-Expand (RFC 5869 §2.3) using HMAC-SHA256 in counter mode:
 *   T(0) = empty
 *   T(i) = HMAC-SHA256(seed, T(i-1) || info || i)   for i = 1..ceil(out_len/32)
 * Returns 0 on success, -1 on invalid arguments.
 */
int entropy_hkdf_expand(const uint8_t seed[SHARDKEY_SEED_LEN],
                        const void *info, size_t info_len,
                        uint8_t *out, size_t out_len);

/*
 * Derive all ceremony random material from the 32-byte mixed seed:
 *   - secret[32]           via info "SHARDKEY-SECRET-V1"
 *   - set_id[8]            via info "SHARDKEY-SETID-V1"
 *   - coeffs[32 * (k - 1)] via info "SHARDKEY-COEFFS-V1"
 * Returns 0 on success, -1 on invalid arguments.
 */
int entropy_derive_ceremony(const uint8_t seed[SHARDKEY_SEED_LEN],
                            uint8_t k,
                            uint8_t out_secret[SHARDKEY_SECRET_LEN],
                            uint8_t *out_coeffs,
                            uint8_t out_set_id[SHARDKEY_SET_ID_LEN]);

#endif /* SHARDKEY_ENTROPY_H */
