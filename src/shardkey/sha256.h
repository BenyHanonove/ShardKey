/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_SHA256_H
#define SHARDKEY_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  64u
#define SHA256_DIGEST_SIZE 32u

struct sha256_ctx {
	uint32_t state[8];
	uint64_t bitcount;
	uint8_t  buf[SHA256_BLOCK_SIZE];
	size_t   buf_len;
};

struct hmac_sha256_ctx {
	struct sha256_ctx inner;
	struct sha256_ctx outer;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void sha256_oneshot(const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const void *key, size_t key_len);
void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *data, size_t len);
void hmac_sha256_final(struct hmac_sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const void *key, size_t key_len,
                 const void *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);

#endif /* SHARDKEY_SHA256_H */
