/* SPDX-License-Identifier: GPL-2.0-only */
#include "sha256.h"
#include "secmem.h"

#include <string.h>

static const uint32_t K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32u - n));
}

static inline uint32_t ch32(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (~x & z);
}

static inline uint32_t maj32(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t ep0(uint32_t x)
{
	return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

static inline uint32_t ep1(uint32_t x)
{
	return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

static inline uint32_t sig0(uint32_t x)
{
	return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

static inline uint32_t sig1(uint32_t x)
{
	return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
}

static inline uint32_t load_be32(const uint8_t b[4])
{
	return ((uint32_t)b[0] << 24u) |
	       ((uint32_t)b[1] << 16u) |
	       ((uint32_t)b[2] << 8u)  |
	       ((uint32_t)b[3]);
}

static inline void store_be32(uint8_t b[4], uint32_t v)
{
	b[0] = (uint8_t)(v >> 24u);
	b[1] = (uint8_t)(v >> 16u);
	b[2] = (uint8_t)(v >> 8u);
	b[3] = (uint8_t)(v);
}

static void sha256_transform(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE])
{
	uint32_t w[64];

	for (size_t i = 0; i < 16u; i++) {
		w[i] = load_be32(&block[i * 4u]);
	}
	for (size_t i = 16u; i < 64u; i++) {
		w[i] = sig1(w[i - 2u]) + w[i - 7u] + sig0(w[i - 15u]) + w[i - 16u];
	}

	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];

	for (size_t i = 0; i < 64u; i++) {
		uint32_t t1 = h + ep1(e) + ch32(e, f, g) + K[i] + w[i];
		uint32_t t2 = ep0(a) + maj32(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

	secmem_zero(w, sizeof(w));
}

void sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667u;
	ctx->state[1] = 0xbb67ae85u;
	ctx->state[2] = 0x3c6ef372u;
	ctx->state[3] = 0xa54ff53au;
	ctx->state[4] = 0x510e527fu;
	ctx->state[5] = 0x9b05688cu;
	ctx->state[6] = 0x1f83d9abu;
	ctx->state[7] = 0x5be0cd19u;
	ctx->bitcount = 0u;
	memset(ctx->buf, 0, sizeof(ctx->buf));
	ctx->buf_len = 0u;
}

void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;

	if (len == 0u) {
		return;
	}

	ctx->bitcount += (uint64_t)len * 8u;

	if (ctx->buf_len > 0u) {
		size_t need = SHA256_BLOCK_SIZE - ctx->buf_len;
		if (len < need) {
			memcpy(&ctx->buf[ctx->buf_len], p, len);
			ctx->buf_len += len;
			return;
		}
		memcpy(&ctx->buf[ctx->buf_len], p, need);
		sha256_transform(ctx->state, ctx->buf);
		p += need;
		len -= need;
		ctx->buf_len = 0u;
	}

	while (len >= SHA256_BLOCK_SIZE) {
		sha256_transform(ctx->state, p);
		p += SHA256_BLOCK_SIZE;
		len -= SHA256_BLOCK_SIZE;
	}

	if (len > 0u) {
		memcpy(ctx->buf, p, len);
		ctx->buf_len = len;
	}
}

void sha256_final(struct sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE])
{
	ctx->buf[ctx->buf_len++] = 0x80u;

	if (ctx->buf_len > 56u) {
		memset(&ctx->buf[ctx->buf_len], 0, SHA256_BLOCK_SIZE - ctx->buf_len);
		sha256_transform(ctx->state, ctx->buf);
		ctx->buf_len = 0u;
	}

	memset(&ctx->buf[ctx->buf_len], 0, 56u - ctx->buf_len);
	store_be32(&ctx->buf[56], (uint32_t)(ctx->bitcount >> 32u));
	store_be32(&ctx->buf[60], (uint32_t)(ctx->bitcount & 0xffffffffu));
	sha256_transform(ctx->state, ctx->buf);

	for (size_t i = 0; i < 8u; i++) {
		store_be32(&out[i * 4u], ctx->state[i]);
	}

	secmem_zero(ctx, sizeof(*ctx));
}

void sha256_oneshot(const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, out);
}

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const void *key, size_t key_len)
{
	uint8_t k_block[SHA256_BLOCK_SIZE];
	uint8_t pad[SHA256_BLOCK_SIZE];

	memset(k_block, 0, sizeof(k_block));
	if (key_len > SHA256_BLOCK_SIZE) {
		sha256_oneshot(key, key_len, k_block);
	} else if (key_len > 0u) {
		memcpy(k_block, key, key_len);
	}

	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
		pad[i] = (uint8_t)(k_block[i] ^ 0x36u);
	}
	sha256_init(&ctx->inner);
	sha256_update(&ctx->inner, pad, SHA256_BLOCK_SIZE);

	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
		pad[i] = (uint8_t)(k_block[i] ^ 0x5cu);
	}
	sha256_init(&ctx->outer);
	sha256_update(&ctx->outer, pad, SHA256_BLOCK_SIZE);

	secmem_zero(k_block, sizeof(k_block));
	secmem_zero(pad, sizeof(pad));
}

void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *data, size_t len)
{
	sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(struct hmac_sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE])
{
	uint8_t inner_digest[SHA256_DIGEST_SIZE];

	sha256_final(&ctx->inner, inner_digest);
	sha256_update(&ctx->outer, inner_digest, SHA256_DIGEST_SIZE);
	sha256_final(&ctx->outer, out);

	secmem_zero(inner_digest, sizeof(inner_digest));
	secmem_zero(ctx, sizeof(*ctx));
}

void hmac_sha256(const void *key, size_t key_len,
                 const void *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE])
{
	struct hmac_sha256_ctx ctx;
	hmac_sha256_init(&ctx, key, key_len);
	hmac_sha256_update(&ctx, data, data_len);
	hmac_sha256_final(&ctx, out);
}
