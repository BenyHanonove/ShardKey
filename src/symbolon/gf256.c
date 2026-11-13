/* SPDX-License-Identifier: GPL-2.0-only */
#include "gf256.h"

uint8_t gf256_add(uint8_t a, uint8_t b)
{
	return (uint8_t)(a ^ b);
}

uint8_t gf256_sub(uint8_t a, uint8_t b)
{
	return (uint8_t)(a ^ b);
}

uint8_t gf256_mul(uint8_t a, uint8_t b)
{
	uint8_t p = 0u;

	for (int i = 0; i < 8; i++) {
		uint8_t lsb_mask = (uint8_t)(0u - (uint8_t)(b & 1u));
		p ^= (uint8_t)(a & lsb_mask);

		uint8_t hi_mask = (uint8_t)(0u - (uint8_t)((a >> 7u) & 1u));
		a = (uint8_t)((uint8_t)(a << 1u) ^ (uint8_t)(0x1bu & hi_mask));
		b >>= 1u;
	}
	return p;
}

uint8_t gf256_inv(uint8_t a)
{
	/*
	 * Fermat's Little Theorem in GF(2^8): a^254 = a^(-1) for a != 0,
	 * and 0^254 = 0. Evaluated via a fixed 11-multiply addition chain.
	 */
	uint8_t a2   = gf256_mul(a, a);          /* a^2   */
	uint8_t a3   = gf256_mul(a2, a);         /* a^3   */
	uint8_t a6   = gf256_mul(a3, a3);        /* a^6   */
	uint8_t a12  = gf256_mul(a6, a6);        /* a^12  */
	uint8_t a15  = gf256_mul(a12, a3);       /* a^15  */
	uint8_t a30  = gf256_mul(a15, a15);      /* a^30  */
	uint8_t a60  = gf256_mul(a30, a30);      /* a^60  */
	uint8_t a120 = gf256_mul(a60, a60);      /* a^120 */
	uint8_t a126 = gf256_mul(a120, a6);      /* a^126 */
	uint8_t a127 = gf256_mul(a126, a);       /* a^127 */
	uint8_t a254 = gf256_mul(a127, a127);    /* a^254 */

	return a254;
}

uint8_t gf256_div(uint8_t a, uint8_t b)
{
	return gf256_mul(a, gf256_inv(b));
}
