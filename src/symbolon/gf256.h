/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SYMBOLON_GF256_H
#define SYMBOLON_GF256_H

#include <stdint.h>

/*
 * Constant-time arithmetic in GF(2^8) with reduction polynomial
 * x^8 + x^4 + x^3 + x + 1 (0x11B, AES polynomial).
 * No lookup tables indexed by operands are used.
 */

uint8_t gf256_add(uint8_t a, uint8_t b);
uint8_t gf256_sub(uint8_t a, uint8_t b);
uint8_t gf256_mul(uint8_t a, uint8_t b);
uint8_t gf256_inv(uint8_t a);
uint8_t gf256_div(uint8_t a, uint8_t b);

#endif /* SYMBOLON_GF256_H */
