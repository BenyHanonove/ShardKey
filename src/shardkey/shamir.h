/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_SHAMIR_H
#define SHARDKEY_SHAMIR_H

#include "secmem.h"
#include <stdint.h>

/*
 * Split a 32-byte secret into n shares with threshold k over GF(2^8).
 *
 * coeffs must point to 32 * (k - 1) bytes of random polynomial coefficients:
 * for secret byte j (0..31), coeffs[j * (k - 1) + d] is a_{j, d+1} for d = 0..k-2.
 * All 256 byte values (including 0) are valid for every coefficient.
 *
 * out_shares[i][j] receives P_j(i + 1) for i = 0..n-1, j = 0..31.
 * Returns 0 on success, -1 on invalid parameters.
 */
int shamir_split(const uint8_t secret[SHARDKEY_SECRET_LEN],
                 const uint8_t *coeffs,
                 uint8_t k,
                 uint8_t n,
                 uint8_t out_shares[][SHARDKEY_SECRET_LEN]);

/*
 * Reconstruct a 32-byte secret from k shares using Lagrange interpolation at x = 0.
 * Used only for the in-RAM ceremony self-test and unit tests.
 *
 * x_coords[0..k-1] are the 1-based share indices (must be non-zero and distinct).
 * y_shares[0..k-1][0..31] are the corresponding 32-byte share payloads.
 * Returns 0 on success, -1 on invalid parameters or duplicate x_coords.
 */
int shamir_combine(const uint8_t *x_coords,
                   const uint8_t y_shares[][SHARDKEY_SECRET_LEN],
                   uint8_t k,
                   uint8_t out_secret[SHARDKEY_SECRET_LEN]);

/*
 * Exhaustively verify in RAM that EVERY k-subset of the n generated shares
 * reconstructs the original 32-byte secret (constant-time compared).
 * Returns 0 if all C(n, k) subsets match, -1 otherwise.
 */
int shamir_verify_all_subsets(const uint8_t secret[SHARDKEY_SECRET_LEN],
                              const uint8_t shares[][SHARDKEY_SECRET_LEN],
                              uint8_t k,
                              uint8_t n);

#endif /* SHARDKEY_SHAMIR_H */
