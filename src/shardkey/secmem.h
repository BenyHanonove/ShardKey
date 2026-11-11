/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARDKEY_SECMEM_H
#define SHARDKEY_SECMEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>

/* Ceremony protocol constants */
#define SHARDKEY_SECRET_LEN        32u
#define SHARDKEY_MIN_SHARES        2u
#define SHARDKEY_MAX_SHARES        16u
#define SHARDKEY_MAX_COEFF_DEG     (SHARDKEY_MAX_SHARES - 1u)
#define SHARDKEY_MAX_COEFF_BYTES   (SHARDKEY_SECRET_LEN * SHARDKEY_MAX_COEFF_DEG)
#define SHARDKEY_SET_ID_LEN        8u
#define SHARDKEY_FINGERPRINT_LEN   8u
#define SHARDKEY_CHECK_LEN         8u
#define SHARDKEY_KERNEL_RND_LEN    64u
#define SHARDKEY_SEED_LEN          32u
#define SHARDKEY_MIN_DICE_ROLLS    100u
#define SHARDKEY_MAX_DICE_ROLLS    1024u
#define SHARDKEY_SHARE_BUF_MAX     512u

/*
 * Static secret pool held in locked RAM.
 * No heap allocations (malloc/calloc/realloc) are ever used for secrets.
 */
struct shardkey_secpool {
	uint8_t kernel_rnd[SHARDKEY_KERNEL_RND_LEN];
	uint8_t dice_rolls[SHARDKEY_MAX_DICE_ROLLS];
	size_t  dice_len;
	uint8_t seed[SHARDKEY_SEED_LEN];
	uint8_t secret[SHARDKEY_SECRET_LEN];
	uint8_t coeffs[SHARDKEY_MAX_COEFF_BYTES];
	uint8_t shares[SHARDKEY_MAX_SHARES][SHARDKEY_SECRET_LEN];
	uint8_t scratch_shares[SHARDKEY_MAX_SHARES][SHARDKEY_SECRET_LEN];
	uint8_t scratch_secret[SHARDKEY_SECRET_LEN];
	uint8_t scratch_x[SHARDKEY_MAX_SHARES];
	uint8_t scratch_idx[SHARDKEY_MAX_SHARES];
	uint8_t set_id[SHARDKEY_SET_ID_LEN];
	uint8_t fingerprint[SHARDKEY_FINGERPRINT_LEN];
	char    share_file_buf[SHARDKEY_SHARE_BUF_MAX];
	char    verify_file_buf[SHARDKEY_SHARE_BUF_MAX];
};

struct termios;

/* Access the global static secret pool */
struct shardkey_secpool *secmem_pool(void);

/*
 * Lock down process memory and core dump behavior:
 *   - setrlimit(RLIMIT_CORE, 0)
 *   - prctl(PR_SET_DUMPABLE, 0)
 *   - mlockall(MCL_CURRENT | MCL_FUTURE) (mandatory if require_mlock is true)
 *   - installs atexit() and signal handlers to wipe all secret buffers
 * Returns 0 on success, -1 on failure.
 */
int secmem_lockdown(bool require_mlock);

/* Zero an arbitrary buffer in a way the compiler cannot elide */
void secmem_zero(void *ptr, size_t len);

/* Wipe the entire static secret pool */
void secmem_wipe_all(void);

/*
 * Register/unregister active raw tty state so signal/exit handlers restore
 * terminal echo even if interrupted during dice collection.
 */
void secmem_register_tty(int fd, const struct termios *orig);
void secmem_unregister_tty(void);

/*
 * Constant-time byte comparison.
 * Returns 1 if a[0..len-1] == b[0..len-1], 0 otherwise.
 */
int secmem_ct_equal(const void *a, const void *b, size_t len);

/* Check if a termination signal (SIGINT, SIGTERM, etc.) was caught */
sig_atomic_t secmem_interrupted(void);

/* Clear the interrupted flag (used by unit tests) */
void secmem_clear_interrupted(void);

#endif /* SHARDKEY_SECMEM_H */
