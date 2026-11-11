/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "drive.h"
#include "entropy.h"
#include "gf256.h"
#include "policy.h"
#include "secmem.h"
#include "sha256.h"
#include "shamir.h"
#include "share_fmt.h"
#include "ui.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_failures = 0;
static int g_checks = 0;

#define TEST_ASSERT(cond, msg, ...)                                           \
	do {                                                                  \
		g_checks++;                                                   \
		if (!(cond)) {                                                \
			fprintf(stderr, "[FAIL] %s:%d: " msg "\n",            \
			        __FILE__, __LINE__, ##__VA_ARGS__);           \
			g_failures++;                                         \
			return;                                               \
		}                                                             \
	} while (0)

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	for (size_t i = 0u; i < out_len; i++) {
		unsigned int b = 0u;
		sscanf(hex + (i * 2u), "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

/* Reference non-optimized polynomial multiply over GF(2^8) mod 0x11B for verification */
static uint8_t ref_gf256_mul(uint8_t a, uint8_t b)
{
	uint16_t p = 0u;
	uint16_t aa = a;
	uint16_t bb = b;
	for (int i = 0; i < 8; i++) {
		if ((bb & (1u << i)) != 0u) {
			p ^= (uint16_t)(aa << i);
		}
	}
	for (int i = 14; i >= 8; i--) {
		if ((p & (1u << i)) != 0u) {
			p ^= (uint16_t)(0x11bu << (i - 8));
		}
	}
	return (uint8_t)(p & 0xffu);
}

static void test_gf256_exhaustive(void)
{
	/* Exhaustively check all 65,536 pairs (a, b) */
	for (unsigned int a = 0u; a < 256u; a++) {
		uint8_t ua = (uint8_t)a;
		TEST_ASSERT(gf256_add(ua, 0u) == ua, "a + 0 != a for a=%u", a);
		TEST_ASSERT(gf256_add(ua, ua) == 0u, "a + a != 0 for a=%u", a);
		TEST_ASSERT(gf256_sub(ua, ua) == 0u, "a - a != 0 for a=%u", a);
		TEST_ASSERT(gf256_mul(ua, 0u) == 0u, "a * 0 != 0 for a=%u", a);
		TEST_ASSERT(gf256_mul(ua, 1u) == ua, "a * 1 != a for a=%u", a);

		if (a == 0u) {
			TEST_ASSERT(gf256_inv(0u) == 0u, "inv(0) != 0");
		} else {
			uint8_t inv = gf256_inv(ua);
			TEST_ASSERT(inv != 0u, "inv(%u) == 0", a);
			TEST_ASSERT(gf256_mul(ua, inv) == 1u, "a * inv(a) != 1 for a=%u", a);
			TEST_ASSERT(gf256_mul(inv, ua) == 1u, "inv(a) * a != 1 for a=%u", a);
			TEST_ASSERT(gf256_inv(inv) == ua, "inv(inv(a)) != a for a=%u", a);
		}

		for (unsigned int b = 0u; b < 256u; b++) {
			uint8_t ub = (uint8_t)b;
			uint8_t prod = gf256_mul(ua, ub);
			uint8_t expected = ref_gf256_mul(ua, ub);
			TEST_ASSERT(prod == expected,
			            "gf256_mul(%u, %u) = %u, expected %u",
			            a, b, (unsigned int)prod, (unsigned int)expected);
			TEST_ASSERT(prod == gf256_mul(ub, ua),
			            "commutativity failed for (%u, %u)", a, b);
			if (b != 0u) {
				uint8_t q = gf256_div(ua, ub);
				TEST_ASSERT(gf256_mul(q, ub) == ua,
				            "div/mul failed for (%u, %u)", a, b);
			}
		}
	}

	/* Check distributivity on a grid of triples */
	for (unsigned int a = 0u; a < 256u; a += 7u) {
		for (unsigned int b = 0u; b < 256u; b += 11u) {
			for (unsigned int c = 0u; c < 256u; c += 13u) {
				uint8_t lhs = gf256_mul((uint8_t)a, gf256_add((uint8_t)b, (uint8_t)c));
				uint8_t rhs = gf256_add(gf256_mul((uint8_t)a, (uint8_t)b),
				                        gf256_mul((uint8_t)a, (uint8_t)c));
				TEST_ASSERT(lhs == rhs, "distributivity failed");
			}
		}
	}
}

static void test_sha256_and_hmac(void)
{
	uint8_t digest[SHA256_DIGEST_SIZE];
	char hex[SHA256_DIGEST_SIZE * 2u + 1u];

	/* FIPS 180-4 Vector 1: "" */
	sha256_oneshot("", 0u, digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	            "SHA-256(\"\") mismatch: %s", hex);

	/* FIPS 180-4 Vector 2: "abc" */
	sha256_oneshot("abc", 3u, digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	            "SHA-256(\"abc\") mismatch: %s", hex);

	/* FIPS 180-4 Vector 3: 448-bit message */
	const char *v3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	sha256_oneshot(v3, strlen(v3), digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
	            "SHA-256(448-bit) mismatch: %s", hex);

	/* FIPS 180-4 Vector 4: 896-bit message, fed 1 byte at a time */
	const char *v4 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
	                 "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	for (size_t i = 0u; i < strlen(v4); i++) {
		sha256_update(&ctx, &v4[i], 1u);
	}
	sha256_final(&ctx, digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1") == 0,
	            "SHA-256(896-bit incremental) mismatch: %s", hex);

	/* RFC 4231 Test Case 1 */
	uint8_t key1[20];
	memset(key1, 0x0bu, sizeof(key1));
	hmac_sha256(key1, sizeof(key1), "Hi There", 8u, digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0,
	            "RFC 4231 TC1 mismatch: %s", hex);

	/* RFC 4231 Test Case 2 */
	hmac_sha256("Jefe", 4u, "what do ya want for nothing?", 28u, digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0,
	            "RFC 4231 TC2 mismatch: %s", hex);

	/* RFC 4231 Test Case 3 */
	uint8_t key3[20];
	uint8_t data3[50];
	memset(key3, 0xaau, sizeof(key3));
	memset(data3, 0xddu, sizeof(data3));
	hmac_sha256(key3, sizeof(key3), data3, sizeof(data3), digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe") == 0,
	            "RFC 4231 TC3 mismatch: %s", hex);

	/* RFC 4231 Test Case 6 & 7: 131-byte key (> 64-byte block) */
	uint8_t key6[131];
	memset(key6, 0xaau, sizeof(key6));
	const char *data6 = "Test Using Larger Than Block-Size Key - Hash Key First";
	hmac_sha256(key6, sizeof(key6), data6, strlen(data6), digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54") == 0,
	            "RFC 4231 TC6 mismatch: %s", hex);

	const char *data7 = "This is a test using a larger than block-size key and a larger "
	                    "than block-size data. The key needs to be hashed before being "
	                    "used by the HMAC algorithm.";
	hmac_sha256(key6, sizeof(key6), data7, strlen(data7), digest);
	share_fmt_hex_encode(digest, SHA256_DIGEST_SIZE, hex);
	TEST_ASSERT(strcmp(hex, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2") == 0,
	            "RFC 4231 TC7 mismatch: %s", hex);
}

static void test_policy(void)
{
	/* Exhaustive check of all n in 2..16 */
	for (int n = 2; n <= 16; n++) {
		uint8_t maj = policy_majority((uint8_t)n);
		TEST_ASSERT(maj == (uint8_t)((n / 2) + 1), "majority(%d) wrong", n);

		for (int k = -2; k < (int)maj; k++) {
			TEST_ASSERT(policy_validate(n, k) == POLICY_ERR_K_BELOW_MAJ,
			            "expected k=%d below majority for n=%d", k, n);
		}
		for (int k = (int)maj; k < n; k++) {
			TEST_ASSERT(policy_validate(n, k) == POLICY_OK,
			            "expected POLICY_OK for n=%d, k=%d", n, k);
		}
		TEST_ASSERT(policy_validate(n, n) == POLICY_OK_NEEDS_WARNING,
		            "expected POLICY_OK_NEEDS_WARNING for k == n == %d", n);
		for (int k = n + 1; k <= 20; k++) {
			TEST_ASSERT(policy_validate(n, k) == POLICY_ERR_K_ABOVE_N,
			            "expected POLICY_ERR_K_ABOVE_N for n=%d, k=%d", n, k);
		}

		/* Test 'M' and 'm' shortcut */
		uint8_t parsed_k = 0u;
		enum policy_result mr = policy_parse_k("M\n", (uint8_t)n, &parsed_k);
		if (n == 2) {
			TEST_ASSERT(mr == POLICY_OK_NEEDS_WARNING && parsed_k == 2u,
			            "M for n=2 should be k=2 with warning");
		} else {
			TEST_ASSERT(mr == POLICY_OK && parsed_k == maj,
			            "M for n=%d should be %u", n, (unsigned int)maj);
		}
		mr = policy_parse_k("  m  ", (uint8_t)n, &parsed_k);
		TEST_ASSERT((mr == POLICY_OK || mr == POLICY_OK_NEEDS_WARNING) && parsed_k == maj,
		            "m for n=%d failed", n);
	}

	TEST_ASSERT(policy_majority(0u) == 0u, "majority(0) should be 0");
	TEST_ASSERT(policy_majority(1u) == 0u, "majority(1) should be 0");
	TEST_ASSERT(policy_majority(17u) == 0u, "majority(17) should be 0");
	TEST_ASSERT(policy_validate(1, 1) == POLICY_ERR_N_OUT_OF_RANGE, "n=1 should fail");
	TEST_ASSERT(policy_validate(17, 9) == POLICY_ERR_N_OUT_OF_RANGE, "n=17 should fail");

	uint8_t n_out = 0u;
	uint8_t k_out = 0u;
	TEST_ASSERT(policy_parse_n("5\n", &n_out) == POLICY_OK && n_out == 5u, "parse n=5");
	TEST_ASSERT(policy_parse_n("16", &n_out) == POLICY_OK && n_out == 16u, "parse n=16");
	TEST_ASSERT(policy_parse_n("0", &n_out) == POLICY_ERR_N_OUT_OF_RANGE, "parse n=0");
	TEST_ASSERT(policy_parse_n("1", &n_out) == POLICY_ERR_N_OUT_OF_RANGE, "parse n=1");
	TEST_ASSERT(policy_parse_n("17", &n_out) == POLICY_ERR_N_OUT_OF_RANGE, "parse n=17");
	TEST_ASSERT(policy_parse_n("05", &n_out) == POLICY_ERR_PARSE, "leading zero rejected");
	TEST_ASSERT(policy_parse_n("00", &n_out) == POLICY_ERR_PARSE, "double zero rejected");
	TEST_ASSERT(policy_parse_n("", &n_out) == POLICY_ERR_PARSE, "empty rejected");
	TEST_ASSERT(policy_parse_n("5a", &n_out) == POLICY_ERR_PARSE, "trailing alpha rejected");
	TEST_ASSERT(policy_parse_k("0", 5u, &k_out) == POLICY_ERR_K_BELOW_MAJ, "parse k=0 below maj");
	TEST_ASSERT(policy_parse_k("03", 5u, &k_out) == POLICY_ERR_PARSE, "parse k=03 leading zero");

	TEST_ASSERT(policy_is_yes("YES"), "YES accepted");
	TEST_ASSERT(policy_is_yes("  YES\r\n"), "trimmed YES accepted");
	TEST_ASSERT(!policy_is_yes("yes"), "lowercase yes rejected");
	TEST_ASSERT(!policy_is_yes("Yes"), "mixed case Yes rejected");
	TEST_ASSERT(!policy_is_yes("Y"), "single Y rejected");
	TEST_ASSERT(!policy_is_yes(""), "empty rejected");

	TEST_ASSERT(policy_is_abort("ABORT"), "ABORT accepted");
	TEST_ASSERT(policy_is_abort("  ABORT\r\n"), "trimmed ABORT accepted");
	TEST_ASSERT(policy_is_abort("  abort\n"), "trimmed lowercase abort accepted");
	TEST_ASSERT(!policy_is_abort("ABORTED"), "ABORTED rejected");
	TEST_ASSERT(!policy_is_abort(""), "empty abort rejected");
}

static void test_dice_and_entropy(void)
{
	uint8_t dice_buf[SHARDKEY_MAX_DICE_ROLLS];
	struct dice_collector dc;

	TEST_ASSERT(entropy_dice_init(&dc, dice_buf, sizeof(dice_buf)) == 0, "dice_init");

	/* Feed ignored characters */
	const char *ignored = "0789abcdefXYZ !@#$%^&*()-_=+[]{}|;:',.<>/?\t";
	for (size_t i = 0u; i < strlen(ignored); i++) {
		TEST_ASSERT(entropy_dice_feed_char(&dc, ignored[i]) == DICE_IGNORED,
		            "char '%c' should be ignored", ignored[i]);
	}
	TEST_ASSERT(dc.count == 0u, "count should still be 0");
	TEST_ASSERT(entropy_dice_feed_char(&dc, '\n') == DICE_NEED_MORE,
	            "Enter at 0 rolls must return DICE_NEED_MORE");

	/* Feed 99 valid rolls */
	for (size_t i = 0u; i < 99u; i++) {
		char d = (char)('1' + (i % 6u));
		TEST_ASSERT(entropy_dice_feed_char(&dc, d) == DICE_ACCEPTED, "roll %zu", i);
	}
	TEST_ASSERT(dc.count == 99u, "count == 99");
	TEST_ASSERT(entropy_dice_feed_char(&dc, '\n') == DICE_NEED_MORE,
	            "Enter at 99 rolls must return DICE_NEED_MORE");
	TEST_ASSERT(entropy_dice_feed_char(&dc, '\r') == DICE_NEED_MORE,
	            "CR at 99 rolls must return DICE_NEED_MORE");

	/* 100th roll + Enter */
	TEST_ASSERT(entropy_dice_feed_char(&dc, '4') == DICE_ACCEPTED, "100th roll");
	TEST_ASSERT(dc.count == 100u, "count == 100");
	TEST_ASSERT(entropy_dice_feed_char(&dc, '\n') == DICE_DONE,
	            "Enter at 100 rolls must return DICE_DONE");

	/* Mixing test: fixed inputs -> deterministic outputs; 1-bit change -> completely different */
	uint8_t krnd1[SHARDKEY_KERNEL_RND_LEN];
	uint8_t krnd2[SHARDKEY_KERNEL_RND_LEN];
	for (size_t i = 0u; i < SHARDKEY_KERNEL_RND_LEN; i++) {
		krnd1[i] = (uint8_t)i;
		krnd2[i] = (uint8_t)i;
	}

	uint8_t seed1[SHARDKEY_SEED_LEN];
	uint8_t seed1_dup[SHARDKEY_SEED_LEN];
	uint8_t seed2[SHARDKEY_SEED_LEN];
	uint8_t seed3[SHARDKEY_SEED_LEN];

	TEST_ASSERT(entropy_mix_seed(krnd1, dice_buf, 100u, seed1) == 0, "mix_seed 1");
	TEST_ASSERT(entropy_mix_seed(krnd1, dice_buf, 100u, seed1_dup) == 0, "mix_seed dup");
	TEST_ASSERT(memcmp(seed1, seed1_dup, SHARDKEY_SEED_LEN) == 0, "deterministic mix_seed");

	/* Reject < 100 dice rolls or out-of-range dice byte */
	TEST_ASSERT(entropy_mix_seed(krnd1, dice_buf, 99u, seed2) == -1, "reject 99 rolls");
	dice_buf[50] = '7';
	TEST_ASSERT(entropy_mix_seed(krnd1, dice_buf, 100u, seed2) == -1, "reject '7' in dice");
	dice_buf[50] = (uint8_t)('1' + (50u % 6u));

	/* Flip one kernel random byte */
	krnd2[31] ^= 0x01u;
	TEST_ASSERT(entropy_mix_seed(krnd2, dice_buf, 100u, seed2) == 0, "mix_seed krnd diff");
	TEST_ASSERT(memcmp(seed1, seed2, SHARDKEY_SEED_LEN) != 0,
	            "1-bit change in kernel_rnd must change seed");

	/* Change one dice roll */
	uint8_t orig_roll = dice_buf[99];
	dice_buf[99] = (orig_roll == '6') ? (uint8_t)'1' : (uint8_t)'6';
	TEST_ASSERT(entropy_mix_seed(krnd1, dice_buf, 100u, seed3) == 0, "mix_seed dice diff");
	TEST_ASSERT(memcmp(seed1, seed3, SHARDKEY_SEED_LEN) != 0,
	            "1-roll change in dice must change seed");
	dice_buf[99] = orig_roll;

	/* Derive ceremony material from seed1 and seed2, verify known-answer and avalanche */
	char seed1_hex[65];
	share_fmt_hex_encode(seed1, sizeof(seed1), seed1_hex);
	TEST_ASSERT(strcmp(seed1_hex,
	                   "d0cfaccf86b7b82c45ac62781a16dedc8269fdda525d8dc1a8701652b4b9c287") == 0,
	            "seed1 KAT mismatch: %s", seed1_hex);

	uint8_t sec1[32], sec2[32];
	uint8_t coeffs1[64], coeffs2[64];
	uint8_t setid1[8], setid2[8];

	TEST_ASSERT(entropy_derive_ceremony(seed1, 3u, sec1, coeffs1, setid1) == 0, "derive 1");
	TEST_ASSERT(entropy_derive_ceremony(seed2, 3u, sec2, coeffs2, setid2) == 0, "derive 2");

	char sec1_hex[65];
	char setid1_hex[17];
	char coeffs1_hex[129];
	share_fmt_hex_encode(sec1, sizeof(sec1), sec1_hex);
	share_fmt_hex_encode(setid1, sizeof(setid1), setid1_hex);
	share_fmt_hex_encode(coeffs1, sizeof(coeffs1), coeffs1_hex);
	TEST_ASSERT(strcmp(sec1_hex,
	                   "814f728bcab53cac2854fea3a90a1e0cf5faca78ebe84c8fa5e4b4e71092d958") == 0,
	            "sec1 KAT mismatch: %s", sec1_hex);
	TEST_ASSERT(strcmp(setid1_hex, "c29372774cf95c59") == 0,
	            "setid1 KAT mismatch: %s", setid1_hex);
	TEST_ASSERT(strcmp(coeffs1_hex,
	                   "e822f54fc5d05d62e84b58714eceff2742e09c552496523130b3b9d0ed5bc21"
	                   "6a604089fe157484fa5647a958268099271a582a3886910cb71969815738925cb") == 0,
	            "coeffs1 KAT mismatch: %s", coeffs1_hex);

	TEST_ASSERT(memcmp(sec1, sec2, 32u) != 0, "secrets must differ");
	TEST_ASSERT(memcmp(coeffs1, coeffs2, 64u) != 0, "coeffs must differ");
	TEST_ASSERT(memcmp(setid1, setid2, 8u) != 0, "set_ids must differ");

	/* Live kernel getrandom test */
	uint8_t kbuf[64];
	memset(kbuf, 0, sizeof(kbuf));
	TEST_ASSERT(entropy_get_kernel_random(kbuf, sizeof(kbuf)) == 0, "getrandom(64)");
	uint8_t zeros[64];
	memset(zeros, 0, sizeof(zeros));
	TEST_ASSERT(memcmp(kbuf, zeros, sizeof(kbuf)) != 0, "getrandom returned all zeros");
}

static void test_shamir_and_share_vectors(void)
{
	/*
	 * Known-Answer Test Vector (documented in docs/SHARE_FORMAT.md §5):
	 *   threshold k = 3, shares n = 5
	 *   secret[j]   = j           (00010203...1f)
	 *   a_{j,1}     = 0x20 + j
	 *   a_{j,2}     = 0x40 + j
	 *   set_id      = 7f3a9c0e5b21d846
	 */
	uint8_t secret[SHARDKEY_SECRET_LEN];
	uint8_t coeffs[SHARDKEY_SECRET_LEN * 2u];
	uint8_t set_id[SHARDKEY_SET_ID_LEN];
	uint8_t fp[SHARDKEY_FINGERPRINT_LEN];
	uint8_t shares[5][SHARDKEY_SECRET_LEN];

	for (size_t j = 0u; j < SHARDKEY_SECRET_LEN; j++) {
		secret[j] = (uint8_t)j;
		coeffs[j * 2u]      = (uint8_t)(0x20u + j);
		coeffs[j * 2u + 1u] = (uint8_t)(0x40u + j);
	}
	hex_to_bytes("7f3a9c0e5b21d846", set_id, sizeof(set_id));

	TEST_ASSERT(share_fmt_fingerprint(secret, fp) == SHARE_FMT_OK, "fingerprint");
	char fp_hex[17];
	share_fmt_hex_encode(fp, sizeof(fp), fp_hex);
	TEST_ASSERT(strcmp(fp_hex, "2ff70fe219b3a5a5") == 0,
	            "unexpected fingerprint: %s", fp_hex);

	TEST_ASSERT(shamir_split(secret, coeffs, 3u, 5u, shares) == 0, "shamir_split 3-of-5");
	TEST_ASSERT(shamir_verify_all_subsets(secret,
	                                      (const uint8_t (*)[32])shares,
	                                      3u, 5u) == 0,
	            "shamir_verify_all_subsets 3-of-5");

	static const char *expected_share_files[5] = {
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 1\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n"
		"check: 2a2c1d24961824fd\n",

		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 2\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 5b5c55524740494e63646d6a7f7871762b2c25223730393e13141d1a0f080106\n"
		"check: 329ee93a25f4e0b1\n",

		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 3\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 3b3c35322720292e03040d0a1f1811164b4c45425750595e73747d7a6f686166\n"
		"check: 1a9f79aa28038b9b\n",

		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 4\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: ecf9c6d3b8ad928744516e7b10053a2fa7b28d98f3e6d9cc0f1a25305b4e7164\n"
		"check: c5e32e514b485b28\n",

		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 5\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 8c99a6b3d8cdf2e724310e1b70655a4fc7d2edf89386b9ac6f7a45503b2e1104\n"
		"check: ce679027135570be\n"
	};

	struct shardkey_share_record parsed_recs[5];

	for (uint8_t i = 0u; i < 5u; i++) {
		struct shardkey_share_record rec;
		memset(&rec, 0, sizeof(rec));
		rec.threshold = 3u;
		rec.shares = 5u;
		rec.index = (uint8_t)(i + 1u);
		memcpy(rec.set_id, set_id, sizeof(set_id));
		memcpy(rec.fingerprint, fp, sizeof(fp));
		memcpy(rec.data, shares[i], SHARDKEY_SECRET_LEN);

		char buf[SHARDKEY_SHARE_BUF_MAX];
		size_t len = 0u;
		TEST_ASSERT(share_fmt_encode(&rec, buf, sizeof(buf), &len) == SHARE_FMT_OK,
		            "encode share %u", (unsigned int)(i + 1u));
		TEST_ASSERT(strcmp(buf, expected_share_files[i]) == 0,
		            "share %u mismatch:\ngot:\n%s\nexpected:\n%s",
		            (unsigned int)(i + 1u), buf, expected_share_files[i]);

		TEST_ASSERT(share_fmt_parse(buf, len, &parsed_recs[i]) == SHARE_FMT_OK,
		            "parse share %u", (unsigned int)(i + 1u));
		TEST_ASSERT(parsed_recs[i].threshold == 3u &&
		            parsed_recs[i].shares == 5u &&
		            parsed_recs[i].index == (uint8_t)(i + 1u) &&
		            memcmp(parsed_recs[i].set_id, set_id, 8u) == 0 &&
		            memcmp(parsed_recs[i].fingerprint, fp, 8u) == 0 &&
		            memcmp(parsed_recs[i].data, shares[i], 32u) == 0,
		            "parsed share %u fields mismatch", (unsigned int)(i + 1u));

		/* Flipping any single character in buf must fail share_fmt_parse */
		for (size_t pos = 0u; pos < len; pos++) {
			if (buf[pos] == '\n') {
				continue;
			}
			char orig = buf[pos];
			buf[pos] = (orig == 'a') ? 'b' : 'a';
			struct shardkey_share_record bad_rec;
			int prc = share_fmt_parse(buf, len, &bad_rec);
			TEST_ASSERT(prc != SHARE_FMT_OK,
			            "corrupted char at pos %zu in share %u was not rejected",
			            pos, (unsigned int)(i + 1u));
			buf[pos] = orig;
		}
	}

	TEST_ASSERT(share_fmt_validate_set(parsed_recs, 5u) == SHARE_FMT_OK,
	            "validate full set of 5");
	TEST_ASSERT(share_fmt_validate_set(parsed_recs, 3u) == SHARE_FMT_OK,
	            "validate subset of 3");
	TEST_ASSERT(share_fmt_validate_set(parsed_recs, 2u) == SHARE_FMT_ERR_TOO_FEW,
	            "reject subset of 2 < threshold 3");

	/* Duplicate index rejection */
	struct shardkey_share_record dup_recs[3] = {
		parsed_recs[0], parsed_recs[1], parsed_recs[0]
	};
	TEST_ASSERT(share_fmt_validate_set(dup_recs, 3u) == SHARE_FMT_ERR_DUPLICATE_IDX,
	            "reject duplicate share index");

	/* Mismatched set-id rejection */
	struct shardkey_share_record mismatch_recs[3] = {
		parsed_recs[0], parsed_recs[1], parsed_recs[2]
	};
	mismatch_recs[2].set_id[0] ^= 0xffu;
	TEST_ASSERT(share_fmt_validate_set(mismatch_recs, 3u) == SHARE_FMT_ERR_SET_MISMATCH,
	            "reject mismatched set-id");

	/* Test zero top coefficients explicitly (degree collapse must still rebuild) */
	memset(coeffs, 0, sizeof(coeffs));
	TEST_ASSERT(shamir_split(secret, coeffs, 3u, 5u, shares) == 0, "split zero coeffs");
	TEST_ASSERT(shamir_verify_all_subsets(secret,
	                                      (const uint8_t (*)[32])shares,
	                                      3u, 5u) == 0,
	            "verify_all_subsets with zero coeffs");

	/* Test across multiple (n, k) configurations including max n=16, k=9 */
	static const uint8_t configs[][2] = {
		{ 2u, 2u },
		{ 3u, 2u },
		{ 3u, 3u },
		{ 5u, 3u },
		{ 7u, 4u },
		{ 10u, 6u },
		{ 16u, 9u },
		{ 16u, 16u }
	};

	uint8_t seed[32];
	sha256_oneshot("SHARDKEY-TEST-SEED", 18u, seed);

	for (size_t c = 0u; c < sizeof(configs) / sizeof(configs[0]); c++) {
		uint8_t n = configs[c][0];
		uint8_t k = configs[c][1];
		uint8_t c_secret[32];
		uint8_t c_coeffs[SHARDKEY_MAX_COEFF_BYTES];
		uint8_t c_setid[8];
		uint8_t c_shares[SHARDKEY_MAX_SHARES][32];

		TEST_ASSERT(entropy_derive_ceremony(seed, k, c_secret, c_coeffs, c_setid) == 0,
		            "derive for %u-of-%u", (unsigned int)k, (unsigned int)n);
		TEST_ASSERT(shamir_split(c_secret, c_coeffs, k, n, c_shares) == 0,
		            "split for %u-of-%u", (unsigned int)k, (unsigned int)n);
		TEST_ASSERT(shamir_verify_all_subsets(c_secret,
		                                      (const uint8_t (*)[32])c_shares,
		                                      k, n) == 0,
		            "verify_all_subsets for %u-of-%u", (unsigned int)k, (unsigned int)n);

		/* Corrupting 1 share must cause shamir_verify_all_subsets to fail */
		c_shares[n - 1u][15] ^= 0x01u;
		TEST_ASSERT(shamir_verify_all_subsets(c_secret,
		                                      (const uint8_t (*)[32])c_shares,
		                                      k, n) == -1,
		            "corrupted share must fail subset verification for %u-of-%u",
		            (unsigned int)k, (unsigned int)n);
	}
}

static void test_secmem(void)
{
	/* Lockdown without requiring mlockall (since ASan maps huge shadow memory) */
	TEST_ASSERT(secmem_lockdown(false) == 0, "secmem_lockdown(false)");

	struct shardkey_secpool *pool = secmem_pool();
	memset(pool->secret, 0x5au, sizeof(pool->secret));
	secmem_wipe_all();

	uint8_t zeros[SHARDKEY_SECRET_LEN];
	memset(zeros, 0, sizeof(zeros));
	TEST_ASSERT(secmem_ct_equal(pool->secret, zeros, sizeof(zeros)) == 1,
	            "secmem_wipe_all must zero secret");

	uint8_t a[32], b[32];
	memset(a, 0xaa, sizeof(a));
	memset(b, 0xaa, sizeof(b));
	TEST_ASSERT(secmem_ct_equal(a, b, sizeof(a)) == 1, "ct_equal identical");
	b[0] ^= 0x01u;
	TEST_ASSERT(secmem_ct_equal(a, b, sizeof(a)) == 0, "ct_equal diff at 0");
	b[0] ^= 0x01u;
	b[31] ^= 0x80u;
	TEST_ASSERT(secmem_ct_equal(a, b, sizeof(a)) == 0, "ct_equal diff at 31");
}

static void test_drive_and_ui(void)
{
	char tmp_tpl[] = "/tmp/shardkey-test-XXXXXX";
	char *tmp_root = mkdtemp(tmp_tpl);
	TEST_ASSERT(tmp_root != NULL, "mkdtemp");

	char sys_block[128];
	char sys_devs[128];
	char dev_dir[128];
	char mnt_dir[128];

	snprintf(sys_block, sizeof(sys_block), "%s/sys/block", tmp_root);
	snprintf(sys_devs, sizeof(sys_devs), "%s/sys/devices", tmp_root);
	snprintf(dev_dir, sizeof(dev_dir), "%s/dev", tmp_root);
	snprintf(mnt_dir, sizeof(mnt_dir), "%s/mnt", tmp_root);

	/* Create synthetic sysfs layout with 1 internal SATA disk (sda) and 1 USB disk (sdb) */
	char cmd[2048];
	snprintf(cmd, sizeof(cmd),
	         "mkdir -p '%s' '%s/pci0000:00/ata1/block/sda/device' "
	         "'%s/pci0000:00/usb1/1-1/block/sdb/device' '%s' '%s'",
	         sys_block, sys_devs, sys_devs, dev_dir, mnt_dir);
	TEST_ASSERT(system(cmd) == 0, "mkdir synthetic sysfs");

	snprintf(cmd, sizeof(cmd),
	         "ln -s '../devices/pci0000:00/ata1/block/sda' '%s/sda' && "
	         "ln -s '../devices/pci0000:00/usb1/1-1/block/sdb' '%s/sdb' && "
	         "printf '15633408\\n' > '%s/pci0000:00/usb1/1-1/block/sdb/size' && "
	         "printf 'SanDisk \\n' > '%s/pci0000:00/usb1/1-1/block/sdb/device/vendor' && "
	         "printf 'Cruzer Blade\\n' > '%s/pci0000:00/usb1/1-1/block/sdb/device/model'",
	         sys_block, sys_block, sys_devs, sys_devs, sys_devs);
	TEST_ASSERT(system(cmd) == 0, "populate synthetic sysfs");

	TEST_ASSERT(!drive_is_usb_block(sys_block, "sda"), "SATA sda must not be USB");
	TEST_ASSERT(drive_is_usb_block(sys_block, "sdb"), "USB sdb must be detected as USB");
	TEST_ASSERT(!drive_is_usb_block(sys_block, "nvme0n1"), "nvme0n1 must not be USB");

	struct drive_info list[4];
	size_t count = 0u;
	TEST_ASSERT(drive_scan_usb(sys_block, dev_dir, list, 4u, &count) == 0, "drive_scan_usb");
	TEST_ASSERT(count == 1u, "expected 1 USB drive, got %zu", count);
	TEST_ASSERT(strcmp(list[0].name, "sdb") == 0, "expected sdb");
	TEST_ASSERT(strcmp(list[0].vendor, "SanDisk") == 0, "vendor='%s'", list[0].vendor);
	TEST_ASSERT(strcmp(list[0].model, "Cruzer Blade") == 0, "model='%s'", list[0].model);
	TEST_ASSERT(list[0].size_bytes == 15633408ULL * 512ULL, "size_bytes mismatch");

	/* Test drive_write_files_in_dir and drive_verify_files_in_dir */
	struct shardkey_share_record rec;
	memset(&rec, 0, sizeof(rec));
	rec.threshold = 3u;
	rec.shares = 5u;
	rec.index = 1u;
	memset(rec.set_id, 0x11u, sizeof(rec.set_id));
	memset(rec.fingerprint, 0x22u, sizeof(rec.fingerprint));
	memset(rec.data, 0x33u, sizeof(rec.data));

	char share_buf[SHARDKEY_SHARE_BUF_MAX];
	char verify_buf[SHARDKEY_SHARE_BUF_MAX];
	char readme_buf[1024];
	size_t share_len = 0u;
	size_t readme_len = 0u;

	TEST_ASSERT(share_fmt_encode(&rec, share_buf, sizeof(share_buf), &share_len) == SHARE_FMT_OK,
	            "encode for drive test");
	TEST_ASSERT(share_fmt_readme(1u, 3u, 5u, rec.set_id, rec.fingerprint,
	                             readme_buf, sizeof(readme_buf), &readme_len) == SHARE_FMT_OK,
	            "readme for drive test");

	TEST_ASSERT(drive_write_files_in_dir(mnt_dir, 1u, 5u,
	                                     share_buf, share_len,
	                                     readme_buf, readme_len) == 0,
	            "drive_write_files_in_dir");
	TEST_ASSERT(drive_verify_files_in_dir(mnt_dir, 1u, 5u,
	                                      share_buf, share_len,
	                                      verify_buf, sizeof(verify_buf)) == 0,
	            "drive_verify_files_in_dir valid");

	/* Tamper with the written share file on disk and confirm verification fails */
	char share_path[256];
	snprintf(share_path, sizeof(share_path), "%s/shardkey-share-1-of-5.txt", mnt_dir);
	int fd = open(share_path, O_RDWR);
	TEST_ASSERT(fd >= 0, "open share file for tamper test");
	TEST_ASSERT(lseek(fd, 120, SEEK_SET) == 120, "lseek");
	TEST_ASSERT(write(fd, "0", 1u) == 1, "tamper write");
	close(fd);

	TEST_ASSERT(drive_verify_files_in_dir(mnt_dir, 1u, 5u,
	                                      share_buf, share_len,
	                                      verify_buf, sizeof(verify_buf)) != 0,
	            "tampered share file must fail verification");

	/* Test UI policy prompt & dice collector via memory streams */
	const char *policy_input = "5\n2\n5\nYES\nYES\n";
	char ui_out_buf[4096];
	memset(ui_out_buf, 0, sizeof(ui_out_buf));
	FILE *in_fp = fmemopen((void *)policy_input, strlen(policy_input), "r");
	FILE *out_fp = fmemopen(ui_out_buf, sizeof(ui_out_buf) - 1u, "w");
	TEST_ASSERT(in_fp != NULL && out_fp != NULL, "fmemopen policy");

	uint8_t chosen_n = 0u, chosen_k = 0u;
	TEST_ASSERT(ui_prompt_policy(in_fp, out_fp, &chosen_n, &chosen_k) == 0,
	            "ui_prompt_policy");
	fclose(in_fp);
	fclose(out_fp);
	TEST_ASSERT(chosen_n == 5u && chosen_k == 5u, "expected 5-of-5");
	TEST_ASSERT(strstr(ui_out_buf, "Refused: threshold k cannot be below a majority") != NULL,
	            "expected refusal message for k=2");
	TEST_ASSERT(strstr(ui_out_buf, "WARNING: k = n") != NULL,
	            "expected k=n warning message");

	/* UI dice test: ensure dice digits are never echoed to output */
	char dice_input[128];
	for (size_t i = 0u; i < 100u; i++) {
		dice_input[i] = (char)('1' + (i % 6u));
	}
	dice_input[100] = '\n';
	dice_input[101] = '\0';

	memset(ui_out_buf, 0, sizeof(ui_out_buf));
	in_fp = fmemopen(dice_input, strlen(dice_input), "r");
	out_fp = fmemopen(ui_out_buf, sizeof(ui_out_buf) - 1u, "w");
	uint8_t collected[SHARDKEY_MAX_DICE_ROLLS];
	size_t collected_len = 0u;
	TEST_ASSERT(ui_collect_dice(in_fp, out_fp, collected,
	                            sizeof(collected), &collected_len) == 0,
	            "ui_collect_dice");
	fclose(in_fp);
	fclose(out_fp);
	TEST_ASSERT(collected_len == 100u, "expected 100 rolls collected");
	TEST_ASSERT(strstr(ui_out_buf, "123456") == NULL,
	            "dice rolls must never be echoed in UI output");

	/* UI dice CRLF + subsequent prompt continuity test */
	char crlf_dice_and_yes[140];
	for (size_t i = 0u; i < 100u; i++) {
		crlf_dice_and_yes[i] = (char)('1' + (i % 6u));
	}
	memcpy(crlf_dice_and_yes + 100u, "\r\nYES\r\n", 8u);
	in_fp = fmemopen(crlf_dice_and_yes, strlen(crlf_dice_and_yes), "r");
	out_fp = fmemopen(ui_out_buf, sizeof(ui_out_buf) - 1u, "w");
	TEST_ASSERT(ui_collect_dice(in_fp, out_fp, collected,
	                            sizeof(collected), &collected_len) == 0,
	            "ui_collect_dice CRLF");
	TEST_ASSERT(collected_len == 100u, "expected 100 rolls with CRLF");
	TEST_ASSERT(ui_confirm_erase_drive(in_fp, out_fp, 1u, 3u, &list[0]) == 1,
	            "CRLF after dice rolls must not leave stray LF that breaks next prompt");
	fclose(in_fp);
	fclose(out_fp);

	/* UI dice > 1024 rolls (DICE_FULL) + Enter + subsequent prompt continuity test */
	char full_dice_and_yes[1100];
	for (size_t i = 0u; i < 1050u; i++) {
		full_dice_and_yes[i] = (char)('1' + (i % 6u));
	}
	memcpy(full_dice_and_yes + 1050u, "\nYES\n", 6u);
	in_fp = fmemopen(full_dice_and_yes, strlen(full_dice_and_yes), "r");
	out_fp = fmemopen(ui_out_buf, sizeof(ui_out_buf) - 1u, "w");
	TEST_ASSERT(ui_collect_dice(in_fp, out_fp, collected,
	                            sizeof(collected), &collected_len) == 0,
	            "ui_collect_dice DICE_FULL");
	TEST_ASSERT(collected_len == SHARDKEY_MAX_DICE_ROLLS, "expected 1024 rolls capped");
	TEST_ASSERT(ui_confirm_erase_drive(in_fp, out_fp, 1u, 3u, &list[0]) == 1,
	            "excess rolls after DICE_FULL must not corrupt next prompt");
	fclose(in_fp);
	fclose(out_fp);

	/* Test drive_inspect_existing_dir (earlier share and boot stick detection) */
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'/*", mnt_dir);
	TEST_ASSERT(system(cmd) == 0, "clean mnt_dir");
	TEST_ASSERT(drive_write_files_in_dir(mnt_dir, 1u, 5u,
	                                     share_buf, share_len,
	                                     readme_buf, readme_len) == 0,
	            "re-write share 1 for inspect test");
	TEST_ASSERT(drive_inspect_existing_dir(mnt_dir, 2u, 5u, rec.set_id) == DRIVE_EXISTING_EARLIER_SHARE,
	            "must detect share 1 from current ceremony");
	uint8_t other_set_id[SHARDKEY_SET_ID_LEN];
	memset(other_set_id, 0x99u, sizeof(other_set_id));
	TEST_ASSERT(drive_inspect_existing_dir(mnt_dir, 2u, 5u, other_set_id) == DRIVE_EXISTING_NONE,
	            "share from different ceremony set_id must not trigger earlier-share refusal");

	snprintf(cmd, sizeof(cmd), "mkdir -p '%s/shardkey' && touch '%s/shardkey/bzImage'",
	         mnt_dir, mnt_dir);
	TEST_ASSERT(system(cmd) == 0, "create boot stick marker");
	TEST_ASSERT(drive_inspect_existing_dir(mnt_dir, 1u, 5u, rec.set_id) == DRIVE_EXISTING_BOOT_STICK,
	            "must detect ShardKey boot stick marker");

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmp_root);
	TEST_ASSERT(system(cmd) == 0, "cleanup tmp_root");
}

struct sim_ceremony_state {
	char    tmp_root[128];
	char    sys_block[160];
	char    sys_devs[160];
	char    dev_dir[160];
	char    mnt_dir[160];
	char    saved_shares[4][SHARDKEY_SHARE_BUF_MAX];
	size_t  saved_lens[4];
	int     share1_insert_step;
	int     share2_insert_step;
	int     share2_verify_step;
	bool    trigger_sigint_on_share1;
};

static void sim_plug_usb(const struct sim_ceremony_state *st, const char *dev_name)
{
	char cmd[2048];
	snprintf(cmd, sizeof(cmd),
	         "mkdir -p '%s/pci0000:00/usb1/1-1/block/%s/device' && "
	         "printf '1048576\\n' > '%s/pci0000:00/usb1/1-1/block/%s/size' && "
	         "printf 'ShardKey\\n' > '%s/pci0000:00/usb1/1-1/block/%s/device/vendor' && "
	         "printf 'TestUSB\\n' > '%s/pci0000:00/usb1/1-1/block/%s/device/model' && "
	         "ln -sf '../devices/pci0000:00/usb1/1-1/block/%s' '%s/%s'",
	         st->sys_devs, dev_name,
	         st->sys_devs, dev_name,
	         st->sys_devs, dev_name,
	         st->sys_devs, dev_name,
	         dev_name, st->sys_block, dev_name);
	TEST_ASSERT(system(cmd) == 0, "sim_plug_usb system failed");
}

static void sim_unplug_all_usb(const struct sim_ceremony_state *st)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'/sd*", st->sys_block);
	TEST_ASSERT(system(cmd) == 0, "sim_unplug_all_usb system failed");
}

static void sim_drive_event_cb(const char *event, uint8_t share_idx, void *user_data)
{
	struct sim_ceremony_state *st = (struct sim_ceremony_state *)user_data;
	char cmd[1024];

	if (strcmp(event, "wait_boot_removed") == 0 ||
	    strcmp(event, "wait_all_removed") == 0 ||
	    strcmp(event, "wait_removed_declined") == 0 ||
	    strcmp(event, "wait_removed_reinsert") == 0) {
		sim_unplug_all_usb(st);
		return;
	}

	if (strcmp(event, "wait_removed_done") == 0) {
		/* Save a copy of the verified share file before unplugging */
		char fname[64];
		char fpath[512];
		if (share_fmt_filename(share_idx, 3u, fname, sizeof(fname)) == SHARE_FMT_OK) {
			snprintf(fpath, sizeof(fpath), "%s/%s", st->mnt_dir, fname);
			int fd = open(fpath, O_RDONLY);
			if (fd >= 0) {
				ssize_t r = read(fd, st->saved_shares[share_idx],
				                 sizeof(st->saved_shares[share_idx]) - 1u);
				if (r > 0) {
					st->saved_shares[share_idx][r] = '\0';
					st->saved_lens[share_idx] = (size_t)r;
				}
				close(fd);
			}
		}
		sim_unplug_all_usb(st);
		return;
	}

	if (strcmp(event, "wait_inserted_write") == 0) {
		if (st->trigger_sigint_on_share1 && share_idx == 1u) {
			raise(SIGINT);
			return;
		}
		snprintf(cmd, sizeof(cmd), "rm -rf '%s'/*", st->mnt_dir);
		TEST_ASSERT(system(cmd) == 0, "clean mnt_dir");

		if (share_idx == 1u) {
			st->share1_insert_step++;
			if (st->share1_insert_step == 1) {
				/* Attempt 1: accidentally insert the boot stick */
				snprintf(cmd, sizeof(cmd),
				         "mkdir -p '%s/shardkey' && touch '%s/shardkey/bzImage'",
				         st->mnt_dir, st->mnt_dir);
				TEST_ASSERT(system(cmd) == 0, "create mock boot stick marker");
				sim_plug_usb(st, "sda");
				return;
			}
			sim_plug_usb(st, "sdb");
			return;
		}

		if (share_idx == 2u) {
			st->share2_insert_step++;
			if (st->share2_insert_step == 1) {
				/* Attempt 1: accidentally re-insert Share 1's drive */
				char fpath[512];
				snprintf(fpath, sizeof(fpath),
				         "%s/shardkey-share-1-of-3.txt", st->mnt_dir);
				int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
				if (fd >= 0) {
					ssize_t wr = write(fd, st->saved_shares[1], st->saved_lens[1]);
					TEST_ASSERT(wr == (ssize_t)st->saved_lens[1], "write saved share 1");
					close(fd);
				}
				sim_plug_usb(st, "sdb");
				return;
			}
			sim_plug_usb(st, "sdc");
			return;
		}

		sim_plug_usb(st, "sdd");
		return;
	}

	if (strcmp(event, "wait_inserted_verify") == 0) {
		if (share_idx == 1u) {
			sim_plug_usb(st, "sdb");
		} else if (share_idx == 2u) {
			st->share2_verify_step++;
			if (st->share2_verify_step == 1) {
				/* Corrupt 1 byte on disk before read-back verification */
				char fpath[512];
				snprintf(fpath, sizeof(fpath),
				         "%s/shardkey-share-2-of-3.txt", st->mnt_dir);
				int fd = open(fpath, O_RDWR);
				if (fd >= 0) {
					(void)lseek(fd, 120, SEEK_SET);
					ssize_t wr = write(fd, "0", 1u);
					TEST_ASSERT(wr == 1, "corrupt 1 byte");
					close(fd);
				}
			}
			sim_plug_usb(st, "sdc");
		} else {
			sim_plug_usb(st, "sdd");
		}
	}
}

static void test_ceremony_end_to_end(void)
{
	struct sim_ceremony_state st;
	memset(&st, 0, sizeof(st));
	snprintf(st.tmp_root, sizeof(st.tmp_root), "/tmp/shardkey-ceremony-XXXXXX");
	TEST_ASSERT(mkdtemp(st.tmp_root) != NULL, "mkdtemp ceremony");

	snprintf(st.sys_block, sizeof(st.sys_block), "%s/sys/block", st.tmp_root);
	snprintf(st.sys_devs, sizeof(st.sys_devs), "%s/sys/devices", st.tmp_root);
	snprintf(st.dev_dir, sizeof(st.dev_dir), "%s/dev", st.tmp_root);
	snprintf(st.mnt_dir, sizeof(st.mnt_dir), "%s/mnt", st.tmp_root);

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s' '%s' '%s' '%s'",
	         st.sys_block, st.sys_devs, st.dev_dir, st.mnt_dir);
	TEST_ASSERT(system(cmd) == 0, "mkdir ceremony dirs");

	/* Start with boot stick sda present so wait_boot_removed is exercised */
	sim_plug_usb(&st, "sda");

	/*
	 * Build scripted ceremony input:
	 *   1. "\n" (Remove boot stick prompt)
	 *   2. "3\nM\nYES\n" (2-of-3 policy)
	 *   3. 100 dice rolls + "\r\n"
	 *   4. Share 1:
	 *      - "\n" (retry after boot stick refused)
	 *      - "NO\n" (decline erase on first prompt)
	 *      - "YES\n" (confirm erase on second prompt)
	 *   5. Share 2:
	 *      - "\n" (retry after Share 1 drive refused)
	 *      - "YES\n" (confirm erase for attempt 1)
	 *      - "\n" (retry after read-back corruption on attempt 1)
	 *      - "YES\n" (confirm erase for attempt 2)
	 *   6. Share 3:
	 *      - "YES\n" (confirm erase)
	 */
	char input_buf[512];
	size_t pos = 0u;
	pos += (size_t)snprintf(input_buf + pos, sizeof(input_buf) - pos,
	                        "\n3\nM\nYES\n");
	for (size_t i = 0u; i < 100u; i++) {
		input_buf[pos++] = (char)('1' + (i % 6u));
	}
	pos += (size_t)snprintf(input_buf + pos, sizeof(input_buf) - pos,
	                        "\r\n"
	                        "\nNO\nYES\n"
	                        "\nYES\n\nYES\n"
	                        "YES\n");

	char out_buf[16384];
	char err_buf[4096];
	memset(out_buf, 0, sizeof(out_buf));
	memset(err_buf, 0, sizeof(err_buf));

	FILE *in_fp = fmemopen(input_buf, pos, "r");
	FILE *out_fp = fmemopen(out_buf, sizeof(out_buf) - 1u, "w");
	FILE *err_fp = fmemopen(err_buf, sizeof(err_buf) - 1u, "w");
	TEST_ASSERT(in_fp != NULL && out_fp != NULL && err_fp != NULL, "fmemopen ceremony");

	struct shardkey_ceremony_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.in = in_fp;
	cfg.out = out_fp;
	cfg.err = err_fp;
	cfg.sys_block_dir = st.sys_block;
	cfg.dev_dir = st.dev_dir;
	cfg.mount_dir = st.mnt_dir;
	cfg.prep_script = "/bin/true";
	cfg.poll_ms = 0u;
	cfg.require_mlock = false;
	cfg.skip_mount_syscalls = true;
	cfg.on_drive_event = sim_drive_event_cb;
	cfg.user_data = &st;

	secmem_clear_interrupted();
	int rc = shardkey_ceremony_run(&cfg);
	fclose(in_fp);
	fclose(out_fp);
	fclose(err_fp);

	TEST_ASSERT(rc == 0, "shardkey_ceremony_run failed (rc=%d, err=%s)", rc, err_buf);
	TEST_ASSERT(strstr(out_buf, "appears to be the ShardKey boot stick") != NULL,
	            "expected boot stick refusal message");
	TEST_ASSERT(strstr(out_buf, "already contains an earlier share from this ceremony") != NULL,
	            "expected earlier-share refusal message");
	TEST_ASSERT(strstr(out_buf, "read-back verification failed") != NULL,
	            "expected read-back corruption error message");
	TEST_ASSERT(strstr(out_buf, "All 3 shares written and verified.") != NULL,
	            "expected ceremony completion message");

	/* Parse all 3 written share files and verify all 2-of-3 subsets rebuild the secret */
	struct shardkey_share_record recs[3];
	for (uint8_t idx = 1u; idx <= 3u; idx++) {
		TEST_ASSERT(st.saved_lens[idx] > 0u, "saved share %u empty", (unsigned int)idx);
		TEST_ASSERT(share_fmt_parse(st.saved_shares[idx], st.saved_lens[idx],
		                            &recs[idx - 1u]) == SHARE_FMT_OK,
		            "parse saved share %u", (unsigned int)idx);
	}
	TEST_ASSERT(share_fmt_validate_set(recs, 3u) == SHARE_FMT_OK, "validate 3 ceremony shares");

	uint8_t rebuilt_12[32], rebuilt_13[32], rebuilt_23[32];
	uint8_t x12[2] = { recs[0].index, recs[1].index };
	uint8_t y12[2][32];
	memcpy(y12[0], recs[0].data, 32u);
	memcpy(y12[1], recs[1].data, 32u);

	uint8_t x13[2] = { recs[0].index, recs[2].index };
	uint8_t y13[2][32];
	memcpy(y13[0], recs[0].data, 32u);
	memcpy(y13[1], recs[2].data, 32u);

	uint8_t x23[2] = { recs[1].index, recs[2].index };
	uint8_t y23[2][32];
	memcpy(y23[0], recs[1].data, 32u);
	memcpy(y23[1], recs[2].data, 32u);

	TEST_ASSERT(shamir_combine(x12, (const uint8_t (*)[32])y12, 2u, rebuilt_12) == 0, "combine 1,2");
	TEST_ASSERT(shamir_combine(x13, (const uint8_t (*)[32])y13, 2u, rebuilt_13) == 0, "combine 1,3");
	TEST_ASSERT(shamir_combine(x23, (const uint8_t (*)[32])y23, 2u, rebuilt_23) == 0, "combine 2,3");
	TEST_ASSERT(memcmp(rebuilt_12, rebuilt_13, 32u) == 0 &&
	            memcmp(rebuilt_12, rebuilt_23, 32u) == 0,
	            "all 2-subsets must rebuild identical secret");

	uint8_t calc_fp[SHARDKEY_FINGERPRINT_LEN];
	TEST_ASSERT(share_fmt_fingerprint(rebuilt_12, calc_fp) == SHARE_FMT_OK, "calc_fp");
	TEST_ASSERT(memcmp(calc_fp, recs[0].fingerprint, SHARDKEY_FINGERPRINT_LEN) == 0,
	            "rebuilt secret fingerprint must match share fingerprint");

	/* Confirm entire static secret pool is wiped after ceremony completion */
	struct shardkey_secpool zero_pool;
	memset(&zero_pool, 0, sizeof(zero_pool));
	TEST_ASSERT(secmem_ct_equal(secmem_pool(), &zero_pool, sizeof(zero_pool)) == 1,
	            "secmem_pool must be completely zeroed after ceremony");

	/* Test SIGINT interruption during ceremony aborts cleanly and wipes pool */
	sim_unplug_all_usb(&st);
	st.trigger_sigint_on_share1 = true;
	pos = 0u;
	pos += (size_t)snprintf(input_buf + pos, sizeof(input_buf) - pos, "\n2\n2\nYES\nYES\n");
	for (size_t i = 0u; i < 100u; i++) {
		input_buf[pos++] = (char)('1' + (i % 6u));
	}
	input_buf[pos++] = '\n';
	input_buf[pos] = '\0';

	memset(out_buf, 0, sizeof(out_buf));
	memset(err_buf, 0, sizeof(err_buf));
	in_fp = fmemopen(input_buf, pos, "r");
	out_fp = fmemopen(out_buf, sizeof(out_buf) - 1u, "w");
	err_fp = fmemopen(err_buf, sizeof(err_buf) - 1u, "w");
	cfg.in = in_fp;
	cfg.out = out_fp;
	cfg.err = err_fp;

	secmem_clear_interrupted();
	rc = shardkey_ceremony_run(&cfg);
	fclose(in_fp);
	fclose(out_fp);
	fclose(err_fp);

	TEST_ASSERT(rc != 0, "ceremony interrupted by SIGINT must return non-zero");
	TEST_ASSERT(secmem_interrupted() == SIGINT, "secmem_interrupted must record SIGINT");
	TEST_ASSERT(secmem_ct_equal(secmem_pool(), &zero_pool, sizeof(zero_pool)) == 1,
	            "secmem_pool must be completely zeroed after SIGINT abort");
	secmem_clear_interrupted();

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", st.tmp_root);
	TEST_ASSERT(system(cmd) == 0, "cleanup ceremony tmp_root");
}

static void test_edge_cases(void)
{
	/* 1. Malformed share format edge cases */
	struct shardkey_share_record rec;
	TEST_ASSERT(share_fmt_parse(NULL, 10u, &rec) == SHARE_FMT_ERR_ARG, "NULL buf");
	TEST_ASSERT(share_fmt_parse("", 0u, &rec) == SHARE_FMT_ERR_ARG, "empty buf");

	/* CRLF line endings rejected */
	const char *crlf_share =
		"SHARDKEY-SHARE-V1\r\n"
		"scheme: shamir-gf256\r\n"
		"threshold: 3\r\n"
		"shares: 5\r\n"
		"index: 1\r\n"
		"set-id: 7f3a9c0e5b21d846\r\n"
		"fingerprint: 2ff70fe219b3a5a5\r\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\r\n"
		"check: 2a2c1d24961824fd\r\n";
	TEST_ASSERT(share_fmt_parse(crlf_share, strlen(crlf_share), &rec) == SHARE_FMT_ERR_SYNTAX,
	            "CRLF must be rejected");

	/* Uppercase hex rejected */
	const char *upper_hex_share =
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 1\n"
		"set-id: 7F3A9C0E5B21D846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n"
		"check: 2a2c1d24961824fd\n";
	TEST_ASSERT(share_fmt_parse(upper_hex_share, strlen(upper_hex_share), &rec) == SHARE_FMT_ERR_HEX,
	            "uppercase hex must be rejected");

	/* Policy violation inside share file (threshold < majority) rejected */
	const char *bad_policy_share =
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 2\n"
		"shares: 5\n"
		"index: 1\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n"
		"check: 2a2c1d24961824fd\n";
	TEST_ASSERT(share_fmt_parse(bad_policy_share, strlen(bad_policy_share), &rec) == SHARE_FMT_ERR_POLICY,
	            "threshold below majority in share file must be rejected");

	/* Out-of-range index inside share file rejected */
	const char *bad_index_share =
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 6\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n"
		"check: 2a2c1d24961824fd\n";
	TEST_ASSERT(share_fmt_parse(bad_index_share, strlen(bad_index_share), &rec) == SHARE_FMT_ERR_INDEX,
	            "index > shares in share file must be rejected");

	/* Trailing newline / garbage after check line rejected */
	const char *trailing_garbage =
		"SHARDKEY-SHARE-V1\n"
		"scheme: shamir-gf256\n"
		"threshold: 3\n"
		"shares: 5\n"
		"index: 1\n"
		"set-id: 7f3a9c0e5b21d846\n"
		"fingerprint: 2ff70fe219b3a5a5\n"
		"data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n"
		"check: 2a2c1d24961824fd\n\n";
	TEST_ASSERT(share_fmt_parse(trailing_garbage, strlen(trailing_garbage), &rec) == SHARE_FMT_ERR_SYNTAX,
	            "extra trailing newline must be rejected");

	/* 2. Shamir invalid boundary arguments */
	uint8_t dummy_sec[32] = { 0 };
	uint8_t dummy_coeffs[64] = { 0 };
	uint8_t dummy_shares[4][32];
	TEST_ASSERT(shamir_split(NULL, dummy_coeffs, 2u, 3u, dummy_shares) == -1, "NULL secret");
	TEST_ASSERT(shamir_split(dummy_sec, dummy_coeffs, 1u, 3u, dummy_shares) == -1, "k=1 invalid");
	TEST_ASSERT(shamir_split(dummy_sec, dummy_coeffs, 2u, 17u, dummy_shares) == -1, "n=17 invalid");
	TEST_ASSERT(shamir_split(dummy_sec, dummy_coeffs, 4u, 3u, dummy_shares) == -1, "k>n invalid");

	uint8_t bad_x_zero[2] = { 0u, 1u };
	uint8_t bad_x_dup[2]  = { 2u, 2u };
	TEST_ASSERT(shamir_combine(bad_x_zero, (const uint8_t (*)[32])dummy_shares, 2u, dummy_sec) == -1,
	            "x=0 must be rejected in shamir_combine");
	TEST_ASSERT(shamir_combine(bad_x_dup, (const uint8_t (*)[32])dummy_shares, 2u, dummy_sec) == -1,
	            "duplicate x must be rejected in shamir_combine");

	/* 3. HKDF-Expand boundary lengths (max 255 * 32 = 8160 bytes) */
	uint8_t seed[32] = { 0x42u };
	uint8_t *big_out = malloc(8161u);
	TEST_ASSERT(big_out != NULL, "malloc 8161");
	TEST_ASSERT(entropy_hkdf_expand(seed, "test", 4u, big_out, 8160u) == 0,
	            "max HKDF length 8160 must succeed");
	TEST_ASSERT(entropy_hkdf_expand(seed, "test", 4u, big_out, 8161u) == -1,
	            "HKDF length 8161 (> 255*32) must be rejected");
	free(big_out);

	/* 4. Drive name validation and size formatting */
	TEST_ASSERT(!drive_is_usb_block("/sys/block", "../sda"), "path traversal rejected");
	TEST_ASSERT(!drive_is_usb_block("/sys/block", "sda1"), "partition name rejected");
	TEST_ASSERT(!drive_is_usb_block("/sys/block", "sd"), "bare sd rejected");
	TEST_ASSERT(!drive_is_usb_block("/sys/block", "sdA"), "uppercase sdA rejected");

	char sz_str[32];
	drive_format_size(0ULL, sz_str, sizeof(sz_str));
	TEST_ASSERT(strcmp(sz_str, "0 B") == 0, "0 B format: %s", sz_str);
	drive_format_size(4096ULL, sz_str, sizeof(sz_str));
	TEST_ASSERT(strcmp(sz_str, "4 KiB") == 0, "4 KiB format: %s", sz_str);
	drive_format_size(512ULL * 1024ULL * 1024ULL, sz_str, sizeof(sz_str));
	TEST_ASSERT(strcmp(sz_str, "512.0 MiB") == 0, "512 MiB format: %s", sz_str);
	drive_format_size(8ULL * 1024ULL * 1024ULL * 1024ULL, sz_str, sizeof(sz_str));
	TEST_ASSERT(strcmp(sz_str, "8.0 GiB") == 0, "8 GiB format: %s", sz_str);

	/* 5. Prep script execution via fork+execve */
	TEST_ASSERT(drive_run_prep_script("/bin/true", "/dev/null") == 0, "/bin/true exit 0");
	TEST_ASSERT(drive_run_prep_script("/bin/false", "/dev/null") == -1, "/bin/false exit 1");
	TEST_ASSERT(drive_run_prep_script("/nonexistent/prep-drive.sh", "/dev/null") == -1,
	            "nonexistent script fails");
}

int main(void)
{
	test_gf256_exhaustive();
	test_sha256_and_hmac();
	test_policy();
	test_dice_and_entropy();
	test_shamir_and_share_vectors();
	test_secmem();
	test_drive_and_ui();
	test_ceremony_end_to_end();
	test_edge_cases();

	if (g_failures > 0) {
		fprintf(stderr, "[test_shardkey] FAILED (%d failure(s) out of %d checks).\n",
		        g_failures, g_checks);
		return 1;
	}

	printf("[test_shardkey] PASS: all %d checks succeeded.\n", g_checks);
	return 0;
}
