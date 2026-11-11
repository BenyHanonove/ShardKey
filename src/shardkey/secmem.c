/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "secmem.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

static _Alignas(64) struct shardkey_secpool g_secpool;
static volatile sig_atomic_t g_interrupted = 0;
static volatile sig_atomic_t g_tty_fd = -1;
static struct termios g_tty_orig;
static bool g_atexit_registered = false;

struct shardkey_secpool *secmem_pool(void)
{
	return &g_secpool;
}

void secmem_zero(void *ptr, size_t len)
{
	if (ptr == NULL || len == 0) {
		return;
	}
	explicit_bzero(ptr, len);
	__asm__ __volatile__("" : : "r"(ptr) : "memory");
}

void secmem_register_tty(int fd, const struct termios *orig)
{
	if (fd < 0 || orig == NULL) {
		return;
	}
	g_tty_orig = *orig;
	g_tty_fd = (sig_atomic_t)fd;
}

void secmem_unregister_tty(void)
{
	g_tty_fd = -1;
}

void secmem_wipe_all(void)
{
	secmem_zero(&g_secpool, sizeof(g_secpool));
	int fd = (int)g_tty_fd;
	if (fd >= 0) {
		g_tty_fd = -1;
		(void)tcsetattr(fd, TCSANOW, &g_tty_orig);
	}
}

int secmem_ct_equal(const void *a, const void *b, size_t len)
{
	const volatile uint8_t *pa = (const volatile uint8_t *)a;
	const volatile uint8_t *pb = (const volatile uint8_t *)b;
	uint32_t diff = 0;

	for (size_t i = 0; i < len; i++) {
		diff |= (uint32_t)(pa[i] ^ pb[i]);
	}
	return (int)(1u & ((diff - 1u) >> 8));
}

sig_atomic_t secmem_interrupted(void)
{
	return g_interrupted;
}

void secmem_clear_interrupted(void)
{
	g_interrupted = 0;
}

static void secmem_signal_handler(int sig)
{
	secmem_wipe_all();
	g_interrupted = (sig_atomic_t)sig;

	/*
	 * For fatal synchronous signals (SIGABRT, SIGSEGV, SIGBUS, SIGFPE, SIGILL),
	 * terminate immediately via _exit after wiping secret memory.
	 */
	if (sig == SIGABRT || sig == SIGSEGV || sig == SIGBUS ||
	    sig == SIGFPE || sig == SIGILL) {
		_exit(128 + sig);
	}
}

int secmem_lockdown(bool require_mlock)
{
	secmem_wipe_all();

	struct rlimit rl;
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl) != 0) {
		return -1;
	}

	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
		return -1;
	}

	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
		if (require_mlock) {
			return -1;
		}
	}

	if (!g_atexit_registered) {
		if (atexit(secmem_wipe_all) != 0) {
			return -1;
		}
		g_atexit_registered = true;
	}

	static const int trapped_sigs[] = {
		SIGINT, SIGTERM, SIGHUP, SIGQUIT,
		SIGABRT, SIGSEGV, SIGBUS, SIGFPE, SIGILL
	};

	for (size_t i = 0; i < sizeof(trapped_sigs) / sizeof(trapped_sigs[0]); i++) {
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = secmem_signal_handler;
		sigfillset(&sa.sa_mask);
		/* No SA_RESTART so blocking reads break out promptly on Ctrl-C */
		sa.sa_flags = 0;
		if (sigaction(trapped_sigs[i], &sa, NULL) != 0) {
			return -1;
		}
	}

	return 0;
}
