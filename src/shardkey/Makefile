# SPDX-License-Identifier: GPL-2.0-only
#
# ShardKey C ceremony program and unit test Makefile.
# Reference: docs/PLAN.md (§1 step 5, §4 Phase 2) and docs/DECISIONS.md (D-004).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

SRC_DIR   := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BUILD_DIR ?= $(SRC_DIR)/../../build/tool

ifeq ($(origin CC),default)
CC        := musl-gcc
endif
CC        ?= musl-gcc
HOSTCC    ?= cc

WARN_FLAGS := -std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow -Wstrict-prototypes
CFLAGS     ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 $(WARN_FLAGS)
LDFLAGS    ?= -static

SAN_FLAGS    ?= -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_CFLAGS  ?= -O1 -g $(WARN_FLAGS) $(SAN_FLAGS) -I"$(SRC_DIR)"
TEST_LDFLAGS ?= $(SAN_FLAGS)

LIB_SRCS := \
	secmem.c \
	sha256.c \
	entropy.c \
	policy.c \
	gf256.c \
	shamir.c \
	share_fmt.c \
	drive.c \
	ui.c

TOOL_OBJS          := $(patsubst %.c,$(BUILD_DIR)/obj/%.o,$(LIB_SRCS) main.c)
LIB_TEST_OBJS      := $(patsubst %.c,$(BUILD_DIR)/test-obj/%.o,$(LIB_SRCS))
TEST_OBJS          := $(LIB_TEST_OBJS) \
                      $(BUILD_DIR)/test-obj/main.o \
                      $(BUILD_DIR)/test-obj/test_main.o
COMBINE_CHECK_OBJS := $(LIB_TEST_OBJS) \
                      $(BUILD_DIR)/test-obj/combine_check.o

TARGET_BIN         := $(BUILD_DIR)/shardkey
TEST_BIN           := $(BUILD_DIR)/test_shardkey
COMBINE_CHECK_BIN  := $(BUILD_DIR)/combine_check
MUSL_SYSROOT       := $(BUILD_DIR)/musl-sysroot

.PHONY: all test verify-static ensure-cc clean

all: $(TARGET_BIN) verify-static

ensure-cc:
	@if ! command -v "$(CC)" >/dev/null 2>&1; then \
		if [[ "$(CC)" == "musl-gcc" ]] && \
		   compgen -G "/var/cache/apt/archives/musl-tools_*.deb" >/dev/null && \
		   compgen -G "/var/cache/apt/archives/musl-dev_*.deb" >/dev/null && \
		   compgen -G "/var/cache/apt/archives/musl_*.deb" >/dev/null; then \
			if [[ ! -x "$(MUSL_SYSROOT)/usr/bin/musl-gcc" ]]; then \
				mkdir -p "$(MUSL_SYSROOT)"; \
				for deb in /var/cache/apt/archives/musl_*.deb \
				           /var/cache/apt/archives/musl-dev_*.deb \
				           /var/cache/apt/archives/musl-tools_*.deb; do \
					dpkg-deb -x "$${deb}" "$(MUSL_SYSROOT)"; \
				done; \
				sed -i \
					-e "s|/usr/include/x86_64-linux-musl|$(MUSL_SYSROOT)/usr/include/x86_64-linux-musl|g" \
					-e "s|/usr/lib/x86_64-linux-musl|$(MUSL_SYSROOT)/usr/lib/x86_64-linux-musl|g" \
					-e "s|/lib/ld-musl|$(MUSL_SYSROOT)/lib/ld-musl|g" \
					"$(MUSL_SYSROOT)/usr/lib/x86_64-linux-musl/musl-gcc.specs"; \
				sed -i \
					-e "s|/usr/lib/x86_64-linux-musl/musl-gcc.specs|$(MUSL_SYSROOT)/usr/lib/x86_64-linux-musl/musl-gcc.specs|g" \
					"$(MUSL_SYSROOT)/usr/bin/musl-gcc"; \
			fi; \
		else \
			echo "[shardkey] ERROR: compiler '$(CC)' not found." >&2; \
			exit 1; \
		fi; \
	fi

$(BUILD_DIR)/obj/%.o: $(SRC_DIR)/%.c | ensure-cc
	@mkdir -p "$(dir $@)"
	@cc_bin="$(CC)"; \
	if ! command -v "$${cc_bin}" >/dev/null 2>&1 && [[ -x "$(MUSL_SYSROOT)/usr/bin/musl-gcc" ]]; then \
		cc_bin="$(MUSL_SYSROOT)/usr/bin/musl-gcc"; \
	fi; \
	"$${cc_bin}" $(CFLAGS) -I"$(SRC_DIR)" -c "$<" -o "$@"

$(TARGET_BIN): $(TOOL_OBJS)
	@mkdir -p "$(dir $@)"
	@cc_bin="$(CC)"; \
	if ! command -v "$${cc_bin}" >/dev/null 2>&1 && [[ -x "$(MUSL_SYSROOT)/usr/bin/musl-gcc" ]]; then \
		cc_bin="$(MUSL_SYSROOT)/usr/bin/musl-gcc"; \
	fi; \
	"$${cc_bin}" $(CFLAGS) $(TOOL_OBJS) $(LDFLAGS) -o "$@"

verify-static: $(TARGET_BIN)
	@file_out="$$(file "$(TARGET_BIN)")"; \
	if [[ "$${file_out}" != *"statically linked"* ]]; then \
		echo "[shardkey] ERROR: $(TARGET_BIN) is not statically linked: $${file_out}" >&2; \
		exit 1; \
	fi
	@readelf_out="$$(readelf -d "$(TARGET_BIN)")"; \
	if [[ "$${readelf_out}" != *"There is no dynamic section in this file"* ]]; then \
		echo "[shardkey] ERROR: $(TARGET_BIN) has a dynamic section:" >&2; \
		echo "$${readelf_out}" >&2; \
		exit 1; \
	fi
	@if nm -u $(TOOL_OBJS) | grep -E '\b(malloc|calloc|realloc)\b' >/dev/null 2>&1; then \
		echo "[shardkey] ERROR: $(TARGET_BIN) object files reference heap allocation (malloc/calloc/realloc)!" >&2; \
		exit 1; \
	fi
	@echo "[shardkey] OK: $(TARGET_BIN) is statically linked with no dynamic section and no heap allocations."

$(BUILD_DIR)/test-obj/%.o: $(SRC_DIR)/%.c
	@mkdir -p "$(dir $@)"
	$(HOSTCC) $(TEST_CFLAGS) -DSHARDKEY_TEST_BUILD=1 -c "$<" -o "$@"

$(BUILD_DIR)/test-obj/test_main.o: $(SRC_DIR)/tests/test_main.c
	@mkdir -p "$(dir $@)"
	$(HOSTCC) $(TEST_CFLAGS) -DSHARDKEY_TEST_BUILD=1 -c "$<" -o "$@"

$(BUILD_DIR)/test-obj/combine_check.o: $(SRC_DIR)/tests/combine_check.c
	@mkdir -p "$(dir $@)"
	$(HOSTCC) $(TEST_CFLAGS) -DSHARDKEY_TEST_BUILD=1 -c "$<" -o "$@"

$(TEST_BIN): $(TEST_OBJS)
	@mkdir -p "$(dir $@)"
	$(HOSTCC) $(TEST_CFLAGS) $(TEST_OBJS) $(TEST_LDFLAGS) -o "$@"

$(COMBINE_CHECK_BIN): $(COMBINE_CHECK_OBJS)
	@mkdir -p "$(dir $@)"
	$(HOSTCC) $(TEST_CFLAGS) $(COMBINE_CHECK_OBJS) $(TEST_LDFLAGS) -o "$@"

test: $(TEST_BIN) $(COMBINE_CHECK_BIN)
	"$(TEST_BIN)"

clean:
	@rm -rf "$(BUILD_DIR)/obj" "$(BUILD_DIR)/test-obj" "$(MUSL_SYSROOT)" "$(TARGET_BIN)" "$(TEST_BIN)" "$(COMBINE_CHECK_BIN)"
