# SPDX-License-Identifier: GPL-2.0-only
#
# ShardKey top-level Makefile.
# Out-of-tree intermediates go into build/; release artifacts go into out/.
#
# Reference: docs/PLAN.md (§4) and README.md (§Quick start).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT_DIR    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BUILD_DIR   ?= $(ROOT_DIR)/build
OUT_DIR     ?= $(ROOT_DIR)/out
CONFIG_DIR  := $(ROOT_DIR)/config
SCRIPTS_DIR := $(ROOT_DIR)/scripts

# Export build and output paths plus reproducible build settings
export ROOT_DIR
export BUILD_DIR
export OUT_DIR
export LC_ALL := C
export TZ     := UTC

.DEFAULT_GOAL := all

.PHONY: all check-host fetch tool test-tool busybox rootfs kernel image \
        sign verify usb test clean distclean

all: image

check-host:
	@"$(SCRIPTS_DIR)/check-host.sh" --all

fetch:
	@"$(SCRIPTS_DIR)/check-host.sh" --fetch
	@"$(SCRIPTS_DIR)/fetch.sh"

tool: check-host
	@mkdir -p "$(BUILD_DIR)/tool"
	@if [[ -f "$(ROOT_DIR)/src/shardkey/Makefile" ]]; then \
		$(MAKE) -C "$(ROOT_DIR)/src/shardkey" BUILD_DIR="$(BUILD_DIR)/tool"; \
	else \
		echo "[make] ERROR: src/shardkey/Makefile not yet implemented (Phase 2)." >&2; \
		exit 1; \
	fi

test-tool:
	@mkdir -p "$(BUILD_DIR)/tool-test"
	@if [[ -f "$(ROOT_DIR)/src/shardkey/Makefile" ]]; then \
		$(MAKE) -C "$(ROOT_DIR)/src/shardkey" test BUILD_DIR="$(BUILD_DIR)/tool-test"; \
	else \
		echo "[make] ERROR: src/shardkey/Makefile not yet implemented (Phase 2)." >&2; \
		exit 1; \
	fi

busybox: check-host
	@mkdir -p "$(BUILD_DIR)/busybox"
	@if [[ -x "$(SCRIPTS_DIR)/build-busybox.sh" ]]; then \
		"$(SCRIPTS_DIR)/build-busybox.sh"; \
	else \
		echo "[make] ERROR: scripts/build-busybox.sh not yet implemented (Phase 3)." >&2; \
		exit 1; \
	fi

rootfs: tool busybox
	@mkdir -p "$(BUILD_DIR)/rootfs" "$(OUT_DIR)"
	@if [[ -x "$(SCRIPTS_DIR)/build-rootfs.sh" ]]; then \
		"$(SCRIPTS_DIR)/build-rootfs.sh"; \
	else \
		echo "[make] ERROR: scripts/build-rootfs.sh not yet implemented (Phase 4)." >&2; \
		exit 1; \
	fi

kernel: rootfs
	@mkdir -p "$(BUILD_DIR)/kernel" "$(OUT_DIR)"
	@if [[ -x "$(SCRIPTS_DIR)/build-kernel.sh" ]]; then \
		"$(SCRIPTS_DIR)/build-kernel.sh"; \
	else \
		echo "[make] ERROR: scripts/build-kernel.sh not yet implemented (Phase 5)." >&2; \
		exit 1; \
	fi

image: kernel
	@mkdir -p "$(OUT_DIR)"
	@if [[ -x "$(SCRIPTS_DIR)/build-image.sh" ]]; then \
		"$(SCRIPTS_DIR)/build-image.sh"; \
	elif [[ -f "$(OUT_DIR)/bzImage" || -f "$(OUT_DIR)/bzImage.unsigned" ]]; then \
		echo "[make] Image build complete in $(OUT_DIR)."; \
	else \
		echo "[make] ERROR: image build not yet implemented (Phases 5-7)." >&2; \
		exit 1; \
	fi

sign:
	@if [[ -x "$(SCRIPTS_DIR)/sign.sh" ]]; then \
		"$(SCRIPTS_DIR)/sign.sh" "$${KEY:-}"; \
	else \
		echo "[make] ERROR: scripts/sign.sh not yet implemented (Phase 7)." >&2; \
		exit 1; \
	fi

verify:
	@if [[ -x "$(SCRIPTS_DIR)/verify-release.sh" ]]; then \
		"$(SCRIPTS_DIR)/verify-release.sh"; \
	else \
		echo "[make] ERROR: scripts/verify-release.sh not yet implemented (Phase 7)." >&2; \
		exit 1; \
	fi

usb:
	@if [[ -z "$${DEV:-}" ]]; then \
		echo "[make] ERROR: DEV is required (e.g., sudo make usb DEV=/dev/sdX)." >&2; \
		exit 1; \
	fi
	@if [[ -x "$(SCRIPTS_DIR)/make-usb.sh" ]]; then \
		"$(SCRIPTS_DIR)/make-usb.sh" "$(DEV)"; \
	else \
		echo "[make] ERROR: scripts/make-usb.sh not yet implemented (Phase 7)." >&2; \
		exit 1; \
	fi

test: test-tool
	@if [[ -x "$(SCRIPTS_DIR)/qemu-test.sh" ]]; then \
		"$(SCRIPTS_DIR)/qemu-test.sh"; \
	else \
		echo "[make] ERROR: scripts/qemu-test.sh not yet implemented (Phase 6)." >&2; \
		exit 1; \
	fi

clean:
	@rm -rf "$(OUT_DIR)" \
		"$(BUILD_DIR)/tool" \
		"$(BUILD_DIR)/tool-test" \
		"$(BUILD_DIR)/busybox" \
		"$(BUILD_DIR)/rootfs" \
		"$(BUILD_DIR)/kernel"
	@if [[ -d "$(BUILD_DIR)" ]] && [[ -z "$$(ls -A "$(BUILD_DIR)")" ]]; then \
		rmdir "$(BUILD_DIR)"; \
	fi
	@echo "[make] Cleaned build outputs (preserved $(BUILD_DIR)/src if present; use 'make distclean' to remove downloaded sources)."

distclean:
	@rm -rf "$(BUILD_DIR)" "$(OUT_DIR)"
	@echo "[make] Removed $(BUILD_DIR) and $(OUT_DIR)."
