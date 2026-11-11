# ShardKey — Implementation Plan

This is the full plan for building ShardKey. It starts with a review of the original
11-step outline, then lays out the work in phases with a clear "done when" for each.

Related documents: [DECISIONS.md](DECISIONS.md) · [KERNEL_CONFIG.md](KERNEL_CONFIG.md) ·
[SHARE_FORMAT.md](SHARE_FORMAT.md) · [SIGNING.md](SIGNING.md) · [THREAT_MODEL.md](THREAT_MODEL.md)

---

## 1. Review of the original 11-step outline

The original outline is sound. The changes below fix gaps (things that would stop the
system from booting or working) and a few security weaknesses.

| # | Original step | Verdict | Change and reason |
|---|---|---|---|
| 1 | Download latest stable kernel | **Changed** | Use the latest **LTS** branch, pin the exact point release, and **verify the kernel.org GPG signature**. "Latest stable" changes every week and gets ~3 months of fixes; LTS gets years, and pinning makes builds repeatable. |
| 2 | `make allnoconfig` | **Kept** | Run as `make ARCH=x86_64 allnoconfig KCONFIG_ALLCONFIG=config/kernel/shardkey.config` so the result is driven by a file in git, not by hand. |
| 3 | `make menuconfig` to enable 64-bit, TTY, initramfs, USB, xHCI/EHCI, SCSI disk, FAT | **Changed** | `menuconfig` is only used to explore; the real config is a version-controlled **fragment**. The outline's list is **missing items the system cannot work without**: a keyboard driver (USB HID + PS/2), `BINFMT_SCRIPT` (otherwise the `/init` *script* can't run), `DEVTMPFS`, `PCI` (xHCI/EHCI sit on PCI), `USB_STORAGE` (SCSI disk alone doesn't see flash drives), `NLS` codepages (VFAT won't mount without them), `ACPI` (otherwise "power off" only halts), `EFI_STUB` + an EFI framebuffer console (for UEFI machines). Full list in [KERNEL_CONFIG.md](KERNEL_CONFIG.md). |
| 4 | C program: `getrandom`, Shamir in RAM, verify, `explicit_bzero` | **Kept + extended** | Also: `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, constant-time GF(2⁸) math, verify **every** k-subset, add a per-share checksum. The C program also **owns the whole ceremony loop**, so share bytes never pass through the shell, pipes, or tmpfs files. |
| 5 | Static build with `musl-gcc` | **Kept** | `musl-gcc -static -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Werror`. Also built natively on the host (with sanitizers) for unit tests. |
| 6 | rootfs with static BusyBox + our tool | **Kept** | BusyBox built from `allnoconfig` + only the applets we use (list in §4, Phase 3). |
| 7 | `/init` as PID 1: mount `/proc /sys /dev`, loop over drive insertions, then panic / reboot | **Changed** | `/init` does setup and launches `shardkey`; the **drive loop lives in the C program** (see step 4). Before the ceremony, `/init` requires that **no USB drive is present** (the boot stick must be removed) so the boot stick can never be mistaken for a share drive. Ending changed: see step 11. |
| 8 | `cpio | gzip -9 > initramfs.cpio.gz` | **Kept + changed** | The cpio is made **reproducible** (sorted file list, fixed mtimes, fixed owner) and is **embedded into the kernel** (`CONFIG_INITRAMFS_SOURCE`). One file to boot, no way to swap the initramfs. The standalone `.cpio.gz` is still produced as a build artifact. |
| 9 | `make -j$(nproc) bzImage` | **Kept** | With `KBUILD_BUILD_TIMESTAMP`, `KBUILD_BUILD_USER`, `KBUILD_BUILD_HOST` fixed for repeatable output. |
| 10 | Syslinux boot USB, boot into RAM | **Changed** | Syslinux is used for **BIOS** only. On **UEFI** the kernel's EFI stub boots directly as `\EFI\BOOT\BOOTX64.EFI` — the same `bzImage` file, **signed for Secure Boot** with our own key ([SIGNING.md](SIGNING.md)). One stick boots both. "Boot into RAM" is automatic: an initramfs always lives in RAM. |
| 11 | Crash the kernel (`echo c > /proc/sysrq-trigger`) or forced power cut | **Changed** | A kernel crash does **not** erase RAM — the machine stays powered and memory keeps its contents. A reboot is worse (RAM stays powered, warm-boot attacks). New ending: wipe buffers in the program → drop page cache → kernel zeroes freed pages (`init_on_free=1`) → `poweroff -f` (ACPI). Operator leaves the machine unpowered for several minutes. `MAGIC_SYSRQ` is removed from the kernel entirely. |

## 2. Decisions summary

Full reasoning in [DECISIONS.md](DECISIONS.md).

| Topic | Decision |
|---|---|
| Base system ("distro") | **None — built from scratch**: kernel.org LTS + static BusyBox + our C tool |
| Build machine OS | **Debian 13 (stable)**, x86_64 |
| Kernel | Latest **LTS** branch, exact version pinned in `config/versions.env` |
| C library | **musl**, static (`musl-gcc` from Debian `musl-tools`) |
| Target machines | x86_64, **UEFI and legacy BIOS** |
| Boot | Kernel EFI stub (UEFI) + Syslinux (BIOS); initramfs embedded in kernel |
| Image integrity | **Signed in v1**: Secure Boot signature on the kernel + signed `SHA256SUMS`, one offline RSA-2048 key ([SIGNING.md](SIGNING.md)) |
| Secret | 256-bit random secret |
| Randomness | **Mandatory ≥ 100 dice rolls** mixed with `getrandom()` via SHA-256 / HMAC-SHA256 |
| Sharing scheme | Shamir over GF(2⁸), byte-wise, x = 1..n |
| Threshold | Chosen **on screen** during the ceremony: `n` in 2..16, then `k` = majority (one key) or any number from majority to `n`; `k = n` only after a warning |
| Ceremony | **One boot, one ceremony** produces all n shares (shares depend on the same polynomial) |
| Copies | One drive per share |
| Share drive layout | MBR + one FAT32 partition |
| Per-drive check | Write → "unplug and re-insert" → read back and verify → next |
| Ending | Wipe + **power off** (not reboot, not panic) |
| Recovery tool | **Out of scope** (separate project); we publish the share format |
| License | GPL-2.0-only |
| Docs language | English |

## 3. Ceremony flow (what the operator sees)

```
power on → firmware boots USB stick → kernel + initramfs load into RAM
   │
   ▼
/init (PID 1): mount /proc /sys /dev, set console, lock down
   │
   ▼
"Remove the boot stick and all other USB drives. Press Enter."
   │   (waits until /sys/block has no USB disks)
   ▼
"How many shares (n)? [2-16]"                       → e.g. 5
"Threshold (k): press M for majority (3), or type a number from 3 to 5"
   │   k < majority → refused;  k = n → warning "losing ANY one drive loses the
   │   secret forever", type YES to accept
"Create 3-of-5 shares? Type YES"
   ▼
"Roll a die and type the results (digits 1-6). At least 100 rolls."
   │   shows only a counter (e.g. 37/100); other characters are ignored;
   │   Enter after ≥ 100 rolls finishes
   ▼
shardkey: seed = mix(dice, getrandom) → secret, coefficients, set ID
   │   → split into n shares → verify all k-subsets
   │   shows: "3-of-5, set ID 7F3A…, secret fingerprint 9C21…"
   ▼
for i in 1..n:
   "Insert blank drive for share i/n"            (detect new /sys/block/sdX)
   show size / vendor / model → "Type YES to erase it"
   wipe start of drive → MBR + one FAT32 partition → mkfs.vfat
   mount → write SHARDKEY/SHARE-i-of-n.txt → fsync → umount → sync
   "Unplug the drive, then plug it back in"      (wait for removal, then re-insert)
   mount read-only → read file → compare to RAM copy + checksum → umount
   "Share i/n OK. Unplug and label it 'Share i of n, set 7F3A'."
   │   on any failure: explain, offer to retry the same share on the same/another drive
   ▼
explicit_bzero(all secrets) → exit
   │
   ▼
/init: drop caches → "Done. Powering off." → poweroff -f
```

If `shardkey` exits with an error, is killed, or the operator aborts (Ctrl-C), `/init`
still runs the wipe-and-power-off path. PID 1 never drops to a shell and never exits.

## 4. Phases

Each phase ends with something that can be checked. Phases 2 and 3 can be done in
parallel.

### Phase 0 — Documents (this phase)
- README, LICENSE, PLAN, DECISIONS, KERNEL_CONFIG, SHARE_FORMAT, SIGNING, THREAT_MODEL.
- **Done when:** the questions in §6 are answered and the docs are committed.

### Phase 1 — Build skeleton and pinned sources
- `config/versions.env`: kernel LTS point release, BusyBox version, Syslinux, each with
  SHA-256.
- `scripts/fetch.sh`: downloads into `build/src/`, verifies SHA-256, verifies the
  kernel GPG signature (kernel.org signs the *uncompressed* `.tar`; check against the
  pinned fingerprints of Greg Kroah-Hartman / Linus Torvalds).
- Top-level `Makefile` with targets: `fetch`, `tool`, `busybox`, `rootfs`, `kernel`,
  `image`, `usb`, `test`, `clean`. Out-of-tree builds into `build/`, outputs in `out/`.
- `scripts/check-host.sh`: verifies required Debian packages are installed.
- **Done when:** `make fetch` on a clean Debian 13 gets and verifies everything, and
  fails loudly if a hash or signature is wrong.

### Phase 2 — The `shardkey` C program
Source layout (`src/shardkey/`):

| File | Job |
|---|---|
| `secmem.c/h` | `mlockall(MCL_CURRENT\|MCL_FUTURE)`, `prctl(PR_SET_DUMPABLE,0)`, `setrlimit(RLIMIT_CORE,0)`; a small fixed pool of secret buffers, all wiped with `explicit_bzero` on exit and in signal handlers |
| `entropy.c/h` | `getrandom(buf, len, 0)` with loop on short reads / `EINTR`; refuses `GRND_NONBLOCK` fallback. Dice input (digits 1–6, ≥ 100 rolls). Mixing: `seed = SHA-256("SHARDKEY-SEED-V1" ‖ kernel_random[64] ‖ len(dice) ‖ dice)`; all random material (secret, coefficients, set ID) is then expanded from `seed` with HMAC-SHA256 in counter mode (HKDF-Expand style), so it is strong if **either** source is |
| `policy.c/h` | Read `n` (2..16) and `k`; `majority(n) = ⌊n/2⌋+1`; enforce `majority(n) ≤ k ≤ n`; warning + YES for `k = n` |
| `gf256.c/h` | GF(2⁸) add/mul/inverse with the AES polynomial 0x11B, **constant-time** (no lookup tables indexed by secret data) |
| `shamir.c/h` | `split(secret, k, n) → shares`, `combine(k shares) → secret` (combine is used **only** for the self-test) |
| `sha256.c/h` | Small SHA-256 + HMAC-SHA256 for seed mixing, the secret fingerprint and share checksums (FIPS 180-4 and RFC 4231 test vectors) |
| `share_fmt.c/h` | Encode/parse the share file ([SHARE_FORMAT.md](SHARE_FORMAT.md)) |
| `drive.c/h` | Detect USB disk insert/remove by polling `/sys/block`; read vendor/model/size; calls `/lib/shardkey/prep-drive.sh` via `fork`+`execv` for partition/format/mount |
| `ui.c/h` | Console prompts; never prints share bytes or the secret |
| `main.c` | Ceremony state machine (§3) |
| `tests/` | Host-side unit tests |

Rules for the code:
- Coefficients of each byte polynomial are drawn uniformly from GF(2⁸), **including
  zero** for the top coefficient (forcing it non-zero would leak information).
- `k` and `n` are chosen at runtime (§3) and validated in `policy.c`; buffers are
  sized for the maximum `n = 16` so nothing is allocated after the choice.
- The dice digits are secret material too: kept in the locked pool, never echoed
  (only a counter), wiped right after mixing.
- Secret comparison with a constant-time compare.
- No `malloc` for secret data — fixed static buffers inside the locked pool.
- Compiled with `-Wall -Wextra -Werror -Wconversion`; host test build with
  `-fsanitize=address,undefined`.

Tests:
- GF(2⁸) exhaustive tests: every `a*b`, every `a*inv(a)=1`.
- Shamir: random secrets, every k-subset rebuilds; fixed known-answer vectors.
- Share format: encode → parse round trip; corrupted byte → checksum fails.
- SHA-256 / HMAC-SHA256: FIPS and RFC 4231 test vectors.
- Policy: for every `n` in 2..16, every `k` below majority is refused, majority..n
  accepted, `k = n` requires the warning.
- Dice parser: ignores non-digit and 0/7/8/9 characters, refuses to finish under 100 rolls.
- Mixing: fixed inputs → fixed known outputs; changing one dice roll or one kernel byte
  changes everything.
- **Done when:** `make test-tool` passes on the host, and the static musl binary has
  no dynamic section (`readelf -d` shows nothing, `file` says "statically linked").

### Phase 3 — BusyBox
- `make allnoconfig`, then enable only: `ash` (as `sh`), `mount`, `umount`, `mkdir`,
  `cat`, `echo`, `sleep`, `dd`, `fdisk`, `mkfs.vfat`, `sync`, `poweroff`, `blockdev`,
  `stty`, `clear`, `ls` (debug), `CONFIG_STATIC=y`, `CONFIG_FEATURE_SH_STANDALONE`.
  No networking applets, no `mdev`, no `telnetd`, no `wget`.
- Build with `CC=musl-gcc`. Known risk: BusyBox needs kernel headers that Debian's
  `musl-gcc` doesn't add by default — handle with `-isystem` pointing to sanitized
  headers from our pinned kernel (`make headers_install`).
- **Done when:** a static `busybox` with exactly the listed applets, no network code
  (`busybox --list` checked by script).

### Phase 4 — Root filesystem and `/init`
- `rootfs/init` (BusyBox `ash`, PID 1):
  1. `mount -t proc`, `sysfs`, `devtmpfs` (devtmpfs is also auto-mounted).
  2. `echo 0 > /proc/sys/kernel/printk`-style quieting; set console.
  3. Wait for "no USB disks present" (§3).
  4. Run `/bin/shardkey`; capture exit status.
  5. Always: `sync`, `echo 3 > /proc/sys/vm/drop_caches`, show result, `poweroff -f`.
  6. Traps for INT/TERM so the wipe path always runs; the script never `exec`s a shell.
- `rootfs/lib/shardkey/prep-drive.sh <dev>`: zero first 1 MiB, MBR with one FAT32
  (type `0x0c`) partition, `mkfs.vfat -F 32 -n SHARDKEY`. Refuses any device that is
  not a USB disk (checks `/sys/block/<dev>` resolves under a USB path).
- `scripts/build-rootfs.sh`: builds `build/rootfs/` with `/init`, `/bin/busybox` +
  symlinks, `/bin/shardkey`, `/lib/shardkey/`, empty `/proc /sys /dev /mnt`. Device
  nodes `/dev/console` and `/dev/null` are declared in a kernel `gen_init_cpio` list
  (no root needed to build).
- Reproducible cpio: `find . -print0 | sort -z | cpio --null -o --format=newc
  --reproducible`, all mtimes set to `SOURCE_DATE_EPOCH`, owner `0:0`.
- **Done when:** the cpio boots under QEMU with any kernel and reaches the first prompt.

### Phase 5 — Kernel
- `config/kernel/shardkey.config` = the "keep" list from [KERNEL_CONFIG.md](KERNEL_CONFIG.md).
- `scripts/build-kernel.sh`: `allnoconfig` with the fragment, `olddefconfig`, then
  `scripts/verify-kconfig.sh` which **fails the build** if any required symbol is
  missing or any forbidden symbol (`CONFIG_NET`, `CONFIG_MODULES`, `CONFIG_SWAP`, …)
  is set. Then `make bzImage` with the initramfs embedded and the kernel command line
  built in (`CONFIG_CMDLINE_OVERRIDE=y`, so a bootloader can't add `init=/bin/sh`).
- **Done when:** `out/bzImage` boots in QEMU with OVMF (UEFI) and SeaBIOS (BIOS),
  verify script passes, and two clean builds give the same SHA-256.

### Phase 6 — QEMU end-to-end tests
- `scripts/qemu-test.sh`: runs the image with `-nic none`, `qemu-xhci`, and n
  virtual USB drives that are hot-plugged and unplugged through the QEMU monitor
  (`device_add usb-storage` / `device_del`), driving the prompts through a serial
  console (serial console enabled only in a **debug** kernel variant).
- Checks on the resulting drive images (host side, `mtools`): each has one valid share
  file, set IDs match, indices 1..n are all different, and a host-only test helper
  rebuilds the secret from every k-subset.
- Failure tests: wrong drive inserted (boot stick), drive pulled mid-write,
  write-protected drive, same drive re-inserted for the next share, Ctrl-C.
- **Done when:** all scenarios pass in both UEFI and BIOS modes.

### Phase 7 — Signing and boot stick creation
- Signing, as described in [SIGNING.md](SIGNING.md):
  - `scripts/gen-signing-key.sh` (one time, offline): RSA-2048 key + self-signed
    certificate; private key encrypted onto a USB drive; public `.crt`/`.cer`/fingerprint
    into `keys/`.
  - `scripts/sign.sh` (`make sign`): `sbsign` the kernel → `out/bzImage`; write
    `out/SHA256SUMS`; sign it → `out/SHA256SUMS.sig`.
  - `scripts/verify-release.sh` (`make verify`): signature, hashes, `sbverify`, print
    certificate fingerprint.
- `scripts/make-usb.sh /dev/sdX`: refuses to run unless `make verify` passes; confirms
  the device (size/model, type `YES`), MBR, one FAT32 partition marked active, copies
  the **signed** `bzImage` to `/EFI/BOOT/BOOTX64.EFI` and `/shardkey/bzImage`, installs
  Syslinux (`syslinux --install`, `mbr.bin`), writes `syslinux.cfg`, `SHA256SUMS` and
  `SHA256SUMS.sig`; then reads everything back from the stick and checks the hashes.
- Also produce `out/shardkey.img` (a disk image) so the stick can be written with any
  tool and its hash checked.
- **Done when:** the stick boots a real UEFI machine **with Secure Boot on** (and an
  unsigned image is refused), and a real BIOS machine.

### Phase 8 — Hardening review and real-hardware dry run
- Review the code and config against [THREAT_MODEL.md](THREAT_MODEL.md).
- Dry run on the actual ceremony machine with throwaway drives.
- Write the final operator runbook (§5) from what was learned.

## 5. Ceremony runbook

Draft — finalized in Phase 8.

**Before the day**
1. Build and sign on the build machine (`make`, `make sign`), then `make verify`.
   Ideally a second person rebuilds from the same commit and gets the same
   `bzImage.unsigned` hash.
2. Write the boot stick (`make usb`); it is read back and checked automatically.
3. Prepare the ceremony machine (UEFI): ShardKey certificate enrolled, Secure Boot
   **on**, boot from USB enabled, network cable unplugged, Wi-Fi card removed if
   possible. Confirm an unsigned image is refused ([SIGNING.md](SIGNING.md) §4.4).
4. Decide `n` and `k` in advance (`k` must be at least a majority of `n`).
5. Prepare `n` new USB drives, labels, and a six-sided die.

**On the day**
1. Power on from the boot stick. Check the version banner on screen.
2. Remove the boot stick when asked.
3. Enter `n`, then `k` (M = majority), and confirm.
4. Roll the die at least 100 times and type each result. Don't say the numbers aloud
   or write them down.
5. Write down the set ID and secret fingerprint shown on screen (not secret).
6. Insert, confirm, re-insert, and label each share drive as prompted.
7. When "Powering off" appears and the machine is off, unplug it and keep it unpowered
   for at least 5 minutes.
8. Hand each drive to its holder.

**If the ceremony is aborted:** shares already written are part of a set that no
longer has a "rest". If fewer than `k` were written they reveal nothing, but they must
still be erased or destroyed so they aren't mixed up later. If `k` or more were
written, the secret **can** be rebuilt from them — treat them as live or destroy them.

## 6. Resolved questions

All Phase 0 questions are answered (details in [DECISIONS.md](DECISIONS.md)):

| Question | Answer |
|---|---|
| Default `k`/`n` | Not fixed: operator picks `n`, then `k` (majority by one key, never below majority, `k = n` with warning) — D-017 |
| Share drive layout | MBR + one FAT32 partition — D-019 |
| Dice entropy | **Mandatory**, ≥ 100 rolls — D-018 |
| Secure Boot | In v1, own key, plus signed hash list — D-020 |
| License | GPL-2.0-only — D-021 |

No open questions remain for Phase 0.
