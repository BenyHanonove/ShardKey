# ShardKey — Decisions Log

Short records of each design decision: what we chose, what else was considered, and why.
Newest decisions go at the bottom. Change a decision by adding a new entry that
replaces the old one — don't edit history.

---

## D-001 — No distro: build the system from scratch

**Decision:** The ceremony system is a kernel.org kernel + static BusyBox + our static C
program, nothing else. No Debian, Alpine, Tails, or Buildroot inside the image.

**Considered:**
| Option | For | Against |
|---|---|---|
| **From scratch** ✅ | Every byte in the image is something we chose; total code is small enough to read; no package manager, services, or default config to strip out | We write the build scripts ourselves |
| Buildroot | Mature, repeatable builds, handles cross-toolchains | Another large layer to trust and audit; its defaults must still be checked line by line |
| Alpine Linux | Already musl + BusyBox, fast to start | Generic kernel with thousands of modules, OpenRC, apk — far more than we need, and removing it is harder than never adding it |
| Tails / other live distros | Polished, amnesic by design | Huge (GBs), networking built in, hard to audit |

**Why:** The whole security argument of ShardKey is "the system cannot do anything except
this one job". That is easiest to prove when we start from nothing (`allnoconfig`) and
add only what is needed.

## D-002 — Build machine runs Debian stable

**Decision:** Builds run on **Debian 13 (stable)**, x86_64.

**Why:** Long support, slow-changing toolchain (repeatable builds), and it packages
everything we need: `musl-tools` (gives `musl-gcc`), `syslinux`, `mtools`, `dosfstools`,
`qemu-system-x86`, `ovmf`. The build machine is online and is **not** trusted with
secrets — it never sees one.

## D-003 — Kernel: latest LTS, pinned

**Decision:** Use the latest **longterm (LTS)** kernel branch from kernel.org. The exact
point release and its hash live in `config/versions.env`. The tarball's GPG signature is
checked against pinned maintainer key fingerprints.

**Replaces:** "latest stable" from the original outline.

**Why:** Stable branches get fixes for about three months; LTS for years. Pinning means
two people building the same commit get the same kernel. We update deliberately, not
by accident.

## D-004 — musl, static linking

**Decision:** Both BusyBox and `shardkey` are statically linked against **musl** with
`musl-gcc`.

**Why:** No dynamic loader, no shared libraries, nothing loaded at runtime that isn't in
the binary. musl is small and readable. glibc static linking is possible but officially
discouraged (NSS, `dlopen` surprises).

## D-005 — Boot both UEFI and BIOS from one kernel file

**Decision:** Kernel built with `CONFIG_EFI_STUB=y` and the initramfs embedded
(`CONFIG_INITRAMFS_SOURCE`). The **same** `bzImage` is:
- copied to `\EFI\BOOT\BOOTX64.EFI` → UEFI firmware runs it directly;
- loaded by **Syslinux** on legacy BIOS machines.

**Why:** One artifact to hash and check. No GRUB (large, scriptable). No `syslinux.efi`
(less reliable on real UEFI firmware than the kernel's own stub).

**Limitation (superseded by D-020):** ~~The image is not signed, so Secure Boot must be
off in v1.~~ The kernel is signed for Secure Boot in v1.

## D-006 — Initramfs embedded in the kernel

**Decision:** The initramfs is built into the kernel image rather than loaded as a
separate file.

**Why:** One file, one hash. Nobody can swap a different initramfs onto the stick and
keep the same kernel. The standalone `initramfs.cpio.gz` is still produced for
inspection.

## D-007 — Kernel command line built in and locked

**Decision:** `CONFIG_CMDLINE_BOOL=y`, `CONFIG_CMDLINE_OVERRIDE=y`. Anything the
bootloader passes is ignored.

**Why:** Prevents `init=/bin/sh`, `rdinit=`, debugging options, or turning off memory
zeroing from the boot menu.

## D-008 — Secret: a random 256-bit value

*Amended by D-018 (the randomness source now also includes dice).*

**Decision:** ShardKey generates a fresh 256-bit secret with `getrandom(…, 0)`. It does
not accept a user-supplied secret in v1.

**Why:** Generic and useful as a master key / disk-encryption key / root-of-trust
seed. Generating inside the air-gapped system means the secret never existed anywhere
else. Accepting a typed secret would need a keyboard-entry UI and would mean the secret
already exists outside the system.

## D-009 — Shamir over GF(2⁸), byte-wise

**Decision:** Each of the 32 secret bytes gets its own random polynomial of degree
`k−1` over GF(2⁸) (AES polynomial 0x11B). Share `i` is the evaluation at `x = i`,
`i = 1..n`. Coefficients are uniform over all 256 values, including zero.

**Why:** The standard construction (used by HashiCorp Vault, ssss, and others), simple
and fast, perfect secrecy. Byte-wise GF(2⁸) avoids big-number math. We implement the
field operations in constant time even though the machine is single-user, because it
costs nothing.

## D-010 — `k` and `n` fixed at build time

*Replaced by D-017.*

**Decision:** `k` and `n` are compile-time constants (default 3-of-5). The operator does
not choose them during the ceremony.

**Why:** Fewer choices on the day means fewer mistakes. The image's hash pins the
policy: whoever checks the hash also knows the threshold. To change the policy, build a
new image.

## D-011 — One ceremony produces all shares

**Decision:** All `n` shares are produced in one boot. The machine is not powered off
between shares.

**Why:** Shamir shares are not independent: they are all points on the same secret
polynomials, which exist only in RAM. Powering off between shares would destroy the
polynomials and the next share would belong to a different secret.

## D-012 — Write, re-insert, verify — one drive per share

**Decision:** For each share: format → write → `fsync` → unmount → operator **unplugs
and re-inserts** the drive → mount read-only → compare with the copy in RAM → unmount.
One drive per share; no extra copies in v1.

**Why:** Re-inserting forces the read to come from the drive's flash, not the kernel's
page cache, so we verify what is really stored.

## D-013 — End with wipe + power off

**Decision:** Wipe all secret buffers (`explicit_bzero`), drop the page cache, then
`poweroff -f` via ACPI. Kernel boots with `init_on_free=1 init_on_alloc=1` so freed
pages are zeroed. `CONFIG_MAGIC_SYSRQ` is not built.

**Replaces:** "crash the kernel via `echo c > /proc/sysrq-trigger`" and "zero-out reboot".

**Why:** A kernel crash leaves the machine powered with RAM intact. A reboot keeps RAM
powered too. Only cutting power starts RAM decay, and software wiping before that
removes the data even if the RAM is frozen and read (cold-boot attack).

## D-014 — Recovery is a separate project

**Decision:** ShardKey contains `combine()` only for its internal self-test. A tool that
reads share files and rebuilds the secret is a separate project.

**Why:** Different threat model (recovery happens when and where the secret is needed),
different lifecycle. ShardKey publishes the share format so that tool can be written
against a stable spec.

## D-015 — Internal disks invisible

**Decision:** No SATA/AHCI, NVMe, MMC/SD, or other internal storage drivers are built.

**Why:** If the kernel cannot see the internal disks, nothing can ever be written to
them — not by bug, not by mistake. The only block devices that can exist are USB disks.

## D-016 — Documentation in English

**Decision:** All repository documentation and code comments are in English.

## D-017 — `n` and `k` chosen on screen, `k` at least a majority

**Replaces:** D-010.

**Decision:** At the start of the ceremony the operator enters `n` (2..16). Then `k`:
one key (`M`) selects the **majority**, `⌊n/2⌋+1`; or the operator types another number,
which must be **at least the majority** and at most `n`. `k = n` is allowed only after a
warning ("losing any one drive loses the secret forever") and typing `YES`. A final
"Create k-of-n shares? YES" confirms.

| n | majority (minimum k) | allowed k |
|---|---|---|
| 2 | 2 | 2 (= n, warning) |
| 3 | 2 | 2, 3 |
| 5 | 3 | 3, 4, 5 |
| 7 | 4 | 4 … 7 |
| 16 | 9 | 9 … 16 |

**Why:** One image serves every ceremony. The majority rule means a minority of holders
can never rebuild the secret on their own. The limit of 16 keeps the ceremony practical
and the buffers fixed-size.

**Trade-off:** The image hash no longer pins the policy; the chosen `k`/`n` are shown on
screen and written into every share file.

## D-018 — Dice rolls are mandatory

**Amends:** D-008.

**Decision:** The operator must type **at least 100 rolls** of a six-sided die (digits
1–6; ≈ 258 bits). The ceremony can't continue without them. All random material is
derived from both sources:

```
seed = SHA-256("SHARDKEY-SEED-V1" ‖ getrandom(64 bytes) ‖ len(dice) ‖ dice)
secret, coefficients, set-id = HMAC-SHA256(seed, counter …)   (HKDF-Expand style)
```

The dice digits are never echoed (only a counter is shown) and are wiped right after
mixing.

**Why:** The result is strong if **either** source is good: a broken or backdoored
hardware RNG is covered by the dice, and lazy or biased dice rolling is covered by the
kernel. Costs a few minutes at the ceremony.

## D-019 — Share drives: MBR + one FAT32 partition

**Decision:** Confirmed: MBR partition table, one primary partition type `0x0c`, FAT32.

**Why:** Reads cleanly on Windows, macOS and Linux. A whole-disk "superfloppy" saves a
few lines of code but some systems (older Windows especially) handle it badly.

## D-020 — Signed image in v1: Secure Boot + signed hash list

**Replaces:** the "Secure Boot must be off" limitation in D-005.

**Decision:** One offline **RSA-2048 X.509** signing key. After every build:
- the kernel is signed with `sbsign` (Secure Boot signature embedded in `bzImage`);
- `SHA256SUMS` of every released file is signed with OpenSSL → `SHA256SUMS.sig`.

The public certificate is in `keys/`. The ceremony machine has the certificate enrolled
in its UEFI `db` (preferably as the only entry) and Secure Boot turned on. The private
key never touches the build machine's disk and is never committed. Full procedure in
[SIGNING.md](SIGNING.md).

**Considered:** shim + MOK (works on machines that can't enroll custom keys, but adds a
Microsoft-signed binary we didn't build and trusts Microsoft's key); GPG for the hash
list (a second key type to manage).

**Why:** The goal is "prove the software wasn't changed". Two independent checks: the
signed hash list before writing the stick (works everywhere), and Secure Boot at every
boot (the firmware refuses a modified image). One key keeps it simple. RSA-2048 because
every UEFI firmware supports it. Legacy BIOS machines get only the first check.

## D-021 — License: GPL-2.0-only

**Decision:** The project is licensed under GPL-2.0-only.

**Why:** Same license as the Linux kernel and BusyBox, which are shipped inside the
image anyway. Anyone distributing a modified ShardKey must publish its source — fitting
for a tool whose trust depends on being auditable.
