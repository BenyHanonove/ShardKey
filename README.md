<p align="center">
  <img src="docs/logo.svg" width="120" alt="Symbolon logo: a round token broken in two halves that fit together">
</p>

# Symbolon

> *symbolon* (Greek σύμβολον): a token broken into pieces and shared between parties.
> Only the pieces put back together prove who you are. It is where the word *symbol*
> comes from.

**A single-purpose, air-gapped Linux system that generates a 256-bit secret, splits it
into Shamir's Secret Shares, writes each share to its own USB flash drive, and then
wipes itself from memory and powers off.**

> Status: **implemented (Phases 1–7 verified in host & QEMU BIOS/UEFI/Secure Boot tests);**
> real-hardware dry run and independent review are next. See [docs/PLAN.md](docs/PLAN.md).

---

## What it is

Symbolon is not a Linux distribution you install. It is one bootable image — a
hand-configured Linux kernel with a tiny root filesystem built into it — that does
exactly one job, one time, on a computer with no network:

1. Boot from a signed USB stick (Secure Boot on UEFI machines). The whole system loads
   into RAM. The boot stick is then removed.
2. The operator chooses **n** (how many shares, 2–16) and **k** (how many are needed to
   rebuild). One key picks the **majority** (`⌊n/2⌋+1`); any other `k` must be at least
   the majority. `k = n` is allowed only after a warning.
3. The operator types in **at least 100 dice rolls**. They are mixed (SHA-256) with
   kernel randomness from `getrandom`, so the result is strong if either source is.
4. Generate a random 256-bit secret and split it into `n` shares, any `k` of which can
   rebuild it (Shamir's Secret Sharing over GF(2⁸)).
5. Check, in RAM, that **every** combination of `k` shares rebuilds the original secret.
6. For each share: the operator inserts a blank USB drive → Symbolon formats it, writes
   the share, and asks the operator to **unplug and re-insert** the drive → reads it
   back and verifies it byte-for-byte → asks for the next drive.
7. Zero every key buffer (`explicit_bzero`), and power the machine **off** (not reboot).

The secret itself is never written anywhere, never shown on screen, and never leaves
the RAM of the ceremony process. Only the shares leave the machine, one per drive.

**Out of scope:** rebuilding the secret from shares. That is a separate project.
Symbolon only publishes the share file format ([docs/SHARE_FORMAT.md](docs/SHARE_FORMAT.md))
so a recovery tool can read it.

## Why build it this way

| Goal | How Symbolon gets there |
|---|---|
| No network, ever | The kernel is built **without the networking subsystem** (`CONFIG_NET=n`). There is no network stack to attack or misconfigure — not "disabled", absent. |
| No trace on the host machine | No SATA, NVMe, or SD drivers are built in, so the internal disks are **invisible** to the system. Nothing can be written to them. There is no swap. |
| Tiny, auditable code base | No distro. One kernel config fragment, one static BusyBox, one small C program, one shell `init`. Everything is in this repository. |
| No dynamic code | No loadable kernel modules (`CONFIG_MODULES=n`), no shared libraries (static musl binaries). |
| Secrets stay in RAM and get wiped | `mlockall`, no core dumps, `explicit_bzero` on every buffer, kernel zeroes freed pages (`init_on_free=1`), then a full power-off. |
| Works on old and new PCs | One kernel file boots both **UEFI** (EFI stub) and **legacy BIOS** (Syslinux). |
| Proof the image wasn't changed | Every release is **signed** with an offline Symbolon key. Before writing the stick you check the signature; on UEFI machines **Secure Boot** refuses to boot an image we didn't sign. See [docs/SIGNING.md](docs/SIGNING.md). |
| Randomness you don't have to trust blindly | Operator dice rolls + kernel randomness, mixed with SHA-256. |
| A threshold that makes sense | `k` can never be lower than a majority of `n`. |
| Repeatable builds | Every upstream version is pinned and signature-checked; build timestamps are fixed so the same inputs give the same image hash. |

## Architecture at a glance

```
 Build machine (Debian stable, online)              Ceremony machine (air-gapped)
 ─────────────────────────────────────              ─────────────────────────────
 kernel.org LTS source ──┐                          ┌───────────── RAM only ─────────────┐
 BusyBox source ─────────┤  verify sigs + hashes    │ Linux kernel (no NET, no modules)  │
 musl (musl-gcc) ────────┤                          │  └ embedded initramfs:             │
 src/symbolon (C) ───────┘                          │     /init      (BusyBox sh, PID 1) │
        │                                           │     /bin/busybox (static)          │
        ▼                                           │     /bin/symbolon (static, C)      │
  bzImage (EFI stub + embedded initramfs) ──USB──▶  └────────────────────────────────────┘
  + syslinux (BIOS) on one boot stick                      │ writes 1 share per drive
                                                           ▼
                                                 [USB 1] [USB 2] ... [USB n]
```

## Repository layout (planned)

```
Symbolon/
├── README.md                 ← you are here
├── docs/
│   ├── PLAN.md               ← full implementation plan, phases, review of the original 11 steps
│   ├── DECISIONS.md          ← decisions log: why from-scratch, why LTS, why poweroff, ...
│   ├── KERNEL_CONFIG.md      ← which drivers we keep, which we remove, and how
│   ├── SHARE_FORMAT.md       ← on-drive share file format (v1, draft)
│   ├── SIGNING.md            ← how releases are signed and checked (Secure Boot + signed hashes)
│   └── THREAT_MODEL.md       ← what we defend against and what we don't
├── keys/                     ← PUBLIC signing certificate / key only (never the private key)
├── config/
│   ├── versions.env          ← pinned upstream versions + SHA-256 sums
│   ├── kernel/symbolon.config    ← kernel config fragment (the "keep" list)
│   ├── busybox/symbolon.config   ← BusyBox applet list
│   └── syslinux/syslinux.cfg
├── src/symbolon/             ← the C ceremony program + unit tests
├── rootfs/                   ← /init and helper scripts
├── scripts/                  ← fetch, verify, build, make-usb, qemu-test
└── Makefile
```

## Quick start (once implemented)

```bash
make check-host    # verify all required host packages are installed
```

```bash
make fetch         # download + verify kernel, BusyBox, (musl via distro package)
```

```bash
make               # build symbolon, BusyBox, rootfs, kernel → out/bzImage
```

```bash
make test          # host unit tests + QEMU boot test (UEFI and BIOS) with virtual USB drives
```

```bash
make sign          # sign the kernel (Secure Boot) and SHA256SUMS — needs the offline signing key
```

```bash
make verify        # check signatures and hashes of out/ against keys/
```

```bash
sudo make usb DEV=/dev/sdX   # write the boot stick (DESTROYS /dev/sdX)
```

Then follow the operator runbook in [docs/PLAN.md § Ceremony runbook](docs/PLAN.md#ceremony-runbook).

## Requirements

- **Build machine:** Debian 13 (stable) x86_64 (or compatible Debian/Ubuntu x86_64 host).
  Install all required build and test dependencies with:
  ```bash
  sudo apt-get update && sudo apt-get install -y \
    build-essential bc bison flex libelf-dev musl-tools \
    cpio xz-utils bzip2 syslinux syslinux-common mtools dosfstools \
    gnupg sbsigntool openssl qemu-system-x86 ovmf curl ca-certificates
  ```
  You can verify the host setup at any time by running `make check-host` (which runs
  `scripts/check-host.sh`).
- **Signing key:** kept offline (separate USB drive or hardware token), used only for
  `make sign`. See [docs/SIGNING.md](docs/SIGNING.md).
- **Ceremony machine:** any x86_64 PC, ≥ 512 MB RAM, a USB port and a keyboard.
  Preferred: **UEFI with Secure Boot on and the Symbolon certificate enrolled**. Legacy
  BIOS works but has no boot-time signature check (only the check before writing the
  stick). Remove or disconnect network cards / Wi-Fi if you can — the kernel cannot use
  them anyway.
- **Ceremony supplies:** one boot stick, `n` blank share drives (contents will be
  erased), and at least one six-sided die.

## Security notice

Symbolon has **not** yet received an independent third-party security audit and
still requires a real-hardware dry run on your ceremony machine before protecting real
assets. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the runbook in
[docs/PLAN.md](docs/PLAN.md) (§5) before use.

## License

Symbolon is licensed under the **GNU General Public License v2.0 only**
(`GPL-2.0-only`), the same license as the Linux kernel and BusyBox it ships with.
See [LICENSE](LICENSE).
