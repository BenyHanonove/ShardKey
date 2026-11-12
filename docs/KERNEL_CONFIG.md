# ShardKey — Kernel Configuration

Which kernel features and drivers ShardKey keeps, which it removes, and how the
removal is done and checked.

Target: **x86_64**, latest LTS kernel (pinned in `config/versions.env`).

---

## 1. How drivers are removed

We do not start from a distro kernel and switch things off. We start with **everything
off** and switch on only what is listed here.

```bash
# 1. Everything off, then apply our "keep" list (a version-controlled fragment)
make O=build/kernel ARCH=x86_64 allnoconfig KCONFIG_ALLCONFIG=config/kernel/shardkey.config
```

```bash
# 2. Resolve dependencies without asking questions
make O=build/kernel ARCH=x86_64 olddefconfig
```

```bash
# 3. Fail the build if anything required is missing or anything forbidden is present
scripts/verify-kconfig.sh build/kernel/.config
```

```bash
# 4. Build (the initramfs and command line are already baked into the config)
make O=build/kernel ARCH=x86_64 -j"$(nproc)" bzImage
```

- `allnoconfig` answers "no" to every option it can. With `KCONFIG_ALLCONFIG`, our
  fragment's values are applied first, so the result is: **our list + the minimum the
  kernel forces on**.
- `make menuconfig` is used only to **explore** (find a symbol's name, see what depends
  on what). Any change found there is copied into the fragment by hand, so the
  config always lives in git.
- `scripts/verify-kconfig.sh` reads the final `.config` and checks two lists:
  every symbol in §3 must be `=y`, every symbol in §4 must be unset. If the kernel
  silently drops or adds an option (it happens when upgrading versions), the build stops.
- Upgrading the kernel: run `make listnewconfig` and review every new symbol before
  bumping the pinned version.

Because `CONFIG_MODULES=n`, everything below is built **into** the kernel (`=y`). There
are no `.ko` files and no way to load one.

## 2. Built-in kernel command line

```
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE_OVERRIDE=y
CONFIG_CMDLINE="console=tty0 loglevel=3 init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 efi=noruntime panic=0"
```

| Parameter | Why |
|---|---|
| `console=tty0` | Messages on the screen |
| `loglevel=3` | Only errors, so kernel messages don't scroll over the ceremony prompts |
| `init_on_alloc=1 init_on_free=1` | Kernel zeroes memory when it is handed out and when it is freed — secrets in freed pages (page cache, pipe buffers) disappear |
| `page_alloc.shuffle=1` | Randomizes the page allocator |
| `efi=noruntime` | No EFI runtime services after boot — nothing can write to firmware variables (NVRAM) |
| `panic=0` | On a kernel panic, halt and stay halted (never auto-reboot into something else) |

`CONFIG_CMDLINE_OVERRIDE=y` means anything typed at the Syslinux prompt or passed by
UEFI is **ignored**.

## 3. Keep list (must be `=y`)

### Core

| Symbol | Why |
|---|---|
| `64BIT` | x86_64 only (set by `ARCH=x86_64`) |
| `PRINTK` | Kernel can print errors to the console |
| `BINFMT_ELF` | Run our static ELF binaries |
| `BINFMT_SCRIPT` | Run `/init`, which is a `#!/bin/sh` **script** — without this the system can't start |
| `FUTEX` | Used internally by musl |
| `PROC_FS`, `SYSFS` | `/proc` and `/sys` (drive detection reads `/sys/block`) |
| `DEVTMPFS`, `DEVTMPFS_MOUNT` | Kernel creates `/dev/sdX` nodes itself — no `udev`/`mdev` needed |
| `BLK_DEV_INITRD` | Boot from an initramfs |
| `INITRAMFS_SOURCE="…/initramfs.list"` | Embed the root filesystem into the kernel image |
| `RD_GZIP`, `INITRAMFS_COMPRESSION_GZIP` | Compress the embedded initramfs |
| `ACPI` | Needed for real **power off** (`poweroff -f`); without it the machine only halts. Also required by `EFI` on x86 |
| `PCI`, `PCI_MSI` | USB host controllers are PCI devices |

### Boot (UEFI + BIOS)

| Symbol | Why |
|---|---|
| `EFI`, `EFI_STUB` | Kernel is itself a UEFI program (`BOOTX64.EFI`). After the build it is signed with `sbsign` for Secure Boot — no extra kernel option needed ([SIGNING.md](SIGNING.md)) |
| `RELOCATABLE`, `RANDOMIZE_BASE` | KASLR; also required for the EFI stub to load anywhere |

### Console and keyboard

| Symbol | Why |
|---|---|
| `TTY`, `VT`, `VT_CONSOLE` | Text console on the screen |
| `VGA_CONSOLE` | Text mode on **BIOS** machines |
| `FB`, `FB_EFI`, `FRAMEBUFFER_CONSOLE`, `FONT_8x16` | Console on **UEFI** machines (no VGA text mode there). If `FB_EFI` is unavailable in the pinned kernel: `DRM`, `DRM_SIMPLEDRM`, `SYSFB_SIMPLEFB`, `DRM_FBDEV_EMULATION` |
| `INPUT`, `INPUT_KEYBOARD` | Input layer |
| `SERIO`, `SERIO_I8042`, `KEYBOARD_ATKBD` | PS/2 keyboards and most **laptop built-in** keyboards |
| `HID`, `HID_GENERIC`, `USB_HID` | **USB keyboards** |

### USB and flash drives

| Symbol | Why |
|---|---|
| `USB_SUPPORT`, `USB`, `USB_PCI` | USB core |
| `USB_XHCI_HCD`, `USB_XHCI_PCI` | USB 3.x controllers (all modern machines) |
| `USB_EHCI_HCD`, `USB_EHCI_PCI` | USB 2.0 controllers |
| `USB_OHCI_HCD`, `USB_OHCI_HCD_PCI`, `USB_UHCI_HCD` | USB 1.1 companion controllers — needed for keyboards on older BIOS machines |
| `USB_STORAGE` | USB mass-storage (flash drives) |
| `USB_UAS` | USB Attached SCSI — some USB 3 drives prefer it |
| `BLOCK`, `SCSI`, `BLK_DEV_SD` | Flash drives appear as SCSI disks `/dev/sdX` |
| `MSDOS_PARTITION` | Read the MBR partition table we write |

### Filesystem

| Symbol | Why |
|---|---|
| `FAT_FS`, `VFAT_FS` | Share drives are FAT32 — readable on any OS |
| `FAT_DEFAULT_CODEPAGE=437`, `FAT_DEFAULT_IOCHARSET="iso8859-1"` | Defaults for mounting |
| `NLS`, `NLS_CODEPAGE_437`, `NLS_ISO8859_1` | VFAT refuses to mount without these |

### Hardening

| Symbol | Why |
|---|---|
| `INIT_ON_ALLOC_DEFAULT_ON`, `INIT_ON_FREE_DEFAULT_ON` | Zero memory on alloc/free (same as the cmdline, belt and braces) |
| `STACKPROTECTOR`, `STACKPROTECTOR_STRONG` | Stack canaries |
| `STRICT_KERNEL_RWX` | Kernel code read-only, data non-executable |
| `HARDENED_USERCOPY` | Bounds checks on kernel↔user copies |
| `SLAB_FREELIST_RANDOM`, `SLAB_FREELIST_HARDENED` | Heap hardening |
| `SECURITY_DMESG_RESTRICT` | Kernel log not readable by unprivileged code |
| `BUG_ON_DATA_CORRUPTION`, `PANIC_ON_OOPS` | Stop instead of continuing in a broken state |

## 4. Forbidden list (must be unset)

Most of these are already off after `allnoconfig`; the verify script makes sure they
**stay** off.

| Symbol | Why it must not exist |
|---|---|
| `NET` | Whole networking stack: Ethernet, Wi-Fi (`WIRELESS`, `CFG80211`), Bluetooth (`BT`), IPv4/IPv6, sockets to anywhere. Removing `NET` removes all of them |
| `MODULES` | No loadable kernel code after boot |
| `SWAP` | Secrets can never be paged out to a disk |
| `HIBERNATION`, `SUSPEND` | RAM is never written to disk or kept powered while "asleep" |
| `COREDUMP` | A crashing program can't dump its memory |
| `KEXEC`, `KEXEC_FILE`, `CRASH_DUMP` | Can't load another kernel that would keep current RAM |
| `MAGIC_SYSRQ` | No keyboard shortcuts into the kernel (we power off cleanly instead) |
| `ATA`, `SATA_AHCI`, `BLK_DEV_NVME`, `NVME_CORE`, `MMC` | **Internal disks and SD cards are invisible** — nothing can be written to them |
| `FIREWIRE`, `THUNDERBOLT` (removed in 6.18; covered by `USB4`), `USB4`, `PCMCIA` | Ports that give devices direct memory access (DMA attacks) |
| `USB_GADGET`, `USB_NET_DRIVERS`, `USB_SERIAL` | USB networking / device mode |
| `SOUND`, `DRM` (unless the simpledrm fallback is needed), `MEDIA_SUPPORT`, `WLAN` | Hardware we don't use |
| `BLK_DEV_LOOP`, `MD`, `BLK_DEV_DM` | Extra block layers we don't use |
| `EXT4_FS`, `BTRFS_FS`, `XFS_FS`, `NTFS3_FS`, `ISO9660_FS`, `FUSE_FS` | Filesystems we don't use |
| `EFIVAR_FS`, `EFI_VARS` (removed in 6.x; covered by `EFIVAR_FS`) | No access to firmware variables |
| `DEVMEM`, `DEVPORT` | No raw `/dev/mem` / `/dev/port` |
| `DEBUG_FS`, `KPROBES`, `FTRACE`, `BPF_SYSCALL`, `PROFILING` | Debug and tracing interfaces that can read memory (`PERF_EVENTS` is unconditionally selected by `X86` in 6.18; see D-022) |
| `IO_URING`, `USERFAULTFD` | Large attack surface, unused (`EXPERT=y` is enabled to turn off `COREDUMP` and `IO_URING`; see D-022) |
| `IA32_EMULATION`, `X86_X32_ABI` | Only 64-bit programs run |
| `IKCONFIG` | Not needed (the config is in git) |
| `MICROCODE_LATE_LOADING`, `MICROCODE_DBG` | No microcode loading at runtime (`MICROCODE` itself is an unprompted `def_bool y` on x86 in 6.18; see D-022) |

## 5. Debug variant (QEMU only)

For automated tests the build can produce a **debug** kernel that adds:

```
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
# and console=ttyS0 in CONFIG_CMDLINE
```

This lets `scripts/qemu-test.sh` drive the prompts over a serial line. The debug image
has a different hash, is written to `out/debug/`, and **must never be used for a real
ceremony**. The verify script runs in a strict mode for the release image and a relaxed
mode (allows only the symbols above) for the debug image.

## 6. Known hardware risks

These may come up during the real-hardware dry run (Phase 8):

- **x2APIC machines:** some recent firmware enables x2APIC before boot; the kernel
  then needs `X86_X2APIC`, which on bare metal also needs interrupt remapping (an
  IOMMU driver). Add only if a target machine needs it.
- **SMP:** `allnoconfig` leaves `SMP=n` (one CPU). That boots on multi-core machines
  and is simpler. Switch on only if a machine misbehaves without it.
- **Unusual USB controllers** or keyboards that need a vendor-specific HID driver.
- **UEFI-only machines without a GOP framebuffer** (rare): would need the simpledrm
  fallback in §3.
