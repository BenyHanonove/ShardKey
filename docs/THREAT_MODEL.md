# Symbolon — Threat Model

What Symbolon protects, who it protects against, what it assumes, and what it
explicitly does not handle.

---

## 1. What we protect

| Asset | Where it exists | For how long |
|---|---|---|
| The 256-bit secret | RAM of the `symbolon` process only | From generation until wipe at the end of the ceremony (minutes) |
| The polynomial coefficients | Same | Same |
| Each share | RAM, then its own USB drive | RAM: until wipe. Drive: until the holder destroys it |

The goal: after the ceremony, the secret exists **nowhere** except implied by the
shares, and fewer than `k` shares reveal nothing.

## 2. Trust assumptions

- **The build machine is honest at build time.** It never sees secrets, but it produces
  the image. Mitigation: pinned and signature-checked sources, reproducible builds —
  a second person on another machine can rebuild and compare hashes.
- **The offline signing key is not stolen.** Whoever holds it can make images that
  pass both signature checks ([SIGNING.md](SIGNING.md)).
- **The ceremony machine's hardware and firmware are not backdoored.** Symbolon cannot
  defend against malicious firmware, a CPU backdoor, or a hardware keylogger/implant.
  (A keylogger would capture the dice rolls; the kernel randomness still protects the
  secret unless the CPU/RNG is also compromised.)
- **At least one randomness source is good:** either the kernel RNG (`getrandom`
  blocks until the CRNG is seeded) **or** the operator's dice rolls.
- **The operator follows the runbook** and the room is physically controlled (no
  cameras on the screen, no unknown devices plugged in).

## 3. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Secret leaks over a network | No networking code in the kernel at all (`CONFIG_NET=n`). Removing network hardware is still recommended |
| Secret written to the machine's internal disk | No SATA/NVMe/MMC drivers — the kernel cannot see internal disks. No swap, no hibernation |
| Secret written to firmware (NVRAM) | `efi=noruntime`, no `EFIVAR_FS` |
| Secret left in RAM after the ceremony | `explicit_bzero` on all buffers; page cache dropped; kernel zeroes freed pages (`init_on_free=1`); `poweroff`, never reboot or panic |
| Cold-boot attack (freezing RAM and reading it) | Software wipe happens **before** power off; operator keeps the machine unpowered ≥ 5 minutes |
| Secret paged out or dumped | `mlockall`, no swap, `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `COREDUMP=n` |
| Code injected at boot (`init=/bin/sh`, other initramfs) | Command line locked in the kernel (`CMDLINE_OVERRIDE`); initramfs embedded in the kernel |
| Image modified after build (on the build machine, in transit, or on the stick) | Signed `SHA256SUMS` checked before writing and after writing the stick; Secure Boot with our certificate refuses a modified kernel at boot |
| A different system pretending to be Symbolon | Ceremony machine's UEFI `db` holds **only** the Symbolon certificate, so nothing else boots |
| Weak or backdoored hardware RNG | Mandatory ≥ 100 dice rolls mixed in with SHA-256 |
| Biased or lazy dice rolling | Kernel randomness mixed in; either source alone is enough |
| Dice rolls observed | Never echoed on screen (counter only); runbook: don't say them aloud |
| Threshold set too low (a minority of holders could rebuild) | `k` below a majority of `n` is refused |
| Threshold set to `k = n` by mistake | Explicit warning + `YES` |
| Code loaded at runtime | No kernel modules, static binaries only, no shell left for the operator |
| Malicious USB device (BadUSB pretending to be a keyboard or network card) | No USB network drivers. A fake keyboard can only type into Symbolon's prompts, which only accept "YES" / Enter. Use new drives from a trusted source |
| DMA attack via FireWire/Thunderbolt/PCMCIA | Those drivers aren't built |
| Boot stick formatted as a share by mistake | Ceremony refuses to start until **all** USB drives are removed, then treats only newly inserted drives as targets |
| Share written badly (bad flash, removed too early) | `fsync`, unplug/re-insert, read back from the drive and compare; per-share `check` |
| Shares from different ceremonies mixed up | `set-id` in every share; label drives with the set ID |
| Secret visible on screen | The secret and share bytes are never printed; only set ID and fingerprint |
| Timing side channel in field math | Constant-time GF(2⁸) operations, constant-time compare |
| Ceremony aborted halfway | Wipe-and-power-off path always runs; runbook says what to do with already-written drives |
| Upstream source tampered | SHA-256 pins + kernel.org GPG signature check |

## 4. Out of scope

- Malicious hardware, firmware, or CPU microcode.
- Physical attackers in the room during the ceremony.
- What happens to share drives after the ceremony (storage, holders colluding —
  any `k` holders together **can** rebuild the secret, by design).
- Flash wear-levelling: deleted data on a share drive may survive in flash cells. Only
  shares are ever written to share drives, so this doesn't leak the secret.
- Recovery of the secret (separate project, separate threat model).
- Boot-time signature checks on **legacy BIOS** machines (no Secure Boot there; only
  the pre-write signature check applies).
