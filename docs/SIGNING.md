# Symbolon — Signing and Verifying the Image

**Goal:** be able to prove that the image booted on the ceremony machine is exactly
the one we built from this repository, and that nobody changed it on the way.

This document explains the idea in plain terms, then the exact steps.

---

## 1. The idea in one minute

- We create **one signing key pair** (once): a **private key** that stays offline and
  is used to sign, and a **public certificate** that anyone can use to check.
- After every build we sign two things with the private key:
  1. **The kernel image itself** (Secure Boot signature, embedded in the file).
  2. **`SHA256SUMS`**, a list of the hashes of every file we release.
- Two independent checks then protect the image:

| Check | When | Who does it | What it catches |
|---|---|---|---|
| **Signed hash list** | Before writing the boot stick, and again after writing it | The operator, on the build machine (`make verify`) | Any change to the files after signing, or a bad copy to the stick |
| **Secure Boot** | Every time the ceremony machine boots | The machine's firmware, automatically | A modified or foreign image on the stick — the firmware refuses to start it |

Secure Boot only exists on **UEFI** machines. On a legacy **BIOS** machine only the
first check applies, so real ceremonies should use a UEFI machine with Secure Boot on.

## 2. Why we don't just "check the hash on screen"

The image could print its own hash at boot, but a modified image could print anything
it likes. The check must be done by something **outside** the image: the build machine
(before writing) and the firmware (at boot).

## 3. One key, one tool

| Item | Choice | Why |
|---|---|---|
| Key type | RSA-2048 X.509 certificate | The format UEFI firmware understands. RSA-2048 is the size every firmware supports (some reject larger keys) |
| Tool | **OpenSSL** for key and hash-list signatures, **sbsigntool** (`sbsign`, `sbverify`) for the kernel | Both are standard Debian packages |
| Number of keys | **One** key pair for both jobs | Simpler to protect one offline key than two. Deliberate trade-off |

Files in the repository (`keys/`) — **public only**:
- `keys/symbolon-signing.crt` — certificate (PEM) used by `make verify` and `sbverify`
- `keys/symbolon-signing.cer` — same certificate in DER form, for enrolling in firmware
- `keys/FINGERPRINT.txt` — SHA-256 fingerprint of the certificate, also printed on paper

The private key (`symbolon-signing.key`) is **never** committed and never stored on the
build machine.

## 4. Steps

### 4.1 Create the key (once, offline)

On a machine with no network (can be the build machine with the cable unplugged):

```bash
scripts/gen-signing-key.sh /media/keyusb
```

What it does: generates the RSA-2048 key + self-signed certificate (valid 10 years,
subject `CN=Symbolon Signing`), encrypts the private key with a passphrase, writes it
to the given USB drive, and writes the public `.crt`, `.cer`, and fingerprint into
`keys/`. Make **two** copies of the key drive and store them in separate safe places.
Write the fingerprint on paper.

If the private key is ever lost, nothing breaks — generate a new one, re-enroll it.
If it is ever **stolen**, someone could make images that pass both checks: generate a
new key, remove the old certificate from every ceremony machine.

### 4.2 Sign a build

```bash
make                      # builds out/bzImage.unsigned and the rest
```

```bash
make sign KEY=/media/keyusb/symbolon-signing.key
```

What it does:
1. `sbsign` → `out/bzImage` (the kernel with its Secure Boot signature embedded).
2. Writes `out/SHA256SUMS` with hashes of `bzImage`, `bzImage.unsigned`,
   `symbolon.img`, `initramfs.cpio.gz`.
3. `openssl dgst -sha256 -sign` → `out/SHA256SUMS.sig`.
4. Unplug the key drive.

### 4.3 Verify a build

```bash
make verify
```

What it does:
1. `openssl dgst -sha256 -verify` checks `SHA256SUMS.sig` against `keys/symbolon-signing.crt`.
2. `sha256sum -c SHA256SUMS` checks every file.
3. `sbverify --cert keys/symbolon-signing.crt out/bzImage` checks the kernel signature.
4. Prints the certificate fingerprint — compare it with the one on paper.

After writing the boot stick, `make usb` reads the stick back and checks it against
`SHA256SUMS` too.

### 4.4 Enroll the certificate on the ceremony machine (once per machine)

Menus differ between vendors; the steps are roughly:

1. Copy `keys/symbolon-signing.cer` to a FAT32 USB drive.
2. Enter firmware setup → **Secure Boot** → set mode to **Custom**.
3. **Key Management → db → Append / Enroll from file** → pick `symbolon-signing.cer`.
4. **Recommended for a dedicated ceremony machine:** remove the other entries from `db`
   (Microsoft keys), so this machine can boot **only** Symbolon. Otherwise any
   Microsoft-signed system (e.g. another live USB pretending to be Symbolon) could still
   boot on it.
5. Turn **Secure Boot on**, save, reboot.
6. **Test it:** boot an unsigned image (`out/bzImage.unsigned` on a test stick) — the
   machine must **refuse**. Then boot the signed stick — it must start.

## 5. Signatures and repeatable builds

The Secure Boot signature is embedded in `bzImage`, so the signed file's hash depends on
the key. That's why we also publish `bzImage.unsigned`:

- A second person rebuilds from the same commit → compares their `bzImage.unsigned`
  hash with ours (must be equal).
- Anyone can strip the signature from our signed kernel (`sbattach --remove`) and get
  a file identical to `bzImage.unsigned`.

So the signature proves **who** released it, and the repeatable build proves **what**
it contains.

## 6. Scripts and Makefile targets (to be written)

| Script | Target | Job |
|---|---|---|
| `scripts/gen-signing-key.sh` | — (run by hand, once) | Create key pair offline |
| `scripts/sign.sh` | `make sign` | Sign kernel + `SHA256SUMS` |
| `scripts/verify-release.sh` | `make verify` | All checks in §4.3 |
| `scripts/make-usb.sh` | `make usb` | Write stick, then read back and verify |
