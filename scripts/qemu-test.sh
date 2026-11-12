#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 6 QEMU end-to-end verification suite for ShardKey.
# Exercises the debug kernel (out/debug/bzImage) in BOTH BIOS (SeaBIOS) and
# UEFI (OVMF) modes with virtual xHCI USB storage hot-plug/unplug over QMP:
#   - Boot stick USB detection and forced removal at startup
#   - Happy path ceremonies:
#       * BIOS: 2-of-3 shares (mtools host check + combine_check across all C(3,2)=3 subsets)
#       * UEFI: 3-of-5 shares (mtools host check + combine_check across all C(5,3)=10 subsets)
#   - Failure & recovery tests (run in both BIOS and UEFI modes):
#       1. Wrong drive inserted (boot stick rejected)
#       2. Write-protected drive inserted (readonly=true rejected cleanly)
#       3. Drive pulled mid-write (device_del during format/write recovers to retry)
#       4. Earlier share from same ceremony re-inserted for next share (rejected)
#       5. Ctrl-C (0x03) interruption mid-ceremony (wipes memory, clears caches, powers off rc=0)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/versions.env
source "${ROOT_DIR}/config/versions.env"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"

DEBUG_KERNEL="${OUT_DIR}/debug/bzImage"
INITRAMFS_IMG="${OUT_DIR}/initramfs.cpio.gz"
COMBINE_CHECK="${BUILD_DIR}/tool-test/combine_check"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
SYSLINUX_MBR="/usr/lib/syslinux/mbr/mbr.bin"

log() {
    printf '[qemu-test] %s\n' "$*"
}

die() {
    printf '[qemu-test] ERROR: %s\n' "$*" >&2
    exit 1
}

for cmd in qemu-system-x86_64 sfdisk mkfs.vfat syslinux mcopy mdir mmd dd truncate python3; do
    command -v "${cmd}" >/dev/null 2>&1 || die "missing required host command: ${cmd}"
done
for req in "${OVMF_CODE}" "${OVMF_VARS}" "${SYSLINUX_MBR}"; do
    [[ -r "${req}" ]] || die "missing required host file: ${req}"
done

if [[ ! -x "${COMBINE_CHECK}" ]]; then
    log "Building host share verification helper (${COMBINE_CHECK})..."
    make -C "${ROOT_DIR}/src/shardkey" BUILD_DIR="${BUILD_DIR}/tool-test" test >/dev/null
fi
[[ -x "${COMBINE_CHECK}" ]] || die "failed to build ${COMBINE_CHECK}"

if [[ ! -f "${INITRAMFS_IMG}" ]]; then
    log "Building initramfs (${INITRAMFS_IMG})..."
    "${ROOT_DIR}/scripts/build-rootfs.sh"
fi

if [[ ! -f "${DEBUG_KERNEL}" ]] || [[ "${INITRAMFS_IMG}" -nt "${DEBUG_KERNEL}" ]]; then
    log "Building QEMU debug kernel (${DEBUG_KERNEL})..."
    "${ROOT_DIR}/scripts/build-kernel.sh" --debug
fi
[[ -f "${DEBUG_KERNEL}" ]] || die "missing debug kernel: ${DEBUG_KERNEL}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shardkey-qemu-test.XXXXXX")"
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# Build a 72 MiB hybrid BIOS (Syslinux) + UEFI (EFI_STUB) virtual USB boot stick image
# with an active MBR FAT32 LBA (0x0c) partition starting at sector 2048 (offset 1 MiB).
BOOT_IMG="${WORK_DIR}/boot-stick.img"
PART_IMG="${WORK_DIR}/boot-part.img"
SYSLINUX_CFG="${WORK_DIR}/syslinux.cfg"

truncate -s 72M "${BOOT_IMG}"
printf 'label: dos\nunit: sectors\n\n2048,,c,*\n' | sfdisk -q "${BOOT_IMG}" >/dev/null
dd if="${SYSLINUX_MBR}" of="${BOOT_IMG}" bs=440 count=1 conv=notrunc status=none

# Format partition separately then copy into sector 2048 so host mkfs.vfat needs no --offset
PART_SECTORS=$((72 * 1024 * 2 - 2048))
PART_BLOCKS=$((PART_SECTORS / 2))
mkfs.vfat -F 32 -n SHARDKEY -C "${PART_IMG}" "${PART_BLOCKS}" >/dev/null
dd if="${PART_IMG}" of="${BOOT_IMG}" bs=512 seek=2048 conv=notrunc status=none
rm -f "${PART_IMG}"

cat >"${SYSLINUX_CFG}" <<'EOF'
DEFAULT shardkey
PROMPT 0
TIMEOUT 0

LABEL shardkey
    LINUX /shardkey/bzImage
EOF

BOOT_MTOOLS_IMG="${BOOT_IMG}@@1048576"
mmd -i "${BOOT_MTOOLS_IMG}" ::/EFI ::/EFI/BOOT ::/shardkey ::/syslinux
syslinux --offset $((2048 * 512)) -d /syslinux -i "${BOOT_IMG}"
mcopy -i "${BOOT_MTOOLS_IMG}" "${DEBUG_KERNEL}" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${BOOT_MTOOLS_IMG}" "${DEBUG_KERNEL}" ::/shardkey/bzImage
mcopy -i "${BOOT_MTOOLS_IMG}" "${SYSLINUX_CFG}" ::/syslinux/syslinux.cfg
rm -f "${SYSLINUX_CFG}"

log "Prepared hybrid BIOS/UEFI test boot stick image cleanly."

python3 - "${WORK_DIR}" "${BOOT_IMG}" "${OVMF_CODE}" "${OVMF_VARS}" "${COMBINE_CHECK}" "${DEBUG_KERNEL}" <<'PYEOF'
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time

WORK_DIR, BOOT_IMG, OVMF_CODE, OVMF_VARS, COMBINE_CHECK, DEBUG_KERNEL = sys.argv[1:7]
DISK_SIZE = 72 * 1024 * 1024  # 72 MiB sparse raw image (clean FAT32 cluster count)


def make_blank_disk(name):
    path = os.path.join(WORK_DIR, name)
    with open(path, "wb") as f:
        f.truncate(DISK_SIZE)
    return path


def read_mbr_part_offset(img_path):
    with open(img_path, "rb") as f:
        mbr = f.read(512)
    if len(mbr) != 512 or mbr[510:512] != b"\x55\xaa":
        raise AssertionError(f"{img_path}: missing MBR signature")
    entry = mbr[446:462]
    ptype = entry[4]
    start_lba = struct.unpack("<I", entry[8:12])[0]
    if ptype != 0x0C or start_lba == 0:
        raise AssertionError(f"{img_path}: unexpected MBR entry type=0x{ptype:02x} lba={start_lba}")
    return start_lba * 512


def run_mtools_verify(img_paths, expected_k, expected_n, expected_set_id, expected_fp):
    extracted = []
    out_dir = os.path.join(WORK_DIR, f"extracted_{expected_k}of{expected_n}_{os.getpid()}_{int(time.time()*1000)}")
    os.makedirs(out_dir, exist_ok=True)

    for idx, img_path in enumerate(img_paths, start=1):
        offset = read_mbr_part_offset(img_path)
        m_img = f"{img_path}@@{offset}"

        # List directory via mdir
        res = subprocess.run(["mdir", "-b", "-i", m_img, "::/"], capture_output=True, text=True, check=True)
        entries = [line.strip().split("/")[-1] for line in res.stdout.splitlines() if line.strip()]
        entries_lower = sorted(e.lower() for e in entries)
        expected_share_name = f"shardkey-share-{idx}-of-{expected_n}.txt"
        expected_files = sorted(["readme.txt", expected_share_name])
        if entries_lower != expected_files:
            raise AssertionError(
                f"Share {idx} drive unexpected directory entries: got {entries}, expected {expected_files}"
            )

        share_dst = os.path.join(out_dir, expected_share_name)
        readme_dst = os.path.join(out_dir, f"README-{idx}.txt")
        subprocess.run(["mcopy", "-n", "-i", m_img, f"::/{expected_share_name}", share_dst], check=True)
        subprocess.run(["mcopy", "-n", "-i", m_img, "::/README.txt", readme_dst], check=True)

        with open(readme_dst, "r", encoding="utf-8") as f:
            readme_text = f.read()
        if f"Share {idx} of {expected_n}" not in readme_text:
            raise AssertionError(f"README.txt missing 'Share {idx} of {expected_n}'")
        if expected_set_id not in readme_text or expected_fp not in readme_text:
            raise AssertionError("README.txt missing ceremony set_id or fingerprint")

        extracted.append(share_dst)

    # Host-only C verification across all C(n, k) subsets
    chk = subprocess.run([COMBINE_CHECK, *extracted], capture_output=True, text=True)
    if chk.returncode != 0:
        raise AssertionError(f"combine_check failed (rc={chk.returncode}):\n{chk.stderr}\n{chk.stdout}")

    expected_subsets = 1
    for i in range(expected_k):
        expected_subsets = expected_subsets * (expected_n - i) // (i + 1)
    expected_line = (
        f"OK set_id={expected_set_id} fingerprint={expected_fp} "
        f"k={expected_k} n={expected_n} subsets={expected_subsets}"
    )
    if expected_line not in chk.stdout:
        raise AssertionError(f"Unexpected combine_check output:\n{chk.stdout}\nExpected: {expected_line}")
    print(f"[qemu-test]   Host reconstruction verified: {chk.stdout.strip()}")


class QemuSession:
    def __init__(self, mode, case_name, boot_img):
        self.mode = mode
        self.case_name = case_name
        self.run_dir = os.path.join(WORK_DIR, f"{mode}_{case_name}")
        os.makedirs(self.run_dir, exist_ok=True)
        self.ser_sock = os.path.join(self.run_dir, "ser.sock")
        self.mon_sock = os.path.join(self.run_dir, "mon.sock")
        self.transcript = []
        self.rx_buf = ""
        self.usb_seq = 0
        self.proc = None
        self.ser = None
        self.mon = None
        self.qmp_buf = ""
        self.events = []

        cmd = [
            "qemu-system-x86_64",
            "-machine", "q35",
            "-m", "256M",
            "-nographic",
            "-nic", "none",
            "-device", "qemu-xhci,id=xhci",
            "-chardev", f"socket,id=ser,path={self.ser_sock},server=on,wait=off",
            "-serial", "chardev:ser",
            "-chardev", f"socket,id=mon,path={self.mon_sock},server=on,wait=off",
            "-mon", "chardev=mon,mode=control",
            "-drive", f"if=none,id=bd_boot,format=raw,readonly=on,file={boot_img}",
            "-device", "usb-storage,bus=xhci.0,id=usb_boot,drive=bd_boot,bootindex=1",
        ]
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            cmd.extend(["-accel", "kvm"])
        cmd.extend(["-accel", "tcg"])

        if mode == "uefi":
            vars_copy = os.path.join(self.run_dir, "OVMF_VARS.fd")
            shutil.copyfile(OVMF_VARS, vars_copy)
            cmd.extend([
                "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
                "-drive", f"if=pflash,format=raw,file={vars_copy}",
            ])

        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ser = self._connect(self.ser_sock)
        self.mon = self._connect(self.mon_sock)
        self._qmp_init()

    def _connect(self, path):
        for _ in range(100):
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace")
                raise RuntimeError(f"QEMU exited early rc={self.proc.returncode}: {err}")
            if os.path.exists(path):
                try:
                    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sk.connect(path)
                    return sk
                except OSError:
                    sk.close()
            time.sleep(0.05)
        raise TimeoutError(f"Timed out connecting to {path}")

    def _drain_qmp_lines(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.mon], [], [], min(0.1, max(0.01, end - time.time())))
            if r:
                chunk = self.mon.recv(4096).decode("utf-8", "replace")
                if not chunk:
                    break
                self.qmp_buf += chunk
                if "\n" in self.qmp_buf:
                    return
            elif self.qmp_buf:
                break

    def _pop_qmp_objs(self):
        objs = []
        while "\n" in self.qmp_buf:
            line, self.qmp_buf = self.qmp_buf.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            objs.append(json.loads(line))
        return objs

    def _qmp_init(self):
        self._drain_qmp_lines(5.0)
        greetings = self._pop_qmp_objs()
        if not any("QMP" in g for g in greetings):
            raise RuntimeError(f"Unexpected QMP greeting: {greetings}")
        self.qmp({"execute": "qmp_capabilities"})

    def qmp(self, obj, allow_error=False):
        self.mon.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        end = time.time() + 10.0
        while time.time() < end:
            for item in self._pop_qmp_objs():
                if "event" in item:
                    self.events.append(item)
                    continue
                if "return" in item:
                    return item
                if "error" in item:
                    if allow_error:
                        return item
                    raise RuntimeError(f"QMP error on {obj}: {item}")
            self._drain_qmp_lines(0.2)
        raise TimeoutError(f"QMP timed out for {obj}")

    def attach_usb(self, img_path, read_only=False):
        self.usb_seq += 1
        bd_id = f"bd_{self.usb_seq}"
        dev_id = f"usb_{self.usb_seq}"
        self.qmp({
            "execute": "blockdev-add",
            "arguments": {
                "driver": "raw",
                "node-name": bd_id,
                "read-only": bool(read_only),
                "file": {"driver": "file", "filename": img_path},
            },
        })
        self.qmp({
            "execute": "device_add",
            "arguments": {
                "driver": "usb-storage",
                "bus": "xhci.0",
                "id": dev_id,
                "drive": bd_id,
            },
        })
        return dev_id, bd_id

    def detach_usb(self, dev_id, bd_id=None):
        self.qmp({"execute": "device_del", "arguments": {"id": dev_id}})
        end = time.time() + 10.0
        deleted = False
        while time.time() < end:
            # Check buffered events first
            for ev in list(self.events):
                if ev.get("event") == "DEVICE_DELETED" and ev.get("data", {}).get("device") == dev_id:
                    deleted = True
            if deleted:
                break
            self._drain_qmp_lines(0.1)
            for item in self._pop_qmp_objs():
                if "event" in item:
                    self.events.append(item)
                    if item.get("event") == "DEVICE_DELETED" and item.get("data", {}).get("device") == dev_id:
                        deleted = True
            if deleted:
                break
        if bd_id is not None:
            for _ in range(25):
                res = self.qmp(
                    {"execute": "blockdev-del", "arguments": {"node-name": bd_id}},
                    allow_error=True,
                )
                if "return" in res:
                    break
                time.sleep(0.1)

    def read_until(self, needle, timeout=30.0):
        _, buf = self.read_until_any([needle], timeout=timeout)
        return buf

    def read_until_any(self, needles, timeout=30.0):
        end = time.time() + timeout
        while True:
            best_idx = None
            best_needle = None
            for needle in needles:
                idx = self.rx_buf.find(needle)
                if idx != -1 and (best_idx is None or idx < best_idx):
                    best_idx = idx
                    best_needle = needle
            if best_needle is not None:
                cut = best_idx + len(best_needle)
                matched_chunk = self.rx_buf[:cut]
                self.rx_buf = self.rx_buf[cut:]
                return best_needle, matched_chunk

            rem = end - time.time()
            if rem <= 0:
                break
            r, _, _ = select.select([self.ser], [], [], min(0.2, rem))
            if r:
                raw = self.ser.recv(4096)
                if not raw:
                    break
                text = raw.decode("utf-8", "replace")
                self.transcript.append(text)
                self.rx_buf += text

        full = "".join(self.transcript)
        raise TimeoutError(
            f"[{self.mode}:{self.case_name}] Timed out waiting for any of {needles!r}.\n"
            f"--- Pending rx_buf ---\n{self.rx_buf}\n--- Full transcript ---\n{full[-4000:]}"
        )

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.ser.sendall(data)

    def wait_poweroff(self, timeout=20.0):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                break
            r, _, _ = select.select([self.ser], [], [], 0.2)
            if r:
                raw = self.ser.recv(4096)
                if raw:
                    text = raw.decode("utf-8", "replace")
                    self.transcript.append(text)
                    self.rx_buf += text
        rc = self.proc.wait(timeout=5)
        if rc != 0:
            raise AssertionError(f"[{self.mode}:{self.case_name}] Expected QEMU rc=0, got {rc}")
        return "".join(self.transcript[-10:])

    def close(self):
        for sk in (self.ser, self.mon):
            if sk is not None:
                try:
                    sk.close()
                except OSError:
                    pass
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def boot_and_unplug_boot_stick(sess):
    # Booting from usb-storage triggers either /init's USB gate (if xHCI probed
    # before PID 1 started) or /bin/shardkey's USB wait after Press Enter.
    matched, _ = sess.read_until_any(
        [
            "Remove all USB drives (including the boot stick) to continue...",
            "Remove the boot stick and all other USB drives. Press Enter.",
        ],
        timeout=35.0,
    )
    if matched.startswith("Remove all USB drives"):
        sess.detach_usb("usb_boot", "bd_boot")
        sess.read_until("All USB drives removed.", timeout=15.0)
        sess.read_until("Remove the boot stick and all other USB drives. Press Enter.", timeout=15.0)
        sess.send("\r")
        return False

    # Allow xHCI usb-storage probe to settle, then trigger removal wait & unplug
    time.sleep(1.5)
    sess.send("\r")
    gate, _ = sess.read_until_any(
        [
            "Waiting until all USB drives are removed...",
            "How many shares (n)? [2-16]: ",
        ],
        timeout=15.0,
    )
    sess.detach_usb("usb_boot", "bd_boot")
    if gate.startswith("Waiting"):
        sess.read_until("How many shares (n)? [2-16]: ", timeout=15.0)
    return True


def start_policy_and_dice(sess, n, k_input, rolls=110, at_policy_prompt=False):
    if not at_policy_prompt:
        sess.read_until("How many shares (n)? [2-16]: ")
    sess.send(f"{n}\r")
    sess.read_until("Threshold (k):")
    sess.send(f"{k_input}\r")
    if (n == 2 and k_input.upper() == "M") or str(n) == k_input:
        sess.read_until("Type YES to accept k = n:")
        sess.send("YES\r")
    sess.read_until("shares? Type YES:")
    sess.send("YES\r")
    sess.read_until("Rolls: 0/100")
    seq = ("123456" * ((rolls // 6) + 2))[:rolls]
    sess.send(seq)
    sess.read_until("press Enter to finish")
    sess.send("\r")
    info = sess.read_until("Ceremony parameters ready:")
    _, info_tail = sess.read_until_any(["\r\n\r\n", "\n\n"])
    info += info_tail
    m = re.search(r"set ID ([0-9a-f]{16}), secret fingerprint ([0-9a-f]{16})", info)
    if not m:
        raise AssertionError(f"Could not parse set ID / fingerprint from:\n{info}")
    return m.group(1), m.group(2)


def write_and_verify_share(sess, idx, n, img_path):
    sess.read_until(f"Insert blank drive for share {idx}/{n}...")
    dev_id, bd_id = sess.attach_usb(img_path, read_only=False)
    sess.read_until("Type YES to erase it:")
    sess.send("YES\r")
    sess.read_until("Unplug the drive, then plug it back in to verify...", timeout=45.0)
    sess.detach_usb(dev_id, bd_id)
    time.sleep(0.5)
    dev_id2, bd_id2 = sess.attach_usb(img_path, read_only=False)
    sess.read_until(f"Share {idx}/{n} OK. Unplug and label it", timeout=25.0)
    sess.detach_usb(dev_id2, bd_id2)


def test_happy_path(mode, n, k_expected):
    print(f"[qemu-test] Running happy_path ({mode}, {k_expected}-of-{n})...")
    sess = QemuSession(mode, f"happy_{k_expected}of{n}", BOOT_IMG)
    try:
        at_policy = boot_and_unplug_boot_stick(sess)
        set_id, fp = start_policy_and_dice(sess, n, "M", rolls=120, at_policy_prompt=at_policy)
        imgs = [make_blank_disk(f"{mode}_happy_s{i}.img") for i in range(1, n + 1)]
        for idx, img in enumerate(imgs, start=1):
            write_and_verify_share(sess, idx, n, img)
        sess.read_until(f"All {n} shares written and verified. Wiping memory...")
        sess.read_until("ShardKey ceremony completed (exit 0). Caches cleared; powering off.")
        sess.wait_poweroff()
    finally:
        sess.close()

    run_mtools_verify(imgs, k_expected, n, set_id, fp)
    print(f"[qemu-test] PASS: happy_path ({mode}, {k_expected}-of-{n})")


def test_failure_modes(mode):
    print(f"[qemu-test] Running failure_modes ({mode})...")
    sess = QemuSession(mode, "failures", BOOT_IMG)
    ro_img = make_blank_disk(f"{mode}_ro.img")
    pulled_img = make_blank_disk(f"{mode}_pulled.img")
    s1_img = make_blank_disk(f"{mode}_fail_s1.img")
    s2_img = make_blank_disk(f"{mode}_fail_s2.img")

    try:
        at_policy = boot_and_unplug_boot_stick(sess)
        set_id, fp = start_policy_and_dice(sess, 2, "M", rolls=108, at_policy_prompt=at_policy)

        # 1. Wrong drive inserted (boot stick)
        sess.read_until("Insert blank drive for share 1/2...")
        dev_b, bd_b = sess.attach_usb(BOOT_IMG, read_only=True)
        sess.read_until("ERROR on share 1/2: this drive appears to be the ShardKey boot stick")
        sess.read_until("press Enter to retry share 1/2 (or type ABORT to cancel):")
        sess.detach_usb(dev_b, bd_b)
        time.sleep(0.4)
        sess.send("\r")

        # 2. Write-protected drive
        sess.read_until("Insert blank drive for share 1/2...")
        dev_ro, bd_ro = sess.attach_usb(ro_img, read_only=True)
        sess.read_until("Type YES to erase it:")
        sess.send("YES\r")
        out_ro = sess.read_until("press Enter to retry share 1/2 (or type ABORT to cancel):", timeout=30.0)
        if "Read-only file system" not in out_ro and "failed to partition and format USB drive" not in out_ro:
            raise AssertionError(f"Expected write-protected error, got:\n{out_ro}")
        sess.detach_usb(dev_ro, bd_ro)
        time.sleep(0.4)
        sess.send("\r")

        # 3. Drive pulled mid-write
        sess.read_until("Insert blank drive for share 1/2...")
        dev_pull, bd_pull = sess.attach_usb(pulled_img, read_only=False)
        sess.read_until("Type YES to erase it:")
        sess.send("YES\r")
        sess.read_until("Formatting and partitioning")
        sess.detach_usb(dev_pull, bd_pull)
        sess.read_until("ERROR on share 1/2:")
        sess.read_until("press Enter to retry share 1/2 (or type ABORT to cancel):")
        time.sleep(0.4)
        sess.send("\r")

        # Recover and write share 1 cleanly
        write_and_verify_share(sess, 1, 2, s1_img)

        # 4. Same drive (share 1) re-inserted for share 2
        sess.read_until("Insert blank drive for share 2/2...")
        dev_dup, bd_dup = sess.attach_usb(s1_img, read_only=False)
        sess.read_until("ERROR on share 2/2: this drive already contains an earlier share from this ceremony")
        sess.read_until("press Enter to retry share 2/2 (or type ABORT to cancel):")
        sess.detach_usb(dev_dup, bd_dup)
        time.sleep(0.4)
        sess.send("\r")

        # Recover and write share 2 cleanly
        write_and_verify_share(sess, 2, 2, s2_img)
        sess.read_until("All 2 shares written and verified. Wiping memory...")
        sess.read_until("ShardKey ceremony completed (exit 0). Caches cleared; powering off.")
        sess.wait_poweroff()
    finally:
        sess.close()

    run_mtools_verify([s1_img, s2_img], 2, 2, set_id, fp)
    print(f"[qemu-test] PASS: failure_modes ({mode})")


def test_ctrl_c_interrupt(mode):
    print(f"[qemu-test] Running ctrl_c_interrupt ({mode})...")
    sess = QemuSession(mode, "ctrlc", BOOT_IMG)
    try:
        at_policy = boot_and_unplug_boot_stick(sess)
        if not at_policy:
            sess.read_until("How many shares (n)? [2-16]: ")
        sess.send("3\r")
        sess.read_until("Threshold (k):")
        sess.send("M\r")
        sess.read_until("shares? Type YES:")
        sess.send("YES\r")
        sess.read_until("Rolls: 0/100")
        sess.send("123456123456")
        sess.read_until("Rolls: 12/100")
        # 5. Send Ctrl-C (0x03) mid-ceremony during raw dice collection
        sess.send(b"\x03")
        sess.read_until("ShardKey exited with status 1. Caches cleared; powering off.")
        sess.wait_poweroff()
    finally:
        sess.close()
    print(f"[qemu-test] PASS: ctrl_c_interrupt ({mode})")


def test_uefi_secboot():
    sec_code = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
    sec_vars = "/usr/share/OVMF/OVMF_VARS_4M.snakeoil.fd"
    sec_key = "/usr/share/ovmf/PkKek-1-snakeoil.key"
    sec_cert = "/usr/share/ovmf/PkKek-1-snakeoil.pem"
    if not all(os.path.exists(p) for p in (sec_code, sec_vars, sec_key, sec_cert)):
        print("[qemu-test] SKIP: uefi_secboot (OVMF snakeoil Secure Boot files absent)")
        return

    print("[qemu-test] Running uefi_secboot (Secure Boot refusal of unsigned + boot of signed)...")
    sec_dir = os.path.join(WORK_DIR, "secboot")
    os.makedirs(sec_dir, exist_ok=True)

    plain_key = os.path.join(sec_dir, "snakeoil.key")
    signed_kernel = os.path.join(sec_dir, "bzImage.signed")
    signed_img = os.path.join(sec_dir, "secboot-signed.img")
    part_img = os.path.join(sec_dir, "part.img")

    subprocess.run(
        ["openssl", "rsa", "-in", sec_key, "-passin", "pass:snakeoil", "-out", plain_key],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sbsign", "--key", plain_key, "--cert", sec_cert, "--output", signed_kernel, DEBUG_KERNEL],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(["sbverify", "--cert", sec_cert, signed_kernel], check=True, stdout=subprocess.DEVNULL)

    with open(signed_img, "wb") as f:
        f.truncate(DISK_SIZE)
    subprocess.run(
        ["sfdisk", "-q", signed_img],
        input="label: dos\nunit: sectors\n\n2048,,c,*\n",
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    part_blocks = (72 * 1024 * 2 - 2048) // 2
    subprocess.run(
        ["mkfs.vfat", "-F", "32", "-n", "SHARDKEY", "-C", part_img, str(part_blocks)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["dd", f"if={part_img}", f"of={signed_img}", "bs=512", "seek=2048", "conv=notrunc", "status=none"],
        check=True,
    )
    m_img = f"{signed_img}@@1048576"
    subprocess.run(["mmd", "-i", m_img, "::/EFI", "::/EFI/BOOT"], check=True)
    subprocess.run(["mcopy", "-i", m_img, signed_kernel, "::/EFI/BOOT/BOOTX64.EFI"], check=True)

    def launch_secboot(name, img_path):
        vars_copy = os.path.join(sec_dir, f"{name}_vars.fd")
        shutil.copyfile(sec_vars, vars_copy)
        ser_sock = os.path.join(sec_dir, f"{name}_ser.sock")
        cmd = [
            "qemu-system-x86_64",
            "-machine", "q35,smm=on",
            "-m", "256M",
            "-nographic",
            "-nic", "none",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,readonly=on,file={sec_code}",
            "-drive", f"if=pflash,format=raw,file={vars_copy}",
            "-device", "qemu-xhci,id=xhci",
            "-drive", f"if=none,id=bd,format=raw,readonly=on,file={img_path}",
            "-device", "usb-storage,bus=xhci.0,id=u,drive=bd,bootindex=1",
            "-chardev", f"socket,id=ser,path={ser_sock},server=on,wait=off",
            "-serial", "chardev:ser",
        ]
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            cmd.extend(["-accel", "kvm"])
        cmd.extend(["-accel", "tcg"])
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sk = None
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError(f"QEMU exited early rc={proc.returncode}: {proc.stderr.read().decode()}")
            if os.path.exists(ser_sock):
                try:
                    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sk.connect(ser_sock)
                    break
                except OSError:
                    sk.close()
                    sk = None
            time.sleep(0.05)
        if sk is None:
            proc.kill()
            proc.wait()
            raise TimeoutError(f"Timed out connecting to {ser_sock}")
        return proc, sk

    # 1. Unsigned image must be REFUSED under UEFI Secure Boot
    p_u, sk_u = launch_secboot("unsigned", BOOT_IMG)
    try:
        out_u = ""
        end = time.time() + 15.0
        while time.time() < end:
            r, _, _ = select.select([sk_u], [], [], 0.2)
            if r:
                out_u += sk_u.recv(4096).decode("utf-8", "replace")
                if "Access Denied" in out_u or "Security Violation" in out_u:
                    break
        if "ShardKey" in out_u:
            raise AssertionError(f"Unsigned kernel booted under Secure Boot!\n{out_u}")
        if "Access Denied" not in out_u and "Security Violation" not in out_u:
            raise AssertionError(f"Expected Secure Boot refusal for unsigned image, got:\n{out_u}")
    finally:
        sk_u.close()
        p_u.kill()
        p_u.wait()

    # 2. Signed image must BOOT under UEFI Secure Boot
    p_s, sk_s = launch_secboot("signed", signed_img)
    try:
        out_s = ""
        end = time.time() + 20.0
        while time.time() < end:
            r, _, _ = select.select([sk_s], [], [], 0.2)
            if r:
                out_s += sk_s.recv(4096).decode("utf-8", "replace")
                if "Press Enter." in out_s:
                    break
        if "Press Enter." not in out_s:
            raise AssertionError(f"Signed kernel did not boot under Secure Boot:\n{out_s}")
        sk_s.sendall(b"\x03")
        end_pow = time.time() + 15.0
        while p_s.poll() is None and time.time() < end_pow:
            r, _, _ = select.select([sk_s], [], [], 0.2)
            if r:
                out_s += sk_s.recv(4096).decode("utf-8", "replace")
        rc = p_s.wait(timeout=5)
        if rc != 0 or "Caches cleared; powering off." not in out_s:
            raise AssertionError(f"Signed Secure Boot guest did not power off cleanly rc={rc}:\n{out_s}")
    finally:
        sk_s.close()
        if p_s.poll() is None:
            p_s.kill()
            p_s.wait()

    print("[qemu-test] PASS: uefi_secboot (unsigned refused, signed booted)")


def main():
    start = time.time()
    test_happy_path("bios", 3, 2)
    test_happy_path("uefi", 5, 3)
    for mode in ("bios", "uefi"):
        test_failure_modes(mode)
        test_ctrl_c_interrupt(mode)
    test_uefi_secboot()
    elapsed = time.time() - start
    print(f"[qemu-test] ALL BIOS, UEFI & SECURE BOOT E2E TESTS PASSED in {elapsed:.1f}s.")


main()
PYEOF
