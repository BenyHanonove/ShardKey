#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Generate the offline Symbolon release signing key pair (one-time setup).
# Follows docs/SIGNING.md (§3, §4.1):
#   - RSA-2048 private key, AES-256 encrypted, written ONLY to the external key drive
#   - Self-signed X.509 certificate (CN=Symbolon Signing, 10-year validity)
#   - Public outputs in keys/ (or $SYMBOLON_KEYS_DIR):
#       symbolon-signing.crt  (PEM)
#       symbolon-signing.cer  (DER for UEFI firmware db enrollment)
#       FINGERPRINT.txt       (SHA-256 fingerprint for out-of-band verification)
#
# Usage:
#   scripts/gen-signing-key.sh [--force] [--pass-file <path>] <key-usb-dir>

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS_DIR="${SYMBOLON_KEYS_DIR:-${ROOT_DIR}/keys}"

log() {
    printf '[gen-signing-key] %s\n' "$*"
}

die() {
    printf '[gen-signing-key] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/gen-signing-key.sh [--force] [--pass-file <path>] <key-usb-dir>

Generates an encrypted RSA-2048 private key at <key-usb-dir>/symbolon-signing.key
and public certificates + fingerprint in keys/.
EOF
}

FORCE=0
PASS_FILE=""
DEST_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)
            FORCE=1
            shift
            ;;
        --pass-file)
            [[ $# -ge 2 ]] || die "--pass-file requires a path"
            PASS_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [[ -z "${DEST_DIR}" ]] || die "unexpected extra argument: $1"
            DEST_DIR="$1"
            shift
            ;;
    esac
done

[[ -n "${DEST_DIR}" ]] || { usage >&2; die "destination USB directory is required"; }
[[ -d "${DEST_DIR}" ]] || die "destination directory does not exist: ${DEST_DIR}"
[[ -w "${DEST_DIR}" ]] || die "destination directory is not writable: ${DEST_DIR}"

command -v openssl >/dev/null 2>&1 || die "openssl is required"

REAL_ROOT="$(cd -P "${ROOT_DIR}" && pwd)"
REAL_DEST="$(cd -P "${DEST_DIR}" && pwd)"
case "${REAL_DEST}" in
    "${REAL_ROOT}"|"${REAL_ROOT}"/*)
        die "refusing to write private key inside repository directory: ${REAL_DEST}"
        ;;
esac

if [[ -n "${PASS_FILE}" ]]; then
    [[ -r "${PASS_FILE}" ]] || die "passphrase file not readable: ${PASS_FILE}"
fi

KEY_OUT="${REAL_DEST}/symbolon-signing.key"
CRT_OUT="${KEYS_DIR}/symbolon-signing.crt"
CER_OUT="${KEYS_DIR}/symbolon-signing.cer"
FP_OUT="${KEYS_DIR}/FINGERPRINT.txt"

if [[ "${FORCE}" -eq 0 ]]; then
    for existing in "${KEY_OUT}" "${CRT_OUT}" "${CER_OUT}" "${FP_OUT}"; do
        if [[ -e "${existing}" ]]; then
            die "refusing to overwrite existing file (pass --force to replace): ${existing}"
        fi
    done
fi

umask 077
mkdir -p "${KEYS_DIR}"

EXT_CFG="$(mktemp "${TMPDIR:-/tmp}/symbolon-x509.XXXXXX.cnf")"
cleanup() {
    rm -f "${EXT_CFG}"
}
trap cleanup EXIT

cat >"${EXT_CFG}" <<'EOF'
[req]
distinguished_name = req_dn
x509_extensions = v3_codesign
prompt = no

[req_dn]
CN = Symbolon Signing

[v3_codesign]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF

log "Generating encrypted RSA-2048 private key at ${KEY_OUT} ..."
if [[ -n "${PASS_FILE}" ]]; then
    openssl genrsa -aes256 -passout "file:${PASS_FILE}" -out "${KEY_OUT}" 2048
else
    openssl genrsa -aes256 -out "${KEY_OUT}" 2048
fi
chmod 0400 "${KEY_OUT}"

log "Creating self-signed X.509 certificate (10-year validity, CN=Symbolon Signing)..."
umask 022
if [[ -n "${PASS_FILE}" ]]; then
    openssl req -new -x509 -sha256 -days 3650 \
        -config "${EXT_CFG}" -extensions v3_codesign \
        -key "${KEY_OUT}" -passin "file:${PASS_FILE}" \
        -out "${CRT_OUT}"
else
    openssl req -new -x509 -sha256 -days 3650 \
        -config "${EXT_CFG}" -extensions v3_codesign \
        -key "${KEY_OUT}" \
        -out "${CRT_OUT}"
fi

openssl x509 -in "${CRT_OUT}" -outform DER -out "${CER_OUT}"

FP_LINE="$(openssl x509 -in "${CRT_OUT}" -noout -fingerprint -sha256)"
SUBJECT_LINE="$(openssl x509 -in "${CRT_OUT}" -noout -subject)"
DATES_LINES="$(openssl x509 -in "${CRT_OUT}" -noout -dates)"

{
    printf '# Symbolon Signing Certificate Fingerprint (public)\n'
    printf '# Compare against hardware enrollment and `make verify` output.\n'
    printf '%s\n' "${SUBJECT_LINE}"
    printf '%s\n' "${DATES_LINES}"
    printf '%s\n' "${FP_LINE}"
} >"${FP_OUT}"

chmod 0644 "${CRT_OUT}" "${CER_OUT}" "${FP_OUT}"

log "Private key written to: ${KEY_OUT}"
log "Public PEM certificate: ${CRT_OUT}"
log "Public DER certificate: ${CER_OUT}"
log "Fingerprint file:       ${FP_OUT}"
log "${FP_LINE}"
log "Make two offline backups of ${KEY_OUT} and store them in separate safe places."
