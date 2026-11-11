#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Download and cryptographically verify all pinned upstream sources into build/src/:
#   1. Linux LTS kernel tarball (.tar.xz) + detached signature (.tar.sign)
#      - Verify SHA-256 of the compressed .tar.xz archive
#      - Verify OpenPGP signature over the *uncompressed* .tar stream against
#        pinned maintainer fingerprints (Linus Torvalds / Greg Kroah-Hartman)
#   2. BusyBox tarball (.tar.bz2) — verify SHA-256
#   3. Syslinux tarball (.tar.xz) — verify SHA-256
#
# Reference: docs/PLAN.md (§4 Phase 1) and docs/DECISIONS.md (D-003).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/config/versions.env}"

if [[ ! -f "${VERSIONS_FILE}" ]]; then
    echo "[fetch] ERROR: versions file not found: ${VERSIONS_FILE}" >&2
    exit 1
fi

# Preserve optional environment overrides before sourcing versions.env
_OVR_KERNEL_SHA256="${KERNEL_SHA256:-}"
_OVR_BUSYBOX_SHA256="${BUSYBOX_SHA256:-}"
_OVR_SYSLINUX_SHA256="${SYSLINUX_SHA256:-}"
_OVR_KERNEL_PGP_FINGERPRINTS="${KERNEL_PGP_FINGERPRINTS:-}"

# shellcheck source=../config/versions.env
. "${VERSIONS_FILE}"

[[ -n "${_OVR_KERNEL_SHA256}" ]] && KERNEL_SHA256="${_OVR_KERNEL_SHA256}"
[[ -n "${_OVR_BUSYBOX_SHA256}" ]] && BUSYBOX_SHA256="${_OVR_BUSYBOX_SHA256}"
[[ -n "${_OVR_SYSLINUX_SHA256}" ]] && SYSLINUX_SHA256="${_OVR_SYSLINUX_SHA256}"
[[ -n "${_OVR_KERNEL_PGP_FINGERPRINTS}" ]] && KERNEL_PGP_FINGERPRINTS="${_OVR_KERNEL_PGP_FINGERPRINTS}"

BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
SRC_DIR="${SRC_DIR:-${BUILD_DIR}/src}"

mkdir -p "${SRC_DIR}"

die() {
    echo "[fetch] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[fetch] $*"
}

download_file() {
    local url="$1"
    local dest="$2"
    local name
    name="$(basename "${dest}")"

    if [[ -f "${dest}" ]]; then
        info "Using cached ${name}"
        return 0
    fi

    info "Downloading ${name} from ${url} ..."
    local part="${dest}.part.$$"
    if ! curl --fail --location --proto '=https' --tlsv1.2 \
              --retry 3 --retry-delay 2 --connect-timeout 20 \
              --output "${part}" "${url}"; then
        rm -f "${part}"
        die "Failed to download ${url}"
    fi
    mv -f "${part}" "${dest}"
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local name
    name="$(basename "${file}")"

    if [[ ! -f "${file}" ]]; then
        die "File missing for SHA-256 check: ${file}"
    fi

    expected="$(echo "${expected}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
        die "Malformed expected SHA-256 for ${name}: '${expected}'"
    fi

    local actual
    actual="$(sha256sum "${file}" | awk '{print tolower($1)}')"

    if [[ "${actual}" != "${expected}" ]]; then
        echo "[fetch] ERROR: SHA-256 mismatch for ${name}!" >&2
        echo "  Expected: ${expected}" >&2
        echo "  Actual:   ${actual}" >&2
        exit 1
    fi

    info "SHA-256 OK: ${name} (${actual})"
}

ensure_kernel_keyring() {
    local gnupghome="$1"
    local cached_keyring="${SRC_DIR}/.kernel-release-keys.gpg"
    local staging_home="${gnupghome}/staging"
    mkdir -p -m 700 "${staging_home}"

    if [[ -s "${cached_keyring}" ]]; then
        gpg --batch --quiet --homedir "${staging_home}" --import "${cached_keyring}" >/dev/null 2>&1 || true
    fi

    # Check whether all pinned fingerprints are present in staging_home
    local have_fp_list
    have_fp_list="$(gpg --batch --homedir "${staging_home}" --with-colons --list-keys 2>/dev/null \
        | awk -F: '$1 == "pub" { want=1; next } want && $1 == "fpr" { print toupper($10); want=0 }' || true)"

    local need_fetch=0
    for req_fpr in ${KERNEL_PGP_FINGERPRINTS}; do
        req_fpr="$(echo "${req_fpr}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
        if [[ ! "${req_fpr}" =~ ^[0-9A-F]{40}$ ]]; then
            die "Malformed pinned PGP fingerprint: '${req_fpr}'"
        fi
        if ! echo "${have_fp_list}" | grep -qx "${req_fpr}"; then
            need_fetch=1
            break
        fi
    done

    if [[ "${need_fetch}" -eq 1 ]]; then
        info "Fetching kernel.org release signing keys via WKD / keys.openpgp.org ..."
        # 1. Try kernel.org Web Key Directory (WKD)
        if [[ -n "${KERNEL_PGP_WKD_IDS:-}" ]]; then
            # shellcheck disable=SC2086
            gpg --batch --quiet --homedir "${staging_home}" \
                --auto-key-locate clear,wkd \
                --locate-external-keys ${KERNEL_PGP_WKD_IDS} >/dev/null 2>&1 || true
        fi

        # 2. Fallback per-fingerprint via keys.openpgp.org VKS endpoint
        have_fp_list="$(gpg --batch --homedir "${staging_home}" --with-colons --list-keys 2>/dev/null \
            | awk -F: '$1 == "pub" { want=1; next } want && $1 == "fpr" { print toupper($10); want=0 }' || true)"

        for req_fpr in ${KERNEL_PGP_FINGERPRINTS}; do
            req_fpr="$(echo "${req_fpr}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
            if ! echo "${have_fp_list}" | grep -qx "${req_fpr}"; then
                local key_asc="${staging_home}/${req_fpr}.asc"
                if curl --fail --silent --location --proto '=https' --tlsv1.2 \
                        --retry 3 --connect-timeout 15 \
                        --output "${key_asc}" \
                        "https://keys.openpgp.org/vks/v1/by-fingerprint/${req_fpr}"; then
                    gpg --batch --quiet --homedir "${staging_home}" --import "${key_asc}" >/dev/null 2>&1 || true
                fi
            fi
        done

        # Update cache with any valid keys in staging
        # shellcheck disable=SC2086
        gpg --batch --quiet --homedir "${staging_home}" \
            --export ${KERNEL_PGP_FINGERPRINTS} > "${cached_keyring}.tmp.$$" 2>/dev/null || true
        if [[ -s "${cached_keyring}.tmp.$$" ]]; then
            mv -f "${cached_keyring}.tmp.$$" "${cached_keyring}"
        else
            rm -f "${cached_keyring}.tmp.$$"
        fi
    fi

    # Export strictly the pinned fingerprints from staging into the verification gnupghome
    local exported_keys="${gnupghome}/pinned.gpg"
    # shellcheck disable=SC2086
    gpg --batch --quiet --homedir "${staging_home}" \
        --export ${KERNEL_PGP_FINGERPRINTS} > "${exported_keys}" 2>/dev/null || true
    rm -rf "${staging_home}"

    if [[ ! -s "${exported_keys}" ]]; then
        die "No kernel PGP public keys matching pinned fingerprints (${KERNEL_PGP_FINGERPRINTS}) could be loaded."
    fi

    gpg --batch --quiet --homedir "${gnupghome}" --import "${exported_keys}" >/dev/null 2>&1
    rm -f "${exported_keys}"

    # Verify that at least one pinned key is present and NO unpinned primary keys exist
    have_fp_list="$(gpg --batch --homedir "${gnupghome}" --with-colons --list-keys 2>/dev/null \
        | awk -F: '$1 == "pub" { want=1; next } want && $1 == "fpr" { print toupper($10); want=0 }' || true)"

    if [[ -z "${have_fp_list}" ]]; then
        die "No kernel PGP public keys matching pinned fingerprints could be loaded."
    fi

    local matched_count=0
    while IFS= read -r fpr; do
        [[ -z "${fpr}" ]] && continue
        local allowed=0
        for req_fpr in ${KERNEL_PGP_FINGERPRINTS}; do
            req_fpr="$(echo "${req_fpr}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
            if [[ "${fpr}" == "${req_fpr}" ]]; then
                allowed=1
                matched_count=$((matched_count + 1))
                break
            fi
        done
        if [[ "${allowed}" -ne 1 ]]; then
            die "Untrusted key fingerprint found in temporary keyring: ${fpr}"
        fi
    done <<< "${have_fp_list}"

    if [[ "${matched_count}" -eq 0 ]]; then
        die "None of the pinned kernel PGP fingerprints (${KERNEL_PGP_FINGERPRINTS}) are in the keyring."
    fi
}

verify_kernel_gpg() {
    local tar_xz="$1"
    local sign_file="$2"

    if [[ ! -f "${tar_xz}" ]]; then
        die "Kernel archive missing: ${tar_xz}"
    fi
    if [[ ! -f "${sign_file}" ]]; then
        die "Kernel signature file missing: ${sign_file}"
    fi

    # Verify strict ASCII-armored PGP signature framing (no NUL bytes, no leading/trailing garbage)
    if ! tr -d '\000' < "${sign_file}" | cmp -s - "${sign_file}"; then
        die "Malformed or tampered PGP armor (contains NUL byte) in $(basename "${sign_file}")."
    fi
    local first_line last_line begin_count end_count
    first_line="$(head -n 1 "${sign_file}" | tr -d '\r')"
    last_line="$(tail -n 1 "${sign_file}" | tr -d '\r')"
    begin_count="$(grep -c '^-----BEGIN PGP SIGNATURE-----' "${sign_file}" || true)"
    end_count="$(grep -c '^-----END PGP SIGNATURE-----' "${sign_file}" || true)"
    if [[ "${first_line}" != "-----BEGIN PGP SIGNATURE-----" || \
          "${last_line}" != "-----END PGP SIGNATURE-----" || \
          "${begin_count}" -ne 1 || "${end_count}" -ne 1 ]]; then
        die "Malformed or tampered PGP armor in $(basename "${sign_file}")."
    fi

    local gnupghome
    gnupghome="$(mktemp -d "${SRC_DIR}/.gnupg.XXXXXX")"
    chmod 700 "${gnupghome}"
    # Clean up temporary GnuPG home on function return or script exit
    trap 'rm -rf "${gnupghome}"' RETURN

    ensure_kernel_keyring "${gnupghome}"

    info "Verifying kernel OpenPGP signature on uncompressed $(basename "${tar_xz}" .xz) ..."
    local gpg_status=""
    local verify_rc=0
    gpg_status="$(xz -dc "${tar_xz}" \
        | gpg --batch --homedir "${gnupghome}" --status-fd=1 --verify "${sign_file}" - 2>&1)" || verify_rc=$?

    if [[ "${verify_rc}" -ne 0 ]]; then
        echo "${gpg_status}" >&2
        die "OpenPGP signature verification failed for $(basename "${tar_xz}") (exit ${verify_rc})."
    fi

    if echo "${gpg_status}" | grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NODATA|UNEXPECTED|FAILURE)'; then
        echo "${gpg_status}" >&2
        die "OpenPGP reported an invalid/expired/revoked signature for $(basename "${tar_xz}")."
    fi

    local newsig_count goodsig_count validsig_count
    newsig_count="$(echo "${gpg_status}" | grep -cE '^\[GNUPG:\] NEWSIG(\s|$)' || true)"
    goodsig_count="$(echo "${gpg_status}" | grep -cE '^\[GNUPG:\] GOODSIG ' || true)"
    validsig_count="$(echo "${gpg_status}" | grep -cE '^\[GNUPG:\] VALIDSIG ' || true)"

    if [[ "${newsig_count}" -ne 1 || "${goodsig_count}" -ne 1 || "${validsig_count}" -ne 1 ]]; then
        echo "${gpg_status}" >&2
        die "OpenPGP output did not contain exactly one valid signature (NEWSIG=${newsig_count}, GOODSIG=${goodsig_count}, VALIDSIG=${validsig_count})."
    fi

    local validsig_line
    validsig_line="$(echo "${gpg_status}" | grep -E '^\[GNUPG:\] VALIDSIG ' | head -n 1)"

    # Format: [GNUPG:] VALIDSIG <signing-fpr> <date> <ts> <exp> <ver> <res> <pkalgo> <hashalgo> <class> <primary-key-fpr>
    local signing_fpr primary_fpr
    signing_fpr="$(echo "${validsig_line}" | awk '{print toupper($3)}')"
    primary_fpr="$(echo "${validsig_line}" | awk '{print toupper($12)}')"
    [[ -z "${primary_fpr}" ]] && primary_fpr="${signing_fpr}"

    local fpr_ok=0
    for allowed_fpr in ${KERNEL_PGP_FINGERPRINTS}; do
        allowed_fpr="$(echo "${allowed_fpr}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
        if [[ "${primary_fpr}" == "${allowed_fpr}" || "${signing_fpr}" == "${allowed_fpr}" ]]; then
            fpr_ok=1
            break
        fi
    done

    if [[ "${fpr_ok}" -ne 1 ]]; then
        echo "${gpg_status}" >&2
        die "Kernel signature fingerprint (${primary_fpr}) is NOT in pinned list (${KERNEL_PGP_FINGERPRINTS})."
    fi

    info "OpenPGP signature OK: $(basename "${tar_xz}") signed by pinned key ${primary_fpr}"
}

# ─────────────────────────────────────────────────────────────
# 1. Linux LTS kernel + GPG signature
# ─────────────────────────────────────────────────────────────
KERNEL_ARCHIVE_PATH="${SRC_DIR}/${KERNEL_TARBALL}"
KERNEL_SIGN_PATH="${SRC_DIR}/${KERNEL_SIGN}"

download_file "${KERNEL_URL}" "${KERNEL_ARCHIVE_PATH}"
download_file "${KERNEL_SIGN_URL}" "${KERNEL_SIGN_PATH}"
verify_sha256 "${KERNEL_ARCHIVE_PATH}" "${KERNEL_SHA256}"
verify_kernel_gpg "${KERNEL_ARCHIVE_PATH}" "${KERNEL_SIGN_PATH}"

# ─────────────────────────────────────────────────────────────
# 2. BusyBox
# ─────────────────────────────────────────────────────────────
BUSYBOX_ARCHIVE_PATH="${SRC_DIR}/${BUSYBOX_TARBALL}"

download_file "${BUSYBOX_URL}" "${BUSYBOX_ARCHIVE_PATH}"
verify_sha256 "${BUSYBOX_ARCHIVE_PATH}" "${BUSYBOX_SHA256}"

# ─────────────────────────────────────────────────────────────
# 3. Syslinux
# ─────────────────────────────────────────────────────────────
SYSLINUX_ARCHIVE_PATH="${SRC_DIR}/${SYSLINUX_TARBALL}"

download_file "${SYSLINUX_URL}" "${SYSLINUX_ARCHIVE_PATH}"
verify_sha256 "${SYSLINUX_ARCHIVE_PATH}" "${SYSLINUX_SHA256}"

info "All upstream sources fetched and verified in ${SRC_DIR}."
