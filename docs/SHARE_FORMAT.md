# ShardKey — Share File Format (v1, draft)

This document defines what ShardKey writes to each share drive. It is the contract
between ShardKey and the separate recovery tool. Status: **draft** — may change until
the first release; after that, changes require a new version number.

---

## 1. Drive layout

| Item | Value |
|---|---|
| Partition table | MBR, one primary partition, type `0x0c` (FAT32 LBA) |
| Filesystem | FAT32, volume label `SHARDKEY` |
| Files | `shardkey-share-<i>-of-<n>.txt` — the share<br>`README.txt` — plain-language note for the holder (no secret data) |

FAT32 is chosen so the share can be read on any operating system without special
drivers.

## 2. Share file

Plain ASCII text, LF (`\n`) line endings, exactly these lines in this order, each
`key: value` with one space after the colon. Hex is lower-case.

```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 3
set-id: 7f3a9c0e5b21d846
fingerprint: 9c21e07a4b3d5f18
data: 3b0d…(64 hex chars)…e1a4
check: 51c2a07d9e33b6f0
```

| Field | Meaning |
|---|---|
| `SHARDKEY-SHARE-V1` | Magic + format version |
| `scheme` | `shamir-gf256`: byte-wise Shamir over GF(2⁸), reduction polynomial `x⁸+x⁴+x³+x+1` (0x11B) |
| `threshold` | `k`: number of shares needed to rebuild. Chosen by the operator; always `⌊n/2⌋+1 ≤ k ≤ n` |
| `shares` | `n`: number of shares created, `2..16` |
| `index` | `x` coordinate of this share, `1..n` |
| `set-id` | 8 random bytes (16 hex), the same in every share of one ceremony. Not secret. Prevents mixing shares from different ceremonies |
| `fingerprint` | First 8 bytes of `SHA-256("SHARDKEY-FP-V1" ‖ secret)`. Lets the recovery tool confirm it rebuilt the right secret. Not secret: 64 bits of a hash of a 256-bit random value reveal nothing usable |
| `data` | 32 bytes (64 hex): `data[j] = P_j(index)` where `P_j` is the polynomial for secret byte `j` |
| `check` | First 8 bytes of `SHA-256` over every preceding line of the file, including their `\n` |

### About `check`
`check` catches **accidental** damage (bad flash, typos when copying by hand). It is
**not** a signature: anyone can edit a share and recompute it. Protection against a
deliberately altered share is the `fingerprint` test after rebuilding (see §4).

## 3. Math

For each secret byte `s_j` (`j = 0..31`), ShardKey picks `k−1` random coefficients
`a_{j,1} … a_{j,k−1}`, uniform over all 256 byte values (zero allowed), and defines
(the secret, the coefficients and `set-id` all come from the dice + kernel seed, see
DECISIONS D-018)

```
P_j(x) = s_j + a_{j,1}·x + a_{j,2}·x² + … + a_{j,k−1}·x^(k−1)     over GF(2⁸)
```

Share `i` holds `P_j(i)` for every `j`. Any `k` shares rebuild `s_j = P_j(0)` by Lagrange
interpolation at zero; `k−1` or fewer shares give no information about `s_j`.

## 4. Rules for a recovery tool

A recovery tool reading v1 shares must:

1. Reject a file whose first line isn't `SHARDKEY-SHARE-V1`, or with missing, extra, or
   out-of-order fields.
2. Reject a file whose `check` doesn't match.
3. Reject a set with different `set-id`, `threshold`, `shares`, or `fingerprint` values.
4. Reject duplicate `index` values, any `index` outside `1..shares`, `shares` outside
   `2..16`, and `threshold` outside `⌊shares/2⌋+1 .. shares`.
5. Require at least `threshold` shares.
6. After rebuilding, compute the fingerprint and **reject the result if it doesn't
   match**. If more than `threshold` shares are given, try subsets to find a bad share.

## 5. Test vectors

To be added in Phase 2: a fixed secret, fixed coefficients, and the expected share
files, so the recovery project can test against them.
