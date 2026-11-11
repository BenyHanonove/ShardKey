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

### 5.1 Share split and file encoding (3-of-5)

Parameters:
- `threshold` (`k`): `3`
- `shares` (`n`): `5`
- `secret` (32 bytes, `s_j = j` for `j = 0..31`):
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- Polynomial coefficients for byte `j` (`j = 0..31`):
  - Degree-1 coefficient `a_{j,1} = 0x20 + j`:
    `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
  - Degree-2 coefficient `a_{j,2} = 0x40 + j`:
    `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f`
- `set-id` (8 bytes): `7f3a9c0e5b21d846`
- `fingerprint` (`SHA-256("SHARDKEY-FP-V1" ‖ secret)[0..7]`): `2ff70fe219b3a5a5`

Expected share files:

#### `shardkey-share-1-of-5.txt`
```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 1
set-id: 7f3a9c0e5b21d846
fingerprint: 2ff70fe219b3a5a5
data: 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
check: 2a2c1d24961824fd
```

#### `shardkey-share-2-of-5.txt`
```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 2
set-id: 7f3a9c0e5b21d846
fingerprint: 2ff70fe219b3a5a5
data: 5b5c55524740494e63646d6a7f7871762b2c25223730393e13141d1a0f080106
check: 329ee93a25f4e0b1
```

#### `shardkey-share-3-of-5.txt`
```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 3
set-id: 7f3a9c0e5b21d846
fingerprint: 2ff70fe219b3a5a5
data: 3b3c35322720292e03040d0a1f1811164b4c45425750595e73747d7a6f686166
check: 1a9f79aa28038b9b
```

#### `shardkey-share-4-of-5.txt`
```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 4
set-id: 7f3a9c0e5b21d846
fingerprint: 2ff70fe219b3a5a5
data: ecf9c6d3b8ad928744516e7b10053a2fa7b28d98f3e6d9cc0f1a25305b4e7164
check: c5e32e514b485b28
```

#### `shardkey-share-5-of-5.txt`
```
SHARDKEY-SHARE-V1
scheme: shamir-gf256
threshold: 3
shares: 5
index: 5
set-id: 7f3a9c0e5b21d846
fingerprint: 2ff70fe219b3a5a5
data: 8c99a6b3d8cdf2e724310e1b70655a4fc7d2edf89386b9ac6f7a45503b2e1104
check: ce679027135570be
```

Any 3 of the 5 share files above reconstruct `secret = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` with matching `fingerprint = 2ff70fe219b3a5a5`.

### 5.2 Seed mixing and HKDF-Expand derivation

- `kernel_random` (64 bytes, `kernel_random[i] = i` for `i = 0..63`):
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
- `dice` (100 ASCII bytes, `dice[i] = '1' + (i mod 6)` for `i = 0..99`):
  `"1234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234561234"`
- `len(dice)` (8-byte big-endian unsigned integer): `0000000000000064`
- Mixed `seed = SHA-256("SHARDKEY-SEED-V1" ‖ kernel_random ‖ len(dice) ‖ dice)`:
  `d0cfaccf86b7b82c45ac62781a16dedc8269fdda525d8dc1a8701652b4b9c287`
- Derived material via RFC 5869 `HKDF-Expand(PRK = seed, info)`:
  - `secret` (`info = "SHARDKEY-SECRET-V1"`, 32 bytes):
    `814f728bcab53cac2854fea3a90a1e0cf5faca78ebe84c8fa5e4b4e71092d958`
  - `set-id` (`info = "SHARDKEY-SETID-V1"`, 8 bytes):
    `c29372774cf95c59`
  - `coeffs` for `k = 3` (`info = "SHARDKEY-COEFFS-V1"`, 64 bytes, `coeffs[2*j] = a_{j,1}`, `coeffs[2*j+1] = a_{j,2}`):
    `e822f54fc5d05d62e84b58714eceff2742e09c552496523130b3b9d0ed5bc216a604089fe157484fa5647a958268099271a582a3886910cb71969815738925cb`

