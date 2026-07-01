# Full Codebase Integration Audit

## Implemented in this package

### 1. EBUT remains the only rate-limit core

Old NTAT slot generators, `RateLimitState`, `RateLimitProof`, and `used_tags` are not used. EBUT enforces rate limits through:

```text
DBepoch: N_T = x * H_epoch(T)
DBspend: k_cur spend nullifier
Nspent: spend nonce set
```

### 2. Non-transferability

Daily/refund token statements now carry the master ownership secret `x`:

```text
DailyToken  = Sig(x, k_daily, cmax, T, Emax)
RefundToken = Sig(x, k_next,  m,    T, Emax)
```

Spend requires proving the same hidden `x`; handing over only `k_cur` or a daily token is not enough.

### 3. Expiry with unique Unix `Emax`

`Emax` is now `u64`. Refresh and spend both prove:

```text
Emax - now_unix >= 0
```

using a 64-bit cross-curve equality/range proof.

### 4. Revocation through signed gaps over hidden `Emax`

`Emax` is the revocation handle. The revocation proof shows:

```text
ea < Emax < eb
```

for a server-signed non-revoked gap. The v3 gap proof now uses the same BLS bases as EBUT’s Emax commitment (`h5` and `h0`), so refresh/spend Emax commitments can be used directly.

### 5. Reversible file binding

`src/file_binding.rs` uses reversible 28-byte Ristretto encoding and ElGamal:

```text
M_i = Encode(chunk_i)
C1_i = r_i * G
C2_i = M_i + r_i * (xG)
```

The file proof verifies:

```text
D_i = C2_i - M_i = x * C1_i
```

against a binding tag:

```text
B_file = x * H_file
```

### 6. Same-x bridge

`src/same_x_bridge.rs` proves that the same canonical 248-bit `x` opens:

```text
C_bls  = x * h1 + r * h0
C_rist = x * H_file
```

Upload verification checks the BLS commitment equals `spend_proof.x_bls_commitment`, so the file-binding `x` is tied to the EBUT token’s hidden `x`.

### 7. Safer transcripts

- BEQ transcripts bind context and all surrounding BBS/bridge commitments.
- Gap proof no longer hashes debug formatting of `Gt`; it uses canonical bytes.
- Upload same-x proof binds the full statement and caller-provided context.

## Notes before production

- Run `cargo check` and `cargo test` in a real Rust environment.
- Independently re-audit the manually derived combined MSM equations in refresh/spend.
- The optimized batch verifiers intentionally fall back to individual verification until the new six-generator layout is audited.
- The same-x secret is intentionally canonical 248-bit. Generate user master secrets via `CanonicalX`, not arbitrary full-field scalars, when file binding is required.
