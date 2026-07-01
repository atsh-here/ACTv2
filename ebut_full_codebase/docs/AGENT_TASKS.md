# Agent Tasks — Completion Status

All previously listed integration tasks have been implemented in this package as far as possible without a Rust compiler in the sandbox.

## Completed

1. **Non-transferable daily/refund tokens**
   - Daily/refund commitments now carry `x`, token secret `k`, balance, epoch `T`, and unique Unix `Emax`.
   - Spend proves knowledge of the signed hidden `x`; transferring only `k_cur` is insufficient.

2. **Refresh proof extended**
   - Refresh proves the master token signs `(x, cmax, Emax)`.
   - Refresh proves `N_T = x * H_epoch(T)`.
   - Refresh proves `now_unix <= Emax` through a 64-bit BEQ/range proof on `Emax - now_unix`.
   - Refresh exposes and verifies `x_bls_commitment = x*h1 + r_x*h0`.

3. **Spend proof extended**
   - Spend proves daily/refund token signs `(x, k_cur, cbal, T, Emax)`.
   - Spend proves refund balance `m = cbal - s` and `m >= 0`.
   - Spend proves spend-time `now_unix <= Emax` with a second 64-bit BEQ/range proof.
   - Spend exposes and verifies `x_bls_commitment = x*h1 + r_x*h0` for upload same-`x` bridging.

4. **Revocation integrated**
   - Revocation gap proof now uses 64-bit Bulletproof ranges.
   - v3 gap BLS commitment bases are aligned with EBUT `h5`/`h0`, so `C_Emax = Emax*h5 + r*h0` from refresh/spend is directly consumable.
   - Added `verify_refresh_not_revoked` and `verify_spend_not_revoked` wrappers.
   - Added upload-with-revocation verifier.

5. **Same-x bridge integrated into upload**
   - Upload verification now requires the same-x statement BLS commitment to match `spend_proof.x_bls_commitment`.
   - Upload verification requires the Ristretto commitment to match the file-binding tag.

6. **64-bit upgrade**
   - BEQ/range proof is upgraded to 64-bit.
   - `Emax` is now `u64` in mint/refresh/spend/server paths.
   - Revocation gap proof uses 64-bit diff proofs.

7. **Canonical transcript serialization**
   - Removed `format!("{:?}", Gt)` from the gap proof transcript and replaced it with `Gt::to_bytes()`.

8. **Tests updated**
   - Tests now cover refresh, spend, transfer-without-x failure, expired token failure, and x-commitment tampering.

## Still not performed in this environment

- `cargo check` / `cargo test` could not be run because the sandbox does not provide `cargo` or `rustc`.
- Before production, run the full test suite and perform an independent cryptographic audit.
