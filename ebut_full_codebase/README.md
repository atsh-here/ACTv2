# EBUT Storage Integrated Codebase

This repository integrates:

- non-transferable EBUT tokens,
- EBUT epoch rate limiting,
- expiry through a unique per-user Unix `Emax`,
- revocation through signed gap non-membership over hidden `Emax`,
- reversible Ristretto ElGamal file binding,
- BLS12-381 ↔ Ristretto same-`x` equality for upload accountability.

## Important design

Use one canonical ownership secret:

```text
x = CanonicalX, 248-bit integer
```

Embed it into both worlds:

```text
x_BLS       -> EBUT/BBS+ token messages
x_Ristretto -> file-binding ElGamal/DLEQ
```

`Emax` is a unique Unix timestamp per user. It is hidden in EBUT proofs and used for both expiry and blacklist revocation.

## Main modules

- `master_mint.rs`: blind master minting on `(x, cmax, Emax)`.
- `epoch_refresh.rs`: EBUT refresh, epoch nullifier, expiry proof, BLS x commitment.
- `spend.rs`: non-transferable spend/refund, balance proof, spend-time expiry proof, BLS x commitment.
- `revocation.rs`: signed-gap non-membership wrappers for hidden `Emax`.
- `file_binding.rs`: reversible Ristretto ElGamal file binding.
- `same_x_bridge.rs`: cross-curve equality proof for `x`.
- `upload.rs`: EBUT spend + revocation + file binding + same-x composition.

## Removed from old NTAT

The old NTAT `rate_limit.rs`, slot generators, `RateLimitState`, `RateLimitProof`, and `used_tags` are not used. EBUT replaces them.

## Build note

This sandbox did not include `cargo` or `rustc`, so I could not run the compiler here. Run:

```bash
cargo check
cargo test
```

in a local Rust environment before treating this as working code.
