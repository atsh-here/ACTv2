//! Upload-level composition for EBUT spend + reversible file binding.
//!
//! The verifier performs three independent checks:
//! 1. EBUT spend/refund proof for rate limiting and balance.
//! 2. Reversible Ristretto ElGamal file-binding proof.
//! 3. Cross-curve same-`x` proof linking an EBUT/BLS commitment to the
//!    Ristretto file-binding tag.
//!
//! Security boundary: the caller must provide a `SameXStatement` whose BLS
//! commitment is itself proven inside the EBUT spend/refresh proof to contain
//! the signed hidden `x`. This module verifies the cross-curve link and the file
//! proof; EBUT proof modules must expose/verify that BLS commitment.

use blstrs::G2Projective;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};

use crate::error::{ActError, Result};
use crate::file_binding::{FileCommitment, FileProof, verify_file_proof};
use crate::same_x_bridge::{SameXProof, SameXStatement};
use crate::revocation::{RevocationContext, verify_spend_not_revoked};
use crate::v3_zkp::gap::ServerPublicKey as RevocationServerPublicKey;
use crate::v3_zkp::prover::TimedProof as RevocationProof;
use crate::setup::{Generators, ServerKeys};
use crate::spend::{SpendProof, SpendResponse, verify_spend};
use crate::types::Scalar;

/// Public tag used by the Ristretto file-binding proof.
///
/// `binding_tag = x_ristretto * binding_generator`.
#[derive(Clone, Debug)]
pub struct FileBindingTag {
    /// Hash-to-Ristretto generator bound to app_id, policy_id, file_id,
    /// file_root, epoch/time, Emax, and revocation list version.
    pub binding_generator: RistrettoPoint,
    /// `x * binding_generator`.
    pub binding_tag: RistrettoPoint,
}

/// Full upload proof object.
#[derive(Clone, Debug)]
pub struct UploadSpendProof {
    /// EBUT spend proof. This must be the non-transferable variant whose token
    /// contains hidden `x` and `Emax`.
    pub spend_proof: SpendProof,
    /// 128-bit spend nonce used by EBUT server state.
    pub nonce: [u8; 16],
    /// File commitment/manifest.
    pub file_commitment: FileCommitment,
    /// Merkle + DLEQ file proof.
    pub file_proof: FileProof,
    /// File-binding tag public statement.
    pub file_binding: FileBindingTag,
    /// Cross-curve statement linking a BLS commitment to the Ristretto file tag.
    pub same_x_statement: SameXStatement,
    /// Proof for `same_x_statement`.
    pub same_x_proof: SameXProof,
    /// Context bytes bound into the same-x proof. Must include h_ctx, app_id,
    /// policy_id, server key id, epoch/time, Emax commitment, file_id, root,
    /// and revocation-list version.
    pub same_x_context: Vec<u8>,
}

/// Verify an EBUT spend and a reversible ElGamal file proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_upload_spend<R: RngCore + CryptoRng>(
    proof: &UploadSpendProof,
    current_epoch: u32,
    now_unix: u64,
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    rng: &mut R,
) -> Result<SpendResponse> {
    // 1. EBUT spend/rate-limit/balance proof.
    let response = verify_spend(
        &proof.spend_proof,
        current_epoch,
        now_unix,
        &proof.nonce,
        generators,
        pk_daily,
        keys,
        h_ctx,
        rng,
    )?;

    // 2. The same-x BLS commitment must be the one proven inside the EBUT spend proof.
    if proof.same_x_statement.bls_x_base != generators.h[1]
        || proof.same_x_statement.bls_blind_base != generators.h[0]
        || proof.same_x_statement.bls_x_commitment != proof.spend_proof.x_bls_commitment
    {
        return Err(ActError::VerificationFailed("same-x BLS statement does not match EBUT spend proof".into()));
    }

    // 3. File-binding proof must use the same public Ristretto tag as the
    // cross-curve statement.
    if proof.same_x_statement.ristretto_x_base != proof.file_binding.binding_generator
        || proof.same_x_statement.ristretto_x_commitment != proof.file_binding.binding_tag
    {
        return Err(ActError::VerificationFailed("same-x statement does not match file tag".into()));
    }

    // 4. Reversible ElGamal file-binding proof.
    if !verify_file_proof(
        &proof.file_proof,
        &proof.file_commitment,
        &proof.file_commitment.nonce,
        &proof.file_binding.binding_generator,
        &proof.file_binding.binding_tag,
    ) {
        return Err(ActError::VerificationFailed("file-binding proof failed".into()));
    }

    // 5. Cross-curve bridge: BLS commitment to x equals Ristretto file tag x.
    proof.same_x_proof.verify(&proof.same_x_context, &proof.same_x_statement)?;

    Ok(response)
}


/// Verify upload spend and also require revocation non-membership for the same
/// hidden `Emax` carried inside the EBUT spend proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_upload_spend_with_revocation<R: RngCore + CryptoRng>(
    proof: &UploadSpendProof,
    current_epoch: u32,
    now_unix: u64,
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    revocation_ctx: &RevocationContext,
    revocation_proof: &RevocationProof,
    revocation_pk: &RevocationServerPublicKey,
    emax_ristretto_commitment: RistrettoPoint,
    rng: &mut R,
) -> Result<SpendResponse> {
    if revocation_ctx.now_unix != now_unix {
        return Err(ActError::VerificationFailed("revocation context time does not match upload time".into()));
    }
    let response = verify_upload_spend(
        proof, current_epoch, now_unix, generators, pk_daily, keys, h_ctx, rng,
    )?;
    verify_spend_not_revoked(
        revocation_ctx, revocation_proof, revocation_pk, &proof.spend_proof, generators, emax_ristretto_commitment,
    )?;
    Ok(response)
}
