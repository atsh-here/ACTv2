//! Revocation wrapper around signed-gap non-membership.
//!
//! In this design the hidden `Emax` is both the Unix expiry timestamp and the
//! blacklist handle. Revocation succeeds by proving that hidden `Emax` lies in a
//! server-signed open interval `(ea, eb)` of non-revoked values.
//!
//! The integrated v3 gap proof uses 64-bit Bulletproof range proofs for
//! `Emax - ea - 1` and `eb - Emax - 1`. This wrapper therefore rejects gaps
//! that overflow u64 arithmetic.

use blstrs::{G1Projective, Scalar as BlsScalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as RistrettoScalar;

use crate::error::{ActError, Result};
use crate::v3_zkp::gap::ServerPublicKey;
use crate::v3_zkp::prover::{TimedProof, create_non_membership_proof_timed, verify_non_membership_proof_timed};
use crate::setup::Generators;
use crate::epoch_refresh::{RefreshProof, refresh_emax_bls_commitment};
use crate::spend::{SpendProof, spend_emax_bls_commitment};

/// Maximum width supported by the current 64-bit gap range proof.
pub const MAX_GAP_WIDTH_V1: u64 = u64::MAX - 1;

/// Public revocation context. Bind this into outer EBUT transcripts too.
#[derive(Clone, Debug)]
pub struct RevocationContext {
    pub app_id: Vec<u8>,
    pub policy_id: Vec<u8>,
    pub server_key_id: [u8; 32],
    pub revocation_list_version: u64,
    pub now_unix: u64,
}

/// Signed gap and its blindings/commitments.
///
/// The current v3 prototype expects the caller to provide the interval
/// signature `(sigma1, sigma2)` and the BLS/Ristretto blindings used in the
/// equality proof. A production implementation should package these in a
/// canonical wire format.
#[derive(Clone, Debug)]
pub struct GapWitnessInputs {
    pub emax: u64,
    pub r1_emax: RistrettoScalar,
    pub r2_emax: BlsScalar,
    pub interval: (u64, u64),
    pub signature: (G1Projective, G1Projective),
    pub r2_ea: BlsScalar,
    pub r2_eb: BlsScalar,
    pub r1_ea: RistrettoScalar,
    pub r1_eb: RistrettoScalar,
}

/// Verify static gap constraints before proving or verifying.
pub fn validate_gap_interval(emax: u64, interval: (u64, u64), now_unix: u64) -> Result<()> {
    let (ea, eb) = interval;
    if !(ea < emax && emax < eb) {
        return Err(ActError::ProtocolError("Emax not inside revocation gap".into()));
    }
    if eb <= ea {
        return Err(ActError::ProtocolError("invalid revocation gap".into()));
    }
    if now_unix > emax {
        return Err(ActError::ProtocolError("Emax expired".into()));
    }
    Ok(())
}

/// Create the current v1 non-membership proof for `Emax`.
pub fn prove_emax_not_revoked(
    ctx: &RevocationContext,
    server_pk: &ServerPublicKey,
    inputs: GapWitnessInputs,
) -> Result<TimedProof> {
    validate_gap_interval(inputs.emax, inputs.interval, ctx.now_unix)?;
    // The v3 proof does not yet consume ctx internally; callers must also bind
    // ctx into the EBUT outer transcript. This wrapper keeps the context visible
    // at the API boundary so it cannot be forgotten by the upload/refresh layer.
    Ok(create_non_membership_proof_timed(
        inputs.emax,
        inputs.r1_emax,
        inputs.r2_emax,
        server_pk,
        inputs.interval,
        inputs.signature,
        inputs.r2_ea,
        inputs.r2_eb,
        inputs.r1_ea,
        inputs.r1_eb,
    ))
}

/// Verify v1 non-membership proof. This verifies the proof equations and also
/// requires the caller-provided public commitments to the hidden Emax.
pub fn verify_emax_not_revoked(
    _ctx: &RevocationContext,
    proof: &TimedProof,
    server_pk: &ServerPublicKey,
    user_com_rist: RistrettoPoint,
    user_com_bls: G1Projective,
) -> Result<()> {
    let (ok, _timing) = verify_non_membership_proof_timed(proof, server_pk, user_com_rist, user_com_bls);
    if ok { Ok(()) } else { Err(ActError::VerificationFailed("revocation gap proof failed".into())) }
}


/// Verify that the hidden `Emax` proven by a refresh proof is not revoked.
///
/// This ties revocation to EBUT by using the BLS commitment to `Emax` already
/// proven inside [`RefreshProof`]: `C_Emax = proof.c_delta + now_unix*h5`.
pub fn verify_refresh_not_revoked(
    ctx: &RevocationContext,
    revocation_proof: &TimedProof,
    server_pk: &ServerPublicKey,
    refresh_proof: &RefreshProof,
    generators: &Generators,
    user_com_rist: RistrettoPoint,
) -> Result<()> {
    let user_com_bls = refresh_emax_bls_commitment(refresh_proof, ctx.now_unix, generators);
    verify_emax_not_revoked(ctx, revocation_proof, server_pk, user_com_rist, user_com_bls)
}

/// Verify that the hidden `Emax` proven by a spend proof is not revoked.
///
/// This ties revocation to EBUT by using the BLS commitment to `Emax` already
/// proven inside [`SpendProof`]: `C_Emax = proof.c_delta + now_unix*h5`.
pub fn verify_spend_not_revoked(
    ctx: &RevocationContext,
    revocation_proof: &TimedProof,
    server_pk: &ServerPublicKey,
    spend_proof: &SpendProof,
    generators: &Generators,
    user_com_rist: RistrettoPoint,
) -> Result<()> {
    let user_com_bls = spend_emax_bls_commitment(spend_proof, ctx.now_unix, generators);
    verify_emax_not_revoked(ctx, revocation_proof, server_pk, user_com_rist, user_com_bls)
}
