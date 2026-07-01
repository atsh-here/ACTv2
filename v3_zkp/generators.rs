use ff::Field; // FIX: Gives access to BlsScalar::ONE
use blstrs::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar as BlsScalar};
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use ff::PrimeField;
use group::{Curve, Group};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static RISTRETTO_GV: OnceLock<RistrettoPoint> = OnceLock::new();
pub fn ristretto_gv() -> RistrettoPoint {
    *RISTRETTO_GV.get_or_init(|| PedersenGens::default().B)
}

static RISTRETTO_G1: OnceLock<RistrettoPoint> = OnceLock::new();
pub fn ristretto_g1() -> RistrettoPoint {
    *RISTRETTO_G1.get_or_init(|| PedersenGens::default().B_blinding)
}

static BLS_G1_AFFINE: OnceLock<G1Affine> = OnceLock::new();
pub fn bls_g1_affine() -> G1Affine {
    *BLS_G1_AFFINE.get_or_init(|| G1Projective::generator().to_affine())
}

static BLS_H1_AFFINE: OnceLock<G1Affine> = OnceLock::new();
pub fn bls_h1_affine() -> G1Affine {
    *BLS_H1_AFFINE.get_or_init(|| {
        let hash = Sha256::digest(b"bls_hv");
        let mut array = [0u8; 32];
        array.copy_from_slice(&hash);
        let scalar = BlsScalar::from_repr_vartime(array).unwrap_or(BlsScalar::ONE);
        (G1Projective::generator() * scalar).to_affine()
    })
}

static NEG_G2_PREPARED: OnceLock<G2Prepared> = OnceLock::new();
pub fn neg_g2_prepared() -> &'static G2Prepared {
    NEG_G2_PREPARED.get_or_init(|| G2Prepared::from(-G2Affine::from(G2Projective::generator())))
}
