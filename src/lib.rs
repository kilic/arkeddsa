use ark_ff::PrimeField;
use digest::Digest;
impl ark_std::error::Error for Error {}
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};

pub mod ed_on_bn254_twist;
pub mod eddsa;
pub mod signature;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub use eddsa::*;

pub(crate) fn from_digest<F: PrimeField, D: Digest>(digest: D) -> F {
    let bytes = digest.finalize();
    F::from_le_bytes_mod_order(&bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Verify,
    BadDigestOutput,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Error::Verify => write!(f, "Signature verification failed"),
            Error::BadDigestOutput => write!(f, "Bad digest output size"),
        }
    }
}

/// Generates poseidon constants and returns the config
pub fn poseidon_config<F: PrimeField>(
    rate: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> PoseidonConfig<F> {
    let prime_bits = F::MODULUS_BIT_SIZE as u64;
    let (ark, mds) = find_poseidon_ark_and_mds(
        prime_bits,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, 5, mds, ark, rate, 1)
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::sponge::Absorb;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ff::PrimeField;
    use digest::Digest;
    use rand_core::OsRng;

    use super::poseidon_config;
    use crate::SigningKey;

    fn run_test<TE: TECurveConfig + Clone, D: Digest>()
    where
        TE::BaseField: Absorb + PrimeField,
    {
        let poseidon = poseidon_config::<TE::BaseField>(4, 8, 55);
        let signing_key = SigningKey::<TE>::generate::<D>(&mut OsRng).unwrap();
        let message_raw = b"xxx yyy <<< zzz >>> bunny";
        let message = TE::BaseField::from_le_bytes_mod_order(message_raw);
        let signature = signing_key.sign::<D>(&poseidon, &message);
        let public_key = signing_key.public_key();
        public_key.verify(&poseidon, &message, &signature).unwrap();
    }

    #[test]
    fn test_eddsa() {
        run_test::<ark_ed_on_bn254::EdwardsConfig, sha2::Sha512>();
        run_test::<ark_ed_on_bn254::EdwardsConfig, blake2::Blake2b512>();
        run_test::<crate::ed_on_bn254_twist::EdwardsConfig, sha2::Sha512>();
        run_test::<ark_ed_on_bls12_381::EdwardsConfig, sha2::Sha512>();
        run_test::<ark_ed_on_bls12_381_bandersnatch::EdwardsConfig, sha2::Sha512>();
    }
}
