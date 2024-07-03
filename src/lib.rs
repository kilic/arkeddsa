pub mod ed_on_bn254_twist;
pub mod eddsa;
pub mod signature;

use ark_ff::PrimeField;
use digest::Digest;
pub use eddsa::*;

pub(crate) fn from_digest<F: PrimeField, D: Digest>(digest: D) -> F {
    let bytes = digest.finalize();
    F::from_le_bytes_mod_order(&bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Verify,
    BadOutputSize,
    InvalidData,
}

#[cfg(test)]
mod test {

    use crate::SigningKey;
    use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
    use ark_crypto_primitives::sponge::Absorb;
    use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr};
    use ark_ff::PrimeField;
    use digest::Digest;
    use rand_core::OsRng;

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

    fn run_test<A: AffineRepr, D: Digest>()
    where
        A::BaseField: Absorb + PrimeField,
        A::Config: TECurveConfig,
    {
        let poseidon = poseidon_config(4, 8, 55);
        let signing_key = SigningKey::<A>::generate::<D>(&mut OsRng).unwrap();
        let message = b"xxx yyy <<< zzz >>> bunny";
        let signature = signing_key.sign::<D, _>(&poseidon, &message[..]);
        let public_key = signing_key.public_key();
        public_key
            .verify::<_>(&poseidon, &message[..], &signature)
            .unwrap();
    }

    #[test]
    fn test_eddsa() {
        run_test::<ark_ed_on_bn254::EdwardsAffine, sha2::Sha512>();
        run_test::<ark_ed_on_bn254::EdwardsAffine, blake2::Blake2b512>();
        run_test::<crate::ed_on_bn254_twist::EdwardsAffine, sha2::Sha512>();
        run_test::<ark_ed_on_bls12_381::EdwardsAffine, sha2::Sha512>();
        run_test::<ark_ed_on_bls12_381_bandersnatch::EdwardsAffine, sha2::Sha512>();
    }
}
