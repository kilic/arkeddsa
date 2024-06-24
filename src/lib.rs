pub mod ed_on_bn254_twist;
pub mod eddsa;
pub mod poseidon;
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
    use ark_crypto_primitives::sponge::Absorb;
    use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr};
    use ark_ff::PrimeField;
    use digest::Digest;
    use rand_core::OsRng;

    use crate::SigningKey;

    fn run_test<A: AffineRepr, D: Digest>()
    where
        A::BaseField: Absorb + PrimeField,
        A::Config: TECurveConfig,
    {
        let poseidon = crate::poseidon::poseidon_config(4, 8, 55);
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
