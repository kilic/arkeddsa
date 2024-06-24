use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;

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
