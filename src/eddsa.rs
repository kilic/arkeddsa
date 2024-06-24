use crate::{signature::Signature, Error};
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use digest::Digest;
use digest::OutputSizeUser;
use rand_core::CryptoRngCore;

fn prune_buffer<F: PrimeField>(mut bytes: [u8; 32]) -> F {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    F::from_le_bytes_mod_order(&bytes[..])
}

#[derive(Copy, Clone, Debug)]
/// EdDSA secret key is 32 byte data
pub struct SecretKey([u8; 32]);

impl SecretKey {
    fn expand<F: PrimeField, D: Digest>(&self) -> (F, [u8; 32]) {
        let hash = D::new().chain_update(self.0).finalize();
        let (buffer, hash_prefix) = hash.split_at(32);
        let buffer: [u8; 32] = buffer.try_into().unwrap();
        let hash_prefix: [u8; 32] = hash_prefix.try_into().unwrap();
        let x = prune_buffer(buffer);
        (x, hash_prefix)
    }
}

#[derive(Copy, Clone, Debug)]
/// `PublicKey` is EdDSA signature verification key
pub struct PublicKey<A: AffineRepr>(A)
where
    A::Config: TECurveConfig;

#[derive(Copy, Clone, Debug)]
/// `SigningKey` produces EdDSA signatures for given message
pub struct SigningKey<A: AffineRepr>
where
    A::Config: TECurveConfig,
{
    secret_key: SecretKey,
    public_key: PublicKey<A>,
}

impl<A: AffineRepr> SigningKey<A>
where
    A::Config: TECurveConfig,
    A::BaseField: PrimeField + Absorb,
{
    pub fn new<D: Digest>(secret_key: &SecretKey) -> Result<Self, Error> {
        (<D as OutputSizeUser>::output_size() == 64)
            .then_some(())
            .ok_or(Error::BadOutputSize)?;

        let (x, _) = secret_key.expand::<A::ScalarField, D>();
        let public_key: A = (A::generator() * x).into_affine();
        let signing_key = Self {
            secret_key: *secret_key,
            public_key: PublicKey(public_key),
        };

        Ok(signing_key)
    }

    pub fn generate<D: Digest>(rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        let mut secret_key = SecretKey([0; 32]);
        rng.fill_bytes(&mut secret_key.0);
        Self::new::<D>(&secret_key)
    }

    pub fn public_key(&self) -> PublicKey<A> {
        self.public_key
    }

    pub fn sign<D: Digest, E: Absorb>(
        &self,
        poseidon: &PoseidonConfig<A::BaseField>,
        message: &[E],
    ) -> Signature<A> {
        let (x, prefix) = self.secret_key.expand::<A::ScalarField, D>();

        let mut h = D::new();
        h.update(prefix);
        message
            .iter()
            .for_each(|m| h.update(m.to_sponge_bytes_as_vec()));
        let r: A::ScalarField = crate::from_digest(h);
        let sig_r = (A::generator() * r).into_affine();

        let mut poseidon = PoseidonSponge::new(poseidon);
        let (sig_r_x, sig_r_y) = sig_r.xy().unwrap();
        poseidon.absorb(sig_r_x);
        poseidon.absorb(sig_r_y);
        let (vk_x, vk_y) = self.public_key.0.xy().unwrap();
        poseidon.absorb(vk_x);
        poseidon.absorb(vk_y);
        message.iter().for_each(|m| poseidon.absorb(m));

        let k = poseidon.squeeze_field_elements::<A::ScalarField>(1);
        let k = k.first().unwrap();

        let sig_s = (x * k) + r;

        Signature::new(sig_r, sig_s)
    }
}

impl<A: AffineRepr> PublicKey<A>
where
    A::Config: TECurveConfig,
    A::BaseField: PrimeField + Absorb,
{
    pub fn verify<E: Absorb>(
        &self,
        poseidon: &PoseidonConfig<A::BaseField>,
        message: &[E],
        signature: &Signature<A>,
    ) -> Result<(), Error> {
        let mut poseidon = PoseidonSponge::new(poseidon);

        let (sig_r_x, sig_r_y) = signature.r().xy().unwrap();
        poseidon.absorb(sig_r_x);
        poseidon.absorb(sig_r_y);
        let (vk_x, vk_y) = self.0.xy().unwrap();
        poseidon.absorb(vk_x);
        poseidon.absorb(vk_y);
        message.iter().for_each(|m| poseidon.absorb(m));

        let k = poseidon.squeeze_field_elements::<A::ScalarField>(1);
        let k = k.first().unwrap();

        let kx_b = self.0 * k;
        let s_b = A::generator() * signature.s();
        let r_rec: A = (s_b - kx_b).into();

        (signature.r() == &r_rec).then_some(()).ok_or(Error::Verify)
    }
}
