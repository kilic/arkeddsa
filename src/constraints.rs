/// This file implements the EdDSA verification in-circuit.
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_relations::r1cs::ConstraintSystemRef;

use ark_r1cs_std::{
    boolean::Boolean, fields::fp::FpVar, fields::nonnative::NonNativeFieldVar, groups::CurveVar,
    ToBitsGadget, ToConstraintFieldGadget,
};

use crate::Error;

/// CF stands for ConstraintField
pub type CF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// gadget to compute the EdDSA verification in-circuit
pub fn verify<C, GC>(
    cs: ConstraintSystemRef<CF<C>>,
    poseidon_config: PoseidonConfig<CF<C>>,
    pk: GC,
    sig: (GC, NonNativeFieldVar<C::ScalarField, CF<C>>),
    msg: FpVar<CF<C>>,
) -> Result<Boolean<CF<C>>, Error>
where
    C: CurveGroup,
    GC: CurveVar<C, CF<C>> + ToConstraintFieldGadget<CF<C>>,
{
    let (r, s): (GC, NonNativeFieldVar<C::ScalarField, CF<C>>) = sig;

    let r_xy = r.to_constraint_field().unwrap();
    let pk_xy = pk.to_constraint_field().unwrap();

    let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);
    poseidon.absorb(&r_xy).unwrap();
    poseidon.absorb(&pk_xy).unwrap();
    poseidon.absorb(&msg).unwrap();
    let k = poseidon.squeeze_field_elements(1).unwrap();
    let k = k.first().unwrap();

    let kx_b = pk.scalar_mul_le(k.to_bits_le().unwrap().iter()).unwrap();

    let g = GC::new_constant(cs.clone(), C::generator()).unwrap();
    let s_b = g.scalar_mul_le(s.to_bits_le().unwrap().iter()).unwrap();
    let r_rec: GC = s_b - kx_b;
    Ok(r_rec.is_eq(&r).unwrap())
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::nonnative::NonNativeFieldVar};
    use ark_relations::r1cs::ConstraintSystem;
    use rand_core::OsRng;

    use super::*;
    use crate::ed_on_bn254_twist::{
        constraints::EdwardsVar as GVar, BaseField as Fq, EdwardsConfig, EdwardsProjective as G,
        ScalarField as Fr,
    };
    use crate::{poseidon_config, SigningKey};

    #[test]
    fn gadget_verify() {
        let poseidon_config = poseidon_config::<Fq>(4, 8, 60);
        let sk = SigningKey::<EdwardsConfig>::generate::<blake2::Blake2b512>(&mut OsRng).unwrap();
        let msg_raw = b"xxx yyy <<< zzz >>> bunny";
        let msg = Fq::from_le_bytes_mod_order(msg_raw);
        let sig = sk.sign::<blake2::Blake2b512>(&poseidon_config, &msg);
        let pk = sk.public_key();
        pk.verify(&poseidon_config, &msg, &sig).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();
        let pk_var: GVar = GVar::new_witness(cs.clone(), || Ok(pk.0)).unwrap();
        let r_var: GVar = GVar::new_witness(cs.clone(), || Ok(sig.r)).unwrap();
        let s_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(sig.s)).unwrap();
        let msg_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(msg)).unwrap();

        let res = verify::<G, GVar>(cs.clone(), poseidon_config, pk_var, (r_var, s_var), msg_var)
            .unwrap();
        res.enforce_equal(&Boolean::<Fq>::TRUE).unwrap();

        dbg!(cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
