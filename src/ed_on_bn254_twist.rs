use ark_ec::{
    models::CurveConfig,
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
};
use ark_ff::MontFp;
pub type EdwardsAffine = Affine<EdwardsConfig>;
pub type EdwardsProjective = Projective<EdwardsConfig>;

pub use ark_ed_on_bn254::{Fq, Fr};
pub type BaseField = ark_ed_on_bn254::Fq;
pub type ScalarField = ark_ed_on_bn254::Fr;

/// Twist of `Baby-JubJub` is a twist of twisted Edwards curve. These curves have equations of the
/// form: ax² + y² = 1 + dx²y².
/// over some base finite field BaseField.
///
/// q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EdwardsConfig;

#[cfg(test)]
ark_algebra_test_templates::test_group!(te; EdwardsProjective; te);

impl CurveConfig for EdwardsConfig {
    type BaseField = BaseField;
    type ScalarField = ScalarField;

    /// COFACTOR = 8
    const COFACTOR: &'static [u64] = &[8];

    /// COFACTOR^(-1) mod r =
    /// 2394026564107420727433200628387514462817212225638746351800188703329891451411
    const COFACTOR_INV: ScalarField =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for EdwardsConfig {
    const COEFF_A: BaseField = MontFp!("168700");

    #[inline(always)]
    fn mul_by_a(elem: Self::BaseField) -> Self::BaseField {
        elem * <Self as TECurveConfig>::COEFF_A
    }

    const COEFF_D: BaseField = MontFp!("168696");

    const GENERATOR: EdwardsAffine = EdwardsAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);

    type MontCurveConfig = EdwardsConfig;
}

impl MontCurveConfig for EdwardsConfig {
    /// COEFF_A = 168698
    const COEFF_A: BaseField = MontFp!("168698");
    /// COEFF_B = 168700
    const COEFF_B: BaseField = MontFp!("1");

    type TECurveConfig = EdwardsConfig;
}

/// GENERATOR_X =
/// 19698561148652590122159747500897617769866003486955115824547446575314762165298
pub const GENERATOR_X: BaseField =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");

/// GENERATOR_Y =
/// 19298250018296453272277890825869354524455968081175474282777126169995084727839
pub const GENERATOR_Y: BaseField =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

#[test]
fn test_twist() {
    fn twist(twist: ark_ed_on_bn254::EdwardsAffine) -> EdwardsAffine {
        use ark_ff::Field;
        let inv_sqrt_a = MontFp!("168700").sqrt().unwrap().inverse().unwrap();
        EdwardsAffine {
            x: twist.x * inv_sqrt_a,
            y: twist.y,
        }
    }

    fn untwist(curve: EdwardsAffine) -> ark_ed_on_bn254::EdwardsAffine {
        use ark_ff::Field;
        const A: BaseField = MontFp!("168700");
        let sqrt_a = A.sqrt().unwrap();
        ark_ed_on_bn254::EdwardsAffine {
            x: curve.x * sqrt_a,
            y: curve.y,
        }
    }

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use rand_core::OsRng;

    let v0: ark_ed_on_bn254::EdwardsAffine = ark_ed_on_bn254::EdwardsAffine::generator();
    let u0: crate::ed_on_bn254_twist::EdwardsAffine = twist(v0);
    assert!(u0.is_on_curve());
    assert!(u0.is_in_correct_subgroup_assuming_on_curve());
    let x = Fr::rand(&mut OsRng);
    let u1 = (u0 * x).into_affine();
    let v1 = (v0 * x).into_affine();
    let v2 = untwist(u1);
    assert_eq!(v1, v2);
}
