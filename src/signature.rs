use crate::Error;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

#[derive(Clone, Copy, Debug)]
/// `SignatureComponents` contains the realized parts of a signature
pub struct Signature<A: AffineRepr> {
    r: A,
    s: A::ScalarField,
}

impl<A: AffineRepr> Signature<A>
where
    A::Config: TECurveConfig,
{
    /// Serializes the signature components to bytes as uncompressed.
    /// Expect output size to be `size_of(A::BaseField) * 2 + size_of(A::ScalarField)`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.r.serialize_uncompressed(&mut bytes).unwrap();
        self.s.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    /// Checked deserialization of the signature components from bytes.
    /// Expects input size to be `size_of(A::BaseField) * 2 + size_of(A::ScalarField)`
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature<A>, Error> {
        let point_size = A::Config::serialized_size(ark_serialize::Compress::No);
        (bytes.len() == 32 + A::Config::serialized_size(ark_serialize::Compress::No))
            .then_some(true)
            .ok_or(Error::InvalidData)?;

        let off1 = point_size;
        let off2 = off1 + 32;

        let r =
            A::deserialize_uncompressed(&bytes[00..off1]).map_err(|_| crate::Error::InvalidData)?;
        let s = A::ScalarField::deserialize_uncompressed(&bytes[off1..off2])
            .map_err(|_| crate::Error::InvalidData)?;
        Ok(Signature { r, s })
    }

    pub fn new(r: A, s: A::ScalarField) -> Self {
        Self { r, s }
    }

    pub(crate) fn r(&self) -> &A {
        &self.r
    }

    pub(crate) fn s(&self) -> &A::ScalarField {
        &self.s
    }
}
