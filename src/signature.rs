use ark_ec::twisted_edwards::Affine;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

/// `SignatureComponents` contains the realized parts of a signature
#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<TE: TECurveConfig + Clone> {
    r: Affine<TE>,
    s: TE::ScalarField,
}

impl<TE: TECurveConfig + Clone> Signature<TE> {
    /// Serializes the signature components to bytes as uncompressed.
    /// Expect output size to be `size_of(TE::BaseField) * 2 + size_of(TE::ScalarField)`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.r.serialize_uncompressed(&mut bytes).unwrap();
        self.s.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    /// Checked deserialization of the signature components from bytes.
    /// Expects input size to be `size_of(TE::BaseField) * 2 + size_of(TE::ScalarField)`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let point_size = TE::serialized_size(ark_serialize::Compress::No);
        (bytes.len() == 32 + TE::serialized_size(ark_serialize::Compress::No))
            .then_some(true)
            .ok_or(ark_serialize::SerializationError::InvalidData)?;

        let off1 = point_size;
        let off2 = off1 + 32;

        let r = Affine::<TE>::deserialize_uncompressed(&bytes[00..off1])?;
        let s = TE::ScalarField::deserialize_uncompressed(&bytes[off1..off2])?;
        Ok(Signature { r, s })
    }

    pub fn new(r: Affine<TE>, s: TE::ScalarField) -> Self {
        Self { r, s }
    }

    pub fn r(&self) -> &Affine<TE> {
        &self.r
    }

    pub fn s(&self) -> &TE::ScalarField {
        &self.s
    }
}
