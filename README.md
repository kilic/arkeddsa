# arkeddsa

Do not use in production.

EDDSA signature scheme implementation with Poseidon hasher and ark-works backend. Additionally circom compatible `ed_on_bn254_twist` twist is available.

The `r1cs` feature enables the in-circuit EdDSA verification.

## test
To test including the constraints use the `r1cs` feature flag: `cargo test --features=r1cs`
