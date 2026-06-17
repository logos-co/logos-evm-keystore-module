//! keystore_module — offline Ethereum key management and signing for the Logos
//! wallet. Scrypt-encrypted vaults, BIP39/BIP32 HD derivation, secp256k1
//! signing. No network. Private keys never cross the module boundary.
//!
//! The crypto core (`keystore`) is plain Rust and unit-tested with `cargo test`.
//! The Logos module glue (the generated contract trait impl + install hook) is
//! added behind the `logos_module` feature so the builder compiles it while
//! `cargo test --no-default-features` exercises the core in isolation.

mod keystore;

pub use keystore::{Keystore, KeystoreError};

// The Logos module contract + glue. Feature-gated so the crypto core above can
// be exercised with `cargo test --no-default-features`; the builder compiles it
// via the default `logos_module` feature.
#[cfg(feature = "logos_module")]
mod glue;
