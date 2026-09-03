//! keystore_module — offline Ethereum key management and signing for the Logos
//! wallet. Scrypt-encrypted vaults, BIP39/BIP32 HD derivation, secp256k1
//! signing. No network. Private keys never cross the module boundary.
//!
//! The crypto core (`keystore`) is plain Rust and unit-tested with `cargo test`.
//! The Logos module glue (the generated contract trait impl + install hook) is
//! added behind the `logos_module` feature so the builder compiles it while
//! `cargo test --no-default-features` exercises the core in isolation.

/// Writes that cannot leave a live key, or a half-written file, behind. No policy, no
/// crypto — just the two atomic-write shapes every writer here goes through.
mod atomic;

/// Every path this keystore may write, and the classification of everything found under
/// it. One authority, so a guard cannot check one representation while the data sits in
/// another. Public because `Scan` is what the module reports over IPC.
pub mod layout;

mod keystore;

/// The acknowledgement a random key is created behind, and the type it produces. Its own
/// module so the rest of the crate cannot construct that type — only ask for one.
pub mod ack;

/// HD derivation (BIP-32/BIP-44): the path, the version bytes and the seed's lifetime.
/// Pure logic, like `gate` — no runtime, no I/O.
pub mod hd;

pub use ack::Unrecoverable;
pub use keystore::{Keystore, KeystoreError};

// The Logos module contract + glue. Feature-gated so the crypto core above can
// be exercised with `cargo test --no-default-features`; the builder compiles it
// via the default `logos_module` feature.
#[cfg(feature = "logos_module")]
mod glue;

pub mod gate;
pub mod approval;
