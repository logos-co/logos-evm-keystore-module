//! The one door to a key no recovery phrase covers.
//!
//! The property: **no random key is ever created without an acknowledgement**. It holds by
//! construction — `acknowledged` is what generates the key and the only constructor of the
//! type that carries it, so a mint that skipped it has nothing to persist and does not
//! compile. It replaces a directory scan that tried to decide the same question from what
//! was on disk, which is not decidable. `docs/specs.md` carries the full argument.

use alloy::signers::local::PrivateKeySigner;

use crate::keystore::{KeystoreError, Result};

/// What an unrelated account IS, in the words the refusal and the UI both use. One string,
/// so the module and the screen cannot describe the same choice differently.
pub const NOTICE: &str = "an unrelated account is a key your recovery phrase will not \
                          restore — its only backup is a vault file you export and keep \
                          yourself";

/// A random key, and the proof that someone asked for one on purpose.
///
/// The field is private to this module, so nothing else in the crate can build one; the
/// only constructor refuses without the acknowledgement. That is the whole safety argument,
/// and it does not depend on any scan being complete.
pub struct Unrecoverable(PrivateKeySigner);

impl Unrecoverable {
    /// The ONLY place this crate generates a random key.
    pub fn acknowledged(acknowledge: bool) -> Result<Self> {
        if !acknowledge {
            return Err(KeystoreError::Refused(format!(
                "{NOTICE}. Pass acknowledgeUnrecoverable: true to create it anyway"
            )));
        }
        Ok(Self(PrivateKeySigner::random()))
    }

    pub(crate) fn signer(&self) -> &PrivateKeySigner {
        &self.0
    }
}

/// Hand-written, and deliberately says nothing: this type holds a live secp256k1 secret,
/// and a derived `Debug` is how key material reaches a log.
impl std::fmt::Debug for Unrecoverable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unrecoverable(<acknowledged random key>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_random_key_exists_without_the_acknowledgement() {
        // The mutation check: make this constructor accept `false` and this fails. There is
        // no other path — `Unrecoverable`'s field is private to this module, and
        // `the_only_random_key_in_this_crate_is_the_acknowledged_one` holds that line for
        // the rest of the crate.
        let refused = Unrecoverable::acknowledged(false).unwrap_err().to_string();
        assert!(refused.contains("recovery phrase will not restore"), "got {refused}");
        assert!(refused.contains("acknowledgeUnrecoverable"), "it must name the way in: {refused}");

        let a = Unrecoverable::acknowledged(true).unwrap();
        let b = Unrecoverable::acknowledged(true).unwrap();
        assert_ne!(a.signer().address(), b.signer().address(), "the key is not random");
    }
}
