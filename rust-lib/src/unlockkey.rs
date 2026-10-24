//! A seed's unlock key, as the keystore keeps it. The signer manager unlocks a wallet's data with
//! the public key at `m/1280263247'/n'`, the same from every holder of the seed. The keystore keeps
//! the extended key at `m/1280263247'` sealed under the wallet's password in its group's record, so
//! any index derives behind that password; nothing signs under that purpose. An imported key, a
//! seed of one account, derives its own from the key.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::NetworkKind;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keystore::KeystoreError;

type Result<T> = std::result::Result<T, KeystoreError>;

pub const PURPOSE: u32 = logos_signer_interface::unlock::PURPOSE;
/// scrypt's cost for the sealed key: above a vault's, as it outlives a session's typing.
const LOG_N: u8 = 15;

/// The extended key at `m/1280263247'`, sealed under a password: its chain code and key, 64 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedRoot {
    pub log_n: u8,
    pub salt: String,
    pub sealed: String,
}

fn vault(e: impl std::fmt::Display) -> KeystoreError {
    KeystoreError::Vault(e.to_string())
}

/// The chain code and key at `m/1280263247'` of a BIP-39 seed.
pub fn root_of(seed: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Main, seed).map_err(vault)?;
    let at = master.derive_priv(&secp, &[ChildNumber::from_hardened_idx(PURPOSE).map_err(vault)?]).map_err(vault)?;
    let mut out = Zeroizing::new([0u8; 64]);
    out[..32].copy_from_slice(at.chain_code.as_bytes());
    out[32..].copy_from_slice(&at.private_key.secret_bytes());
    Ok(out)
}

/// The unlock key at index `index` below a root: 33 bytes, compressed.
pub fn key_at(root: &[u8; 64], index: u32) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();
    let chain: [u8; 32] = root[..32].try_into().expect("32 bytes");
    let parent = Xpriv {
        network: NetworkKind::Main,
        depth: 1,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_hardened_idx(PURPOSE).map_err(vault)?,
        private_key: SecretKey::from_slice(&root[32..]).map_err(vault)?,
        chain_code: ChainCode::from(chain),
    };
    let child = ChildNumber::from_hardened_idx(index)
        .map_err(|_| KeystoreError::InvalidParams(format!("unlock index {index}")))?;
    let at = parent.derive_priv(&secp, &[child]).map_err(vault)?;
    Ok(Xpub::from_priv(&secp, &at).public_key.serialize())
}

/// An imported key's own unlock key at `index`: a key it derives, never itself.
pub fn of_imported(private_key: &[u8], index: u32) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();
    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(b"logos-keystore-unlock-v1\0");
        h.update(private_key);
        h.update(index.to_be_bytes());
        h.update(counter.to_be_bytes());
        let scalar = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
        if let Ok(sk) = SecretKey::from_slice(scalar.as_ref()) {
            return Ok(sk.public_key(&secp).serialize());
        }
    }
    unreachable!("a hash lands on a valid key")
}

fn kek(password: &str, salt: &[u8], log_n: u8) -> Result<Zeroizing<[u8; 32]>> {
    if !(10..=20).contains(&log_n) {
        return Err(vault(format!("unusable scrypt cost 2^{log_n}")));
    }
    let params = scrypt::Params::new(log_n, 8, 1, 32).map_err(vault)?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt, &params, out.as_mut()).map_err(vault)?;
    Ok(out)
}

fn aad(group: &str) -> Vec<u8> {
    format!("logos-keystore-unlock-root-v1\0{group}").into_bytes()
}

/// Seal a root under the wallet's password, bound to its group.
pub fn seal(root: &[u8; 64], password: &str, group: &str) -> Result<SealedRoot> {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let k = kek(password, &salt, LOG_N)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = XChaCha20Poly1305::new(&(*k).into())
        .encrypt(&nonce, Payload { msg: root.as_slice(), aad: &aad(group) })
        .map_err(|_| vault("sealing failed"))?;
    let mut sealed = nonce.to_vec();
    sealed.extend(ct);
    Ok(SealedRoot { log_n: LOG_N, salt: hex::encode(salt), sealed: hex::encode(sealed) })
}

/// The root, if the password is the one it was sealed under.
pub fn open(s: &SealedRoot, password: &str, group: &str) -> Option<Zeroizing<[u8; 64]>> {
    let salt = hex::decode(&s.salt).ok()?;
    let bytes = hex::decode(&s.sealed).ok()?;
    if bytes.len() < 24 + 16 {
        return None;
    }
    let (nonce, ct) = bytes.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    let k = kek(password, &salt, s.log_n).ok()?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(&(*k).into()).decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad(group) }).ok()?,
    );
    let root: [u8; 64] = plain.as_slice().try_into().ok()?;
    Some(Zeroizing::new(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn seed() -> [u8; 64] {
        let mut s = [0u8; 64];
        let phrase = "test test test test test test test test test test test junk";
        let m = alloy::signers::local::coins_bip39::Mnemonic::<alloy::signers::local::coins_bip39::English>::new_from_phrase(phrase).unwrap();
        s.copy_from_slice(&m.to_seed(None).unwrap());
        s
    }

    #[test]
    fn the_key_at_an_index_is_the_seeds_at_the_unlock_path() {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Test, &seed()).unwrap();
        for n in [0u32, 1, 7] {
            let path = bitcoin::bip32::DerivationPath::from_str(&format!("m/1280263247'/{n}'")).unwrap();
            let want = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap()).public_key.serialize();
            assert_eq!(key_at(&root_of(&seed()).unwrap(), n).unwrap(), want, "index {n}");
        }
    }

    #[test]
    fn a_sealed_root_opens_with_its_password_and_group_only() {
        let root = root_of(&seed()).unwrap();
        let s = seal(&root, "pw", "g_1").unwrap();
        assert_eq!(open(&s, "pw", "g_1").unwrap().as_slice(), root.as_slice());
        assert!(open(&s, "nope", "g_1").is_none());
        assert!(open(&s, "pw", "g_2").is_none());
        assert!(!s.sealed.contains(&hex::encode(&root[32..])));
    }

    #[test]
    fn an_imported_key_gives_its_own_key_per_index() {
        let k = [7u8; 32];
        assert_eq!(of_imported(&k, 0).unwrap(), of_imported(&k, 0).unwrap());
        assert_ne!(of_imported(&k, 0).unwrap(), of_imported(&k, 1).unwrap());
        assert_ne!(of_imported(&k, 0).unwrap(), of_imported(&[8u8; 32], 0).unwrap());
    }
}
