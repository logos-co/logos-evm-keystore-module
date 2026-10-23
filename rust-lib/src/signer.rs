//! The keystore as a `logos.signer/1` signer: it lists its accounts and signs hashes the signer
//! manager prepares, with the account's password or inside an unlock. It parses no request.

use std::str::FromStr;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use zeroize::Zeroizing;

use logos_signer_interface::jobs::{JobTable, KeyJobs};
use logos_signer_interface::unlock::is_reserved;
use logos_signer_interface::wire::{
    Account, Chain, Collects, ErrorCode, Family, HashItem, JobState, JobStatus, Payload, RequestKind, Result,
    Scheme, Secret, SignRequest, Signature, SignerError, SignerInfo, UnlockKey, UnlockKeyRequest,
};
use logos_signer_interface::{Signer, INTERFACE};

use crate::btc::{self, AccountPublic, AccountSecret};
use crate::keystore::{Keystore, KeystoreError};
use crate::locked::LockedBytes;

fn invalid(msg: impl Into<String>) -> SignerError {
    SignerError::new(ErrorCode::Invalid, msg)
}

fn internal(e: impl std::fmt::Display) -> SignerError {
    SignerError::new(ErrorCode::Internal, e.to_string())
}

/// One message for every way a vault fails to open, as `prove_custody` gives: no oracle.
pub fn from_keystore(e: KeystoreError) -> SignerError {
    let code = match &e {
        KeystoreError::Vault(_) => {
            return SignerError::new(ErrorCode::WrongSecret, "the password for this account is not correct")
        }
        KeystoreError::NotFound(_) => ErrorCode::UnknownAccount,
        KeystoreError::Locked(_) => ErrorCode::Locked,
        KeystoreError::InvalidAddress(_)
        | KeystoreError::InvalidKey(_)
        | KeystoreError::InvalidParams(_)
        | KeystoreError::Refused(_) => ErrorCode::Invalid,
        _ => ErrorCode::Internal,
    };
    SignerError::new(code, e.to_string())
}

/// What `sign` names: an EVM account by address, or a Bitcoin wallet by group id.
enum Target {
    Evm(Address),
    Bitcoin { id: String, acct: AccountPublic },
}

impl Target {
    fn resolve(ks: &Keystore, id: &str) -> Result<Target> {
        let unknown = || SignerError::new(ErrorCode::UnknownAccount, format!("no account {id}"));
        if let Ok(addr) = Address::from_str(id.trim()) {
            return if ks.has_address(&addr.to_string()) { Ok(Target::Evm(addr)) } else { Err(unknown()) };
        }
        let (acct, _) = ks.bitcoin_account(id.trim()).map_err(|_| unknown())?;
        Ok(Target::Bitcoin { id: id.trim().to_string(), acct })
    }

    fn key(&self) -> String {
        match self {
            Target::Evm(a) => a.to_string().to_ascii_lowercase(),
            Target::Bitcoin { id, .. } => id.to_ascii_lowercase(),
        }
    }
}

/// A key opened for one request, from its vault or from an unlock.
enum Material {
    Evm(PrivateKeySigner),
    Bitcoin(AccountSecret),
}

/// The xpub a request brings has to be this wallet's; the keystore signs with its own.
fn check_brought(target: &Target, xpub: Option<&str>) -> Result<()> {
    let (Target::Bitcoin { acct, .. }, Some(xpub)) = (target, xpub) else { return Ok(()) };
    let brought = bitcoin::bip32::Xpub::from_str(xpub.trim()).map_err(|e| invalid(format!("xpub: {e}")))?;
    let same = brought.public_key == acct.xpub.public_key && brought.chain_code == acct.xpub.chain_code;
    if !same {
        return Err(invalid("the request's xpub is not this wallet's"));
    }
    Ok(())
}

fn open(ks: &Keystore, target: &Target, password: &str) -> Result<Material> {
    match target {
        Target::Evm(a) => ks.signer_for(&a.to_string(), password).map(Material::Evm).map_err(from_keystore),
        Target::Bitcoin { id, acct } => {
            let (secret, _) = ks.open_bitcoin_vault(id, password, acct).map_err(from_keystore)?;
            Ok(Material::Bitcoin(secret))
        }
    }
}

// ── unlocks ──────────────────────────────────────────────────────────────────

enum Held {
    Evm(LockedBytes),
    /// The account key as its base58 text, and the database key as hex.
    Bitcoin { account_key: LockedBytes, database_key: LockedBytes },
}

struct Unlock {
    account: String,
    until: Option<Instant>,
    left: Option<u32>,
    held: Held,
}

/// What an unlock has left, for the manager and the keys app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockView {
    pub account: String,
    pub expires_in_ms: Option<u64>,
    pub count_left: Option<u32>,
}

/// Unlocked keys, in memory only. The keystore enforces the time and the count; the manager keeps
/// the rest of the terms. Nothing here is ever written down.
#[derive(Default)]
pub struct Unlocks {
    entries: Vec<Unlock>,
    /// Added to the clock, so tests move time instead of sleeping.
    skew: Duration,
}

impl Unlocks {
    fn now(&self) -> Instant {
        Instant::now() + self.skew
    }

    #[cfg(test)]
    pub(crate) fn advance(&mut self, by: Duration) {
        self.skew += by;
    }

    fn sweep(&mut self) {
        let now = self.now();
        self.entries.retain(|u| u.until.is_none_or(|t| now < t) && u.left != Some(0));
    }

    /// Lock one account, or every one with `None`. Returns how many were unlocked.
    pub fn lock(&mut self, account: Option<&str>) -> usize {
        self.sweep();
        let before = self.entries.len();
        match account {
            Some(a) => {
                let a = a.trim().to_ascii_lowercase();
                self.entries.retain(|u| u.account != a);
            }
            None => self.entries.clear(),
        }
        before - self.entries.len()
    }

    pub fn list(&mut self) -> Vec<UnlockView> {
        self.sweep();
        let now = self.now();
        self.entries
            .iter()
            .map(|u| UnlockView {
                account: u.account.clone(),
                expires_in_ms: u.until.map(|t| t.saturating_duration_since(now).as_millis() as u64),
                count_left: u.left,
            })
            .collect()
    }

    fn get(&mut self, account: &str) -> Option<&mut Unlock> {
        self.sweep();
        self.entries.iter_mut().find(|u| u.account == account)
    }
}

fn utf8(b: &LockedBytes) -> Result<&str> {
    std::str::from_utf8(b.as_slice()).map_err(internal)
}

// ── signing ──────────────────────────────────────────────────────────────────

/// Check every item against the account before any key is opened.
fn check_items(target: &Target, items: &[HashItem]) -> Result<Vec<([u8; 32], Option<(u32, u32)>)>> {
    if items.is_empty() {
        return Err(invalid("nothing to sign"));
    }
    items
        .iter()
        .map(|item| {
            let digest = logos_signer_interface::verify::hex32(&item.digest)?;
            match target {
                Target::Evm(_) => {
                    if item.scheme != Scheme::Evm {
                        return Err(SignerError::new(ErrorCode::Unsupported, format!("{:?} for an EVM account", item.scheme)));
                    }
                    if item.path.is_some() {
                        return Err(invalid("an EVM account signs with its own key, at no path"));
                    }
                    Ok((digest, None))
                }
                Target::Bitcoin { acct, .. } => {
                    let want = match acct.family {
                        btc::Family::Segwit => Scheme::Ecdsa,
                        btc::Family::Taproot => Scheme::Bip86,
                    };
                    if item.scheme != want {
                        return Err(SignerError::new(
                            ErrorCode::Unsupported,
                            format!("{:?} for a {} wallet", item.scheme, acct.family.describe()),
                        ));
                    }
                    let path = item.path.as_deref().ok_or_else(|| invalid("a Bitcoin item names its path"))?;
                    if is_reserved(path) {
                        return Err(invalid("nothing signs under the unlock keys' purpose"));
                    }
                    let parsed = DerivationPath::from_str(path).map_err(|e| invalid(format!("path {path:?}: {e}")))?;
                    let at = acct
                        .relative(&parsed)
                        .ok_or_else(|| invalid(format!("{path} is not a receive or change key of this wallet")))?;
                    Ok((digest, Some(at)))
                }
            }
        })
        .collect()
}

fn sign_items(
    target: &Target,
    material: &Material,
    items: &[HashItem],
    checked: &[([u8; 32], Option<(u32, u32)>)],
) -> Result<Vec<Signature>> {
    let mut out = Vec::with_capacity(items.len());
    for (i, (digest, at)) in checked.iter().enumerate() {
        out.push(match (material, target) {
            (Material::Evm(signer), Target::Evm(_)) => {
                let sig = signer.sign_hash_sync(&B256::from(*digest)).map_err(internal)?;
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(&sig.r().to_be_bytes::<32>());
                rs[32..].copy_from_slice(&sig.s().to_be_bytes::<32>());
                let key = signer.credential().verifying_key().to_sec1_bytes();
                Signature { item: i, signature: hex::encode(rs), recovery_id: Some(sig.v() as u8), pubkey: hex::encode(key) }
            }
            (Material::Bitcoin(secret), Target::Bitcoin { acct, .. }) => {
                let (change, index) = at.expect("checked: a Bitcoin item has its path");
                sign_bitcoin(secret, acct, i, digest, change, index, items[i].scheme)?
            }
            _ => return Err(internal("the key opened is not this account's kind")),
        });
    }
    Ok(out)
}

fn sign_bitcoin(
    secret: &AccountSecret,
    acct: &AccountPublic,
    item: usize,
    digest: &[u8; 32],
    change: u32,
    index: u32,
    scheme: Scheme,
) -> Result<Signature> {
    let secp = Secp256k1::new();
    let mut child = secret
        .xprv()
        .derive_priv(&secp, &[ChildNumber::Normal { index: change }, ChildNumber::Normal { index }])
        .map_err(internal)?;
    let msg = Message::from_digest(*digest);
    let sig = match (acct.family, scheme) {
        (btc::Family::Segwit, Scheme::Ecdsa) => Signature {
            item,
            signature: hex::encode(secp.sign_ecdsa(&msg, &child.private_key).serialize_compact()),
            recovery_id: None,
            pubkey: hex::encode(child.private_key.public_key(&secp).serialize()),
        },
        (btc::Family::Taproot, Scheme::Bip86) => {
            let tweaked = Keypair::from_secret_key(&secp, &child.private_key).tap_tweak(&secp, None).to_keypair();
            let mut aux = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut aux);
            let sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked, &aux);
            Signature {
                item,
                signature: hex::encode(sig.serialize()),
                recovery_id: None,
                pubkey: hex::encode(tweaked.x_only_public_key().0.serialize()),
            }
        }
        _ => return Err(internal("scheme checked against the family")),
    };
    child.private_key.non_secure_erase();
    Ok(sig)
}

// ── the signer ───────────────────────────────────────────────────────────────

/// The keystore's signer, over the module's state for the length of one call.
pub struct KeystoreSigner<'a> {
    pub ks: &'a Keystore,
    pub unlocks: &'a mut Unlocks,
    pub jobs: &'a mut JobTable,
    pub keys: &'a mut KeyJobs,
}

impl KeystoreSigner<'_> {
    /// Hold an account's key in memory until `ttl` passes or `count` requests are signed.
    pub fn unlock(&mut self, account: &str, password: &str, ttl: Option<Duration>, count: Option<u32>) -> Result<UnlockView> {
        if count == Some(0) || ttl == Some(Duration::ZERO) {
            return Err(invalid("an unlock that allows nothing"));
        }
        let target = Target::resolve(self.ks, account)?;
        let held = match &target {
            Target::Evm(a) => {
                let signer = self.ks.signer_for(&a.to_string(), password).map_err(from_keystore)?;
                Held::Evm(LockedBytes::new(signer.to_bytes().as_slice()))
            }
            Target::Bitcoin { id, acct } => {
                let (secret, database_key) = self.ks.open_bitcoin_vault(id, password, acct).map_err(from_keystore)?;
                Held::Bitcoin {
                    account_key: LockedBytes::new(secret.encode().as_bytes()),
                    database_key: LockedBytes::new(database_key.as_bytes()),
                }
            }
        };
        let key = target.key();
        self.unlocks.lock(Some(&key));
        let until = ttl.map(|d| self.unlocks.now() + d);
        self.unlocks.entries.push(Unlock { account: key.clone(), until, left: count, held });
        Ok(self.unlocks.list().into_iter().find(|u| u.account == key).expect("just unlocked"))
    }

    /// A Bitcoin wallet's database key: with its password, or from its unlock without using a count.
    pub fn database_key(&mut self, group: &str, password: Option<&str>) -> Result<Zeroizing<String>> {
        let target = Target::resolve(self.ks, group)?;
        let Target::Bitcoin { id, acct } = &target else {
            return Err(SignerError::new(ErrorCode::Unsupported, "only a Bitcoin wallet has a database key"));
        };
        if let Some(pw) = password {
            return Ok(self.ks.open_bitcoin_vault(id, pw, acct).map_err(from_keystore)?.1);
        }
        match self.unlocks.get(&target.key()) {
            Some(Unlock { held: Held::Bitcoin { database_key, .. }, .. }) => Ok(Zeroizing::new(utf8(database_key)?.to_string())),
            _ => Err(SignerError::new(ErrorCode::Locked, "this wallet is locked: open it with its password")),
        }
    }

    /// The key an unlock holds, counting one request against it.
    fn from_unlock(&mut self, target: &Target) -> Result<Material> {
        let locked = || SignerError::new(ErrorCode::Locked, "this account is locked: sign with its password, or unlock it");
        let u = self.unlocks.get(&target.key()).ok_or_else(locked)?;
        let material = match (&u.held, target) {
            (Held::Evm(bytes), Target::Evm(_)) => {
                Material::Evm(PrivateKeySigner::from_slice(bytes.as_slice()).map_err(internal)?)
            }
            (Held::Bitcoin { account_key, .. }, Target::Bitcoin { acct, .. }) => {
                Material::Bitcoin(AccountSecret::decode(utf8(account_key)?, acct.chain).map_err(from_keystore)?)
            }
            _ => return Err(internal("the unlock is not this account's kind")),
        };
        if let Some(n) = u.left.as_mut() {
            *n -= 1;
        }
        self.unlocks.sweep();
        Ok(material)
    }
}

pub fn info() -> SignerInfo {
    SignerInfo {
        interface: INTERFACE.into(),
        kind: "keystore".into(),
        model: "scrypt key files".into(),
        families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        request_kinds: vec![RequestKind::Hash],
        shows_request: false,
        collects: Collects::Password,
        unlock_key: true,
    }
}

/// The keystore's documents key accounts by lowercase hex with no `0x`.
fn by_address<'m, V>(m: &'m std::collections::BTreeMap<String, V>, address: &str) -> Option<&'m V> {
    let bare = address.trim_start_matches("0x");
    m.iter().find(|(k, _)| k.trim_start_matches("0x").eq_ignore_ascii_case(bare)).map(|(_, v)| v)
}

pub fn accounts(ks: &Keystore) -> Result<Vec<Account>> {
    let labels = ks.get_labels().map_err(from_keystore)?;
    let provenance = ks.get_provenance().map_err(from_keystore)?;
    let names = ks.get_group_labels().map_err(from_keystore)?;
    let groups = ks.get_groups().map_err(from_keystore)?;
    let seed_of = |address: &str| {
        let group = by_address(&provenance, address).map(|p| p.group.clone()).unwrap_or_default();
        Keystore::seed_of(&groups, &group, address)
    };
    // The wallet an EVM account comes from: its group's fingerprint, else one another group of the
    // same seed recorded. An imported key belongs to no wallet.
    let wallet_of = |gid: &str| {
        let g = groups.get(gid)?;
        g.fingerprint.clone().or_else(|| {
            let seed = g.seed.as_ref()?;
            groups
                .values()
                .filter(|o| o.seed.as_ref().is_some_and(|s| s.id == seed.id))
                .find_map(|o| o.fingerprint.clone())
        })
    };
    let mut out = Vec::new();
    for addr in ks.list_accounts().map_err(from_keystore)? {
        let key = addr.to_string().to_ascii_lowercase();
        out.push(Account {
            id: addr.to_string(),
            family: Family::Evm,
            chain: None,
            path: by_address(&provenance, &key).map(|p| p.path.clone()).filter(|p| !p.is_empty()),
            fingerprint: by_address(&provenance, &key).and_then(|p| wallet_of(&p.group)),
            address: Some(addr.to_string()),
            xpub: None,
            key: None,
            seed: Some(seed_of(&addr.to_string())),
            label: by_address(&labels, &key).cloned().filter(|l| !l.is_empty()),
            available: true,
        });
    }
    for id in ks.bitcoin_groups().map_err(from_keystore)? {
        let Ok((acct, _)) = ks.bitcoin_account(&id) else { continue };
        out.push(Account {
            id: id.clone(),
            family: match acct.family {
                btc::Family::Segwit => Family::Bitcoin,
                btc::Family::Taproot => Family::BitcoinTaproot,
            },
            chain: Some(match acct.chain {
                btc::Chain::Main => Chain::Main,
                btc::Chain::Test => Chain::Test,
            }),
            path: Some(format!("m/{}", acct.origin().to_string().trim_start_matches("m/"))),
            fingerprint: Some(acct.fingerprint.to_string()),
            address: None,
            xpub: Some(acct.xpub.to_string()),
            key: None,
            seed: Some(Keystore::seed_of(&groups, &id, "")),
            label: names.get(&id).cloned().filter(|l| !l.is_empty()),
            available: true,
        });
    }
    Ok(out)
}

impl Signer for KeystoreSigner<'_> {
    fn info(&self) -> SignerInfo {
        info()
    }

    fn accounts(&mut self) -> Result<Vec<Account>> {
        accounts(self.ks)
    }

    fn sign(&mut self, request: SignRequest) -> Result<String> {
        let target = Target::resolve(self.ks, &request.account)?;
        let Payload::Hash { items } = &request.payload else {
            return Err(SignerError::new(ErrorCode::Unsupported, "the keystore signs hashes only"));
        };
        let checked = check_items(&target, items)?;
        check_brought(&target, request.xpub.as_deref())?;
        let material = match &request.secret {
            Some(s) => open(self.ks, &target, s.expose())?,
            None => self.from_unlock(&target)?,
        };
        let outcome = sign_items(&target, &material, items, &checked);
        drop(material);
        let job = self.jobs.start(JobState::Working);
        self.jobs.finish(&job, outcome)?;
        Ok(job)
    }

    fn status(&mut self, job: &str) -> Result<JobStatus> {
        self.jobs.status(job)
    }

    fn result(&mut self, job: &str) -> Result<Vec<Signature>> {
        self.jobs.result(job)
    }

    fn cancel(&mut self, job: &str) -> Result<()> {
        self.jobs.cancel(job)
    }

    /// Done at once: the wallet's password opens its unlock root, or the imported key it is.
    fn unlock_key(&mut self, request: UnlockKeyRequest) -> Result<String> {
        let Some(secret) = &request.secret else {
            return Err(SignerError::new(ErrorCode::Locked, "a keystore wallet unlocks with its password"));
        };
        let outcome = self.ks.unlock_key(&request.seed, request.index, secret.expose()).map_err(|e| match e {
            KeystoreError::NotFound(_) => SignerError::new(ErrorCode::WrongSeed, "this keystore holds no such seed"),
            other => from_keystore(other),
        });
        // A seed it doesn't hold is refused before a job exists, as a wrong secret is.
        let key = outcome?;
        let job = self.keys.start(JobState::Working);
        self.keys.finish(&job, Ok(UnlockKey { key: Secret::new(hex::encode(key)) }))?;
        Ok(job)
    }

    fn unlock_key_status(&mut self, job: &str) -> Result<JobStatus> {
        self.keys.status(job)
    }

    fn unlock_key_result(&mut self, job: &str) -> Result<UnlockKey> {
        self.keys.take(job)
    }

    fn cancel_unlock_key(&mut self, job: &str) -> Result<()> {
        self.keys.cancel(job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::{Chain as BtcChain, Family as BtcFamily};
    use crate::BitcoinImport;
    use logos_signer_interface::conformance::{self, Fixture};
    use logos_signer_interface::verify;
    use logos_signer_interface::Secret;

    const PHRASE: &str = "test test test test test test test test test test test junk";
    const ACCT0_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn keystore() -> (tempfile::TempDir, Keystore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        for family in [BtcFamily::Segwit, BtcFamily::Taproot] {
            ks.import_bitcoin(&BitcoinImport {
                phrase: PHRASE,
                bip39_passphrase: "",
                family,
                chain: BtcChain::Test,
                account: 0,
                password: "pw",
                label: "",
                keep: crate::keystore::KeepPhrase::No,
                start: crate::keystore::WalletStart::Restored(None),
            })
            .unwrap();
        }
        (dir, ks)
    }

    fn no_device(_: &mut KeystoreSigner<'_>, _: &str) {}

    #[test]
    fn the_keystore_passes_the_signer_conformance_suite() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        let fx = Fixture { secret: Some(Secret::new("pw")), wrong_secret: Some(Secret::new("nope")) };
        conformance::run(&mut s, &fx, &mut no_device);
    }

    fn hash_request(account: &Account, secret: Option<&str>) -> (SignRequest, Vec<HashItem>) {
        let items = conformance::items_for(account);
        let req = SignRequest {
            account: account.id.clone(),
            payload: Payload::Hash { items: items.clone() },
            secret: secret.map(Secret::new),
            xpub: None,
        };
        (req, items)
    }

    #[test]
    fn an_unlock_signs_without_the_password_until_its_count_runs_out() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        for account in s.accounts().unwrap() {
            let (req, _) = hash_request(&account, None);
            assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Locked, "{}", account.id);
            assert_eq!(s.unlock(&account.id, "nope", None, Some(2)).unwrap_err().code, ErrorCode::WrongSecret);
            let view = s.unlock(&account.id, "pw", None, Some(2)).unwrap();
            assert_eq!(view.count_left, Some(2));
            for _ in 0..2 {
                let (req, items) = hash_request(&account, None);
                let job = s.sign(req).unwrap();
                let sigs = s.result(&job).unwrap();
                verify::check(&account, &items[0], &sigs[0]).unwrap();
            }
            let (req, _) = hash_request(&account, None);
            assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Locked, "{}: the third request", account.id);
        }
    }

    #[test]
    fn an_unlock_ends_when_its_time_passes_or_on_lock() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        let accounts = s.accounts().unwrap();
        s.unlock(&accounts[0].id, "pw", Some(Duration::from_secs(900)), None).unwrap();
        s.unlock(&accounts[1].id, "pw", None, None).unwrap();
        assert_eq!(s.unlocks.list().len(), 2);
        // Opening each vault takes real time; the skewed clock decides the expiry, not a sleep.
        let left = s.unlocks.list()[0].expires_in_ms.unwrap();
        assert!((800_000..=900_000).contains(&left), "{left}");
        s.unlocks.advance(Duration::from_secs(901));
        let (req, _) = hash_request(&accounts[0], None);
        assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Locked, "expired");
        assert_eq!(s.unlocks.lock(None), 1, "only the untimed one was left");
        let (req, _) = hash_request(&accounts[1], None);
        assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Locked, "locked");
    }

    #[test]
    fn a_password_signs_without_touching_an_unlocks_count() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        let account = s.accounts().unwrap().remove(0);
        s.unlock(&account.id, "pw", None, Some(1)).unwrap();
        let (req, _) = hash_request(&account, Some("pw"));
        s.sign(req).unwrap();
        assert_eq!(s.unlocks.list()[0].count_left, Some(1));
    }

    #[test]
    fn a_database_key_comes_from_the_password_or_an_unlock_only() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        let accounts = s.accounts().unwrap();
        let wallet = accounts.iter().find(|a| a.family == Family::Bitcoin).unwrap();
        let key = s.database_key(&wallet.id, Some("pw")).unwrap();
        assert_eq!(key.len(), 64);
        assert_eq!(s.database_key(&wallet.id, None).unwrap_err().code, ErrorCode::Locked);
        assert_eq!(s.database_key(&wallet.id, Some("nope")).unwrap_err().code, ErrorCode::WrongSecret);
        s.unlock(&wallet.id, "pw", None, Some(1)).unwrap();
        assert_eq!(*s.database_key(&wallet.id, None).unwrap(), *key);
        assert_eq!(s.unlocks.list()[0].count_left, Some(1), "opening uses no count");
        assert_eq!(s.database_key(&accounts[0].id, Some("pw")).unwrap_err().code, ErrorCode::Unsupported);
    }

    #[test]
    fn a_scheme_or_path_that_is_not_the_accounts_is_refused_before_any_vault_opens() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs) = (Unlocks::default(), JobTable::new());
        let mut keys = KeyJobs::new();
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        for account in s.accounts().unwrap() {
            let (mut req, mut items) = hash_request(&account, Some("wrong"));
            items[0].scheme = match account.family {
                Family::Evm => Scheme::Ecdsa,
                _ => Scheme::Evm,
            };
            req.payload = Payload::Hash { items };
            // A wrong password would answer wrong_secret: the item is refused first.
            assert_eq!(s.sign(req).unwrap_err().code, ErrorCode::Unsupported, "{}", account.id);
        }
    }

    #[test]
    fn an_evm_account_names_the_wallet_it_comes_from() {
        let (_dir, ks) = keystore();
        let imported = accounts(&ks).unwrap().into_iter().find(|a| a.family == Family::Evm).unwrap();
        assert_eq!(imported.fingerprint, None, "an imported key belongs to no wallet");
        let derived = ks.import_mnemonic(PHRASE, "", 1, "pw").unwrap().to_string();
        let all = accounts(&ks).unwrap();
        let evm = all.iter().find(|a| a.address.as_deref() == Some(derived.as_str())).unwrap();
        assert_eq!(evm.path.as_deref(), Some("m/44'/60'/0'/0/1"));
        // The phrase's BIP32 master fingerprint, as its Bitcoin wallets carry it.
        assert_eq!(evm.fingerprint.as_deref(), Some("16a93ed0"));
        let segwit = all.iter().find(|a| a.family == Family::Bitcoin).unwrap();
        assert_eq!(segwit.fingerprint, evm.fingerprint);
    }

    #[test]
    fn a_bitcoin_wallet_has_an_origin_as_an_evm_account_does() {
        let (_dir, ks) = keystore();
        ks.import_mnemonic(PHRASE, "", 1, "pw").unwrap();
        let segwit = accounts(&ks).unwrap().into_iter().find(|a| a.family == Family::Bitcoin).unwrap();
        let origins = ks.account_origins().unwrap();
        let o = &origins[&segwit.id];
        assert_eq!(o["devices"][0]["kind"], "keystore");
        assert_eq!(o["path"], "m/84'/1'/0'");
        // The same seed as the EVM account derived from that phrase: one wallet.
        let evm = origins
            .iter()
            .find(|(k, v)| k.starts_with("0x") && v["phrase"]["id"].is_string())
            .map(|(_, v)| v)
            .unwrap();
        assert_eq!(o["phrase"]["id"], evm["phrase"]["id"]);
    }

    #[test]
    fn the_bitcoin_accounts_carry_the_records_xpub_and_path() {
        let (_dir, ks) = keystore();
        let all = accounts(&ks).unwrap();
        let segwit = all.iter().find(|a| a.family == Family::Bitcoin).unwrap();
        assert_eq!(segwit.path.as_deref(), Some("m/84'/1'/0'"));
        assert_eq!(segwit.chain, Some(Chain::Test));
        assert!(segwit.xpub.as_deref().unwrap().starts_with("tpub"));
        let (acct, _) = ks.bitcoin_account(&segwit.id).unwrap();
        assert_eq!(segwit.fingerprint.as_deref(), Some(acct.fingerprint.to_string().as_str()));
    }

    fn unlock_key_of(s: &mut KeystoreSigner<'_>, seed: &str, index: u32, pw: Option<&str>) -> Result<String> {
        let job = s.unlock_key(UnlockKeyRequest { seed: seed.into(), index, secret: pw.map(Secret::new) })?;
        Ok(s.unlock_key_result(&job)?.key.expose().to_string())
    }

    #[test]
    fn a_seeds_branches_name_one_seed_and_give_the_unlock_key_a_card_would() {
        let (_dir, ks) = keystore();
        let (mut unlocks, mut jobs, mut keys) = (Unlocks::default(), JobTable::new(), KeyJobs::new());
        let mut s = KeystoreSigner { ks: &ks, unlocks: &mut unlocks, jobs: &mut jobs, keys: &mut keys };
        let listed = s.accounts().unwrap();
        let bitcoin: Vec<&Account> = listed.iter().filter(|a| a.family.is_bitcoin()).collect();
        assert_eq!(bitcoin.len(), 2);
        let seed = bitcoin[0].seed.clone().unwrap();
        assert_eq!(bitcoin[1].seed.as_deref(), Some(seed.as_str()), "segwit and taproot of one phrase: one seed");
        let imported = listed.iter().find(|a| a.family == Family::Evm).unwrap();
        assert_eq!(imported.seed.as_deref(), Some(format!("key:{}", imported.id.to_ascii_lowercase()).as_str()));

        // The interface's mock holds the same phrase, as a card would: the same key at each index.
        let mut card = logos_signer_interface::mock::MockSigner::new(Default::default());
        let card_seed = card.accounts().unwrap()[0].seed.clone().unwrap();
        for n in [0, 1] {
            let job = card.unlock_key(UnlockKeyRequest { seed: card_seed.clone(), index: n, secret: None }).unwrap();
            let want = card.unlock_key_result(&job).unwrap().key.expose().to_string();
            assert_eq!(unlock_key_of(&mut s, &seed, n, Some("pw")).unwrap(), want, "index {n}");
        }
        assert_eq!(unlock_key_of(&mut s, &seed, 0, Some("nope")).unwrap_err().code, ErrorCode::WrongSecret);
        assert_eq!(unlock_key_of(&mut s, &seed, 0, None).unwrap_err().code, ErrorCode::Locked);
        assert_eq!(unlock_key_of(&mut s, "s_unknown", 0, Some("pw")).unwrap_err().code, ErrorCode::WrongSeed);
    }

    #[test]
    fn the_unlock_key_follows_the_password_and_the_enrolment_names_the_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let derived = ks
            .import_mnemonic_ex(&crate::keystore::ImportRequest {
                phrase: PHRASE,
                bip39_passphrase: "",
                index: 0,
                password: "first",
                storage: crate::keystore::Storage::Plain,
                bip44_account: 0,
                change: 0,
                group_password: "",
                group_label: "Main",
                keep: crate::keystore::KeepPhrase::No,
            })
            .unwrap();
        let e = ks.enrolment(&derived.address.to_string(), "first").unwrap();
        assert_eq!(e.name, "Main");
        assert!(e.seed.starts_with("g_"), "{}", e.seed);
        ks.change_password(&derived.address.to_string(), "first", "second").unwrap();
        assert!(ks.unlock_key(&e.seed, 0, "first").is_err());
        assert_eq!(ks.unlock_key(&e.seed, 0, "second").unwrap(), e.unlock_key);
        let groups = std::fs::read_to_string(dir.path().join("groups.json")).unwrap();
        assert!(!groups.contains(&hex::encode(e.unlock_key)), "no unlock key in the clear");
    }
}
