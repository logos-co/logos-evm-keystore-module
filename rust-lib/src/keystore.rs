//! Keystore core — pure, offline Ethereum key management and signing.
//!
//! No network, no Logos dependencies; this module is unit-testable on its own
//! (`cargo test`). Private keys live only inside a `Keystore`: on disk as
//! scrypt-encrypted JSON vaults (eth-keystore / Web3 Secure Storage), and in
//! memory only while an account is unlocked. Nothing here ever returns a raw
//! private key across its API — only addresses, signed payloads, and
//! (re-encrypted) vault JSON.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::{
    coins_bip39::{English, Mnemonic},
    PrivateKeySigner,
};
use alloy::signers::SignerSync;
use coins_bip32::xkeys::XPriv;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::ack::Unrecoverable;
use crate::atomic;
use crate::btc::{self, AccountPublic, AccountSecret, Chain, Family};
use crate::hd::{self, Bip44Path, Seed};
use crate::index::{self, KeyRing, SeedDoc};
use crate::layout::{self, Doc, Root, Scan, Slot, StageKind};

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("account is locked: {0}")]
    Locked(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// A refusal with a reason the caller is meant to read and act on, rather than a
    /// malformed input. Its text names the method to call instead.
    #[error("{0}")]
    Refused(String),
    /// A sidecar is present but cannot be read or parsed. Deliberately its own variant:
    /// "unreadable" has to stay distinguishable from "absent", because treating the two
    /// alike is what lets a derivable wallet mint a key its phrase cannot recover.
    #[error("{0} is unreadable, and an unreadable file is not an empty one ({1}). Refusing rather than acting as though nothing is configured")]
    Corrupt(String, String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("io error: {0}")]
    Io(String),
}

pub(crate) type Result<T> = std::result::Result<T, KeystoreError>;

/// The prefix of a seed that is one imported key: `k_` + 16 random bytes in hex.
pub const IMPORTED_SEED: &str = "k_";

/// What the signer manager is told when a wallet is added here ([`Keystore::enrolment`]).
pub struct Enrolment {
    pub seed: String,
    pub unlock_key: [u8; 33],
    pub name: String,
    pub origin: Option<String>,
    pub birthday: Option<String>,
}

/// The index keys accounts by lowercase hex with no `0x`.
fn by_key<'m, V>(m: &'m BTreeMap<String, V>, address: &str) -> Option<&'m V> {
    let bare = address.trim_start_matches("0x");
    m.iter().find(|(k, _)| k.trim_start_matches("0x").eq_ignore_ascii_case(bare)).map(|(_, v)| v)
}

/// Manages a directory of scrypt vault files. One vault file per account, named at random; the
/// index (see `crate::index`) says which account each is, sealed per seed.
///
/// There is deliberately NO cache of unlocked signers. Signing *is* vault
/// access: a key is derived from the vault password for one operation and wiped
/// when that operation ends. The previous design kept a `HashMap<Address,
/// Unlocked>` whose entries carried an *optional* deadline, and the only caller
/// passed `None` — so an unlock was an unlimited, process-lifetime signer that
/// any module able to reach this one could spend.
#[derive(Clone)]
pub struct Keystore {
    root: Root,
    /// The index keys this process holds, for the seeds unlocked in the Signer app.
    keys: KeyRing,
    /// Older builds' documents were moved into the index, in this process.
    migrated: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Fields of an unsigned transaction, as JSON from the caller. All numeric
/// fields are hex (`0x…`) or decimal strings to avoid precision loss across the
/// JSON boundary. `fee_mode` selects EIP-1559 (default) vs legacy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTx {
    pub to: Option<String>,
    /// Contract creation must be asked for explicitly. Previously an absent or
    /// blank `to` fell through to `TxKind::Create`, so a transfer whose
    /// recipient failed to render became a contract deployment that burned the
    /// value.
    #[serde(default)]
    pub create: bool,
    /// Present only so an access-list-bearing tx is REFUSED with a reason
    /// rather than silently stripped: the signer previously hardcoded
    /// `access_list: Default::default()`, so a caller's EIP-2930 list was
    /// dropped and the signature covered a different transaction than the one
    /// requested.
    #[serde(default)]
    pub access_list: Option<serde_json::Value>,
    #[serde(default)]
    pub value: String,
    pub nonce: String,
    #[serde(default)]
    pub gas_limit: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub fee_mode: String, // "eip1559" (default) | "legacy"
    #[serde(default)]
    pub max_fee_per_gas: String,
    #[serde(default)]
    pub max_priority_fee_per_gas: String,
    #[serde(default)]
    pub gas_price: String,
}

pub(crate) fn parse_u128(s: &str, what: &str) -> Result<u128> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        s.parse::<u128>()
    };
    v.map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
}

fn parse_u64(s: &str, what: &str) -> Result<u64> {
    // A wrapping `as u64` here silently truncated: `0x10000000000000005` and
    // `0x5` produced BYTE-IDENTICAL signed transactions, so a render built from
    // the caller's string and a signature built from this value could disagree
    // about the nonce. Reject instead.
    let wide = parse_u128(s, what)?;
    u64::try_from(wide)
        .map_err(|_| KeystoreError::InvalidParams(format!("{what}: {wide} does not fit in u64")))
}

fn parse_u256(s: &str, what: &str) -> Result<U256> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16).map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    } else {
        s.parse::<U256>().map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    }
}

fn parse_address(s: &str) -> Result<Address> {
    // Accept with or without `0x`, any case (no EIP-55 checksum requirement) —
    // decode the 20 raw bytes directly rather than going through the
    // checksum-validating FromStr.
    let t = s.trim();
    let hexpart = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let bytes = hex::decode(hexpart).map_err(|e| KeystoreError::InvalidAddress(format!("{s}: {e}")))?;
    if bytes.len() != 20 {
        return Err(KeystoreError::InvalidAddress(format!("{s}: expected 20 bytes, got {}", bytes.len())));
    }
    Ok(Address::from_slice(&bytes))
}

/// Tighten a path's mode. No-op off unix, where the enclosing directory ACL is
/// the control instead.
fn restrict_permissions(path: &Path, mode: u32) -> Result<()> {
    atomic::set_mode(path, mode).map_err(|e| KeystoreError::Io(e.to_string()))
}

/// Before a seed's wallet had a name of its own, an older keys app copied it onto each of the
/// seed's files and accounts: one text, on every one that has a name, which a reader shows as the
/// wallet's. When the wallet is first named, that copy comes off them.
fn adopt_copied_name(d: &mut SeedDoc, seed: &str) {
    if d.wallet_names.contains_key(seed) {
        return;
    }
    let groups: Vec<String> = d
        .groups
        .iter()
        .filter(|(id, _)| Keystore::seed_of_group(&d.groups, id) == seed)
        .map(|(id, _)| id.clone())
        .collect();
    let names: std::collections::BTreeSet<&String> =
        groups.iter().filter_map(|id| d.group_labels.get(id)).filter(|n| !n.trim().is_empty()).collect();
    let [copied] = names.into_iter().collect::<Vec<_>>()[..] else { return };
    let copied = copied.clone();
    d.group_labels.retain(|id, n| !(groups.contains(id) && *n == copied));
    let accounts: Vec<String> =
        d.accounts.iter().filter(|(_, p)| groups.contains(&p.group)).map(|(a, _)| a.clone()).collect();
    d.labels.retain(|a, n| !(accounts.contains(a) && *n == copied));
    d.wallet_names.insert(seed.to_string(), copied);
}

/// An account's key in the index: lowercase hex, no 0x.
fn addr_key(addr: &Address) -> String {
    format!("{:x}", addr)
}

fn new_vault_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("a_{}", hex::encode(b))
}

fn new_key_seed_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{IMPORTED_SEED}{}", hex::encode(b))
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: Root::new(dir), keys: KeyRing::default(), migrated: Default::default() }
    }

    /// Derive the signer for `address` from its vault. The returned signer is
    /// live only for the caller's scope — there is nowhere else it is kept.
    pub fn signer_for(&self, address: &str, password: &str) -> Result<PrivateKeySigner> {
        let addr = parse_address(address)?;
        let path = self.use_vault(&addr)?;
        let key = Zeroizing::new(
            eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        let signer = PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        // The filename is a CLAIM; the decrypted key is the proof. Without this, a vault
        // renamed onto another address's filename signed as that address.
        if signer.address() != addr {
            return Err(KeystoreError::Refused(format!(
                "the vault the index names for {} holds the key for {} — refusing to act as \
                 {addr} with another account's key",
                addr_key(&addr),
                signer.address()
            )));
        }
        Ok(signer)
    }

    /// The key in one vault, by id, whatever account it is: an imported key's seed unlocks
    /// while its account is not listed.
    fn signer_in_vault(&self, id: &str, password: &str) -> Result<PrivateKeySigner> {
        if !self.scan()?.vaults.iter().any(|v| v == id) {
            return Err(KeystoreError::NotFound(format!("vault {id}")));
        }
        let key = Zeroizing::new(
            eth_keystore::decrypt_key(self.root.path(&Slot::Vault(id.to_string())), password)
                .map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(self.root.as_path()).map_err(|e| KeystoreError::Io(e.to_string()))?;
        // create_dir_all honours the umask, so the vault directory was 0755. Tightened, not
        // set: setting it outright re-opened a directory an operator had locked down.
        atomic::tighten_dir(self.root.as_path()).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    /// The vault id the index names for this address, in a seed this process can read.
    fn vault_id(&self, addr: &Address) -> Result<Option<String>> {
        Ok(self.get_provenance()?.remove(&addr_key(addr)).map(|p| p.vault).filter(|v| !v.is_empty()))
    }

    /// The vault the AUTHORITY names for this address.
    ///
    /// The use path used to resolve by `Path::exists`, which follows symlinks — so material
    /// could be live and signable while the scan refused to list it. Signing what the
    /// authority will not name is a contradiction, so the scan decides here too, and
    /// anything else sitting at that path is refused by name rather than taken for the vault.
    fn held_vault(&self, addr: &Address) -> Result<PathBuf> {
        let Some(name) = self.vault_id(addr)? else {
            return Err(KeystoreError::NotFound(addr.to_string()));
        };
        let scan = self.scan()?;
        if scan.vaults.contains(&name) {
            return Ok(self.root.path(&Slot::Vault(name)));
        }
        let rel = Slot::Vault(name).rel().to_string_lossy().into_owned();
        if scan.stray().contains(&rel) {
            return Err(KeystoreError::Refused(format!(
                "{rel} is not a vault this keystore wrote, so it is not this account — call \
                 remove_unexplained to clear it"
            )));
        }
        Err(KeystoreError::NotFound(addr.to_string()))
    }

    /// `held_vault`, settling once if the authority does not name it: a vault an interrupted
    /// write left staged is the ONLY copy of that key, and settle brings it to its real path
    /// rather than letting the account read as absent.
    fn use_vault(&self, addr: &Address) -> Result<PathBuf> {
        match self.held_vault(addr) {
            Err(KeystoreError::NotFound(_)) => {
                self.settle()?;
                self.held_vault(addr)
            }
            other => other,
        }
    }

    /// Addresses the index names a vault on disk for, in the index's form. Taken once, for a
    /// caller asking about many — a scan per index would be the same answer, read n times.
    fn held_addresses(&self) -> Result<Vec<String>> {
        let vaults = self.scan()?.vaults;
        Ok(self
            .get_provenance()?
            .into_iter()
            .filter(|(_, p)| !p.vault.is_empty() && vaults.contains(&p.vault))
            .map(|(addr, _)| addr)
            .collect())
    }

    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24). Does NOT
    /// persist anything — the caller decides whether to import it.
    pub fn create_mnemonic(words: u32) -> Result<String> {
        let count = match words {
            12 | 15 | 18 | 21 | 24 => words as usize,
            _ => return Err(KeystoreError::InvalidParams(format!("word count must be 12/15/18/21/24, got {words}"))),
        };
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, count)
            .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
        Ok(mnemonic.to_phrase())
    }

    /// Write one account's vault, atomically.
    ///
    /// `eth_keystore::encrypt_key` is a single `File::create` straight to the destination,
    /// so writing in place leaves a window where a crash TRUNCATES the live vault. Its whole
    /// public surface is path-based — there is no encrypt-to-string — so the only handle on
    /// that write is the directory it writes into: encrypt into a stage and rename out of
    /// it. The stage sits inside `<ks>/` so the rename never crosses a filesystem, and so
    /// the one scan that finds a live vault finds a half-written one too.
    fn write_vault(&self, id: &str, key: &[u8], password: &str) -> Result<()> {
        #[cfg(test)]
        if tests::FAIL_VAULT_WRITE.with(|f| f.replace(false)) {
            return Err(KeystoreError::Io("a test failed this vault's write".into()));
        }
        self.ensure_dir()?;
        let kind = StageKind::Vault(id.to_string());
        let stage = atomic::Stage::create(self.root.path(&Slot::Stage(kind.clone())))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let file = Slot::staged_name(&kind);
        let mut rng = rand::thread_rng();
        eth_keystore::encrypt_key(stage.path(), &mut rng, key, password, Some(&file))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        stage
            .promote(&file, &self.root.path(&Slot::Vault(id.to_string())))
            .map_err(|e| KeystoreError::Vault(e.to_string()))
    }

    /// The single choke point for a new vault. Its record goes down first, naming the vault's
    /// random id: a crash then leaves a record of a vault never written, which lists nothing,
    /// never a key nothing names. An address already held keeps its vault, written again.
    fn persist_signer(&self, signer: &PrivateKeySigner, password: &str, mut p: Provenance) -> Result<Address> {
        let addr = signer.address();
        // `to_bytes()` hands back the raw secp256k1 secret. Own it in a
        // Zeroizing so it is wiped when this scope ends, on every path.
        let key = Zeroizing::new(signer.to_bytes().0);
        let unlock = if p.group.is_empty() { Some(crate::unlockkey::of_imported(key.as_slice(), 0)?) } else { None };
        let state = self.view()?;
        let k = addr_key(&addr);
        let held = state.merged().accounts.remove(&k);
        if held.is_none() {
            // An imported key here already, in a wallet this process can't read.
            if let Some(locked) = unlock.as_ref().and_then(|u| state.locked_seed_of(u)) {
                return Err(KeystoreError::Refused(format!(
                    "this key is here already, in a locked wallet ({locked}): unlock it in the Signer app first"
                )));
            }
        }
        p.vault = held.as_ref().map(|h| h.vault.clone()).filter(|v| !v.is_empty()).unwrap_or_else(new_vault_id);
        if p.group.is_empty() {
            p.seed = held.as_ref().map(|h| h.seed.clone()).filter(|s| !s.is_empty()).unwrap_or_else(new_key_seed_id);
            p.check = unlock.as_ref().map(|u| index::check_of(&p.seed, u));
        }
        let id = p.vault.clone();
        let before = held.clone();
        self.update_accounts(|all| all.insert(k.clone(), p))?;
        self.write_vault(&id, key.as_slice(), password).inspect_err(|_| {
            let _ = self.update_accounts(|all| match &before {
                Some(b) => all.insert(k.clone(), b.clone()),
                None => all.remove(&k),
            });
        })?;
        Ok(addr)
    }

    /// Import a raw private key (hex, with or without 0x), persisting a vault.
    pub fn import_private_key(&self, priv_hex: &str, password: &str) -> Result<Address> {
        let signer = signer_from_hex(priv_hex)?;
        self.persist_signer(&signer, password, Provenance::of("imported-key"))
    }

    /// Derive account `index` from a mnemonic (+ optional BIP-39 passphrase) and
    /// persist its vault under `password`, keeping nothing.
    pub fn import_mnemonic(&self, phrase: &str, bip39_passphrase: &str, index: u32, password: &str) -> Result<Address> {
        self.import_mnemonic_ex(&ImportRequest {
            phrase,
            bip39_passphrase,
            index,
            password,
            storage: Storage::Plain,
            bip44_account: 0,
            change: 0,
            group_password: "",
            group_label: "",
            wallet_name: "",
            keep: KeepPhrase::No,
        })
        .map(|d| d.address)
    }

    /// Import an existing scrypt keystore JSON, re-encrypting under `new_password`.
    ///
    /// The caller's vault goes on disk INSIDE `<ks>/`, because `eth_keystore::decrypt_key`
    /// takes a path and nothing else. It is their ciphertext — offline-crackable material
    /// with its salt and KDF params — so it gets the same 0700 directory the vaults get,
    /// and, being a `Slot`, it inherits the scan that names it and the sweep that removes
    /// what a kill leaves behind. In shared temp it had neither.
    pub fn import_keystore_json(&self, key_json: &str, password: &str, new_password: &str) -> Result<Address> {
        check_kdf_params(key_json)?;
        self.ensure_dir()?;
        let kind = StageKind::import();
        let stage = atomic::Stage::create(self.root.path(&Slot::Stage(kind.clone())))
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        let scratch = stage
            .write(&Slot::staged_name(&kind), key_json.as_bytes())
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        let key = Zeroizing::new(
            eth_keystore::decrypt_key(&scratch, password)
                .map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        drop(stage);
        let signer = PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        self.persist_signer(&signer, new_password, Provenance::of("imported-json"))
    }

    /// Export an account as a fresh scrypt keystore JSON (string), without
    /// touching the on-disk vault. Requires the vault password.
    pub fn export_keystore_json(&self, address: &str, password: &str) -> Result<String> {
        let addr = parse_address(address)?;
        // Through `signer_for`, so a vault holding a DIFFERENT account's key is refused
        // rather than exported under this address's name.
        self.signer_for(address, password)?;
        std::fs::read_to_string(self.held_vault(&addr)?).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    /// Re-encrypt an existing vault under a new password.
    ///
    /// Through the same staged write as every other vault. The previous version rolled its
    /// own staging directory and called itself crash-safe by construction — which was true
    /// of the DESTINATION and said nothing about the copy left at the source: two of its
    /// exits returned past the cleanup, a panic skipped it, and nothing else ever removed
    /// what it left. A guard that drops, and a scan that classifies, replace all of that.
    pub fn change_password(&self, address: &str, old: &str, new: &str) -> Result<Address> {
        // Deriving the signer IS the check that `old` is correct; a wrong password fails
        // here, before anything on disk is touched.
        let signer = self.signer_for(address, old)?;
        let addr = signer.address();
        let key = Zeroizing::new(signer.to_bytes().0);
        drop(signer);
        let id = self.vault_id(&addr)?.ok_or_else(|| KeystoreError::NotFound(addr.to_string()))?;
        self.write_vault(&id, key.as_slice(), new)?;
        // The wallet's unlock root follows its accounts' password, where `old` sealed it.
        let group = by_key(&self.get_provenance()?, &addr.to_string()).map(|p| p.group.clone()).unwrap_or_default();
        if !group.is_empty() {
            self.reseal_unlock(&group, old, new)?;
        }
        Ok(addr)
    }

    fn reseal_unlock(&self, group: &str, old: &str, new: &str) -> Result<()> {
        let groups = self.get_groups()?;
        let Some(sealed) = groups.get(group).and_then(|g| g.unlock.clone()) else { return Ok(()) };
        let Some(root) = crate::unlockkey::open(&sealed, old, group) else { return Ok(()) };
        let resealed = crate::unlockkey::seal(&root, new, group)?;
        self.update_groups(|gs| {
            if let Some(g) = gs.get_mut(group) {
                g.unlock = Some(resealed.clone());
            }
        })
    }

    /// The seed a group belongs to, as the signer manager knows it: its seed link, else itself.
    pub fn seed_of_group(groups: &BTreeMap<String, Group>, group: &str) -> String {
        groups.get(group).and_then(|g| g.seed.as_ref()).map_or_else(|| group.to_string(), |s| s.id.clone())
    }

    /// The seed an account comes from: its group's, else its own as a key imported on its own.
    pub fn seed_of_account(groups: &BTreeMap<String, Group>, p: &Provenance) -> String {
        if p.group.is_empty() {
            p.seed.clone()
        } else {
            Self::seed_of_group(groups, &p.group)
        }
    }

    /// A seed's unlock key at `index`, behind the password of one of its groups, or of the
    /// imported key it is. From the seed's plain files, as it is asked for while it is locked.
    pub fn unlock_key(&self, seed: &str, index: u32, password: &str) -> Result<[u8; 33]> {
        let seed = seed.trim();
        let state = self.view()?;
        let files = state.seeds.get(seed).ok_or_else(|| KeystoreError::NotFound(format!("seed {seed}")))?;
        if seed.starts_with(IMPORTED_SEED) {
            let vault = files.vaults.first().ok_or_else(|| KeystoreError::NotFound(format!("seed {seed}")))?;
            let signer = self.signer_in_vault(vault, password).map_err(|e| match e {
                KeystoreError::Vault(_) => KeystoreError::Vault("the password for this wallet is not correct".into()),
                other => other,
            })?;
            let key = Zeroizing::new(signer.to_bytes().0);
            return crate::unlockkey::of_imported(key.as_slice(), index);
        }
        let mut sealed_any = false;
        for (id, sealed) in &files.groups {
            let Some(sealed) = sealed else { continue };
            sealed_any = true;
            if let Some(root) = crate::unlockkey::open(sealed, password, id) {
                return crate::unlockkey::key_at(&root, index);
            }
        }
        if !sealed_any {
            return Err(KeystoreError::Refused(
                "this wallet was added before it kept an unlock key: add it again from its phrase".into(),
            ));
        }
        Err(KeystoreError::Vault("the password for this wallet is not correct".into()))
    }

    /// What the signer manager is told when an account or a wallet is added here: its seed, its
    /// unlock key at index 0, the name it goes by, and where its history starts.
    pub fn enrolment(&self, account_or_group: &str, password: &str) -> Result<Enrolment> {
        let id = account_or_group.trim();
        let groups = self.get_groups()?;
        let names = self.get_group_labels()?;
        let wallets = self.wallet_names()?;
        let (seed, name, origin, birthday) = match groups.get(id) {
            Some(g) => (
                Self::seed_of_group(&groups, id),
                names.get(id).cloned().filter(|n| !n.is_empty()),
                g.origin.clone(),
                g.birthday.clone(),
            ),
            None => {
                let addr = parse_address(id)?;
                let p = by_key(&self.get_provenance()?, &addr.to_string())
                    .cloned()
                    .ok_or_else(|| KeystoreError::NotFound(addr.to_string()))?;
                let label = by_key(&self.get_labels()?, &addr.to_string()).cloned().filter(|l| !l.is_empty());
                let name = names.get(&p.group).cloned().filter(|n| !n.is_empty()).or(label);
                (Self::seed_of_account(&groups, &p), name, None, None)
            }
        };
        let unlock_key = self.unlock_key(&seed, 0, password)?;
        let name = wallets.get(&seed).cloned().filter(|n| !n.is_empty()).or(name);
        // The name shows while the wallet is locked, so it never comes from an address.
        let name = name.unwrap_or_else(|| {
            if seed.starts_with(IMPORTED_SEED) { "Imported key".into() } else { "Keystore wallet".into() }
        });
        Ok(Enrolment { seed, unlock_key, name, origin, birthday })
    }

    /// Human-readable account names, in the index beside the accounts they name: readable while
    /// their wallet is unlocked, with no account password.
    pub fn get_labels(&self) -> Result<BTreeMap<String, String>> {
        Ok(self.view()?.merged().labels)
    }

    /// Open an account's vault to prove the caller holds it. One message for every way that
    /// can fail short of the account being absent: a name is not worth an oracle that tells
    /// a wrong password apart from an unreadable vault.
    fn prove_custody(&self, address: &str, password: &str) -> Result<()> {
        self.signer_for(address, password).map(drop).map_err(|e| match e {
            KeystoreError::Vault(_) => {
                KeystoreError::Refused("the password for this account is not correct".into())
            }
            other => other,
        })
    }

    /// Open a wallet's derivation key to prove the caller holds it, at whichever path the
    /// store found it: the staged copy is the same ciphertext under the same password, so an
    /// interrupted import is not a way to name a key without opening it. One message for
    /// every way that can fail, exactly as `prove_custody` gives one.
    fn prove_group_custody(&self, store: &GroupStore, id: &str, password: &str) -> Result<()> {
        let path = if store.keys.iter().any(|k| k == id) {
            self.group_vault_path(id)
        } else {
            self.stage_dir(id).join(Slot::staged_name(&StageKind::Group(id.to_string())))
        };
        let bitcoin = self.get_groups()?.get(id).is_some_and(|g| g.family.is_some());
        let opened = if bitcoin {
            self.open_bitcoin_vault_at(&path, password).map(drop)
        } else {
            self.open_group_vault(&path, password).map(drop)
        };
        opened.map_err(|e| match e {
            KeystoreError::Vault(_) => KeystoreError::Refused(
                "the password for this wallet's derivation key is not correct".into(),
            ),
            other => other,
        })
    }

    /// Set or clear (empty `label`) the name for an address. Refuses an address the keystore
    /// does not hold, so the file cannot accumulate labels for accounts that never existed.
    ///
    /// SETTING one needs the account's own vault password: a name is what a reader shows in
    /// place of an address, so writing one is a claim of custody and has to prove it.
    /// CLEARING needs none — it can only move the display toward the address itself, and it
    /// is the one way to strip a stale name off a vault whose password is lost.
    pub fn set_label(&self, address: &str, label: &str, password: &str) -> Result<()> {
        let addr = parse_address(address)?;
        // An unreadable index says so, rather than "no such account".
        match self.held_vault(&addr) {
            Err(KeystoreError::NotFound(_)) => return Err(KeystoreError::InvalidParams(format!("no such account: {addr}"))),
            Err(e) => return Err(e),
            Ok(_) if !self.has_address(address) => {
                return Err(KeystoreError::InvalidParams(format!("no such account: {addr}")))
            }
            Ok(_) => {}
        }
        let key = addr_key(&addr);
        let label = label.trim().to_string();
        if !label.is_empty() {
            self.prove_custody(address, password)?;
        }
        // Read and write under one lock, so a concurrent rename cannot lose a name.
        self.update_labels(|labels| {
            if label.is_empty() {
                labels.remove(&key);
            } else {
                labels.insert(key, label);
            }
        })
    }

    /// Every account this keystore holds.
    ///
    /// Fallible now, and through the one scan. The previous version was a name-pattern walk
    /// with a silent else: a file it did not recognise was dropped without a word, and an
    /// UNREADABLE keystore directory returned an empty `Vec` — so a user with a funded
    /// wallet was told they had none, and every caller believed it.
    pub fn list_accounts(&self) -> Result<Vec<Address>> {
        Ok(self.account_report()?.accounts)
    }

    /// Everything the module reports about the vault directory, from ONE scan, so the three
    /// answers cannot disagree. Addresses are returned as addresses rather than as the
    /// filenames they were read from: the module renders them EIP-55 checksummed, and a
    /// filename is lowercase.
    pub fn account_report(&self) -> Result<AccountReport> {
        let scan = self.settle()?.left;
        let state = self.view()?;
        let by_vault: BTreeMap<String, String> = state
            .merged()
            .accounts
            .into_iter()
            .filter(|(_, p)| !p.vault.is_empty())
            .map(|(addr, p)| (p.vault, addr))
            .collect();
        let hidden = state.hidden();
        let mut report = AccountReport {
            accounts: Vec::new(),
            staged: scan
                .staged_vaults
                .iter()
                .filter_map(|id| by_vault.get(id))
                .map(|a| parse_address(a))
                .collect::<Result<Vec<_>>>()?,
            unexplained: scan.stray(),
            mismatched: Vec::new(),
        };
        report.unexplained.extend(self.unnamed_vaults(&scan, &state)?);
        let mut vaults: Vec<(&String, &String)> = scan.vaults.iter().filter_map(|id| by_vault.get(id).map(|a| (a, id))).collect();
        // By address, as older builds listed their address-named files.
        vaults.sort();
        for (_, id) in vaults {
            let addr = &by_vault[id];
            if hidden.vaults.contains(id) {
                continue;
            }
            match self.declared_address(id) {
                // Reported as unexplained too, so the one removal path can reach it.
                Some(declared) if &declared != addr => {
                    report.mismatched.push(format!("{id}.json holds 0x{declared}"));
                    report.unexplained.push(format!("{id}.json"));
                }
                _ => report.accounts.push(parse_address(addr)?),
            }
        }
        report.unexplained.sort();
        Ok(report)
    }

    /// Vaults no seed's files name: a key this keystore cannot say whose it is without its
    /// password. Reported as unexplained, so the one removal path reaches them.
    fn unnamed_vaults(&self, scan: &Scan, state: &index::State) -> Result<Vec<String>> {
        let named: std::collections::BTreeSet<String> = state.seeds.values().flat_map(|f| f.vaults.iter().cloned()).collect();
        let indexed: std::collections::BTreeSet<String> =
            state.merged().accounts.into_values().map(|p| p.vault).filter(|v| !v.is_empty()).collect();
        Ok(scan
            .vaults
            .iter()
            .filter(|id| !named.contains(*id) && !indexed.contains(*id))
            .map(|id| Slot::Vault(id.clone()).rel().to_string_lossy().into_owned())
            .collect())
    }

    /// The address a vault file declares, where it declares one. Vaults this module writes
    /// carry no such field; one that does was placed here by something else, and a
    /// disagreement with the index means neither claim can be trusted without a password.
    fn declared_address(&self, name: &str) -> Option<String> {
        let raw = std::fs::read_to_string(self.root.path(&Slot::Vault(name.to_string()))).ok()?;
        let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let declared = v.get("address")?.as_str()?.trim().trim_start_matches("0x");
        Some(declared.to_ascii_lowercase())
    }

    /// Remove one path the scan reported as unexplained.
    ///
    /// Every reported path is removable by name, whatever it turned out to be — a stray
    /// file, a directory where a vault belongs, or a symlink aiming out of the store. Only
    /// a string the scan itself produced is accepted, so no caller can name a path outside
    /// `<ks>/`. `acknowledge` is required because this keystore cannot read the material and
    /// therefore cannot promise it is not a key.
    pub fn remove_unexplained(&self, rel: &str, acknowledge: bool) -> Result<bool> {
        let scan = self.scan()?;
        let mut reported = scan.unexplained_all();
        reported.extend(self.unnamed_vaults(&scan, &self.view()?)?);
        if !reported.iter().any(|p| p == rel) {
            return Err(KeystoreError::NotFound(format!("{rel} is not reported as unexplained")));
        }
        if !acknowledge {
            return Err(KeystoreError::Refused(format!(
                "{rel} is material this keystore did not write and cannot read, so it may be a \
                 live key — acknowledge that to remove it anyway"
            )));
        }
        let path = self
            .root
            .reported(rel)
            .ok_or_else(|| KeystoreError::InvalidParams(format!("not a path under this keystore: {rel}")))?;
        let _guard = self.lock()?;
        remove_path(&path)
    }

    /// What is here that this keystore did not write, relative to its directory. Reported
    /// rather than refused: under `<ks>/` a stray path is at worst one account, and bricking
    /// a wallet over a `.DS_Store` is the worse failure. Under `groups/` it may be a
    /// whole-wallet key, and there it still refuses.
    pub fn unexplained(&self) -> Result<Vec<String>> {
        let scan = self.scan()?;
        let mut out = scan.stray();
        out.extend(self.unnamed_vaults(&scan, &self.view()?)?);
        out.sort();
        Ok(out)
    }

    /// Whether a vault for this address is here. Through the same declared-address rule
    /// `account_report` uses, so the two cannot disagree about what the wallet holds.
    pub fn has_address(&self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => match self.held_vault(&addr) {
                Ok(path) => {
                    let id = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    self.declared_address(&id).is_none_or(|d| d == addr_key(&addr))
                }
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    pub fn delete_account(&self, address: &str, password: &str) -> Result<bool> {
        let addr = parse_address(address)?;
        let path = match self.use_vault(&addr) {
            Err(KeystoreError::NotFound(_)) => return Ok(false),
            other => other?,
        };
        // Require the correct password, and that the vault really holds THIS account, before
        // destroying it: deleting A must never destroy B's only key.
        self.signer_for(address, password)?;
        std::fs::remove_file(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        self.retire(&addr)?;
        Ok(true)
    }

    /// EIP-191 personal_sign over `message` — derives, signs, wipes.
    pub fn sign_message(&self, address: &str, password: &str, message: &str) -> Result<String> {
        sign_message_with(&self.signer_for(address, password)?, message)
    }

    /// Sign an unsigned tx, returning the broadcast-ready EIP-2718 envelope hex.
    pub fn sign_transaction(
        &self,
        address: &str,
        password: &str,
        unsigned_tx_json: &str,
        chain_id: u64,
    ) -> Result<String> {
        sign_transaction_with(&self.signer_for(address, password)?, unsigned_tx_json, chain_id)
    }

    /// Sign a raw 32-byte digest. See [`sign_digest_with`] for the caveat.
    pub fn sign_digest(&self, address: &str, password: &str, digest_hex: &str) -> Result<String> {
        sign_digest_with(&self.signer_for(address, password)?, digest_hex)
    }
}

/// EIP-191 personal_sign. Refuses text that can render differently than it
/// signs (see [`check_displayable`]).
pub fn sign_message_with(signer: &PrivateKeySigner, message: &str) -> Result<String> {
    check_displayable(message, "message")?;
    let sig = signer
        .sign_message_sync(message.as_bytes())
        .map_err(|e| KeystoreError::Signing(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Sign an unsigned tx and return the raw, broadcast-ready signed tx hex
/// (EIP-2718 envelope). Supports legacy (EIP-155) and EIP-1559.
pub fn sign_transaction_with(
    signer: &PrivateKeySigner,
    unsigned_tx_json: &str,
    chain_id: u64,
) -> Result<String> {
    let tx: UnsignedTx = serde_json::from_str(unsigned_tx_json)
        .map_err(|e| KeystoreError::InvalidParams(format!("tx json: {e}")))?;
    sign_parsed_tx(signer, &tx, chain_id)
}

/// Sign an ALREADY-PARSED transaction. The approval path parses once, commits
/// to the parsed value, and signs from that same value — so the bytes a human
/// was shown and the bytes that get signed cannot drift apart.
pub fn sign_parsed_tx(signer: &PrivateKeySigner, tx: &UnsignedTx, chain_id: u64) -> Result<String> {
    let to = match (tx.to.as_deref().map(str::trim).filter(|s| !s.is_empty()), tx.create) {
        (Some(_), true) => {
            return Err(KeystoreError::InvalidParams(
                "tx json: `to` and `create: true` are mutually exclusive".into(),
            ))
        }
        (Some(s), false) => TxKind::Call(parse_address(s)?),
        (None, true) => TxKind::Create,
        (None, false) => {
            return Err(KeystoreError::InvalidParams(
                "tx json: `to` is required; set `create: true` to deploy a contract".into(),
            ))
        }
    };

    if tx.access_list.as_ref().is_some_and(|v| !v.is_null()) {
        return Err(KeystoreError::InvalidParams(
            "tx json: access lists are not supported by this signer — remove `access_list` \
             rather than have it silently dropped from the signed payload"
                .into(),
        ));
    }

    let value = parse_u256(&tx.value, "value")?;
    let nonce = parse_u64(&tx.nonce, "nonce")?;
    let gas_limit = parse_u64(&tx.gas_limit, "gas_limit")?;
    let input = parse_bytes(&tx.data)?;

    let legacy = match tx.fee_mode.trim() {
        "" | "eip1559" => false,
        "legacy" => true,
        other => {
            return Err(KeystoreError::InvalidParams(format!(
                "tx json: fee_mode must be \"eip1559\" or \"legacy\", got {other:?}"
            )))
        }
    };

    let raw = if legacy {
        let t = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: parse_u128(&tx.gas_price, "gas_price")?,
            gas_limit,
            to,
            value,
            input,
        };
        let sig = signer
            .sign_hash_sync(&t.signature_hash())
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        TxEnvelope::Legacy(t.into_signed(sig)).encoded_2718()
    } else {
        let t = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: parse_u128(&tx.max_fee_per_gas, "max_fee_per_gas")?,
            max_priority_fee_per_gas: parse_u128(&tx.max_priority_fee_per_gas, "max_priority_fee_per_gas")?,
            to,
            value,
            input,
            access_list: Default::default(),
        };
        let sig = signer
            .sign_hash_sync(&t.signature_hash())
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        TxEnvelope::Eip1559(t.into_signed(sig)).encoded_2718()
    };

    Ok(format!("0x{}", hex::encode(raw)))
}

/// Sign a raw 32-byte digest (ECDSA over the hash — no EIP-191/712 prefix).
///
/// This signs an OPAQUE hash: unlike a transaction, nothing here can be
/// rendered, so the approval layer must commit to a typed preimage and describe
/// that instead.
pub fn sign_digest_with(signer: &PrivateKeySigner, digest_hex: &str) -> Result<String> {
    let digest = parse_b256(digest_hex)?;
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|e| KeystoreError::Signing(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Parse a 32-byte hash hex (`0x`-prefixed or bare) into a `B256`.
fn parse_b256(s: &str) -> Result<B256> {
    let s = s.trim();
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("digest hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidParams(format!(
            "digest must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// Upper bounds on the KDF work a *caller-supplied* vault may ask us to
/// perform. `eth_keystore::decrypt_key` feeds these straight to scrypt, so an
/// unclamped `n` is a one-file denial of service: `n = u32::MAX` asks for a
/// ~4 TiB allocation and aborts the whole module process.
const MAX_SCRYPT_LOG_N: u32 = 18; // 2^18 = 262144, the Web3/geth standard
const MAX_SCRYPT_R: u64 = 16;
const MAX_SCRYPT_P: u64 = 16;
const MAX_PBKDF2_C: u64 = 10_000_000;
const MAX_KDF_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Reject a vault whose KDF parameters are out of range, BEFORE any derivation
/// is attempted.
fn check_kdf_params(key_json: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(key_json)
        .map_err(|e| KeystoreError::Vault(format!("keystore json: {e}")))?;
    let crypto = v
        .get("crypto")
        .or_else(|| v.get("Crypto"))
        .ok_or_else(|| KeystoreError::Vault("keystore json: missing `crypto`".into()))?;
    let kdf = crypto.get("kdf").and_then(|k| k.as_str()).unwrap_or_default();
    let params = crypto
        .get("kdfparams")
        .ok_or_else(|| KeystoreError::Vault("keystore json: missing `crypto.kdfparams`".into()))?;
    let num = |k: &str| params.get(k).and_then(|x| x.as_u64());

    let bad = |m: String| Err(KeystoreError::Vault(format!("keystore json: {m}")));

    if let Some(dklen) = num("dklen") {
        if dklen != 32 {
            return bad(format!("dklen must be 32, got {dklen}"));
        }
    }

    match kdf {
        "scrypt" => {
            let n = num("n").ok_or_else(|| KeystoreError::Vault("keystore json: scrypt `n` missing".into()))?;
            let r = num("r").unwrap_or(8);
            let p = num("p").unwrap_or(1);
            if !n.is_power_of_two() {
                return bad(format!("scrypt n must be a power of two, got {n}"));
            }
            if n.trailing_zeros() > MAX_SCRYPT_LOG_N {
                return bad(format!("scrypt n = {n} exceeds 2^{MAX_SCRYPT_LOG_N}"));
            }
            if r > MAX_SCRYPT_R || p > MAX_SCRYPT_P {
                return bad(format!("scrypt r/p out of range: r={r}, p={p}"));
            }
            // 128 * r * n is scrypt's working-set size.
            let mem = 128u64.saturating_mul(r).saturating_mul(n);
            if mem > MAX_KDF_MEMORY_BYTES {
                return bad(format!("scrypt would need {mem} bytes, over the {MAX_KDF_MEMORY_BYTES} limit"));
            }
        }
        "pbkdf2" => {
            let c = num("c").ok_or_else(|| KeystoreError::Vault("keystore json: pbkdf2 `c` missing".into()))?;
            if c > MAX_PBKDF2_C {
                return bad(format!("pbkdf2 c = {c} exceeds {MAX_PBKDF2_C}"));
            }
        }
        other => return bad(format!("unsupported kdf {other:?}")),
    }
    Ok(())
}

/// Longest message we will sign. Anything larger cannot be shown to a human in
/// full, and a signer must not sign what an approver cannot display.
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Refuse text whose rendering can differ from its bytes: C0/C1 controls,
/// bidirectional overrides, and zero-width characters. These are exactly the
/// characters that let a display say one thing while the signature covers
/// another.
pub(crate) fn check_displayable(text: &str, what: &str) -> Result<()> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(KeystoreError::InvalidParams(format!(
            "{what}: {} bytes exceeds the {MAX_MESSAGE_BYTES}-byte limit",
            text.len()
        )));
    }
    for c in text.chars() {
        let bad = matches!(c,
            // C0 controls except tab/newline/carriage-return, and DEL + C1.
            '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}'..='\u{9F}'
            // Bidirectional embedding/override/isolate controls.
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            // Zero-width and other invisible formatting.
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
        );
        if bad {
            return Err(KeystoreError::InvalidParams(format!(
                "{what}: refusing U+{:04X} — it can render differently than it signs",
                c as u32
            )));
        }
    }
    Ok(())
}

fn parse_bytes(s: &str) -> Result<Bytes> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let v = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("data: {e}")))?;
    Ok(Bytes::from(v))
}

fn signer_from_hex(priv_hex: &str) -> Result<PrivateKeySigner> {
    let h = priv_hex.trim();
    let h = h.strip_prefix("0x").or_else(|| h.strip_prefix("0X")).unwrap_or(h);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
    PrivateKeySigner::from_slice(&bytes).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
}

// ── Derivation groups ────────────────────────────────────────────────────────
//
// A group is one (mnemonic, BIP-39 passphrase, BIP-44 account) triple. The storage choice
// below is made once for the WHOLE group, because the account key that derives index 3
// derives index 5 as well — a per-account choice would be a lie about what is recoverable.

/// How a group's seed material is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Storage {
    /// Nothing is kept. Adding an account later means entering the phrase again.
    Plain,
    /// The ACCOUNT key `m/44'/60'/<account>'`, in its own scrypt vault — never the root,
    /// which would reach every coin and every BIP-44 account to buy nothing.
    Extkey,
}

impl Storage {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "" | "plain" => Ok(Self::Plain),
            "extkey" => Ok(Self::Extkey),
            other => Err(KeystoreError::InvalidParams(format!(
                "storage must be \"plain\" or \"extkey\", got {other:?}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Extkey => "extkey",
        }
    }
}

/// A local seed identity, shared by all of its coin/account branches. The check is salted by
/// the random ID and derived from a public address; neither the seed nor a root key is retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedLink {
    pub id: String,
    pub check: String,
}

/// A group's record, in its seed's sealed index. `usedPassphrase` is a boolean so a user
/// restoring elsewhere is told a passphrase was involved, never what it was.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Group {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<SeedLink>,
    pub storage: Storage,
    #[serde(rename = "pathPrefix")]
    pub path_prefix: String,
    #[serde(rename = "nextIndex", default)]
    pub next_index: u32,
    #[serde(default)]
    pub retired: Vec<u32>,
    #[serde(rename = "usedPassphrase", default)]
    pub used_passphrase: bool,
    #[serde(default)]
    pub label: String,
    #[serde(rename = "createdMs", default)]
    pub created_ms: u64,
    /// `bitcoin` or `bitcoin_taproot`. Absent on EVM groups, which is all older records hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// `main` or `test`, Bitcoin groups only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// The master fingerprint and the account xpub. Public, but they reveal the wallet's whole
    /// history, as an EVM vault's filename reveals its address. The xpub is Bitcoin groups' only;
    /// the fingerprint names the wallet for an EVM group too, recorded while its seed is in memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
    /// The kept phrase this wallet was made from, when the person chose to keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
    /// `created` or `restored`, Bitcoin groups only; see [`WalletStart`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The first day the wallet could have received coins, `YYYY-MM-DD` in UTC, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday: Option<String>,
    /// The seed's unlock root, sealed under this group's password: what unlocks the wallet's data
    /// in every app. See [`crate::unlockkey`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock: Option<crate::unlockkey::SealedRoot>,
    /// [`index::check_of`] the seed's unlock key: finds the seed again while it is locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

/// Where one account came from, and which vault is its, in its seed's sealed index.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// `derived` | `imported-key` | `imported-json` | `random` | `unknown`.
    pub origin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// Its vault's random id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault: String,
    /// A key imported on its own is a seed of its own: its id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seed: String,
    /// That seed's [`index::check_of`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

impl Provenance {
    fn of(origin: &str) -> Self {
        Self { origin: origin.to_string(), ..Default::default() }
    }
}

/// What a derivation produced.
#[derive(Clone, Debug)]
pub struct Derived {
    pub address: Address,
    pub path: String,
    pub group: String,
    pub index: u32,
}

/// One row of `preview_addresses`: an address, and whether it is already held.
#[derive(Clone, Debug)]
pub struct PreviewEntry {
    pub index: u32,
    pub path: String,
    pub address: Address,
    pub present: bool,
}

/// A group as a reader sees it — no secrets, so this is served ungated.
#[derive(Clone, Debug)]
pub struct GroupView {
    pub id: String,
    pub group: Group,
    pub used_indices: Vec<u32>,
    pub account_count: usize,
    /// Whether an account can be added without the phrase. Checks the vault FILE, not just
    /// the recorded choice, so a deleted key reads as "not derivable" rather than as a promise.
    pub derivable: bool,
    /// A derivation key on disk that no record names. It cannot derive — there is no stored
    /// path prefix — but it can be deleted, and it is listed so that it can be.
    pub stranded: bool,
    /// An interrupted import left a copy of this group's key at the staging path. It cannot
    /// derive and it is not the live vault, but it opens the whole wallet just the same.
    pub staged: bool,
}

/// What `forget_derivation` did. The key is gone in every `Ok` case; these say whether the
/// bookkeeping followed, so the UI can report it rather than assume.
#[derive(Clone, Debug)]
pub struct Forgotten {
    pub group: String,
    /// False means `groups.json` could not be read or rewritten: the key is deleted, but
    /// the group still reads as `extkey` until that file is repaired.
    pub record_updated: bool,
    /// The key had no record at all, and was deleted on the strength of its file.
    pub was_stranded: bool,
    /// A copy left by an interrupted import was removed as well as (or instead of) the vault.
    pub staged_removed: bool,
}

/// What `remove_group` did. Two booleans in the shape of `Forgotten`, so a half-removed
/// wallet is reported rather than read back as a clean removal.
#[derive(Clone, Debug)]
pub struct Removed {
    pub group: String,
    pub record_removed: bool,
    pub name_removed: bool,
}

/// What one `settle` did, and what it left. Reported rather than merely performed: a
/// leftover only named after it has been swept was never nameable.
#[derive(Clone, Debug, Default)]
pub struct Settled {
    /// Staged vaults brought to their real path. Each was the ONLY copy of that key.
    pub promoted: Vec<String>,
    /// Staging directories removed, relative to `<ks>/`.
    pub swept: Vec<String>,
    pub left: Scan,
}

/// The last component of a path this module built from a `Slot`, for reporting.
fn rel_of(path: &Path) -> String {
    path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())
}

/// What the vault directory holds, as a reader sees it.
#[derive(Clone, Debug)]
pub struct AccountReport {
    pub accounts: Vec<Address>,
    /// Vaults an interrupted write left staged. Normally empty — `settle` promotes or reaps
    /// them — and non-empty only when that repair could not run.
    pub staged: Vec<Address>,
    /// Paths under the keystore directory this module did not write.
    pub unexplained: Vec<String>,
    /// Vault files whose own `address` field disagrees with their filename, as
    /// `<file> holds <address>`. Not listed as accounts: the two cannot both be true.
    pub mismatched: Vec<String>,
}

/// One account's provenance, for every account the keystore holds.
#[derive(Clone, Debug)]
pub struct AccountProvenance {
    pub address: Address,
    pub provenance: Provenance,
    pub derivable: bool,
}

/// The wallet identity attached to one account. This is deliberately smaller than
/// `AccountProvenance`: consumers that only need to group accounts should not each grow
/// their own join between provenance and wallet labels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountWallet {
    pub wallet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
}

/// Everything `import_mnemonic` needs. A struct because six of these are optional and
/// three of them are secrets — a positional call would make a swapped pair invisible.
pub struct ImportRequest<'a> {
    pub phrase: &'a str,
    pub bip39_passphrase: &'a str,
    /// The ADDRESS index (the fifth level), not the BIP-44 account.
    pub index: u32,
    pub password: &'a str,
    pub storage: Storage,
    pub bip44_account: u32,
    pub change: u32,
    pub group_password: &'a str,
    /// This account file's own name, empty by default.
    pub group_label: &'a str,
    /// The wallet's name, kept for its seed when the seed has none yet.
    pub wallet_name: &'a str,
    /// Keep the phrase too, or record one kept earlier. The BIP39 passphrase never is.
    pub keep: KeepPhrase<'a>,
}

/// Everything a wallet rename needs. A struct because an `(address, password)` pair sits
/// beside a `(group, label)` pair and one of the four is a secret — positionally, a swap
/// would be invisible, and a password swapped into `label` would be WRITTEN as the name.
pub struct GroupLabelRequest<'a> {
    pub group: &'a str,
    pub label: &'a str,
    /// One account of this wallet. Sent only where an ACCOUNT is what proves the name — the
    /// keystore prices that from what the wallet holds, not from what the caller offers.
    pub address: &'a str,
    /// That account's vault password, or the derivation key's where the wallet has a key and
    /// no accounts. Unread when the wallet holds nothing, and when the name is being cleared.
    pub password: &'a str,
}

/// Most consecutive already-held indices `derive_next_account` will walk past.
const MAX_INDEX_SCAN: u32 = 100;
/// Most addresses one `preview_addresses` call will derive, so it is not a free
/// scrypt-plus-EC-multiply oracle.
pub const MAX_PREVIEW: u32 = 50;

/// Group ids reach the filesystem, so they are validated as ids rather than trusted as
/// names: `g_` + 16 random bytes in hex.
fn check_group_id(id: &str) -> Result<()> {
    if !layout::is_group_id(id) {
        return Err(KeystoreError::InvalidParams(format!("invalid group id {id:?}")));
    }
    Ok(())
}

/// Deliberately NOT the extended key's fingerprint: a fingerprint is derived from public
/// key material, so it would be a stable cross-machine correlator for the same phrase.
fn new_group_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("g_{}", hex::encode(b))
}

/// Everything `groups/` holds, as the one scan classified it. Kept as its own view because
/// the key directory answers a different question from the rest of the keystore: material
/// here may be a whole-wallet key, so it refuses where the account half only reports.
#[derive(Clone, Debug, Default)]
pub struct GroupStore {
    /// Live keys at `groups/<id>.json`.
    pub keys: Vec<String>,
    /// Keys an interrupted `write_group_vault` left at `groups/.stage-<id>/<id>.json`.
    /// Every bit as live: same ciphertext, same password, decrypts to the same account key.
    pub staged: Vec<String>,
    /// Unidentified material anywhere under `<ks>/` whose name or opacity means it could be
    /// a derivation key. Treated as one until someone proves otherwise.
    pub possible_keys: Vec<String>,
    /// `keys` + `staged` + `possible_keys`, as the scan computed it. The ONE query.
    material: Vec<String>,
    /// Symlinks under `<ks>/`, as `<rel> -> <target>`. Where a key that left the keystore
    /// went is the one thing a scan of `<ks>/` can still say about it.
    pub links: Vec<String>,
}

impl From<&Scan> for GroupStore {
    fn from(s: &Scan) -> Self {
        Self {
            keys: s.keys.clone(),
            staged: s.staged.clone(),
            possible_keys: s.possible_keys.clone(),
            material: s.possible_key_material(),
            links: s.links.clone(),
        }
    }
}

impl GroupStore {
    /// Ids naming a key on disk, wherever it sits. This is the set that must be deletable.
    pub fn ids(&self) -> Vec<String> {
        let mut out = self.keys.clone();
        out.extend(self.staged.iter().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Everything here that could open a WHOLE wallet. The one query a mint decision asks.
    pub fn possible_key_material(&self) -> &[String] {
        &self.material
    }

    /// Nothing here could be a key. The only state that may mint a random one.
    pub fn holds_nothing(&self) -> bool {
        self.material.is_empty()
    }
}

/// What one wallet still holds. The ONE answer to "does this wallet hold anything", asked by
/// removal (which refuses while it holds something) and by renaming (which asks for the
/// credential of whatever it holds), so those two cannot drift apart.
#[derive(Clone, Debug)]
pub struct Holdings {
    /// A derivation key on disk at either path. Whole-wallet material either way.
    pub key: bool,
    /// That key sits ONLY at the staging path — an interrupted import.
    pub interrupted: bool,
    pub accounts: usize,
}

impl Holdings {
    fn of(store: &GroupStore, provenance: &BTreeMap<String, Provenance>, group: &str) -> Self {
        let live = store.keys.iter().any(|id| id == group);
        let staged = store.staged.iter().any(|id| id == group);
        Self {
            key: live || staged,
            interrupted: staged && !live,
            accounts: provenance.values().filter(|p| p.group == group).count(),
        }
    }

    /// No key at either path and no account: nothing here to destroy, and nothing a name
    /// could come to stand over — now or later, because with no key it cannot mint one.
    pub fn holds_nothing(&self) -> bool {
        !self.key && self.accounts == 0
    }
}

/// Remove a path whatever it turned out to be — the file, or the directory a crash or a
/// hand-edit left where the file belongs. `Ok(false)` means there was nothing there.
fn remove_path(path: &Path) -> Result<bool> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(KeystoreError::Io(e.to_string())),
    };
    let removed = if meta.is_dir() {
        // A directory nobody may read cannot be recursed into, so the acknowledged removal
        // failed on the exact state it exists to clear. We own it: reopen it and retry once,
        // so a reported path stays actionable rather than being a report and a dead end.
        std::fs::remove_dir_all(path).or_else(|e| match atomic::set_mode(path, 0o700) {
            Ok(()) => std::fs::remove_dir_all(path),
            Err(_) => Err(e),
        })
    } else {
        std::fs::remove_file(path)
    };
    removed.map(|()| true).map_err(|e| KeystoreError::Io(e.to_string()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const DAY_MS: u64 = 86_400_000;

/// A UTC day as `YYYY-MM-DD`, from milliseconds since 1970.
fn utc_day(ms: u64) -> String {
    let (y, m, d) = civil_from_days((ms / DAY_MS) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A birthday the person gave: a real day as `YYYY-MM-DD`, from Bitcoin's first block to tomorrow
/// in UTC, since the person's day may run ahead of it.
fn check_birthday(day: &str) -> Result<()> {
    let bad = || KeystoreError::InvalidParams(format!("birthday must be a day as YYYY-MM-DD, from 2009-01-03 on: {day:?}"));
    let parts: Vec<&str> = day.split('-').collect();
    let [y, m, d] = parts.as_slice() else { return Err(bad()) };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 || !parts.iter().all(|p| p.bytes().all(|c| c.is_ascii_digit())) {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (y.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?, d.parse().map_err(|_| bad())?);
    let days = days_from_civil(y, m, d);
    if !(1..=12).contains(&m) || civil_from_days(days) != (y, m, d) {
        return Err(bad());
    }
    if days < days_from_civil(2009, 1, 3) || days > (now_ms() / DAY_MS) as i64 + 1 {
        return Err(bad());
    }
    Ok(())
}

/// Days since 1970-01-01 of a Gregorian date, by Howard Hinnant's `days_from_civil`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The Gregorian date of a day counted from 1970-01-01, by Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl Keystore {
    fn group_vault_path(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::GroupKey(id.to_string()))
    }

    /// The only other path a key of this group can occupy. Named by id so it is nameable,
    /// and therefore deletable.
    fn stage_dir(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::Stage(StageKind::Group(id.to_string())))
    }

    /// Staged and renamed, never written in place: a crash or a full disk part-way through
    /// `std::fs::write` leaves a TRUNCATED file, and a truncated `groups.json` used to
    /// parse as "no wallets here". The staging name is random, so two processes replacing
    /// one document cannot collide on a single staging path the way `<name>.json.tmp` did.
    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        self.ensure_dir()?;
        let txt =
            serde_json::to_string_pretty(value).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        atomic::write_doc(self.root.as_path(), path, txt.as_bytes())
            .map_err(|e| KeystoreError::Io(e.to_string()))
    }

    /// Read a sidecar, keeping the three states apart: ABSENT is empty, present-and-readable
    /// is its contents, and present-but-unreadable REFUSES. Only the first is "nothing
    /// configured yet"; collapsing the third into it is how a guard fails open.
    fn read_json<T: serde::de::DeserializeOwned + Default>(&self, path: &Path) -> Result<T> {
        let what = || path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        match std::fs::read_to_string(path) {
            Ok(txt) => serde_json::from_str(&txt)
                .map_err(|e| KeystoreError::Corrupt(what(), e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(KeystoreError::Corrupt(what(), e.to_string())),
        }
    }

    /// The index as this process reads it: every seed it holds the key for, and every seed still
    /// waiting for one. Older builds' documents move in first.
    fn view(&self) -> Result<index::State> {
        self.migrate()?;
        index::load(&self.root, &self.keys)
    }

    /// Read, change and write the index as ONE critical section, as [`Self::update`] does a
    /// document: each readable seed's part is written back under its own key.
    fn update_index<R>(&self, f: impl FnOnce(&mut SeedDoc) -> R) -> Result<R> {
        self.migrate()?;
        self.ensure_dir()?;
        let _guard = self.lock()?;
        let state = index::load(&self.root, &self.keys)?;
        let mut doc = state.merged();
        let out = f(&mut doc);
        index::store(&self.root, &self.keys, &state, &doc)?;
        Ok(out)
    }

    fn update_groups<R>(&self, f: impl FnOnce(&mut BTreeMap<String, Group>) -> R) -> Result<R> {
        self.update_index(|d| f(&mut d.groups))
    }

    fn update_accounts<R>(&self, f: impl FnOnce(&mut BTreeMap<String, Provenance>) -> R) -> Result<R> {
        self.update_index(|d| f(&mut d.accounts))
    }

    fn update_labels<R>(&self, f: impl FnOnce(&mut BTreeMap<String, String>) -> R) -> Result<R> {
        self.update_index(|d| f(&mut d.labels))
    }

    fn update_group_labels<R>(&self, f: impl FnOnce(&mut BTreeMap<String, String>) -> R) -> Result<R> {
        self.update_index(|d| f(&mut d.group_labels))
    }

    pub fn get_groups(&self) -> Result<BTreeMap<String, Group>> {
        Ok(self.view()?.merged().groups)
    }

    pub fn get_provenance(&self) -> Result<BTreeMap<String, Provenance>> {
        Ok(self.view()?.merged().accounts)
    }

    /// Wallet names, by group id. Their own map rather than a field of the record, because
    /// the group a reader most needs to name is the stranded one — and its record is exactly
    /// what is missing.
    pub fn get_group_labels(&self) -> Result<BTreeMap<String, String>> {
        Ok(self.view()?.merged().group_labels)
    }

    /// The keys this process holds for the index, shared with whoever asks the signer manager.
    pub fn key_ring(&self) -> KeyRing {
        self.keys.clone()
    }

    /// Seeds whose bookkeeping this process can't read yet, each with the generation its box
    /// needs (none: the current one).
    pub fn closed_seeds(&self) -> Result<Vec<(String, Option<u32>)>> {
        Ok(self.view()?.closed())
    }

    /// Open a seed's bookkeeping with this module's keys for it from the signer manager: the key
    /// of its box's generation, and the current one it is sealed under from then on.
    pub fn open_seed(
        &self,
        seed: &str,
        box_key: &logos_signer_interface::wallets::DataKey,
        current: &logos_signer_interface::wallets::DataKey,
    ) -> Result<bool> {
        self.migrate()?;
        self.ensure_dir()?;
        let _guard = self.lock()?;
        index::open_seed(&self.root, &self.keys, seed, box_key, current)
    }

    /// Forget every index key: every sealed seed reads as locked until it opens again.
    pub fn lock_seeds(&self) {
        self.keys.clear();
    }

    /// How many of this keystore's wallets are locked in this process.
    pub fn locked_wallets(&self) -> Result<usize> {
        Ok(self.locked_seeds()?.len())
    }

    /// The locked wallets, by the names the keystore gives the signer manager for them.
    pub fn locked_seeds(&self) -> Result<Vec<String>> {
        Ok(self.view()?.locked_seeds())
    }

    /// Move older builds' documents into the index, and give their address-named vaults random
    /// names. Once per process; again after a crash part-way, as every step can be repeated.
    fn migrate(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.migrated.load(Ordering::SeqCst) {
            return Ok(());
        }
        let legacy_docs: Vec<Doc> = Doc::LEGACY.into_iter().filter(|d| self.root.path(&Slot::Doc(*d)).exists()).collect();
        let legacy_vaults: Vec<String> = self.raw_scan()?.vaults.into_iter().filter(|v| layout::is_legacy_vault(v)).collect();
        if legacy_docs.is_empty() && legacy_vaults.is_empty() {
            self.migrated.store(true, Ordering::SeqCst);
            return Ok(());
        }
        self.ensure_dir()?;
        let _guard = self.lock()?;
        let old = SeedDoc {
            groups: self.read_json(&self.root.path(&Slot::Doc(Doc::Groups)))?,
            accounts: self.read_json(&self.root.path(&Slot::Doc(Doc::Accounts)))?,
            labels: self.read_json(&self.root.path(&Slot::Doc(Doc::Labels)))?,
            group_labels: self.read_json(&self.root.path(&Slot::Doc(Doc::GroupLabels)))?,
            wallet_names: BTreeMap::new(),
        };
        let state = index::load(&self.root, &self.keys)?;
        let mut doc = state.merged();
        for (k, v) in old.groups {
            doc.groups.entry(k).or_insert(v);
        }
        for (k, v) in old.accounts {
            doc.accounts.entry(k).or_insert(v);
        }
        for (k, v) in old.labels {
            doc.labels.entry(k).or_insert(v);
        }
        for (k, v) in old.group_labels {
            doc.group_labels.entry(k).or_insert(v);
        }
        // Every address-named vault is an account, recorded or not, and gets a random name.
        for v in &legacy_vaults {
            let p = doc.accounts.entry(v.clone()).or_insert_with(|| Provenance::of("unknown"));
            if p.vault.is_empty() {
                p.vault = new_vault_id();
            }
        }
        // A key imported on its own is a seed of its own.
        for p in doc.accounts.values_mut().filter(|p| p.group.is_empty() && p.seed.is_empty()) {
            p.seed = new_key_seed_id();
        }
        index::store(&self.root, &self.keys, &state, &doc)?;
        for (addr, p) in &doc.accounts {
            let from = self.root.path(&Slot::Vault(addr.clone()));
            let to = self.root.path(&Slot::Vault(p.vault.clone()));
            if !p.vault.is_empty() && layout::is_legacy_vault(addr) && from.exists() && !to.exists() {
                std::fs::rename(&from, &to).map_err(|e| KeystoreError::Io(e.to_string()))?;
            }
        }
        for d in legacy_docs {
            remove_path(&self.root.path(&Slot::Doc(d)))?;
        }
        self.migrated.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The ONE writer of a wallet name. Empty clears, like an account label.
    fn write_group_label(&self, id: &str, label: &str) -> Result<()> {
        let label = label.trim().to_string();
        self.update_group_labels(|names| {
            if label.is_empty() {
                names.remove(id);
            } else {
                names.insert(id.to_string(), label);
            }
        })
    }

    /// Name a wallet, or clear the name with an empty string.
    ///
    /// SETTING a name is priced by what the wallet HOLDS, from the one `Holdings` predicate
    /// removal uses: an account's own password where it has accounts, because the name is a
    /// claim about them; the derivation key's password where it has only that, because the
    /// name will come to stand over whatever that key mints. Only a wallet that holds
    /// nothing names nothing, and only that one is free.
    ///
    /// No uniqueness rule: two wallets may carry one name. Which of them a reader is looking
    /// at is a question for whatever renders them, and refusing the write would only make it
    /// unable to show the truth.
    pub fn set_group_label(&self, req: &GroupLabelRequest) -> Result<()> {
        let id = req.group;
        let recorded = self.prove_naming(req)?;
        // A name an older build wrote into the record moves out first, or clearing one here
        // would only reveal the older name still sitting underneath it.
        if recorded.get(id).is_some_and(|g| !g.label.trim().is_empty()) {
            self.update_groups(|groups| {
                if let Some(g) = groups.get_mut(id) {
                    g.label = String::new();
                }
            })?;
        }
        self.write_group_label(id, req.label)
    }

    /// Name a wallet — every account file of one seed, as the header over them shows it — or
    /// clear the name with an empty string. `group` is any file of the seed, and prices the name
    /// as `set_group_label` does. The account files keep names of their own, empty by default.
    pub fn set_wallet_name(&self, req: &GroupLabelRequest) -> Result<()> {
        let recorded = self.prove_naming(req)?;
        let seed = Self::seed_of_group(&recorded, req.group);
        let name = req.label.trim().to_string();
        self.update_index(|d| {
            adopt_copied_name(d, &seed);
            if name.is_empty() {
                d.wallet_names.remove(&seed);
            } else {
                d.wallet_names.insert(seed.clone(), name.clone());
            }
        })
    }

    /// Wallet names, by the seed they name.
    pub fn wallet_names(&self) -> Result<BTreeMap<String, String>> {
        Ok(self.view()?.merged().wallet_names)
    }

    /// Name a new seed's wallet, unless it has a name already.
    fn name_new_wallet(&self, seed: &str, name: &str) -> Result<()> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Ok(());
        }
        check_displayable(&name, "wallet name")?;
        self.update_index(|d| {
            d.wallet_names.entry(seed.to_string()).or_insert(name);
        })
    }

    /// What setting a name on `req.group` costs, checked; the records it read.
    fn prove_naming(&self, req: &GroupLabelRequest) -> Result<BTreeMap<String, Group>> {
        let id = req.group;
        check_group_id(id)?;
        // Its record, its key, an account that came from it, or a name already standing over
        // it: a wallet a reader can SEE is one it can name, and a stranded key or a leftover
        // name is exactly when it needs to.
        let recorded = self.get_groups()?;
        let provenance = self.get_provenance()?;
        let store = self.group_store()?;
        let held = Holdings::of(&store, &provenance, id);
        let named = self.get_group_labels()?.contains_key(id);
        if !recorded.contains_key(id) && held.holds_nothing() && !named {
            return Err(KeystoreError::InvalidParams(format!("no such group: {id}")));
        }
        // Clearing is asked for nothing: it can only move the display toward the addresses
        // themselves, and it is the one way to strip a name off a wallet whose secret is lost.
        if !req.label.trim().is_empty() {
            if held.accounts > 0 {
                if req.address.is_empty() {
                    return Err(KeystoreError::Refused(
                        "naming a wallet that has accounts needs the password of one of them".into(),
                    ));
                }
                // Identical whether the address is unknown, malformed or simply another
                // wallet's: which of those it is answers a question the caller may not ask.
                let belongs = parse_address(req.address)
                    .ok()
                    .and_then(|a| provenance.get(&addr_key(&a)))
                    .is_some_and(|p| p.group == id);
                if !belongs {
                    return Err(KeystoreError::Refused(
                        "that account does not belong to this wallet".into(),
                    ));
                }
                self.prove_custody(req.address, req.password)?;
            } else if held.key {
                if req.password.is_empty() {
                    return Err(KeystoreError::Refused(
                        "naming a wallet that keeps a derivation key needs that key's password".into(),
                    ));
                }
                self.prove_group_custody(&store, id, req.password)?;
            }
        }
        Ok(recorded)
    }

    /// Everything the key directory holds — live keys, staged ones, and anything the layout
    /// does not explain. The FILE is the fact; `groups.json` is only bookkeeping about it,
    /// so this stays answerable when that bookkeeping is unreadable.
    ///
    /// One scan is the authority for all three questions asked of `groups/` (may a random
    /// key be minted, what is derivable, what is deletable), so those answers cannot drift
    /// apart the way "the final path" and "the staging path" did.
    pub fn group_store(&self) -> Result<GroupStore> {
        Ok((&self.scan()?).into())
    }

    /// The key directory as a reader sees it: a locked wallet's keys are not stranded, and
    /// show once it unlocks. An unreadable index hides nothing, so no key turns undeletable.
    pub fn listed_group_store(&self) -> Result<GroupStore> {
        let mut store = self.group_store()?;
        let hidden = self.view().map(|s| s.hidden().groups).unwrap_or_default();
        store.keys.retain(|id| !hidden.contains(id));
        store.staged.retain(|id| !hidden.contains(id));
        Ok(store)
    }

    /// Everything the keystore directory holds, classified. One scan is the authority for
    /// every question asked of it — what may be minted, what is derivable, what is
    /// deletable, and what is here that this keystore did not write — so those answers
    /// cannot drift apart the way "the final path" and "the staging path" did.
    pub fn scan(&self) -> Result<Scan> {
        // Older builds' layout moves in first, so no answer is about files about to be renamed.
        self.migrate()?;
        self.raw_scan()
    }

    fn raw_scan(&self) -> Result<Scan> {
        layout::scan(&self.root).map_err(|u| KeystoreError::Corrupt(u.what, u.why))
    }

    /// Bring the vault directory to a state the layout explains, reporting what it did.
    ///
    /// A staged vault is promoted when the real one is gone (it is then the only copy of
    /// that key, and goes through the same KDF ceiling) and reaped when it is not. Import
    /// scratch is only ever swept. Best-effort about the repair and never about the scan:
    /// a read-only keystore must still list and still sign.
    ///
    /// Callable BY NAME, not only as a side effect of listing, and it says what went — a
    /// leftover named only after it has been swept was never nameable.
    pub fn settle(&self) -> Result<Settled> {
        let scan = self.scan()?;
        let mut out = Settled::default();
        if scan.vault_stages.is_empty() && scan.import_stages.is_empty() {
            out.left = scan;
            return Ok(out);
        }
        if let Ok(_guard) = self.lock() {
            // The caller's ciphertext, left by a kill mid-import. Nothing promotes it: the
            // vault it was being re-encrypted into either landed or did not.
            for nonce in &scan.import_stages {
                let kind = StageKind::Import(nonce.clone());
                let stage = self.root.path(&Slot::Stage(kind));
                if std::fs::remove_dir_all(&stage).is_ok() {
                    out.swept.push(rel_of(&stage));
                }
            }
            for name in &scan.vault_stages {
                let kind = StageKind::Vault(name.clone());
                let stage = self.root.path(&Slot::Stage(kind.clone()));
                let staged = stage.join(Slot::staged_name(&kind));
                let dest = self.root.path(&Slot::Vault(name.clone()));
                if !dest.exists()
                    && self.openable(&staged)
                    && atomic::set_mode(&staged, 0o600)
                        .and_then(|()| std::fs::rename(&staged, &dest))
                        .is_ok()
                {
                    out.promoted.push(name.clone());
                }
                if std::fs::remove_dir_all(&stage).is_ok() {
                    out.swept.push(rel_of(&stage));
                }
            }
        }
        out.left = self.scan()?;
        Ok(out)
    }

    /// Whether a staged vault may be promoted. We wrote it, but it is still a file on disk a
    /// local attacker can swap for a scrypt bomb before its parameters reach the KDF.
    fn openable(&self, path: &Path) -> bool {
        std::fs::read_to_string(path).is_ok_and(|raw| check_kdf_params(&raw).is_ok())
    }

    /// Exclusive across processes, for one bookkeeping read-modify-write.
    fn lock(&self) -> Result<layout::Guard> {
        self.ensure_dir()?;
        layout::lock(&self.root).map_err(|u| {
            KeystoreError::Refused(format!("{} is not available: {}", u.what, u.why))
        })
    }

    /// Read, change and replace one document as ONE critical section.
    ///
    /// The read and the write have to be inside the same lock: two processes each adding an
    /// account both read, both insert, both rename, and one record survives. The closure
    /// gets only the document, so it cannot reach back for the lock and deadlock.
    fn update<T, R>(&self, path: &Path, f: impl FnOnce(&mut T) -> R) -> Result<R>
    where
        T: serde::de::DeserializeOwned + Default + Serialize,
    {
        self.ensure_dir()?;
        let _guard = self.lock()?;
        let mut doc: T = self.read_json(path)?;
        let out = f(&mut doc);
        self.write_json(path, &doc)?;
        Ok(out)
    }

    /// Derivation key ids on disk, at either path. This is what makes a stranded or
    /// half-written key nameable rather than permanent.
    pub fn list_derivation_keys(&self) -> Result<Vec<String>> {
        Ok(self.listed_group_store()?.ids())
    }

    /// Record only what is not already recorded, so walking past an existing account never
    /// rewrites how it actually came to be.
    fn record_provenance_if_absent(&self, addr: &Address, p: Provenance) -> Result<()> {
        let key = addr_key(addr);
        self.update_accounts(|all| {
            all.entry(key).or_insert(p);
        })
    }

    /// The next free index for a group.
    ///
    /// `nextIndex` is a cache, not the authority: it is recomputed from the recorded
    /// accounts on every use, so a corrupted or hand-edited sidecar can only skip an index
    /// — never hand out one that is already in use. A gap costs nothing; a collision is
    /// two vaults claiming one address.
    fn next_index(&self, id: &str, group: &Group) -> Result<u32> {
        let highest = self
            .get_provenance()?
            .values()
            .filter(|p| p.group == id)
            .filter_map(|p| p.index)
            .max();
        Ok(group.next_index.max(highest.map_or(0, |i| i.saturating_add(1))))
    }

    fn bump_next_index(&self, id: &str, used: u32) -> Result<()> {
        self.update_groups(|groups| {
            if let Some(g) = groups.get_mut(id) {
                g.next_index = g.next_index.max(used.saturating_add(1));
            }
        })
    }

    /// The key directory, created if absent — and REFUSED if something other than a real
    /// directory occupies it. A symlink here would put the key outside `<ks>/`, where no
    /// scan can name it and nothing can remove it.
    fn ensure_group_dir(&self) -> Result<PathBuf> {
        let dir = self.root.path(&Slot::GroupDir);
        if let Ok(meta) = std::fs::symlink_metadata(&dir) {
            if !meta.is_dir() {
                return Err(KeystoreError::Refused(
                    "groups/ is not a directory — a derivation key written through it would land \
                     outside this keystore, where nothing can name or remove it. Remove it with \
                     remove_unexplained and try again"
                        .into(),
                ));
            }
        }
        std::fs::create_dir_all(&dir).map_err(|e| KeystoreError::Io(e.to_string()))?;
        restrict_permissions(&dir, 0o700)?;
        Ok(dir)
    }

    /// Write a group's extended key to its own scrypt vault.
    ///
    /// Staged and renamed, like `change_password` and unlike `persist_signer`:
    /// `encrypt_key` writes through `File::create` at the default umask, so restricting
    /// after the fact leaves a window at 0644 at the real path.
    ///
    /// Staged under `groups/` on purpose: a rename stays on one filesystem, so there is no
    /// "somewhere a key cannot be left" — put it where the authority already looks. The
    /// stage guard covers every exit this process can take; the scan covers SIGKILL.
    fn write_group_vault(&self, id: &str, key_b58: &str, password: &str) -> Result<()> {
        check_group_id(id)?;
        if password.is_empty() {
            return Err(KeystoreError::InvalidParams(
                "keeping a derivation key needs a password of its own".into(),
            ));
        }
        self.ensure_group_dir()?;

        let stage = atomic::Stage::create(self.stage_dir(id))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let name = Slot::staged_name(&StageKind::Group(id.to_string()));
        let mut rng = rand::thread_rng();
        eth_keystore::encrypt_key(&stage.path(), &mut rng, key_b58.as_bytes(), password, Some(&name))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        stage
            .promote(&name, &self.group_vault_path(id))
            .map_err(|e| KeystoreError::Vault(e.to_string()))
    }

    /// Open a group's extended key. Live only for the caller's scope, like every other key
    /// here — there is nowhere it is kept.
    fn open_group_key(&self, id: &str, password: &str) -> Result<XPriv> {
        check_group_id(id)?;
        // The authority, not `Path::exists`: a symlink at the key's path resolves to material
        // outside `<ks>/` that no scan of it can name, and deriving from what the report will
        // not list is the same contradiction as signing with it.
        if !self.scan()?.keys.iter().any(|k| k == id) {
            return Err(KeystoreError::NotFound(format!("derivation key for {id}")));
        }
        self.open_group_vault(&self.group_vault_path(id), password)
    }

    /// One group vault file, opened. The path is the caller's, because only DERIVING is
    /// confined to the live key — proving custody may read the staged copy too.
    fn open_group_vault(&self, path: &Path, password: &str) -> Result<XPriv> {
        // We wrote this file, but it is still a file on disk a local attacker can swap for
        // a scrypt bomb before we feed its parameters to the KDF.
        let raw = std::fs::read_to_string(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        check_kdf_params(&raw)?;
        let bytes = Zeroizing::new(
            eth_keystore::decrypt_key(path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        let text = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| KeystoreError::Vault("derivation key is not valid text".into()))?,
        );
        hd::decode_account_key(&text)
    }

    /// The group to derive from. `None` is allowed only when exactly one group can derive;
    /// with several the error names the candidates rather than picking one.
    fn resolve_group(&self, id: Option<&str>) -> Result<(String, Group)> {
        let groups = self.get_groups()?;
        if let Some(id) = id {
            check_group_id(id)?;
            let g = groups
                .get(id)
                .ok_or_else(|| KeystoreError::NotFound(format!("group {id}")))?;
            return Ok((id.to_string(), g.clone()));
        }
        let derivable: Vec<&String> = groups
            .iter()
            .filter(|(_, g)| g.storage == Storage::Extkey && g.family.is_none())
            .map(|(id, _)| id)
            .collect();
        match derivable.as_slice() {
            [only] => Ok(((*only).clone(), groups[*only].clone())),
            [] => Err(KeystoreError::Refused(
                "no wallet in this keystore kept a derivation key — import its recovery \
                 phrase again, choosing to keep one"
                    .into(),
            )),
            many => Err(KeystoreError::Refused(format!(
                "several wallets can derive; name one of: {}",
                many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ))),
        }
    }

    /// Resolve a group that must be able to derive, and the BIP-44 account it is pinned to.
    fn derivable_group(&self, id: Option<&str>) -> Result<(String, Group, u32)> {
        let (id, g) = self.resolve_group(id)?;
        if g.family.is_some() {
            return Err(KeystoreError::Refused(format!(
                "wallet {id} is a Bitcoin wallet; its addresses come from its descriptors, not from here"
            )));
        }
        if g.storage != Storage::Extkey {
            return Err(KeystoreError::Refused(format!(
                "wallet {id} did not keep a derivation key — import its recovery phrase \
                 again to add an account"
            )));
        }
        // Parsed, not trusted: a hand-edited pathPrefix must not redirect derivation.
        let account = Bip44Path::parse_account_prefix(&g.path_prefix)?;
        Ok((id, g, account))
    }

    fn persist_derived(
        &self,
        account_key: &XPriv,
        id: &str,
        path: Bip44Path,
        password: &str,
    ) -> Result<Derived> {
        let signer = hd::signer_in_account(account_key, path.change, path.index)?;
        let address = self.persist_signer(
            &signer,
            password,
            Provenance {
                origin: "derived".into(),
                group: id.to_string(),
                path: path.to_string(),
                index: Some(path.index),
                ..Default::default()
            },
        )?;
        self.bump_next_index(id, path.index)?;
        Ok(Derived { address, path: path.to_string(), group: id.to_string(), index: path.index })
    }

    fn seed_check(seed: &Seed, id: &str) -> Result<String> {
        let key = seed.account_key(0)?;
        let address = hd::signer_in_account(&key, 0, 0)?.address();
        Ok(hex::encode(alloy::primitives::keccak256(
            format!("logos-keystore-seed-v1:{id}:{address}").as_bytes(),
        )))
    }

    /// Verify a legacy branch using its actual public derivation, never a short fingerprint.
    fn seed_matches_group(&self, seed: &Seed, id: &str, group: &Group) -> Result<bool> {
        if let Some(link) = &group.seed {
            return Ok(Self::seed_check(seed, &link.id)? == link.check);
        }
        if let Some(family) = &group.family {
            let family = Family::parse(family)?;
            let chain = Chain::parse(group.chain.as_deref().unwrap_or(""))?;
            let account = btc::parse_account_path(&group.path_prefix, family, chain)?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let (key, _) = AccountSecret::from_seed(&secp, seed.as_secret(), family, chain, account)?;
            return Ok(group.xpub.as_deref() == Some(key.xpub(&secp).to_string().as_str()));
        }
        let account = Bip44Path::parse_account_prefix(&group.path_prefix)?;
        let key = seed.account_key(account)?;
        for (address, origin) in self.get_provenance()? {
            if origin.group == id {
                let path = Bip44Path::parse(&origin.path)?;
                if path.account != account {
                    continue;
                }
                let derived = hd::signer_in_account(&key, path.change, path.index)?.address();
                if parse_address(&address).ok() == Some(derived) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// When adding a branch from the UI, refuse a different phrase/passphrase before any write.
    pub fn check_seed_source(&self, phrase: &str, passphrase: &str, group: &str) -> Result<()> {
        let groups = self.get_groups()?;
        let record = groups.get(group).ok_or_else(|| KeystoreError::NotFound("source wallet".into()))?;
        let seed = Seed::from_mnemonic(phrase, passphrase)?;
        if !self.seed_matches_group(&seed, group, record)? {
            return Err(KeystoreError::Refused(
                "the recovery phrase and BIP39 passphrase do not match this seed group".into(),
            ));
        }
        Ok(())
    }

    /// The seed link a new group of this seed takes, the older groups that learn it, and the
    /// seed's check. Refuses a seed that is here already in a wallet that is locked: its
    /// groups can't be read, so a new one would be a second wallet of the same seed.
    fn seed_link(&self, seed: &Seed) -> Result<(SeedLink, BTreeMap<String, Option<SeedLink>>, String)> {
        let unlock = crate::unlockkey::key_at(&*crate::unlockkey::root_of(seed.as_secret())?, 0)?;
        if let Some(locked) = self.view()?.locked_seed_of(&unlock) {
            return Err(KeystoreError::Refused(format!(
                "this wallet is here already, and locked ({locked}): unlock it in the Signer app first"
            )));
        }
        let groups = self.get_groups()?;
        let mut matching = Vec::new();
        let mut link = None;
        for (id, group) in &groups {
            if self.seed_matches_group(seed, id, group).unwrap_or(false) {
                matching.push(id.clone());
                if link.is_none() {
                    link = group.seed.clone();
                }
            }
        }
        let link = match link {
            Some(link) => link,
            None => {
                let id = new_group_id();
                SeedLink { check: Self::seed_check(seed, &id)?, id }
            }
        };
        let prior = matching
            .into_iter()
            .map(|id| {
                let old = groups[&id].seed.clone();
                (id, old)
            })
            .collect();
        let check = index::check_of(&link.id, &unlock);
        Ok((link, prior, check))
    }

    /// Import a mnemonic, optionally keeping the account key so later accounts can be
    /// derived without the phrase. Creates the group.
    pub fn import_mnemonic_ex(&self, req: &ImportRequest) -> Result<Derived> {
        let path = Bip44Path::new(req.bip44_account, req.change, req.index)?;
        check_displayable(req.wallet_name, "wallet name")?;
        if req.storage == Storage::Extkey && req.group_password.is_empty() {
            return Err(KeystoreError::InvalidParams(
                "keeping a derivation key needs a password of its own".into(),
            ));
        }
        let seed = Seed::from_mnemonic(req.phrase, req.bip39_passphrase)?;
        let account_key = seed.account_key(path.account)?;
        let (seed_link, prior_seeds, check) = self.seed_link(&seed)?;
        let fingerprint = btc::master_fingerprint(seed.as_secret())?.to_string();
        let (phrase, made) = self.phrase_to_record(req.phrase, req.keep)?;

        let id = new_group_id();
        let unlock = crate::unlockkey::seal(&*crate::unlockkey::root_of(seed.as_secret())?, req.password, &id)?;
        let record = Group {
            seed: Some(seed_link.clone()),
            storage: req.storage,
            path_prefix: Bip44Path::account_prefix(path.account),
            next_index: 0,
            retired: Vec::new(),
            used_passphrase: !req.bip39_passphrase.is_empty(),
            // The name lives in its own document; this field is only what older builds wrote.
            label: String::new(),
            created_ms: now_ms(),
            family: None,
            chain: None,
            fingerprint: Some(fingerprint.clone()),
            xpub: None,
            phrase: phrase.clone(),
            origin: None,
            birthday: None,
            unlock: Some(unlock),
            check: Some(check),
        };
        self.update_groups(|groups| {
            for old in prior_seeds.keys() {
                if let Some(group) = groups.get_mut(old) {
                    group.seed = Some(seed_link.clone());
                    // The same seed, so the same wallet: an older EVM group learns its name too.
                    group.fingerprint.get_or_insert_with(|| fingerprint.clone());
                }
            }
            groups.insert(id.clone(), record)
        })
        .inspect_err(|_| self.forget_new_phrase(made, &phrase))?;

        // The record goes down before the key, and both roll back together. A group whose
        // vault is missing reads as "not derivable", which is safe; a vault with no group
        // record would be an unreachable live derivation key sitting on disk.
        let landed = (|| {
            self.write_group_label(&id, req.group_label)?;
            if req.storage == Storage::Extkey {
                let encoded = hd::encode_account_key(&account_key)?;
                self.write_group_vault(&id, &encoded, req.group_password)?;
            }
            self.persist_derived(&account_key, &id, path, req.password)
        })();
        let landed = landed.and_then(|d| self.name_new_wallet(&seed_link.id, req.wallet_name).map(|()| d));

        landed.inspect_err(|_| {
            // Both paths the key can occupy, not just the final one: rolling back only the
            // destination left the staged copy alive and invisible.
            let _ = remove_path(&self.group_vault_path(&id));
            let _ = remove_path(&self.stage_dir(&id));
            let _ = self.write_group_label(&id, "");
            let _ = self.update_groups(|groups| {
                for (old, seed) in &prior_seeds {
                    if let Some(group) = groups.get_mut(old) {
                        group.seed = seed.clone();
                    }
                }
                groups.remove(&id)
            });
            self.forget_new_phrase(made, &phrase);
        })
    }

    /// Add the next account of a group, without the phrase.
    pub fn derive_next_account(
        &self,
        group: Option<&str>,
        group_password: &str,
        password: &str,
        change: u32,
    ) -> Result<Derived> {
        let (id, g, account) = self.derivable_group(group)?;
        let key = self.open_group_key(&id, group_password)?;
        let start = self.next_index(&id, &g)?;
        let held = self.held_addresses()?;

        // Walk past any index whose address is already held — an earlier raw-key import can
        // occupy one — recording what it is on the way, since we have just proved it.
        for offset in 0..MAX_INDEX_SCAN {
            let index = start.saturating_add(offset);
            let path = Bip44Path::new(account, change, index)?;
            let address = hd::address_in_account(&key, change, index)?;
            if !held.contains(&addr_key(&address)) {
                return self.persist_derived(&key, &id, path, password);
            }
            self.record_provenance_if_absent(
                &address,
                Provenance {
                    origin: "derived".into(),
                    group: id.clone(),
                    path: path.to_string(),
                    index: Some(index),
                    ..Default::default()
                },
            )?;
            self.bump_next_index(&id, index)?;
        }
        Err(KeystoreError::Refused(format!(
            "the next {MAX_INDEX_SCAN} indices of wallet {id} are already held"
        )))
    }

    /// Add one account at an index the caller chose.
    pub fn derive_account_at(
        &self,
        group: &str,
        group_password: &str,
        password: &str,
        bip44_account: Option<u32>,
        change: u32,
        index: u32,
    ) -> Result<Derived> {
        let (id, g, account) = self.derivable_group(Some(group))?;
        if let Some(asked) = bip44_account {
            if asked != account {
                return Err(KeystoreError::Refused(format!(
                    "wallet {id} is pinned to {}; its stored key cannot reach account {asked}' \
                     because the BIP-44 account level is hardened",
                    g.path_prefix
                )));
            }
        }
        let path = Bip44Path::new(account, change, index)?;
        let key = self.open_group_key(&id, group_password)?;
        let address = hd::address_in_account(&key, change, index)?;
        if self.held_addresses()?.contains(&addr_key(&address)) {
            return Err(KeystoreError::Refused(format!("{path} is already held, as {address}")));
        }
        self.persist_derived(&key, &id, path, password)
    }

    /// Preview a recovery source without persisting it. Ethereum rows are addresses;
    /// Bitcoin rows are accounts, each previewing its first receive address.
    pub fn preview_mnemonic(&self, phrase: &str, passphrase: &str, family: &str,
                            chain: &str, account: u32, from: u32, count: u32)
        -> Result<Vec<serde_json::Value>> {
        if count == 0 || count > MAX_PREVIEW || from.checked_add(count).is_none_or(|n| n > 0x8000_0000) {
            return Err(KeystoreError::InvalidParams("invalid preview range".into()));
        }
        let seed = Seed::from_mnemonic(phrase, passphrase)?;
        let held = self.held_addresses()?;
        let groups = self.get_groups()?;
        let mut out = Vec::new();
        if family == "evm" {
            let key = seed.account_key(account)?;
            for index in from..from + count {
                let path = Bip44Path::new(account, 0, index)?;
                let address = hd::address_in_account(&key, 0, index)?;
                out.push(serde_json::json!({"family": family, "chain": "main", "account": account,
                    "index": index, "path": path.to_string(), "address": address.to_string(),
                    "present": held.contains(&addr_key(&address))}));
            }
        } else {
            let family = Family::parse(family)?;
            let chain = Chain::parse(chain)?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            for index in from..from + count {
                let (key, fingerprint) = AccountSecret::from_seed(&secp, seed.as_secret(), family, chain, index)?;
                let public = btc::AccountPublic { family, chain, account: index, fingerprint, xpub: key.xpub(&secp) };
                let address = bitcoin::Address::from_script(&public.script_at(&secp, 0, 0)?, chain.network(if chain == Chain::Main { "main" } else { "testnet" })?)
                    .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
                let path = format!("m/{}", public.origin().to_string().trim_start_matches("m/"));
                let present = groups.values().any(|g| g.family.as_deref() == Some(family.as_str())
                    && g.chain.as_deref() == Some(chain.as_str()) && g.xpub.as_deref() == Some(public.xpub.to_string().as_str()));
                out.push(serde_json::json!({"family": family.as_str(), "chain": chain.as_str(),
                    "account": index, "index": index, "path": path, "address": address.to_string(), "present": present}));
            }
        }
        Ok(out)
    }

    /// Addresses only — no keys, no vaults written, and no network. Whether any of them has
    /// on-chain history is a question for a module that already has a network.
    pub fn preview_addresses(
        &self,
        group: &str,
        group_password: &str,
        change: u32,
        from: u32,
        count: u32,
    ) -> Result<Vec<PreviewEntry>> {
        let (id, _, account) = self.derivable_group(Some(group))?;
        let count = match count {
            0 => 10,
            n if n > MAX_PREVIEW => {
                return Err(KeystoreError::InvalidParams(format!(
                    "count must be at most {MAX_PREVIEW}, got {n}"
                )))
            }
            n => n,
        };
        let key = self.open_group_key(&id, group_password)?;
        let held = self.held_addresses()?;
        let mut out = Vec::with_capacity(count as usize);
        for offset in 0..count {
            let index = from.checked_add(offset).ok_or_else(|| {
                KeystoreError::InvalidParams("preview range runs past the last index".into())
            })?;
            let path = Bip44Path::new(account, change, index)?;
            let address = hd::address_in_account(&key, change, index)?;
            out.push(PreviewEntry {
                index,
                path: path.to_string(),
                address,
                present: held.contains(&addr_key(&address)),
            });
        }
        Ok(out)
    }

    /// The ONE way to obtain a random key. `Unrecoverable` is the acknowledgement: it does
    /// not exist unless someone asked for a key no recovery phrase covers, and it carries
    /// the key it generated. Nothing here can mint one without holding it.
    pub fn create_unrelated_account(&self, password: &str, key: Unrecoverable) -> Result<Address> {
        self.persist_signer(key.signer(), password, Provenance::of("random"))
    }

    /// Stop keeping a group's derivation key. Removes every path the id can occupy, and
    /// needs NO password: gating deletion on decryption left a key nobody could open sitting
    /// there refusing every new account — neither derivable nor removable. The Tier D
    /// custodian gate is the authorisation.
    ///
    /// Accounts already derived are untouched; what ends is adding MORE without the phrase.
    pub fn forget_derivation(&self, group: &str) -> Result<Forgotten> {
        check_group_id(group)?;
        if self.view().is_ok_and(|s| s.hidden().groups.contains(group)) {
            return Err(KeystoreError::Refused(format!("wallet {group} is locked: unlock it in the Signer app first")));
        }
        // Readable bookkeeping only: an unreadable groups.json must not stop a key's removal.
        if self.get_groups().is_ok_and(|g| g.get(group).is_some_and(|g| g.family.is_some())) {
            return Err(KeystoreError::Refused(format!(
                "wallet {group} is a Bitcoin wallet, and this key is its only one: forgetting it is deleting the wallet"
            )));
        }
        let removed_key = remove_path(&self.group_vault_path(group))?;
        let removed_staged = remove_path(&self.stage_dir(group))?;
        if !removed_key && !removed_staged {
            return Err(KeystoreError::NotFound(format!("derivation key for {group}")));
        }

        // The key is already gone, so `Ok` means exactly that and `record_updated` says
        // whether the record followed. Failing here instead would report a deletion that
        // did happen as one that did not, and invite a retry that finds nothing.
        let mut out = Forgotten {
            group: group.to_string(),
            record_updated: false,
            was_stranded: false,
            staged_removed: removed_staged,
        };
        let downgraded = self.update_groups(|groups| {
            match groups.get_mut(group) {
                Some(g) => {
                    g.storage = Storage::Plain;
                    true
                }
                None => false,
            }
        });
        match downgraded {
            Ok(true) => out.record_updated = true,
            // The record could not be read or rewritten. The key is gone either way, so
            // `Ok` means exactly that and these two fields say whether the record followed.
            Ok(false) => out.was_stranded = true,
            Err(_) => {}
        }
        Ok(out)
    }

    /// Remove a wallet's record and its name, and nothing else. Refuses while the wallet
    /// holds a derivation key at either path, or an account — so it can never destroy key
    /// material, and `forget_derivation` and `delete_account` stay the only writers that do.
    /// Checking and then acting is safe here: a wallet with no key can never gain an account,
    /// because deriving one goes through `open_group_key` and a re-import mints a new id.
    pub fn remove_group(&self, group: &str) -> Result<Removed> {
        check_group_id(group)?;
        let store = self.group_store()?;
        // The key half first, weighed against no provenance: a torn accounts.json must not
        // turn "still keeps a derivation key" into a refusal that says nothing about the key.
        let key = Holdings::of(&store, &BTreeMap::new(), group);
        if key.key {
            return Err(KeystoreError::Refused(format!(
                "this wallet still keeps a derivation key — stop keeping it first{}",
                if key.interrupted { " (an interrupted import left a copy)" } else { "" }
            )));
        }
        let held = Holdings::of(&store, &self.get_provenance()?, group);
        if held.accounts > 0 {
            return Err(KeystoreError::Refused(format!(
                "this wallet still holds {} account(s); removing its record would leave them \
                 with nothing to name them — delete them first",
                held.accounts
            )));
        }
        let recorded = self.get_groups()?.contains_key(group);
        let named = self.get_group_labels()?.contains_key(group);
        if !recorded && !named {
            return Err(KeystoreError::NotFound(format!("no such group: {group}")));
        }
        // The record goes first: a name left over a vanished record is invisible cruft, while
        // a vanished name over a row still on screen is a user-visible surprise.
        if recorded {
            self.update_groups(|groups| {
                groups.remove(group)
            })?;
        }
        if named {
            self.write_group_label(group, "")?;
        }
        Ok(Removed { group: group.to_string(), record_removed: recorded, name_removed: named })
    }

    /// Every group a reader should see: the recorded ones, plus any derivation key on disk
    /// that no record names. A stranded key is listed rather than hidden — it is live
    /// material, and hiding it is what made it undeletable.
    pub fn list_groups(&self) -> Result<Vec<GroupView>> {
        let state = self.view()?;
        let doc = state.merged();
        let provenance = doc.accounts;
        let recorded = doc.groups;
        let names = doc.group_labels;
        let store = self.group_store()?;
        // A locked wallet's keys are not stranded: they are listed once it unlocks.
        let hidden = state.hidden();
        let mut out: Vec<GroupView> = recorded
            .into_iter()
            .map(|(id, mut group)| {
                // The document is the name; the record's own field is what an older build
                // wrote, and stands only until a rename moves it out.
                if let Some(name) = names.get(&id) {
                    group.label = name.clone();
                }
                let mut used_indices: Vec<u32> = provenance
                    .values()
                    .filter(|p| p.group == id)
                    .filter_map(|p| p.index)
                    .collect();
                used_indices.sort_unstable();
                let account_count = provenance.values().filter(|p| p.group == id).count();
                // Only the FINAL path can derive: a staged copy is an interrupted write, and
                // promoting one to the live key is the same confusion in the other direction.
                let derivable = group.storage == Storage::Extkey && store.keys.contains(&id);
                let staged = store.staged.contains(&id);
                GroupView { id, group, used_indices, account_count, derivable, stranded: false, staged }
            })
            .collect();
        for id in store.ids() {
            if let Some(v) = out.iter_mut().find(|v| v.id == id) {
                v.staged = store.staged.contains(&id);
                continue;
            }
            if hidden.groups.contains(&id) {
                continue;
            }
            // Not derivable: without the record there is no path prefix to derive against.
            // It is still deletable, which is the affordance that matters here.
            let staged = store.staged.contains(&id);
            // A stranded key has no record, which is exactly why the name is not kept in one:
            // this is the row a reader has to name while asking whether to delete it.
            let label = names.get(&id).cloned().unwrap_or_default();
            // Counted, not assumed zero: a key loses its record while the accounts it derived
            // are still here, and "holds nothing" is the precondition removal and renaming
            // both read. A hardcoded 0 says this wallet holds nothing when it holds two.
            let account_count = provenance.values().filter(|p| p.group == id).count();
            out.push(GroupView {
                id,
                group: Group {
                    seed: None,
                    storage: Storage::Extkey,
                    path_prefix: String::new(),
                    next_index: 0,
                    retired: Vec::new(),
                    used_passphrase: false,
                    label,
                    created_ms: 0,
                    family: None,
                    chain: None,
                    fingerprint: None,
                    xpub: None,
                    unlock: None,
                    phrase: None,
                    origin: None,
                    birthday: None,
                    check: None,
                },
                used_indices: Vec::new(),
                account_count,
                derivable: false,
                stranded: true,
                staged,
            });
        }
        Ok(out)
    }

    /// Provenance for every account the keystore holds. Accounts that predate this feature
    /// are reported `unknown` — never guessed, because a guess about recoverability is the
    /// one lie this must not tell.
    pub fn provenance_view(&self) -> Result<Vec<AccountProvenance>> {
        let recorded = self.get_provenance()?;
        let groups = self.get_groups()?;
        let accounts = self.list_accounts()?;
        let keys = self.scan()?.keys;
        Ok(accounts
            .into_iter()
            .map(|address| {
                let provenance = recorded
                    .get(&addr_key(&address))
                    .cloned()
                    .unwrap_or_else(|| Provenance::of("unknown"));
                let derivable = groups.get(&provenance.group).is_some_and(|g| {
                    g.storage == Storage::Extkey && keys.contains(&provenance.group)
                });
                AccountProvenance { address, provenance, derivable }
            })
            .collect())
    }

    /// Join account provenance with the wallet names document. Accounts without a named
    /// derivation group are intentionally absent: there is no wallet identity to assert for
    /// an imported or otherwise ungrouped account.
    pub fn account_wallets(&self) -> Result<BTreeMap<String, AccountWallet>> {
        let labels = self.get_group_labels()?;
        Ok(self
            .provenance_view()?
            .into_iter()
            .filter_map(|account| {
                let label = labels.get(&account.provenance.group)?;
                if label.trim().is_empty() {
                    return None;
                }
                Some((
                    account.address.to_string(),
                    AccountWallet { wallet: label.clone(), index: account.provenance.index },
                ))
            })
            .collect())
    }

    /// Public source metadata only. A seed link is a verified local grouping, never words. EVM
    /// accounts are keyed by address; a Bitcoin wallet, which is its own group, by the group's id.
    pub fn account_origins(&self) -> Result<BTreeMap<String, serde_json::Value>> {
        let groups = self.get_groups()?;
        let labels = self.get_group_labels()?;
        let phrase_of = |gid: &str| {
            groups.get(gid).map(|g| {
                let id = g.seed.as_ref().map(|s| s.id.as_str()).unwrap_or(gid);
                // One deterministic name across the wallets linked to this seed.
                let name = groups.iter().filter(|(other_id, other)| {
                    other.seed.as_ref().map(|s| s.id.as_str()).unwrap_or(other_id) == id
                }).find_map(|(other_id, _)| labels.get(other_id).filter(|s| !s.trim().is_empty()));
                serde_json::json!({ "id": id, "name": name })
            })
        };
        let devices = serde_json::json!([{ "id": "local", "kind": "keystore", "name": "" }]);
        let mut out: BTreeMap<String, serde_json::Value> = self.provenance_view()?.into_iter().map(|a| {
            let p = a.provenance;
            (a.address.to_string(), serde_json::json!({
                "devices": devices, "phrase": phrase_of(&p.group), "kind": p.origin, "path": p.path
            }))
        }).collect();
        for (gid, g) in groups.iter().filter(|(_, g)| g.family.is_some()) {
            out.insert(gid.clone(), serde_json::json!({
                "devices": devices, "phrase": phrase_of(gid), "kind": "derived", "path": g.path_prefix
            }));
        }
        Ok(out)
    }

    /// Retire an index so it is never handed out again. A reused path may collide with an
    /// account that still holds funds; a gap costs nothing.
    fn retire(&self, address: &Address) -> Result<()> {
        let key = addr_key(address);
        let removed = self.update_accounts(|all| {
            all.remove(&key)
        })?;
        let (Some(p), ) = (removed, ) else { return Ok(()) };
        let (Some(index), false) = (p.index, p.group.is_empty()) else {
            return Ok(());
        };
        self.update_groups(|groups| {
            if let Some(g) = groups.get_mut(&p.group) {
                if !g.retired.contains(&index) {
                    g.retired.push(index);
                    g.retired.sort_unstable();
                }
                g.next_index = g.next_index.max(index.saturating_add(1));
            }
        })
    }
}

// ── Bitcoin groups ───────────────────────────────────────────────────────────
//
// A Bitcoin group keeps its account key and its wallet's database key in its own vault, at the
// group key's usual path. Its record holds the public half, so a request can be read without it.

/// Everything a Bitcoin wallet's import needs.
pub struct BitcoinImport<'a> {
    pub phrase: &'a str,
    pub bip39_passphrase: &'a str,
    pub family: Family,
    pub chain: Chain,
    pub account: u32,
    /// The vault's password: it guards the account key and the database key.
    pub password: &'a str,
    /// This account's own name, empty by default.
    pub label: &'a str,
    /// The wallet's name, kept for its seed when the seed has none yet.
    pub wallet_name: &'a str,
    pub keep: KeepPhrase<'a>,
    pub start: WalletStart<'a>,
}

/// Where a Bitcoin wallet's history can begin, for its wallet core to know where to start scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletStart<'a> {
    /// The keys app made its phrase for it: no coin can have reached it before the day it is made.
    Created,
    /// Its phrase came from elsewhere or was kept earlier: the person may give the day it was first used.
    Restored(Option<&'a str>),
}

/// Whether a wallet's phrase is kept. The BIP39 passphrase never is.
#[derive(Clone, Copy, Debug)]
pub enum KeepPhrase<'a> {
    No,
    /// Keep it in a new vault, under this password of its own.
    New(&'a str),
    /// It is already kept, in the vault with this id; the wallet records it.
    Kept(&'a str),
}

/// A Bitcoin wallet just made.
#[derive(Clone, Debug)]
pub struct BitcoinGroup {
    pub id: String,
    pub account: AccountPublic,
}

/// What a Bitcoin wallet's vault holds, as JSON inside the scrypt envelope.
#[derive(Serialize, Deserialize)]
struct BitcoinVault {
    v: u32,
    family: String,
    #[serde(rename = "accountKey")]
    account_key: String,
    /// 32 random bytes, never derived from a key, that open the wallet core's database.
    #[serde(rename = "databaseKey")]
    database_key: String,
}

impl Drop for BitcoinVault {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.account_key.zeroize();
        self.database_key.zeroize();
    }
}

impl Keystore {
    /// Make a Bitcoin wallet from a phrase. The vault lands after its record, and both roll back together.
    pub fn import_bitcoin(&self, req: &BitcoinImport) -> Result<BitcoinGroup> {
        if req.password.is_empty() {
            return Err(KeystoreError::InvalidParams("a Bitcoin wallet's vault needs a password".into()));
        }
        check_displayable(req.label, "label")?;
        check_displayable(req.wallet_name, "wallet name")?;
        match (req.start, req.keep) {
            (WalletStart::Created, KeepPhrase::Kept(_)) => {
                return Err(KeystoreError::InvalidParams(
                    "a wallet from a kept phrase is restored: the phrase is older than the wallet".into(),
                ));
            }
            (WalletStart::Restored(Some(day)), _) => check_birthday(day)?,
            _ => {}
        }
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let seed = Seed::from_mnemonic(req.phrase, req.bip39_passphrase)?;
        let (secret, fingerprint) =
            AccountSecret::from_seed(&secp, seed.as_secret(), req.family, req.chain, req.account)?;
        let (seed_link, prior_seeds, check) = self.seed_link(&seed)?;
        let unlock_root = crate::unlockkey::root_of(seed.as_secret())?;
        drop(seed);
        let account = AccountPublic {
            family: req.family,
            chain: req.chain,
            account: req.account,
            fingerprint,
            xpub: secret.xpub(&secp),
        };
        let mut db_key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), db_key.as_mut());
        let vault = BitcoinVault {
            v: 1,
            family: req.family.as_str().into(),
            account_key: secret.encode().to_string(),
            database_key: hex::encode(&db_key[..]),
        };
        let text =
            Zeroizing::new(serde_json::to_string(&vault).map_err(|e| KeystoreError::Vault(e.to_string()))?);
        drop(vault);

        let (phrase, made) = self.phrase_to_record(req.phrase, req.keep)?;
        let forget_new_phrase = || self.forget_new_phrase(made, &phrase);

        let id = new_group_id();
        let unlock = crate::unlockkey::seal(&unlock_root, req.password, &id)?;
        drop(unlock_root);
        let created_ms = now_ms();
        let (origin, birthday) = match req.start {
            WalletStart::Created => ("created", Some(utc_day(created_ms))),
            WalletStart::Restored(day) => ("restored", day.map(str::to_string)),
        };
        let record = Group {
            seed: Some(seed_link.clone()),
            storage: Storage::Extkey,
            path_prefix: format!("m/{}'/{}'/{}'", req.family.purpose(), req.chain.coin_type(), req.account),
            next_index: 0,
            retired: Vec::new(),
            used_passphrase: !req.bip39_passphrase.is_empty(),
            label: String::new(),
            created_ms,
            family: Some(req.family.as_str().into()),
            chain: Some(req.chain.as_str().into()),
            fingerprint: Some(fingerprint.to_string()),
            xpub: Some(account.xpub.to_string()),
            phrase: phrase.clone(),
            origin: Some(origin.into()),
            birthday,
            unlock: Some(unlock),
            check: Some(check),
        };
        self.update_groups(|groups| {
            for old in prior_seeds.keys() {
                if let Some(group) = groups.get_mut(old) {
                    group.seed = Some(seed_link.clone());
                    // An EVM group of this seed learns which wallet it is.
                    group.fingerprint.get_or_insert_with(|| fingerprint.to_string());
                }
            }
            groups.insert(id.clone(), record)
        })
        .inspect_err(|_| forget_new_phrase())?;
        let landed = (|| {
            self.write_group_label(&id, req.label)?;
            self.write_group_vault(&id, &text, req.password)?;
            self.name_new_wallet(&seed_link.id, req.wallet_name)
        })();
        landed.inspect_err(|_| {
            let _ = remove_path(&self.group_vault_path(&id));
            let _ = remove_path(&self.stage_dir(&id));
            let _ = self.write_group_label(&id, "");
            let _ = self.update_groups(|groups| {
                for (old, seed) in &prior_seeds {
                    if let Some(group) = groups.get_mut(old) {
                        group.seed = seed.clone();
                    }
                }
                groups.remove(&id)
            });
            forget_new_phrase();
        })?;
        Ok(BitcoinGroup { id, account })
    }

    /// A Bitcoin group's public half and the name the signer shows for it, from its record alone.
    pub fn bitcoin_account(&self, id: &str) -> Result<(AccountPublic, String)> {
        check_group_id(id)?;
        let groups = self.get_groups()?;
        let g = groups.get(id).ok_or_else(|| KeystoreError::NotFound(format!("group {id}")))?;
        let corrupt = |what: &str| KeystoreError::Corrupt(Doc::Index.file().into(), format!("wallet {id}: {what}"));
        let family = Family::parse(g.family.as_deref().ok_or_else(|| {
            KeystoreError::Refused(format!("wallet {id} is not a Bitcoin wallet"))
        })?)?;
        let chain = Chain::parse(g.chain.as_deref().unwrap_or_default()).map_err(|_| corrupt("no network"))?;
        let account = btc::parse_account_path(&g.path_prefix, family, chain)?;
        let fingerprint = g
            .fingerprint
            .as_deref()
            .and_then(|f| bitcoin::bip32::Fingerprint::from_str(f).ok())
            .ok_or_else(|| corrupt("no fingerprint"))?;
        let xpub = g
            .xpub
            .as_deref()
            .and_then(|x| bitcoin::bip32::Xpub::from_str(x).ok())
            .filter(|x| x.depth == 3 && x.network == chain.kind())
            .ok_or_else(|| corrupt("no account xpub"))?;
        let name = self
            .get_group_labels()?
            .get(id)
            .filter(|l| !l.trim().is_empty() && check_displayable(l, "label").is_ok())
            .map_or_else(|| id.to_string(), |l| format!("\"{}\"", l.trim()));
        Ok((AccountPublic { family, chain, account, fingerprint, xpub }, name))
    }

    /// First receiving address, derived from the saved public account key without opening a vault.
    pub fn bitcoin_address_preview(&self, id: &str) -> Result<(String, String)> {
        let (account, _) = self.bitcoin_account(id)?;
        let script = account.script_at(&bitcoin::secp256k1::Secp256k1::verification_only(), 0, 0)?;
        let network = match account.chain {
            Chain::Main => bitcoin::Network::Bitcoin,
            Chain::Test => bitcoin::Network::Testnet,
        };
        let address = bitcoin::Address::from_script(&script, network)
            .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
        Ok((address.to_string(), format!("m/{}/0/0", account.origin().to_string().trim_start_matches("m/"))))
    }

    /// How a Bitcoin wallet came to be, and its birthday if known. A record from before either was
    /// kept says `restored`, with no birthday, so its wallet core scans the most.
    pub fn bitcoin_start(&self, id: &str) -> Result<(String, Option<String>)> {
        self.bitcoin_account(id)?;
        let g = self.get_groups()?.remove(id).ok_or_else(|| KeystoreError::NotFound(format!("group {id}")))?;
        Ok((g.origin.unwrap_or_else(|| "restored".into()), g.birthday))
    }

    /// The descriptors a wallet core builds its watch-only wallet from: receive, then change.
    pub fn account_descriptors(&self, id: &str) -> Result<(String, String)> {
        let (acct, _) = self.bitcoin_account(id)?;
        Ok((acct.descriptor(0), acct.descriptor(1)))
    }

    /// Sign a PSBT with a Bitcoin group's key, opened from its vault for this call only.
    pub fn sign_psbt(&self, id: &str, password: &str, acct: &AccountPublic, psbt: &mut bitcoin::Psbt) -> Result<()> {
        let secret = self.open_bitcoin_key(id, password, acct)?;
        crate::psbt::sign(&bitcoin::secp256k1::Secp256k1::new(), acct, &secret, psbt)
    }

    /// The account key, refused unless it is the one the record's xpub describes: a swapped vault signs nothing.
    fn open_bitcoin_key(&self, id: &str, password: &str, acct: &AccountPublic) -> Result<AccountSecret> {
        self.open_bitcoin_vault(id, password, acct).map(|(secret, _)| secret)
    }

    /// The account key and the database key, from a vault checked against the record.
    pub(crate) fn open_bitcoin_vault(
        &self,
        id: &str,
        password: &str,
        acct: &AccountPublic,
    ) -> Result<(AccountSecret, Zeroizing<String>)> {
        check_group_id(id)?;
        if !self.scan()?.keys.iter().any(|k| k == id) {
            return Err(KeystoreError::NotFound(format!("the key of wallet {id}")));
        }
        let vault = self.open_bitcoin_vault_at(&self.group_vault_path(id), password)?;
        if vault.family != acct.family.as_str() {
            return Err(KeystoreError::Vault("the vault is not this wallet's family".into()));
        }
        let secret = AccountSecret::decode(&vault.account_key, acct.chain)?;
        if secret.xpub(&bitcoin::secp256k1::Secp256k1::new()) != acct.xpub {
            return Err(KeystoreError::Refused(format!("the vault of wallet {id} holds another wallet's key")));
        }
        Ok((secret, Zeroizing::new(vault.database_key.clone())))
    }

    /// The ids of every Bitcoin wallet whose record names its family.
    pub fn bitcoin_groups(&self) -> Result<Vec<String>> {
        Ok(self.get_groups()?.into_iter().filter(|(_, g)| g.family.is_some()).map(|(id, _)| id).collect())
    }

    fn open_bitcoin_vault_at(&self, path: &Path, password: &str) -> Result<BitcoinVault> {
        let raw = std::fs::read_to_string(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        check_kdf_params(&raw)?;
        let bytes = Zeroizing::new(
            eth_keystore::decrypt_key(path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        let vault: BitcoinVault = serde_json::from_slice(&bytes)
            .map_err(|_| KeystoreError::Vault("not a Bitcoin wallet's vault".into()))?;
        if vault.v != 1 {
            return Err(KeystoreError::Vault(format!("unknown Bitcoin vault version {}", vault.v)));
        }
        Ok(vault)
    }
}

// ── Kept phrases ─────────────────────────────────────────────────────────────
//
// A recovery phrase the person chose to keep, in its own scrypt vault under a password of its
// own, beside the group keys. Off unless asked for. Deleting the wallets made from it leaves it;
// only `forget_phrase` removes it.

/// A kept phrase, and the wallets whose records say they were made from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptPhrase {
    pub id: String,
    pub groups: Vec<String>,
    /// Only at the staging path, after an interrupted write. Still the whole phrase.
    pub staged: bool,
}

fn check_phrase_id(id: &str) -> Result<()> {
    if !layout::is_phrase_id(id) {
        return Err(KeystoreError::InvalidParams(format!("invalid phrase id {id:?}")));
    }
    Ok(())
}

/// Random, like a group id: a phrase's fingerprint would correlate it across machines.
fn new_phrase_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("p_{}", hex::encode(b))
}

impl Keystore {
    fn phrase_vault_path(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::PhraseVault(id.to_string()))
    }

    fn phrase_stage_dir(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::Stage(StageKind::Phrase(id.to_string())))
    }

    /// The kept phrase an import records, and whether this import made its vault.
    fn phrase_to_record(&self, phrase: &str, keep: KeepPhrase) -> Result<(Option<String>, bool)> {
        match keep {
            KeepPhrase::No => Ok((None, false)),
            KeepPhrase::New(password) => Ok((Some(self.keep_phrase(phrase, password)?), true)),
            KeepPhrase::Kept(p) => {
                check_phrase_id(p)?;
                if !self.scan()?.phrases.iter().any(|k| k == p) {
                    return Err(KeystoreError::NotFound(format!("kept phrase {p}")));
                }
                Ok((Some(p.to_string()), false))
            }
        }
    }

    /// Undo a phrase vault an import made, when the import itself failed.
    fn forget_new_phrase(&self, made: bool, phrase: &Option<String>) {
        if let (true, Some(p)) = (made, phrase) {
            let _ = remove_path(&self.phrase_vault_path(p));
            let _ = remove_path(&self.phrase_stage_dir(p));
        }
    }

    /// Keep a phrase in a new vault, staged and renamed like a group key. Returns its id.
    pub fn keep_phrase(&self, phrase: &str, password: &str) -> Result<String> {
        if password.is_empty() {
            return Err(KeystoreError::InvalidParams("keeping a phrase needs a password of its own".into()));
        }
        let words = hd::normalize_phrase(phrase)?;
        let id = new_phrase_id();
        self.ensure_group_dir()?;
        let kind = StageKind::Phrase(id.clone());
        let stage = atomic::Stage::create(self.phrase_stage_dir(&id)).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let name = Slot::staged_name(&kind);
        let mut rng = rand::thread_rng();
        eth_keystore::encrypt_key(&stage.path(), &mut rng, words.as_bytes(), password, Some(&name))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        stage
            .promote(&name, &self.phrase_vault_path(&id))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        Ok(id)
    }

    /// A kept phrase's words, with its password. Only the live vault answers.
    pub fn show_phrase(&self, id: &str, password: &str) -> Result<Zeroizing<String>> {
        check_phrase_id(id)?;
        if !self.scan()?.phrases.iter().any(|p| p == id) {
            return Err(KeystoreError::NotFound(format!("kept phrase {id}")));
        }
        let path = self.phrase_vault_path(id);
        let raw = std::fs::read_to_string(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        check_kdf_params(&raw)?;
        // One message for every way the vault fails to open, as `prove_custody` gives one.
        let bytes = Zeroizing::new(eth_keystore::decrypt_key(&path, password).map_err(|_| {
            KeystoreError::Refused("the password for this phrase is not correct".into())
        })?);
        let words = std::str::from_utf8(&bytes).map_err(|_| KeystoreError::Vault("not a phrase vault".into()))?;
        hd::normalize_phrase(words).map_err(|_| KeystoreError::Vault("not a phrase vault".into()))
    }

    /// Remove a kept phrase at either path, and its mention from every wallet's record. No
    /// password, like `forget_derivation`: removing a secret needs no proof of holding it.
    pub fn forget_phrase(&self, id: &str) -> Result<bool> {
        check_phrase_id(id)?;
        if self.view().is_ok_and(|s| s.hidden().phrases.contains(id)) {
            return Err(KeystoreError::Refused("this phrase's wallet is locked: unlock it in the Signer app first".into()));
        }
        let removed = remove_path(&self.phrase_vault_path(id))?;
        let staged = remove_path(&self.phrase_stage_dir(id))?;
        self.update_groups(|groups| {
            for g in groups.values_mut().filter(|g| g.phrase.as_deref() == Some(id)) {
                g.phrase = None;
            }
        })?;
        Ok(removed || staged)
    }

    /// Every kept phrase on disk, at either path, with the wallets made from it.
    pub fn kept_phrases(&self) -> Result<Vec<KeptPhrase>> {
        let scan = self.scan()?;
        let state = self.view()?;
        let groups = state.merged().groups;
        // A locked wallet's phrase is listed once it unlocks.
        let hidden = state.hidden();
        Ok(scan
            .phrase_ids()
            .into_iter()
            .filter(|id| !hidden.phrases.contains(id))
            .map(|id| KeptPhrase {
                groups: groups.iter().filter(|(_, g)| g.phrase.as_deref() == Some(id.as_str())).map(|(g, _)| g.clone()).collect(),
                staged: !scan.phrases.contains(&id),
                id,
            })
            .collect())
    }
}

// ── Device wallets' database keys ────────────────────────────────────────────
//
// A Bitcoin wallet whose key is on a device still needs a key for its wallet core's database. The
// keystore keeps one per device account, in its own scrypt vault under a password the person sets
// the first time the wallet is opened. It opens the wallet core's records, never a coin.

/// Which device account a database-key vault belongs to, in `device-wallets.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceWallet {
    /// The signer module that offers the account, such as `keycard_shell_module`.
    pub signer: String,
    /// The account's id in that module.
    pub account: String,
    #[serde(rename = "createdMs", default)]
    pub created_ms: u64,
    /// The first day the wallet could have received coins, `YYYY-MM-DD`, if the person gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday: Option<String>,
}

/// A device wallet's database key, opened, or made by this open.
pub struct DeviceKey {
    pub database_key: Zeroizing<String>,
    pub birthday: Option<String>,
    pub created: bool,
}

/// What a device wallet's vault holds, as JSON inside the scrypt envelope.
#[derive(Serialize, Deserialize)]
struct DeviceVaultDoc {
    v: u32,
    #[serde(rename = "databaseKey")]
    database_key: String,
}

impl Drop for DeviceVaultDoc {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.database_key.zeroize();
    }
}

/// Random, like a group id: an id derived from the account would correlate it across machines.
fn new_device_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("d_{}", hex::encode(b))
}

fn check_device_name(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(KeystoreError::InvalidParams(format!("a device wallet needs its {what}, up to 128 characters")));
    }
    check_displayable(value, what)
}

impl Keystore {
    fn device_wallets_path(&self) -> PathBuf {
        self.root.path(&Slot::Doc(Doc::DeviceWallets))
    }

    fn device_vault_path(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::DeviceVault(id.to_string()))
    }

    fn device_stage_dir(&self, id: &str) -> PathBuf {
        self.root.path(&Slot::Stage(StageKind::Device(id.to_string())))
    }

    fn device_records(&self) -> Result<BTreeMap<String, DeviceWallet>> {
        self.read_json(&self.device_wallets_path())
    }

    /// The device wallets whose database key is on disk, by vault id.
    pub fn device_wallets(&self) -> Result<Vec<(String, DeviceWallet)>> {
        let live = self.scan()?.devices;
        Ok(self.device_records()?.into_iter().filter(|(id, _)| live.contains(id)).collect())
    }

    /// A device wallet's database key. The first open makes it, under `password` and with the
    /// birthday the person gave; every later one needs that password and keeps the first birthday.
    pub fn device_database_key(
        &self,
        signer: &str,
        account: &str,
        password: &str,
        birthday: Option<&str>,
    ) -> Result<DeviceKey> {
        check_device_name(signer, "signer")?;
        check_device_name(account, "account")?;
        if password.is_empty() {
            return Err(KeystoreError::InvalidParams("a device wallet's database key needs a password".into()));
        }
        let live = self.scan()?.devices;
        let found = self.device_records()?.into_iter().find(|(_, w)| w.signer == signer && w.account == account);
        if let Some((id, w)) = found.as_ref().filter(|(id, _)| live.contains(id)) {
            let database_key = self.open_device_vault(id, password)?;
            return Ok(DeviceKey { database_key, birthday: w.birthday.clone(), created: false });
        }
        if let Some(day) = birthday {
            check_birthday(day)?;
        }
        // A record whose vault never landed is an interrupted first open: start it over.
        if let Some((stale, _)) = found {
            self.forget_device_id(&stale)?;
        }
        let id = new_device_id();
        let record =
            DeviceWallet { signer: signer.into(), account: account.into(), created_ms: now_ms(), birthday: birthday.map(str::to_string) };
        self.update(&self.device_wallets_path(), |ws: &mut BTreeMap<String, DeviceWallet>| ws.insert(id.clone(), record.clone()))?;
        let mut raw = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), raw.as_mut());
        let database_key = Zeroizing::new(hex::encode(&raw[..]));
        self.write_device_vault(&id, &database_key, password).inspect_err(|_| {
            let _ = self.forget_device_id(&id);
        })?;
        Ok(DeviceKey { database_key, birthday: record.birthday, created: true })
    }

    /// Staged and renamed like a group key, so a kill leaves something the scan can name.
    fn write_device_vault(&self, id: &str, database_key: &str, password: &str) -> Result<()> {
        let doc = DeviceVaultDoc { v: 1, database_key: database_key.to_string() };
        let text = Zeroizing::new(serde_json::to_string(&doc).map_err(|e| KeystoreError::Vault(e.to_string()))?);
        drop(doc);
        self.ensure_group_dir()?;
        let kind = StageKind::Device(id.to_string());
        let stage = atomic::Stage::create(self.device_stage_dir(id)).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let name = Slot::staged_name(&kind);
        eth_keystore::encrypt_key(&stage.path(), &mut rand::thread_rng(), text.as_bytes(), password, Some(&name))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        stage
            .promote(&name, &self.device_vault_path(id))
            .map_err(|e| KeystoreError::Vault(e.to_string()))
    }

    fn open_device_vault(&self, id: &str, password: &str) -> Result<Zeroizing<String>> {
        let path = self.device_vault_path(id);
        let raw = std::fs::read_to_string(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        check_kdf_params(&raw)?;
        // One message for every way the vault fails to open: no oracle.
        let bad = || KeystoreError::Vault("the password for this wallet's database key is not correct".into());
        let bytes = Zeroizing::new(eth_keystore::decrypt_key(&path, password).map_err(|_| bad())?);
        let doc: DeviceVaultDoc = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        if doc.v != 1 || doc.database_key.len() != 64 {
            return Err(bad());
        }
        Ok(Zeroizing::new(doc.database_key.clone()))
    }

    /// Forget a device wallet's database key at either path, and its record. No password, as
    /// `forget_phrase`: what it opened can no longer be read, and a wallet core starts over.
    pub fn forget_device_wallet(&self, signer: &str, account: &str) -> Result<bool> {
        let ids: Vec<String> = self
            .device_records()?
            .into_iter()
            .filter(|(_, w)| w.signer == signer && w.account == account)
            .map(|(id, _)| id)
            .collect();
        let mut forgotten = false;
        for id in ids {
            forgotten |= self.forget_device_id(&id)?;
        }
        Ok(forgotten)
    }

    fn forget_device_id(&self, id: &str) -> Result<bool> {
        if !layout::is_device_id(id) {
            return Err(KeystoreError::InvalidParams(format!("invalid device wallet id {id:?}")));
        }
        let removed = remove_path(&self.device_vault_path(id))?;
        let staged = remove_path(&self.device_stage_dir(id))?;
        let recorded =
            self.update(&self.device_wallets_path(), |ws: &mut BTreeMap<String, DeviceWallet>| ws.remove(id).is_some())?;
        Ok(removed || staged || recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::eips::eip2718::Decodable2718;
    use alloy::primitives::address;

    thread_local! {
        /// Fails this thread's next vault write, for the tests of what an import undoes.
        pub(super) static FAIL_VAULT_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// An account's vault file, by the account the index names it for.
    fn vault_file(ks: &Keystore, addr: &Address) -> std::path::PathBuf {
        ks.held_vault(addr).unwrap()
    }

    /// What a crash or a hand-edit can leave in the plain index.
    fn corrupt_index(dir: &std::path::Path, body: &str) {
        std::fs::write(dir.join("index.pending.json"), body).unwrap();
    }

    /// Lose every wallet record, as an older build's deleted `groups.json` did.
    fn lose_records(ks: &Keystore) {
        ks.update_groups(|g| g.clear()).unwrap();
    }

    /// Every bookkeeping file, as one text: what anyone who can read the directory reads.
    fn plain_docs(dir: &std::path::Path) -> String {
        ["seeds.json", "index.pending.json", "index.sealed.json"]
            .iter()
            .map(|n| std::fs::read_to_string(dir.join(n)).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // Foundry's canonical test mnemonic → account 0.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ACCT0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const ACCT0_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn recovery_preview_matches_standard_vectors_and_writes_no_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let rows = ks.preview_mnemonic(TEST_MNEMONIC, "", "evm", "main", 0, 0, 5).unwrap();
        assert_eq!(rows[0]["address"], ACCT0.to_string());
        assert_eq!(rows[1]["address"], ACCT1.to_string());
        assert_eq!(rows[4]["path"], "m/44'/60'/0'/0/4");
        let next = ks.preview_mnemonic(TEST_MNEMONIC, "", "evm", "main", 0, 5, 5).unwrap();
        assert_eq!(next[0]["path"], "m/44'/60'/0'/0/5");
        let bip39 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let btc = ks.preview_mnemonic(bip39, "", "bitcoin", "main", 0, 0, 2).unwrap();
        assert_eq!(btc[0]["address"], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(btc[1]["path"], "m/84'/0'/1'");
        let tap = ks.preview_mnemonic(bip39, "", "bitcoin_taproot", "main", 0, 0, 1).unwrap();
        assert_eq!(tap[0]["address"], "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        assert!(ks.get_groups().unwrap().is_empty());
        assert!(ks.list_accounts().unwrap().is_empty());
        assert!(ks.kept_phrases().unwrap().is_empty());
        assert!(ks.preview_mnemonic(TEST_MNEMONIC, "", "evm", "main", 0, HARDENED_INDEX - 2, 5).is_err());
        assert!(ks.preview_mnemonic(TEST_MNEMONIC, "", "evm", "main", 0, 0, MAX_PREVIEW + 1).is_err());
    }

    #[test]
    fn recovery_preview_marks_saved_accounts_and_passphrase_changes_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let imported = ks.import_mnemonic_ex(&req(Storage::Plain, 0)).unwrap();
        let before = ks.export_keystore_json(&imported.address.to_string(), "pw").unwrap();
        let rows = ks.preview_mnemonic(TEST_MNEMONIC, "", "evm", "main", 0, 0, 2).unwrap();
        assert_eq!(rows[0]["present"], true);
        assert_eq!(rows[1]["present"], false);
        let other = ks.preview_mnemonic(TEST_MNEMONIC, "different", "evm", "main", 0, 0, 1).unwrap();
        assert_ne!(other[0]["address"], rows[0]["address"]);
        assert_eq!(before, ks.export_keystore_json(&imported.address.to_string(), "pw").unwrap());
        let file: serde_json::Value = serde_json::from_str(&before).unwrap();
        assert_eq!(file["version"], 3);
        assert!(ks.list_derivation_keys().unwrap().is_empty());
    }

    // ---- hardening regressions -------------------------------------------
    // One test per defect fixed in this pass. Each asserts the DANGEROUS
    // behaviour is gone, not merely that the happy path still works.

    /// The acknowledgement, spelled out at every call site: a random key is unreachable
    /// without one, so a test that wants one has to say so too.
    fn acked() -> Unrecoverable {
        Unrecoverable::acknowledged(true).unwrap()
    }

    /// Build a signed tx for `tx_json`. There is no unlock step: the key is
    /// derived from the vault password for this one signature.
    fn sign_with(dir: &std::path::Path, tx_json: &str) -> Result<String> {
        let ks = Keystore::new(dir);
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.sign_transaction(&addr.to_string(), "pw", tx_json, 1)
    }

    #[test]
    fn there_is_no_unlocked_state_to_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let a = ks.import_private_key(ACCT0_PK, "pw").unwrap().to_string();

        // A correct-password signature must not leave anything behind that a
        // later wrong-password call could spend. Under the old cache, the
        // second call here succeeded.
        assert!(ks.sign_message(&a, "pw", "first").is_ok());
        assert!(ks.sign_message(&a, "wrong", "second").is_err());
        assert!(ks.sign_message(&a, "pw", "third").is_ok());
    }

    #[test]
    fn nonce_that_overflows_u64_is_rejected_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let tx = |nonce: &str| {
            format!(
                r#"{{"to":"0x{:x}","value":"0x0","nonce":"{nonce}","gas_limit":"0x5208",
                    "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}"#,
                ACCT0
            )
        };
        // 0x10000000000000005 truncates to 0x5 in a wrapping cast: the two used
        // to produce byte-identical signed transactions.
        let big = sign_with(dir.path(), &tx("0x10000000000000005"));
        assert!(big.is_err(), "an out-of-range nonce must not sign");
        let small = sign_with(dir.path(), &tx("0x5")).unwrap();
        assert!(!small.is_empty());
    }

    #[test]
    fn unknown_tx_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let tx = format!(
            r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1",
                "chainId":"0x1"}}"#,
            ACCT0
        );
        // A camelCase or typo'd key silently defaulted to 0 before.
        assert!(sign_with(dir.path(), &tx).is_err());
    }

    #[test]
    fn absent_to_is_refused_rather_than_deploying_a_contract() {
        let dir = tempfile::tempdir().unwrap();
        let no_to = r#"{"value":"0x0","nonce":"0x1","gas_limit":"0x5208","fee_mode":"eip1559",
                        "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        let blank_to = r#"{"to":"","value":"0x0","nonce":"0x1","gas_limit":"0x5208","fee_mode":"eip1559",
                           "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        for tx in [no_to, blank_to] {
            let e = sign_with(dir.path(), tx).unwrap_err();
            assert!(format!("{e}").contains("`to` is required"), "got {e}");
        }
        // Deployment is still possible, but only when asked for explicitly.
        let create = r#"{"create":true,"value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                         "data":"0x60006000","fee_mode":"eip1559",
                         "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        assert!(sign_with(dir.path(), create).is_ok());
    }

    #[test]
    fn fee_mode_is_a_closed_set_and_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let tx = |mode: &str| {
            format!(
                r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                    "fee_mode":"{mode}","gas_price":"0x7",
                    "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}"#,
                ACCT0
            )
        };
        // " legacy" used to fall through to EIP-1559 and silently drop gas_price.
        assert!(sign_with(dir.path(), &tx(" legacy")).is_ok());
        // A typo used to be indistinguishable from the default.
        let e = sign_with(dir.path(), &tx("eip1599")).unwrap_err();
        assert!(format!("{e}").contains("fee_mode"), "got {e}");
    }

    #[test]
    fn an_access_list_is_refused_rather_than_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let tx = format!(
            r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1",
                "access_list":[{{"address":"0x{:x}","storageKeys":[]}}]}}"#,
            ACCT0, ACCT0
        );
        let e = sign_with(dir.path(), &tx).unwrap_err();
        assert!(format!("{e}").contains("access list"), "got {e}");
    }

    #[test]
    fn sign_message_refuses_text_that_renders_differently_than_it_signs() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let a = addr.to_string();

        for bad in ["send 1 ETH\u{202E}drow", "zero\u{200B}width", "nul\u{0}byte"] {
            assert!(ks.sign_message(&a, "pw", bad).is_err(), "must refuse {bad:?}");
        }
        // Ordinary text, including newlines, still signs.
        assert!(ks.sign_message(&a, "pw", "hello\nworld").is_ok());
        // And an oversize message is refused rather than signed unseen.
        let huge = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(ks.sign_message(&a, "pw", &huge).is_err());
    }

    #[test]
    fn hostile_kdf_params_are_rejected_before_any_derivation() {
        // n = u32::MAX asked scrypt for a ~4 TiB allocation, aborting the
        // process from a single caller-supplied file.
        let hostile = r#"{"version":3,"crypto":{"kdf":"scrypt","ciphertext":"00","cipher":"aes-128-ctr",
            "cipherparams":{"iv":"00"},"mac":"00",
            "kdfparams":{"n":4294967295,"r":8,"p":1,"dklen":32,"salt":"00"}}}"#;
        // u32::MAX is not a power of two, so it is caught by that rule first.
        let e = check_kdf_params(hostile).unwrap_err();
        assert!(format!("{e}").contains("power of two"), "got {e}");

        // A power of two that is merely far too large hits the size rule, which
        // is the one that stops the enormous allocation.
        let huge = hostile.replace("4294967295", "1073741824"); // 2^30
        let e = check_kdf_params(&huge).unwrap_err();
        assert!(format!("{e}").contains("exceeds") || format!("{e}").contains("bytes"), "got {e}");

        // Oversized r is refused too.
        let big_r = hostile.replace("4294967295", "262144").replace("\"r\":8", "\"r\":64");
        assert!(check_kdf_params(&big_r).is_err());

        // A standard vault passes.
        let ok = hostile.replace("4294967295", "262144");
        assert!(check_kdf_params(&ok).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_directory_and_files_are_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("vaults");
        let ks = Keystore::new(&sub);
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();

        let dmode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "vault dir was {dmode:o}");
        let vault = vault_file(&ks, &addr);
        let fmode = std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600, "vault file was {fmode:o}");
    }

    /// A vault whose scrypt work is at this module's ceiling — legal to `check_kdf_params`
    /// and slow enough that a kill can land inside the derivation.
    fn slow_vault(json: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["crypto"]["kdfparams"]["n"] = serde_json::json!(262_144);
        v.to_string()
    }

    fn import_stages_under(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(".stage-import-"))
            .collect()
    }

    #[test]
    fn a_process_killed_mid_import_leaves_its_scratch_inside_the_keystore() {
        // F1, at the only fidelity that counts. The old test called `import_keystore_json`
        // and asserted on the SUCCESS path, where the RAII guard has already run — it could
        // never observe the case RAII does not cover. This one really kills a real process
        // in the middle of a real import, with SIGKILL, and then looks at what is left.
        //
        // Child half: re-exec of this binary, gated on the env var below.
        if let (Ok(dir), Ok(json)) = (std::env::var("KS_KILL_DIR"), std::env::var("KS_KILL_JSON")) {
            let _ = Keystore::new(&dir).import_keystore_json(&json, "pw", "pw2");
            return;
        }

        let src = tempfile::tempdir().unwrap();
        let ks_src = Keystore::new(src.path());
        let addr = ks_src.import_private_key(ACCT0_PK, "pw").unwrap();
        let json = slow_vault(&ks_src.export_keystore_json(&addr.to_string(), "pw").unwrap());

        let victim = tempfile::tempdir().unwrap();
        let ks = victim.path().join("keystore");
        // The child gets a temp directory of its own, so "shared temp gains nothing" is
        // asserted over EVERY name rather than over a prefix — the prefix filter is exactly
        // what let F1's leftover pass its own test.
        let child_tmp = victim.path().join("tmp");
        std::fs::create_dir_all(&child_tmp).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "keystore::tests::a_process_killed_mid_import_leaves_its_scratch_inside_the_keystore",
                "--exact",
                "--nocapture",
            ])
            .env("KS_KILL_DIR", &ks)
            .env("KS_KILL_JSON", &json)
            .env("TMPDIR", &child_tmp)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();

        // Poll for the scratch rather than sleeping: the kill has to land while scrypt is
        // still grinding, and the file appearing is the signal that it has started.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let stage = loop {
            match import_stages_under(&ks).into_iter().next() {
                Some(p) if p.join("import.json").exists() => break p,
                _ => assert!(
                    std::time::Instant::now() < deadline && child.try_wait().unwrap().is_none(),
                    "the child finished or stalled without staging an import"
                ),
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        child.kill().unwrap(); // SIGKILL: no unwind, no Drop, no cleanup of any kind
        child.wait().unwrap();

        // What a kill leaves is INSIDE the keystore, at this module's own modes — not a
        // 0600 file in a shared directory that no restart ever sweeps.
        let scratch = stage.join("import.json");
        assert!(scratch.exists(), "the scratch copy vanished, so this proved nothing");
        assert_eq!(std::fs::read_dir(&child_tmp).unwrap().count(), 0, "a copy was left in shared temp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&stage), 0o700);
            assert_eq!(mode(&scratch), 0o600);
        }

        // Nameable, and swept by the module's own repair — the property $TMPDIR could not give.
        let ks = Keystore::new(&ks);
        let nonce = stage.file_name().unwrap().to_string_lossy().replace(".stage-import-", "");
        assert_eq!(ks.scan().unwrap().import_stages, vec![nonce], "the leftover was not named");
        ks.settle().unwrap();
        assert!(!stage.exists(), "a full restart did not sweep the leftover");
        assert!(ks.scan().unwrap().import_stages.is_empty());
    }

    #[test]
    fn an_import_takes_its_scratch_from_root_and_leaves_none_of_it_behind() {
        let src = tempfile::tempdir().unwrap();
        let ks_src = Keystore::new(src.path());
        let addr = ks_src.import_private_key(ACCT0_PK, "pw").unwrap();
        let json = ks_src.export_keystore_json(&addr.to_string(), "pw").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dst.path());
        ks.import_keystore_json(&json, "pw", "pw2").unwrap();
        assert!(import_stages_under(dst.path()).is_empty(), "the scratch outlived the import");
        assert!(ks.scan().unwrap().unexplained.is_empty());

        // A failure leaves nothing either — the guard covers the early return, and the
        // scratch never existed anywhere but under `<ks>/`.
        assert!(ks.import_keystore_json(&json, "WRONG", "pw2").is_err());
        assert!(import_stages_under(dst.path()).is_empty(), "a failed import left its scratch");
    }

    #[test]
    fn the_only_source_of_a_path_in_this_crate_is_root() {
        // HOLE 1 at the mechanism: "a writer that invents a path must add a variant" never
        // bound a writer that NEVER ASKED FOR A PATH. There is now nowhere else to get one —
        // `atomic` stages inside `<ks>/`, and every other module goes through `Root`.
        for (file, src) in [
            ("keystore.rs", include_str!("keystore.rs")),
            ("layout.rs", include_str!("layout.rs")),
            ("atomic.rs", include_str!("atomic.rs")),
            ("glue.rs", include_str!("glue.rs")),
            ("hd.rs", include_str!("hd.rs")),
            ("approval.rs", include_str!("approval.rs")),
            ("gate.rs", include_str!("gate.rs")),
            ("lib.rs", include_str!("lib.rs")),
        ] {
            let production = src.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
            assert!(!production.contains("temp_dir()"), "{file} takes a path from shared temp");
            // `atomic` is the one place a staging path is minted, and it mints it inside the
            // directory its caller hands it.
            if file != "atomic.rs" {
                assert!(!production.contains("tempfile::"), "{file} mints a path outside Root");
            }
        }
    }

    #[test]
    fn hd_derivation_matches_known_vector() {
        // The published vectors live in `hd.rs`; this pins the public API to them.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        assert_eq!(ks.import_mnemonic(TEST_MNEMONIC, "", 0, "pw").unwrap(), ACCT0);
        assert_eq!(
            ks.import_mnemonic(TEST_MNEMONIC, "", 1, "pw").unwrap(),
            address!("70997970C51812dc3A010C7d01b50e0d17dc79C8")
        );
    }

    #[test]
    fn private_key_import_matches_address() {
        let signer = signer_from_hex(ACCT0_PK).unwrap();
        assert_eq!(signer.address(), ACCT0);
    }

    #[test]
    fn create_mnemonic_lengths() {
        assert_eq!(Keystore::create_mnemonic(12).unwrap().split_whitespace().count(), 12);
        assert_eq!(Keystore::create_mnemonic(24).unwrap().split_whitespace().count(), 24);
        assert!(Keystore::create_mnemonic(13).is_err());
    }

    #[test]
    fn vault_roundtrip_and_listing() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert_eq!(addr, ACCT0);
        assert!(ks.has_address(&addr.to_string()));
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0]);

        // The vault password is the gate on every signature — there is no
        // unlocked state to be in.
        assert!(ks.signer_for(&addr.to_string(), "wrong").is_err());
        assert_eq!(ks.signer_for(&addr.to_string(), "pw").unwrap().address(), ACCT0);
    }

    #[test]
    fn sign_message_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let sig_hex = ks.sign_message(&addr.to_string(), "pw", "hello logos").unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse::<alloy::primitives::Signature>().unwrap();
        let recovered = sig.recover_address_from_msg("hello logos").unwrap();
        assert_eq!(recovered, ACCT0);
    }

    #[test]
    fn a_wrong_password_cannot_sign() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert!(ks.sign_message(&addr.to_string(), "wrong", "x").is_err());
    }

    #[test]
    fn sign_digest_recovers_signer_from_prehash() {
        use alloy::primitives::b256;
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        // A raw 32-byte digest (e.g. an ERC-4337 UserOperation hash) — signed with
        // no prefix, so it recovers via the prehash (not the EIP-191 msg) path.
        let digest = b256!("00000000000000000000000000000000000000000000000000000000deadbeef");
        let sig_hex = ks.sign_digest(&addr.to_string(), "pw", &digest.to_string()).unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse().unwrap();
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), ACCT0);
        // Bare (no 0x) hex also accepted; wrong length rejected.
        assert!(ks.sign_digest(&addr.to_string(), "pw", &hex::encode(digest)).is_ok());
        assert!(ks.sign_digest(&addr.to_string(), "pw", "0x1234").is_err());
    }

    #[test]
    fn sign_digest_requires_the_vault_password() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let digest = "0x00000000000000000000000000000000000000000000000000000000deadbeef";
        assert!(ks.sign_digest(&addr.to_string(), "wrong", digest).is_err());
    }

    #[test]
    fn sign_eip1559_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0xde0b6b3a7640000",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "max_fee_per_gas": "0x77359400",
            "max_priority_fee_per_gas": "0x3b9aca00",
            "fee_mode": "eip1559"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), "pw", &unsigned, 1).unwrap();
        assert!(raw.starts_with("0x02")); // typed EIP-1559 envelope
        // decode + recover
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }

    #[test]
    fn sign_legacy_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0x1",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "gas_price": "0x3b9aca00",
            "fee_mode": "legacy"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), "pw", &unsigned, 1).unwrap();
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }

    #[test]
    fn change_password_re_encrypts_and_the_old_password_stops_working() {
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().to_path_buf());
        let addr = ks.import_private_key(ACCT0_PK, "old-pw").unwrap();

        ks.change_password(&addr.to_string(), "old-pw", "new-pw").unwrap();

        assert!(ks.signer_for(&addr.to_string(), "new-pw").is_ok(), "the new password must work");
        assert!(
            ks.signer_for(&addr.to_string(), "old-pw").is_err(),
            "the OLD password must stop working — otherwise nothing was re-encrypted"
        );
        // Same account, not a second one.
        assert_eq!(ks.list_accounts().unwrap(), vec![addr]);
    }

    #[test]
    fn a_wrong_old_password_changes_nothing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().to_path_buf());
        let addr = ks.import_private_key(ACCT0_PK, "old-pw").unwrap();

        assert!(ks.change_password(&addr.to_string(), "WRONG", "new-pw").is_err());
        // The vault must survive a refused attempt intact — this is the failure that would
        // destroy the only copy of a key.
        assert!(ks.signer_for(&addr.to_string(), "old-pw").is_ok());
        assert!(ks.signer_for(&addr.to_string(), "new-pw").is_err());
        assert_eq!(ks.list_accounts().unwrap().len(), 1);
    }

    #[test]
    fn labels_round_trip_and_do_not_become_accounts() {
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().to_path_buf());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();

        assert!(ks.get_labels().unwrap().is_empty());
        ks.set_label(&addr.to_string(), "  Savings  ", "pw").unwrap();
        assert_eq!(ks.get_labels().unwrap().values().next().map(String::as_str), Some("Savings"));

        // labels.json sits beside the vaults; it must never be read back as an account.
        assert_eq!(ks.list_accounts().unwrap(), vec![addr], "labels.json must not appear as an account");

        ks.set_label(&addr.to_string(), "   ", "").unwrap();
        assert!(ks.get_labels().unwrap().is_empty(), "an empty label clears the entry");
    }

    #[test]
    fn a_label_for_an_account_we_do_not_hold_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().to_path_buf());
        assert!(ks.set_label("0x0000000000000000000000000000000000000001", "ghost", "pw").is_err());
        assert!(ks.get_labels().unwrap().is_empty());
    }

    #[test]
    fn naming_an_account_needs_its_password_and_clearing_the_name_does_not() {
        // A label is what a wallet shows in PLACE of an address, so writing one is a claim
        // of custody. Clearing can only move the display back toward the address itself.
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().to_path_buf());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let a = addr.to_string();

        for wrong in ["", "PW", "pw ", "not-the-password"] {
            let e = ks.set_label(&a, "Treasury", wrong).unwrap_err();
            assert!(format!("{e}").contains("password for this account is not correct"), "{wrong:?}: {e}");
        }
        assert!(ks.get_labels().unwrap().is_empty(), "a refused rename must write nothing");

        ks.set_label(&a, "Treasury", "pw").unwrap();
        assert_eq!(ks.get_labels().unwrap()[&addr_key(&addr)], "Treasury");

        // The escape hatch: a stale name comes off a vault whose password is lost.
        ks.set_label(&a, "", "nonsense").unwrap();
        assert!(ks.get_labels().unwrap().is_empty());
    }


    // ── HD derivation groups ──────────────────────────────────────────────
    // Addresses below are the published Foundry/Anvil accounts, pinned against the BIP-32
    // and BIP-39 documents in `hd.rs`. Here they are the fixed point that says the storage
    // layer derived the same thing the standard does.

    const ACCT1: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
    const ACCT2: Address = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
    const ACCT3: Address = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");

    fn req<'a>(storage: Storage, index: u32) -> ImportRequest<'a> {
        ImportRequest {
            phrase: TEST_MNEMONIC,
            bip39_passphrase: "",
            index,
            password: "pw",
            storage,
            bip44_account: 0,
            change: 0,
            group_password: "gp",
            group_label: "Main",
            wallet_name: "",
            keep: KeepPhrase::No,
        }
    }

    /// A rename offering no account credential — every call shape that predates the password.
    fn rename<'a>(group: &'a str, label: &'a str) -> GroupLabelRequest<'a> {
        GroupLabelRequest { group, label, address: "", password: "" }
    }

    /// A rename proving custody of one of the wallet's accounts.
    fn rename_as<'a>(group: &'a str, label: &'a str, address: &'a str, password: &'a str) -> GroupLabelRequest<'a> {
        GroupLabelRequest { group, label, address, password }
    }

    /// A rename proving custody of the wallet's DERIVATION KEY: no address, because with no
    /// accounts there is none to hold — only the key that would mint them.
    fn rename_with_key<'a>(group: &'a str, label: &'a str, password: &'a str) -> GroupLabelRequest<'a> {
        GroupLabelRequest { group, label, address: "", password }
    }

    /// A keystore with one EXTKEY group holding account 0, and the group's id.
    fn with_group(dir: &std::path::Path) -> (Keystore, String) {
        let ks = Keystore::new(dir);
        let d = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        assert_eq!(d.address, ACCT0);
        (ks, d.group)
    }

    /// A wallet with nothing left under it — a record and a name, no key, no accounts — and
    /// reached the only way there is: stop keeping the key, then delete what it derived.
    fn emptied(dir: &std::path::Path) -> (Keystore, String) {
        let (ks, group) = with_group(dir);
        ks.forget_derivation(&group).unwrap();
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());
        (ks, group)
    }

    fn bitcoin_import(ks: &Keystore, family: Family) -> BitcoinGroup {
        ks.import_bitcoin(&BitcoinImport {
            phrase: TEST_MNEMONIC,
            bip39_passphrase: "",
            family,
            chain: Chain::Test,
            account: 0,
            password: "pw",
            label: "Savings",
            wallet_name: "",
            keep: crate::keystore::KeepPhrase::No,
            start: crate::keystore::WalletStart::Restored(None),
        })
        .unwrap()
    }

    #[test]
    fn bitcoin_address_previews_use_only_public_records_and_match_published_vectors() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for (family, expected) in [
            (Family::Segwit, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            (Family::Taproot, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
        ] {
            for chain in [Chain::Main, Chain::Test] {
                let dir = tempfile::tempdir().unwrap();
                let ks = Keystore::new(dir.path());
                let group = ks.import_bitcoin(&BitcoinImport {
                    phrase, bip39_passphrase: "", family, chain, account: 0,
                    password: "pw", label: "Savings", wallet_name: "", keep: KeepPhrase::No,
                    start: WalletStart::Restored(None),
                }).unwrap();
                // A public-only copy has neither encrypted keys nor a recovery phrase.
                let public_dir = tempfile::tempdir().unwrap();
                for doc in ["seeds.json", "index.pending.json"] {
                    std::fs::copy(dir.path().join(doc), public_dir.path().join(doc)).unwrap();
                }
                let public = Keystore::new(public_dir.path());
                let (address, path) = public.bitcoin_address_preview(&group.id).unwrap();
                assert_eq!(path, format!("m/{}'/{}'/0'/0/0", family.purpose(), chain.coin_type()));
                if chain == Chain::Main { assert_eq!(address, expected); }
                else { assert!(address.starts_with("tb1")); }
                assert!(public.bitcoin_address_preview("missing").is_err());
            }
        }
    }

    #[test]
    fn a_bitcoin_wallet_keeps_its_key_in_its_vault_and_its_public_half_in_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let g = bitcoin_import(&ks, Family::Segwit);
        assert!(ks.list_derivation_keys().unwrap().contains(&g.id));
        let (acct, name) = ks.bitcoin_account(&g.id).unwrap();
        assert_eq!(acct, g.account);
        assert_eq!(name, "\"Savings\"");
        let (external, internal) = ks.account_descriptors(&g.id).unwrap();
        assert!(external.starts_with(&format!("wpkh([{}/84'/1'/0']tpub", acct.fingerprint)), "{external}");
        assert!(internal.contains("/1/*)#"), "{internal}");
        // The vault opens with its password only, and holds the key the record describes.
        assert!(ks.open_bitcoin_key(&g.id, "wrong", &acct).is_err());
        let secret = ks.open_bitcoin_key(&g.id, "pw", &acct).unwrap();
        assert_eq!(secret.xpub(&bitcoin::secp256k1::Secp256k1::new()), acct.xpub);
        // The account key is in the vault and nowhere in the record.
        let record = plain_docs(dir.path());
        assert!(!record.contains("tprv") && !record.contains("databaseKey"), "{record}");
        assert!(record.contains("\"family\": \"bitcoin\""), "{record}");
    }

    fn bitcoin_import_starting(ks: &Keystore, start: WalletStart, keep: KeepPhrase) -> Result<BitcoinGroup> {
        ks.import_bitcoin(&BitcoinImport {
            phrase: TEST_MNEMONIC,
            bip39_passphrase: "",
            family: Family::Taproot,
            chain: Chain::Test,
            account: 0,
            password: "pw",
            label: "",
            wallet_name: "",
            keep,
            start,
        })
    }

    #[test]
    fn a_bitcoin_wallet_records_where_its_history_can_start() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        // A wallet whose phrase was made for it starts the day it is made, by the keystore's clock.
        let made = bitcoin_import_starting(&ks, WalletStart::Created, KeepPhrase::No).unwrap();
        let record = ks.get_groups().unwrap()[&made.id].clone();
        assert_eq!(record.birthday, Some(utc_day(record.created_ms)));
        assert_eq!(ks.bitcoin_start(&made.id).unwrap(), ("created".to_string(), record.birthday));

        let dated = bitcoin_import_starting(&ks, WalletStart::Restored(Some("2021-11-14")), KeepPhrase::No).unwrap();
        assert_eq!(ks.bitcoin_start(&dated.id).unwrap(), ("restored".to_string(), Some("2021-11-14".to_string())));
        let undated = bitcoin_import_starting(&ks, WalletStart::Restored(None), KeepPhrase::New("pp")).unwrap();
        assert_eq!(ks.bitcoin_start(&undated.id).unwrap(), ("restored".to_string(), None));

        // A kept phrase is older than any wallet made from it later.
        let kept = ks.get_groups().unwrap()[&undated.id].phrase.clone().unwrap();
        let from_kept = bitcoin_import_starting(&ks, WalletStart::Created, KeepPhrase::Kept(&kept));
        assert!(matches!(from_kept, Err(KeystoreError::InvalidParams(_))), "{from_kept:?}");

        // Only a real day from the first block on, and not after tomorrow.
        let before = ks.get_groups().unwrap().len();
        for day in ["2023-02-30", "2008-12-31", "2009-1-03", "2009/01/03", "2021-13-01", "2021-01-00", "+021-01-01", "", "2999-01-01"] {
            let r = bitcoin_import_starting(&ks, WalletStart::Restored(Some(day)), KeepPhrase::No);
            assert!(matches!(r, Err(KeystoreError::InvalidParams(_))), "{day:?}: {r:?}");
        }
        assert_eq!(ks.get_groups().unwrap().len(), before, "a refused birthday records nothing");
        assert!(bitcoin_import_starting(&ks, WalletStart::Restored(Some("2009-01-03")), KeepPhrase::No).is_ok());

        // A record from before birthdays were kept scans the most.
        ks.update_groups(|gs| {
            let g = gs.get_mut(&dated.id).unwrap();
            (g.origin, g.birthday) = (None, None);
        })
        .unwrap();
        assert_eq!(ks.bitcoin_start(&dated.id).unwrap(), ("restored".to_string(), None));
        assert!(ks.bitcoin_start("g_00000000000000000000000000000000").is_err());
    }

    #[test]
    fn a_device_wallets_database_key_is_made_at_its_first_open_and_needs_its_password_after() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let (shell, acct) = ("keycard_shell_module", "shell-73c5da0a-84-1-0");
        assert!(ks.device_wallets().unwrap().is_empty());

        let first = ks.device_database_key(shell, acct, "data-pw", Some("2021-11-14")).unwrap();
        assert!(first.created);
        assert_eq!(first.database_key.len(), 64);
        assert_eq!(first.birthday.as_deref(), Some("2021-11-14"));

        // Later opens need the password it was made with, and keep the first birthday.
        let again = ks.device_database_key(shell, acct, "data-pw", Some("2009-01-03")).unwrap();
        assert!(!again.created);
        assert_eq!(*again.database_key, *first.database_key);
        assert_eq!(again.birthday.as_deref(), Some("2021-11-14"));
        assert!(matches!(ks.device_database_key(shell, acct, "nope", None), Err(KeystoreError::Vault(_))));

        // The same id from another module is another wallet.
        let other = ks.device_database_key("keycard_module", acct, "x", None).unwrap();
        assert!(other.created && *other.database_key != *first.database_key);
        assert_eq!(ks.device_wallets().unwrap().len(), 2);

        // The key is in the vault and nowhere in the record, and the scan explains both.
        let record = std::fs::read_to_string(dir.path().join("device-wallets.json")).unwrap();
        assert!(record.contains(acct) && !record.contains(first.database_key.as_str()), "{record}");
        let scan = ks.scan().unwrap();
        assert_eq!(scan.devices.len(), 2);
        assert!(scan.stray().is_empty() && scan.possible_key_material().is_empty(), "{scan:?}");

        // Forgetting it needs no password, and the next open makes a new key.
        assert!(ks.forget_device_wallet(shell, acct).unwrap());
        assert!(!ks.forget_device_wallet(shell, acct).unwrap());
        let fresh = ks.device_database_key(shell, acct, "new-pw", None).unwrap();
        assert!(fresh.created && *fresh.database_key != *first.database_key && fresh.birthday.is_none());
    }

    #[test]
    fn a_device_wallet_open_refuses_what_it_could_not_keep() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let long = "a".repeat(129);
        for (signer, account, pw, day) in [
            ("", "acct", "pw", None),
            ("keycard_shell_module", "", "pw", None),
            ("keycard_shell_module", "acct", "", None),
            ("keycard_shell_module", "acct", "pw", Some("2008-12-31")),
            ("keycard_shell_module", long.as_str(), "pw", None),
            ("keycard_shell_module", "acct\u{202e}", "pw", None),
        ] {
            let r = ks.device_database_key(signer, account, pw, day);
            assert!(matches!(r, Err(KeystoreError::InvalidParams(_))), "{signer:?} {account:?}: {:?}", r.err().map(|e| e.to_string()));
        }
        assert!(ks.device_wallets().unwrap().is_empty() && !dir.path().join("device-wallets.json").exists());
    }

    #[test]
    fn an_interrupted_first_open_starts_over() {
        // A record whose vault never landed is no wallet: the next open makes its key afresh.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let made = ks.device_database_key("keycard_module", "acct", "pw", None).unwrap();
        let (id, _) = ks.device_wallets().unwrap().remove(0);
        std::fs::remove_file(ks.device_vault_path(&id)).unwrap();
        assert!(ks.device_wallets().unwrap().is_empty());
        let again = ks.device_database_key("keycard_module", "acct", "other", None).unwrap();
        assert!(again.created && *again.database_key != *made.database_key);
        assert_eq!(ks.device_records().unwrap().len(), 1, "the stale record went with it");
    }

    #[test]
    fn days_and_dates_agree_both_ways() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(1_231_006_505_000), "2009-01-03", "the genesis block's time");
        assert_eq!(utc_day(1_709_164_800_000), "2024-02-29");
        assert_eq!(days_from_civil(2009, 1, 3), 14_247);
        for z in (-1_000_000..1_000_000).step_by(7) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z, "{y}-{m}-{d}");
        }
    }

    fn bitcoin_import_keeping(ks: &Keystore, phrase: &str, passphrase: &str, keep: KeepPhrase) -> Result<BitcoinGroup> {
        ks.import_bitcoin(&BitcoinImport {
            phrase,
            bip39_passphrase: passphrase,
            family: Family::Segwit,
            chain: Chain::Test,
            account: 0,
            password: "pw",
            label: "",
            wallet_name: "",
            keep,
            start: WalletStart::Restored(None),
        })
    }

    #[test]
    fn a_phrase_is_kept_only_when_asked_and_shown_again_only_with_its_own_password() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let plain = bitcoin_import(&ks, Family::Segwit);
        assert!(ks.kept_phrases().unwrap().is_empty(), "off unless asked for");
        assert_eq!(ks.get_groups().unwrap()[&plain.id].phrase, None);

        // Pasted with stray whitespace, kept as the words alone.
        let pasted = format!("  {}\n", TEST_MNEMONIC.replace(' ', "  "));
        let g = bitcoin_import_keeping(&ks, &pasted, "", KeepPhrase::New("phrase-pw")).unwrap();
        let id = ks.get_groups().unwrap()[&g.id].phrase.clone().expect("the wallet records its phrase");
        assert_eq!(ks.kept_phrases().unwrap(), vec![KeptPhrase { id: id.clone(), groups: vec![g.id.clone()], staged: false }]);
        let wrong = ks.show_phrase(&id, "pw").unwrap_err();
        assert!(wrong.to_string().contains("password for this phrase is not correct"), "the wallet's is not the phrase's: {wrong}");
        assert_eq!(ks.show_phrase(&id, "phrase-pw").unwrap().as_str(), TEST_MNEMONIC);
        // Key material wherever the scan looks, and never a stray.
        let scan = ks.scan().unwrap();
        assert!(scan.possible_key_material().iter().any(|m| m.contains(&id)), "{scan:?}");
        assert!(scan.stray().is_empty(), "{scan:?}");
    }

    #[test]
    fn seed_groups_join_chains_without_retaining_the_phrase_and_migrate_legacy_records() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let evm = ks.import_mnemonic_ex(&req(Storage::Plain, 0)).unwrap();
        // Model an older record which predates seed grouping.
        ks.update_groups(|groups| {
            groups.get_mut(&evm.group).unwrap().seed = None;
        })
        .unwrap();
        ks.check_seed_source(TEST_MNEMONIC, "", &evm.group).unwrap();
        assert!(ks
            .check_seed_source(TEST_MNEMONIC, "different", &evm.group)
            .is_err());
        let btc = bitcoin_import(&ks, Family::Segwit);
        let groups = ks.get_groups().unwrap();
        assert_eq!(groups[&evm.group].seed, groups[&btc.id].seed);
        assert!(groups[&evm.group].seed.is_some());
        assert!(ks.kept_phrases().unwrap().is_empty());
        let reopened = Keystore::new(dir.path());
        assert_eq!(
            reopened.get_groups().unwrap()[&btc.id].seed,
            groups[&btc.id].seed
        );
        // The same words with a different BIP39 passphrase are a different seed.
        let other =
            bitcoin_import_keeping(&ks, TEST_MNEMONIC, "different", KeepPhrase::No).unwrap();
        let groups = ks.get_groups().unwrap();
        assert_ne!(groups[&other.id].seed, groups[&btc.id].seed);
        assert!(ks
            .check_seed_source(TEST_MNEMONIC, "different", &btc.id)
            .is_err());
        // Public grouping metadata contains neither recovery words nor BIP39 passphrases.
        let json = plain_docs(dir.path());
        assert!(!json.contains(TEST_MNEMONIC) && !json.contains("different"));
    }

    #[test]
    fn failed_import_rolls_back_legacy_seed_associations() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let first = bitcoin_import(&ks, Family::Segwit);
        ks.update_groups(|groups| {
            groups.get_mut(&first.id).unwrap().seed = None;
        })
        .unwrap();
        FAIL_VAULT_WRITE.with(|f| f.set(true));
        assert!(ks.import_mnemonic_ex(&req(Storage::Plain, 0)).is_err());
        let groups = ks.get_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert!(groups[&first.id].seed.is_none());
    }

    #[test]
    fn a_kept_phrase_makes_more_wallets_and_outlives_them_until_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let first = bitcoin_import_keeping(&ks, TEST_MNEMONIC, "", KeepPhrase::New("phrase-pw")).unwrap();
        let id = ks.get_groups().unwrap()[&first.id].phrase.clone().unwrap();
        let words = ks.show_phrase(&id, "phrase-pw").unwrap();
        let second = ks
            .import_bitcoin(&BitcoinImport {
                phrase: &words,
                bip39_passphrase: "",
                family: Family::Taproot,
                chain: Chain::Test,
                account: 0,
                password: "pw",
                label: "",
                wallet_name: "",
                keep: KeepPhrase::Kept(&id),
                start: WalletStart::Restored(None),
            })
            .unwrap();
        let mut both = vec![first.id.clone(), second.id.clone()];
        both.sort();
        assert_eq!(ks.kept_phrases().unwrap()[0].groups, both, "one vault, both wallets name it");
        assert!(bitcoin_import_keeping(&ks, TEST_MNEMONIC, "", KeepPhrase::Kept("p_00000000000000000000000000000000")).is_err());

        // Forgetting needs no password, removes the vault, and clears every wallet's record.
        assert!(ks.forget_phrase(&id).unwrap());
        assert!(ks.kept_phrases().unwrap().is_empty());
        assert!(ks.get_groups().unwrap().values().all(|g| g.phrase.is_none()));
        assert!(ks.show_phrase(&id, "phrase-pw").is_err());
        assert!(!ks.forget_phrase(&id).unwrap(), "nothing left to forget");
        // The wallets themselves are untouched.
        assert!(ks.bitcoin_account(&first.id).is_ok() && ks.bitcoin_account(&second.id).is_ok());
    }

    #[test]
    fn the_bip39_passphrase_is_never_kept() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let g = bitcoin_import_keeping(&ks, TEST_MNEMONIC, "second secret", KeepPhrase::New("phrase-pw")).unwrap();
        let record = &ks.get_groups().unwrap()[&g.id];
        assert!(record.used_passphrase, "the wallet says a passphrase was used");
        let words = ks.show_phrase(record.phrase.as_deref().unwrap(), "phrase-pw").unwrap();
        assert_eq!(words.as_str(), TEST_MNEMONIC, "the phrase, and nothing of the passphrase");
        let groups = plain_docs(dir.path());
        assert!(!groups.contains("second secret"), "{groups}");
    }

    #[test]
    fn an_evm_wallet_keeps_its_phrase_when_asked_and_shares_one_kept_earlier() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let d = ks.import_mnemonic_ex(&ImportRequest { keep: KeepPhrase::New("phrase-pw"), ..req(Storage::Extkey, 0) }).unwrap();
        assert_eq!(d.address, ACCT0);
        let id = ks.get_groups().unwrap()[&d.group].phrase.clone().expect("the wallet records its phrase");
        assert_eq!(ks.show_phrase(&id, "phrase-pw").unwrap().as_str(), TEST_MNEMONIC);
        // A Bitcoin wallet from the same kept phrase: one vault, both wallets name it.
        let b = bitcoin_import_keeping(&ks, TEST_MNEMONIC, "", KeepPhrase::Kept(&id)).unwrap();
        let mut both = vec![d.group.clone(), b.id.clone()];
        both.sort();
        assert_eq!(ks.kept_phrases().unwrap()[0].groups, both);
        // An import that fails after keeping leaves no new phrase vault behind: the account's
        // vault fails once the phrase is already kept.
        FAIL_VAULT_WRITE.with(|f| f.set(true));
        let failed = ks.import_mnemonic_ex(&ImportRequest { index: 1, keep: KeepPhrase::New("other-pw"), ..req(Storage::Extkey, 0) });
        assert!(failed.is_err());
        assert_eq!(ks.kept_phrases().unwrap().len(), 1, "{:?}", ks.kept_phrases());
        assert!(ks.scan().unwrap().stray().is_empty());
    }

    #[test]
    fn keeping_refuses_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        assert!(bitcoin_import_keeping(&ks, TEST_MNEMONIC, "", KeepPhrase::New("")).is_err(), "a phrase needs its own password");
        assert!(ks.keep_phrase("test test test", "pw").is_err(), "not a phrase");
        assert!(ks.get_groups().unwrap().is_empty() && ks.kept_phrases().unwrap().is_empty());
        assert!(ks.show_phrase("../groups", "pw").is_err() && ks.forget_phrase("g_0123456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn a_phrase_left_at_its_staging_path_is_listed_and_forgettable_but_never_shown() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let id = ks.keep_phrase(TEST_MNEMONIC, "phrase-pw").unwrap();
        // What a kill between the write and the rename leaves.
        let stage = dir.path().join("groups").join(format!(".stage-{id}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::rename(dir.path().join("groups").join(format!("{id}.json")), stage.join(format!("{id}.json"))).unwrap();
        assert_eq!(ks.kept_phrases().unwrap(), vec![KeptPhrase { id: id.clone(), groups: vec![], staged: true }]);
        assert!(ks.show_phrase(&id, "phrase-pw").is_err(), "only the live vault answers");
        assert!(ks.forget_phrase(&id).unwrap());
        assert!(ks.scan().unwrap().possible_key_material().is_empty());
    }

    #[test]
    fn an_evm_group_record_adds_only_its_wallet_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        let record = serde_json::to_string(&ks.get_groups().unwrap()).unwrap();
        for field in ["family", "chain", "xpub"] {
            assert!(!record.contains(field), "{field} in {record}");
        }
        let groups = ks.get_groups().unwrap();
        let fingerprint = groups.values().next().unwrap().fingerprint.as_deref().unwrap();
        assert!(fingerprint.len() == 8 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()), "{fingerprint}");
    }

    #[test]
    fn a_bitcoin_wallet_is_refused_where_only_evm_derivation_belongs() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let g = bitcoin_import(&ks, Family::Taproot);
        let e = ks.derive_next_account(Some(&g.id), "pw", "pw", 0).unwrap_err().to_string();
        assert!(e.contains("Bitcoin wallet"), "{e}");
        assert!(ks.preview_addresses(&g.id, "pw", 0, 0, 1).is_err());
        // With only a Bitcoin wallet here, there is no EVM wallet to pick by default.
        assert!(ks.derive_next_account(None, "pw", "pw", 0).is_err());
        // Its key is its only copy, so forgetting it would delete the wallet.
        let e = ks.forget_derivation(&g.id).unwrap_err().to_string();
        assert!(e.contains("only one"), "{e}");
        assert!(ks.list_derivation_keys().unwrap().contains(&g.id));
        // Naming it proves custody with the Bitcoin vault's password.
        assert!(ks.set_group_label(&rename_with_key(&g.id, "Spending", "wrong")).is_err());
        ks.set_group_label(&rename_with_key(&g.id, "Spending", "pw")).unwrap();
    }

    #[test]
    fn an_extkey_group_derives_the_next_accounts_without_the_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());

        let a1 = ks.derive_next_account(None, "gp", "pw1", 0).unwrap();
        let a2 = ks.derive_next_account(Some(&group), "gp", "pw2", 0).unwrap();
        assert_eq!((a1.address, a1.index), (ACCT1, 1));
        assert_eq!((a2.address, a2.index), (ACCT2, 2));
        assert_eq!(a1.path, "m/44'/60'/0'/0/1");

        // Each account keeps its own vault password — deriving does not couple them.
        assert!(ks.signer_for(&a1.address.to_string(), "pw1").is_ok());
        assert!(ks.signer_for(&a1.address.to_string(), "pw2").is_err());

        // What is stored is an ACCOUNT key, not the root: `xprv` version bytes, depth 3.
        let stored = eth_keystore::decrypt_key(ks.group_vault_path(&group), "gp").unwrap();
        let text = String::from_utf8(stored).unwrap();
        assert!(text.starts_with("xprv"), "stored {}", &text[..4]);
        assert!(crate::hd::decode_account_key(&text).is_ok());
    }

    #[test]
    fn the_only_door_to_a_random_key_requires_an_acknowledgement() {
        // What replaced `new_account`. That method minted silently on an empty keystore and
        // refused on a derivable one, so whether it was safe depended on a directory scan
        // being complete — which is not decidable by inspection. This one asks the caller.
        for state in ["empty", "derivable wallet", "plain wallet"] {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            match state {
                "derivable wallet" => { with_group(dir.path()); }
                "plain wallet" => { ks.import_mnemonic_ex(&req(Storage::Plain, 0)).unwrap(); }
                _ => {}
            }
            let before = ks.list_accounts().unwrap().len();

            // The refusal says what an unrelated account IS, not merely that a flag is
            // missing — the user is being asked to understand something, not to retry.
            let refused = Unrecoverable::acknowledged(false).unwrap_err().to_string();
            assert!(refused.contains("recovery phrase will not restore"), "{state}: {refused}");
            assert_eq!(ks.list_accounts().unwrap().len(), before, "{state}: a refusal created one");

            let unrelated = ks.create_unrelated_account("pw", acked()).unwrap();
            assert_eq!(
                ks.provenance_view().unwrap().iter().find(|a| a.address == unrelated).unwrap().provenance.origin,
                "random", "{state}"
            );
        }
    }

    #[test]
    fn the_only_random_key_in_this_crate_is_the_acknowledged_one() {
        // The construction argument, asserted rather than described. `Unrecoverable` holds
        // a private field, so no other module can build one — and if the only generator of
        // a random key lives inside its constructor, there is no code path to a random key
        // that skipped the acknowledgement. A reviewer can check this by grep; so can CI.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let body = std::fs::read_to_string(&path).unwrap();
            // The crate's own tests are callers like any other; only production code counts.
            let production = body.split("#[cfg(test)]").next().unwrap_or("").to_string();
            if production.contains("PrivateKeySigner::random()") {
                found.push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
        }
        assert_eq!(found, vec!["ack.rs".to_string()], "a random key is minted outside the door");
    }

    #[test]
    fn a_plain_group_cannot_derive_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let d = ks.import_mnemonic_ex(&req(Storage::Plain, 0)).unwrap();

        // No vault was written for a group that keeps nothing.
        assert!(!ks.group_vault_path(&d.group).exists());
        let e = ks.derive_next_account(Some(&d.group), "gp", "pw", 0).unwrap_err().to_string();
        assert!(e.contains("import its recovery phrase again"), "got {e}");
        assert!(!ks.list_groups().unwrap()[0].derivable);

        // Re-importing the phrase with the key kept derives the SAME addresses — which is
        // what makes "import it again" an honest offer rather than a new wallet.
        let again = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        assert_eq!(again.address, ACCT0);
        assert_eq!(ks.derive_next_account(Some(&again.group), "gp", "pw", 0).unwrap().address, ACCT1);
    }

    #[test]
    fn the_derivation_key_never_reaches_a_different_bip44_account() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());

        // Account 1' is hardened, so account 0's stored key cannot reach it. The caller is
        // told why rather than handed an opaque failure.
        let e = ks.derive_account_at(&group, "gp", "pw", Some(1), 0, 0).unwrap_err().to_string();
        assert!(e.contains("hardened"), "got {e}");

        // Its own account, at an index the caller picked, is fine.
        let at7 = ks.derive_account_at(&group, "gp", "pw", Some(0), 0, 7).unwrap();
        assert_eq!(at7.path, "m/44'/60'/0'/0/7");
        // And an index already held is refused rather than overwriting a vault.
        assert!(ks.derive_account_at(&group, "gp", "pw2", None, 0, 7).is_err());
        assert!(ks.signer_for(&at7.address.to_string(), "pw").is_ok());
    }

    #[test]
    fn a_wrong_group_password_derives_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        assert!(ks.derive_next_account(Some(&group), "WRONG", "pw", 0).is_err());
        assert!(ks.preview_addresses(&group, "WRONG", 0, 0, 3).is_err());
        assert_eq!(ks.list_accounts().unwrap().len(), 1);
        assert!(ks.group_vault_path(&group).exists(), "a refused attempt must not destroy the key");
        // Deleting is the one thing a wrong password does NOT stop: see
        // `a_key_that_cannot_be_opened_is_still_deletable`.
    }

    #[test]
    fn preview_writes_nothing_and_marks_what_is_already_held() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());

        let rows = ks.preview_addresses(&group, "gp", 0, 0, 4).unwrap();
        assert_eq!(rows.iter().map(|r| r.address).collect::<Vec<_>>(), vec![ACCT0, ACCT1, ACCT2, ACCT3]);
        assert_eq!(rows.iter().map(|r| r.present).collect::<Vec<_>>(), vec![true, false, false, false]);
        assert_eq!(rows[3].path, "m/44'/60'/0'/0/3");

        // A preview is a read: no vault, no group state, no index consumed.
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0]);
        assert_eq!(ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap().index, 1);

        // The change level is addressable, and capped so this is not a free KDF oracle.
        assert_eq!(ks.preview_addresses(&group, "gp", 1, 0, 1).unwrap()[0].path, "m/44'/60'/0'/1/0");
        assert!(ks.preview_addresses(&group, "gp", 0, 0, MAX_PREVIEW + 1).is_err());
    }

    #[test]
    fn a_deleted_index_is_retired_and_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let a1 = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        let a2 = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        assert_eq!((a1.index, a2.index), (1, 2));

        assert!(ks.delete_account(&a1.address.to_string(), "pw").unwrap());
        // The gap stays a gap: re-deriving index 1 under a fresh password would leave two
        // vaults' worth of ambiguity about which password opens what.
        let next = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        assert_eq!(next.index, 3);
        assert_eq!(ks.list_groups().unwrap()[0].group.retired, vec![1]);
        assert!(!ks.get_provenance().unwrap().contains_key(&addr_key(&a1.address)));
    }

    #[test]
    fn the_next_index_is_recomputed_from_the_recorded_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();

        // Corrupt the cache the way a hand-edit would. It is a high-water mark, not the
        // authority: the worst it can do is skip an index, never collide.
        ks.update_groups(|g| {
            g.get_mut(&group).unwrap().next_index = 0;
        })
        .unwrap();
        assert_eq!(ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap().index, 2);

        // An index already occupied by a raw-key import is walked past, not overwritten.
        let dir2 = tempfile::tempdir().unwrap();
        let (ks2, g2) = with_group(dir2.path());
        // Anvil account #1, imported as a bare key: the same address index 1 would derive.
        ks2.import_private_key("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "other")
            .unwrap();
        let d = ks2.derive_next_account(Some(&g2), "gp", "pw", 0).unwrap();
        assert_eq!((d.address, d.index), (ACCT2, 2));
        assert!(ks2.signer_for(&ACCT1.to_string(), "other").is_ok(), "the existing vault must survive");
    }

    #[test]
    fn forget_derivation_downgrades_the_group_and_cannot_be_undone() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();

        ks.forget_derivation(&group).unwrap();
        assert!(!ks.group_vault_path(&group).exists());
        assert_eq!(ks.list_groups().unwrap()[0].group.storage, Storage::Plain);
        assert!(!ks.list_groups().unwrap()[0].derivable);
        assert!(ks.derive_next_account(Some(&group), "gp", "pw", 0).is_err());
        assert!(ks.forget_derivation(&group).is_err(), "nothing left to forget");

        // The accounts themselves are untouched — this reduces exposure, it does not
        // move funds.
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT1, ACCT0]);
        assert!(ks.signer_for(&ACCT1.to_string(), "pw").is_ok());
    }

    // ── Wallet names ──────────────────────────────────────────────────────
    // A group id is not an answer to "which wallet is this?", and the default the UI shows
    // instead — the first account's address — moves when that account is deleted.

    #[test]
    fn a_wallet_name_round_trips_and_clears_like_an_account_name() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());

        // The name given at import lands in the document, not in the record.
        assert_eq!(ks.get_group_labels().unwrap().get(&group).map(String::as_str), Some("Main"));
        assert_eq!(ks.get_groups().unwrap()[&group].label, "");
        assert_eq!(ks.list_groups().unwrap()[0].group.label, "Main");

        ks.set_group_label(&rename_as(&group, "  Cold storage  ", &ACCT0.to_string(), "pw")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Cold storage");
        assert_eq!(ks.list_groups().unwrap()[0].group.label, "Cold storage");

        // It sits beside the vaults, so it must read back as neither an account nor a stray.
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0]);
        assert!(ks.settle().unwrap().left.unexplained.is_empty());

        ks.set_group_label(&rename(&group, "   ")).unwrap();
        assert!(ks.get_group_labels().unwrap().is_empty(), "an empty name clears the entry");
        assert_eq!(ks.list_groups().unwrap()[0].group.label, "");
    }

    #[test]
    fn account_wallets_is_the_canonical_join_of_provenance_and_wallet_names() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let next = ks.derive_next_account(Some(&group), "gp", "pw2", 0).unwrap();
        let ungrouped = ks.create_unrelated_account("loose", acked()).unwrap();

        let wallets = ks.account_wallets().unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(
            wallets[&ACCT0.to_string()],
            AccountWallet { wallet: "Main".into(), index: Some(0) }
        );
        assert_eq!(
            wallets[&next.address.to_string()],
            AccountWallet { wallet: "Main".into(), index: Some(1) }
        );
        assert!(!wallets.contains_key(&ungrouped.to_string()));

        let origins = ks.account_origins().unwrap();
        assert_eq!(origins[&ACCT0.to_string()]["phrase"], origins[&next.address.to_string()]["phrase"]);
        assert_eq!(origins[&ACCT0.to_string()]["phrase"]["name"], "Main");
        assert!(origins[&ungrouped.to_string()]["phrase"].is_null());
        assert_eq!(origins[&ungrouped.to_string()]["kind"], "random");
        ks.set_group_label(&rename(&group, "")).unwrap();
        assert!(ks.account_wallets().unwrap().is_empty());
        assert!(ks.account_origins().unwrap()[&ACCT0.to_string()]["phrase"]["id"].is_string());
    }

    #[test]
    fn a_name_for_a_wallet_that_never_existed_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = with_group(dir.path());
        let e = ks.set_group_label(&rename(&format!("g_{}", "0".repeat(32)), "ghost")).unwrap_err();
        assert!(format!("{e}").contains("no such group"), "got {e}");
        for hostile in ["g_../../../etc/passwd", "../groups/x", "", "g_"] {
            assert!(ks.set_group_label(&rename(hostile, "ghost")).is_err(), "{hostile:?}");
        }
        assert_eq!(ks.get_group_labels().unwrap().len(), 1, "only the imported wallet is named");
    }

    #[test]
    fn a_wallet_name_outlives_both_the_key_and_the_record_that_named_it() {
        // The row a reader most needs to name is the one whose bookkeeping is gone: it is
        // asking whether to delete whole-wallet key material, and an id is not an answer.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let acct = ACCT0.to_string();
        ks.set_group_label(&rename_as(&group, "Cold storage", &acct, "pw")).unwrap();
        lose_records(&ks);

        let stranded = ks.list_groups().unwrap();
        assert!(stranded[0].stranded && stranded[0].id == group);
        assert_eq!(stranded[0].group.label, "Cold storage");

        // With the key gone too, the accounts it derived are still on screen — a reader
        // groups them by provenance — so the name stays readable and settable.
        ks.forget_derivation(&group).unwrap();
        assert!(ks.list_groups().unwrap().is_empty());
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Cold storage");
        ks.set_group_label(&rename_as(&group, "Old phone", &acct, "pw")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Old phone");
    }

    #[test]
    fn an_unreadable_wallet_names_file_refuses_rather_than_erasing_every_name() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let saved = std::fs::read_to_string(dir.path().join("index.pending.json")).unwrap();
        corrupt_index(dir.path(), "{\"x\": ");

        assert!(ks.get_group_labels().is_err());
        assert!(ks.account_wallets().is_err(), "the join must not turn a corrupt names file into no wallets");
        assert!(ks.list_groups().is_err(), "an unreadable name is not an unnamed wallet");
        // Naming a wallet would otherwise write a fresh map over the torn one, silently
        // losing every name it held — and an import would quietly land a nameless wallet.
        // Credentialed on purpose: an uncredentialed call would refuse for the other reason.
        let e = ks
            .set_group_label(&rename_as(&group, "Cold storage", &ACCT0.to_string(), "pw"))
            .unwrap_err();
        assert!(format!("{e}").contains("unreadable"), "got {e}");
        assert!(ks.import_mnemonic_ex(&ImportRequest { bip44_account: 1, ..req(Storage::Extkey, 0) }).is_err());
        corrupt_index(dir.path(), &saved);
        assert_eq!(ks.get_groups().unwrap().len(), 1, "a refused import left a half-made wallet");
    }

    #[test]
    fn two_wallets_may_carry_one_name() {
        // Deliberate: telling them apart is the reader's job, and refusing the write would
        // only stop it showing what the user actually did.
        let dir = tempfile::tempdir().unwrap();
        let (ks, first) = with_group(dir.path());
        let other = ks
            .import_mnemonic_ex(&ImportRequest { bip44_account: 1, ..req(Storage::Extkey, 0) })
            .unwrap();
        ks.set_group_label(&rename_as(&first, "Wallet", &ACCT0.to_string(), "pw")).unwrap();
        ks.set_group_label(&rename_as(&other.group, "Wallet", &other.address.to_string(), "pw")).unwrap();

        let names = ks.get_group_labels().unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.values().all(|n| n == "Wallet"), "a duplicate name must be storable");
    }

    #[test]
    fn a_name_an_older_build_left_in_the_record_is_read_and_then_moved_out_of_it() {
        // The record carried the name before it had a map of its own. It is still shown, but a
        // rename has to leave nothing underneath that can resurface.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.update_group_labels(|n| n.clear()).unwrap();
        ks.update_groups(|g| g.get_mut(&group).unwrap().label = "Legacy".into()).unwrap();
        assert_eq!(ks.list_groups().unwrap()[0].group.label, "Legacy");

        ks.set_group_label(&rename(&group, "")).unwrap();
        assert!(ks.get_group_labels().unwrap().is_empty());
        assert_eq!(ks.get_groups().unwrap()[&group].label, "", "the old name must not resurface");
        assert_eq!(ks.list_groups().unwrap()[0].group.label, "");
    }

    #[test]
    fn naming_a_wallet_with_accounts_needs_one_of_their_passwords() {
        // A wallet name is a claim about the accounts nested under it, so holding one of
        // them is what proves it. The group password would prove the wrong thing: that you
        // can MAKE accounts, not that you own the ones the header speaks for.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let other = ks
            .import_mnemonic_ex(&ImportRequest { bip44_account: 1, ..req(Storage::Extkey, 0) })
            .unwrap();
        let (acct, elsewhere) = (ACCT0.to_string(), other.address.to_string());

        for (r, want) in [
            (rename(&group, "Cold storage"), "needs the password of one of them"),
            (rename_as(&group, "Cold storage", &acct, "wrong"), "password for this account is not correct"),
            (rename_as(&group, "Cold storage", &elsewhere, "pw"), "does not belong to this wallet"),
            (rename_as(&group, "Cold storage", "not-an-address", "pw"), "does not belong to this wallet"),
        ] {
            let e = ks.set_group_label(&r).unwrap_err();
            assert!(format!("{e}").contains(want), "wanted {want:?}, got {e}");
        }
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Main", "a refused rename wrote a name");

        // A swapped pair puts the password in the address slot; the refusal must not say it back.
        let e = ks.set_group_label(&rename_as(&group, "Cold storage", "hunter2", "0xdead")).unwrap_err();
        assert!(!format!("{e}").contains("hunter2"), "the refusal echoed the address slot: {e}");

        ks.set_group_label(&rename_as(&group, "Cold storage", &acct, "pw")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Cold storage");
        // Clearing can only move the display toward the addresses themselves, so it proves
        // nothing and is asked for nothing.
        ks.set_group_label(&rename(&group, "")).unwrap();
        assert!(!ks.get_group_labels().unwrap().contains_key(&group));
    }

    #[test]
    fn only_a_wallet_that_holds_nothing_is_named_without_a_secret() {
        // No key, no account: there is no secret to check against, nothing to mis-attribute,
        // and nothing that can arrive later for the name to come to stand over. Refusing
        // would also be incoherent with removal, which lets this very row be deleted.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = emptied(dir.path());
        ks.set_group_label(&rename(&group, "New")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "New");

        // The stranded key with no accounts holds something, so it buys its name with that
        // key's password — the row is still DELETABLE without one, which is the affordance
        // that matters, and the name still CLEARS without one.
        let d2 = tempfile::tempdir().unwrap();
        let (ks2, g2) = with_group(d2.path());
        assert!(ks2.delete_account(&ACCT0.to_string(), "pw").unwrap());
        lose_records(&ks2);
        assert!(ks2.list_groups().unwrap()[0].stranded);
        let e = ks2.set_group_label(&rename(&g2, "Old phone")).unwrap_err();
        assert!(format!("{e}").contains("keeps a derivation key needs that key's password"), "got {e}");
        ks2.set_group_label(&rename_with_key(&g2, "Old phone", "gp")).unwrap();
        assert_eq!(ks2.list_groups().unwrap()[0].group.label, "Old phone");
        ks2.set_group_label(&rename(&g2, "")).unwrap();
        assert!(ks2.get_group_labels().unwrap().is_empty(), "clearing a name asked for a secret");
    }

    #[test]
    fn a_name_on_a_wallet_that_can_still_mint_accounts_needs_that_key_password() {
        // The measured hole: name a derivable wallet while it has no accounts, having proved
        // nothing, then derive — and the name stands over a real account. "Has no accounts"
        // was read as "holds nothing"; only a wallet with no key can never gain one.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());
        assert!(ks.list_groups().unwrap()[0].derivable, "the wallet can still mint accounts");

        let e = ks.set_group_label(&rename(&group, "Cold storage")).unwrap_err();
        assert!(format!("{e}").contains("keeps a derivation key needs that key's password"), "got {e}");
        let e = ks.set_group_label(&rename_with_key(&group, "Cold storage", "WRONG")).unwrap_err();
        assert!(format!("{e}").contains("password for this wallet's derivation key is not correct"), "got {e}");
        // An address is not a way around it: what the wallet HOLDS prices the name, not what
        // the caller offers, and a wallet with no accounts has none to hold.
        let e = ks
            .set_group_label(&rename_as(&group, "Cold storage", &ACCT0.to_string(), "pw"))
            .unwrap_err();
        assert!(format!("{e}").contains("derivation key is not correct"), "got {e}");
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Main", "a refused rename wrote a name");

        // With the key's password the name is bought by exactly what will mint the account
        // it comes to stand over.
        ks.set_group_label(&rename_with_key(&group, "Cold storage", "gp")).unwrap();
        let d = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        assert_eq!(d.address, ACCT1);
        let listed = ks.list_groups().unwrap();
        assert_eq!((listed[0].group.label.as_str(), listed[0].account_count), ("Cold storage", 1));
    }

    #[test]
    fn a_key_at_the_staging_path_prices_a_name_exactly_as_the_live_one_does() {
        // Same ciphertext, same password — and settle promotes it when the real one is gone,
        // so an interrupted import is not a wallet that holds nothing.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());
        let stage = dir.path().join("groups").join(format!(".stage-{group}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::rename(ks.group_vault_path(&group), stage.join(format!("{group}.json"))).unwrap();

        let e = ks.set_group_label(&rename(&group, "Cold storage")).unwrap_err();
        assert!(format!("{e}").contains("keeps a derivation key needs that key's password"), "got {e}");
        let e = ks.set_group_label(&rename_with_key(&group, "Cold storage", "WRONG")).unwrap_err();
        assert!(format!("{e}").contains("derivation key is not correct"), "got {e}");
        ks.set_group_label(&rename_with_key(&group, "Cold storage", "gp")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Cold storage");
    }

    #[test]
    fn a_name_left_over_a_vanished_record_is_still_nameable_and_still_removable() {
        // A name with no record and no key behind it. `remove_group` takes it, so naming has
        // to reach it too — otherwise the one call that can clear it cannot be aimed.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = emptied(dir.path());
        lose_records(&ks);
        assert!(ks.list_groups().unwrap().is_empty(), "nothing on disk but the name");

        ks.set_group_label(&rename(&group, "Old phone")).unwrap();
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Old phone");
        assert!(ks.remove_group(&group).unwrap().name_removed);
        // And once the name is gone the id is nothing to this keystore again.
        let e = ks.set_group_label(&rename(&group, "Back")).unwrap_err();
        assert!(format!("{e}").contains("no such group"), "got {e}");
    }

    #[test]
    fn a_stranded_group_reports_the_accounts_it_still_holds() {
        // The listing said 0 while the credential check, reading the same provenance, said 1.
        // Both removal and renaming ask "does this wallet hold anything", so a hardcoded 0 is
        // a false "holds nothing" waiting for a consumer to read it.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        lose_records(&ks);

        let listed = ks.list_groups().unwrap();
        assert!(listed[0].stranded && listed[0].id == group);
        assert_eq!(listed[0].account_count, 2, "the listing disagreed with provenance");
        assert!(ks.remove_group(&group).is_err(), "a wallet holding two accounts was removable");
    }

    // ── Removing a wallet ─────────────────────────────────────────────────
    // The row a UI could not get rid of: a record with no key and no accounts. `forget_
    // derivation` removes the KEY and reports not-found when there is none, so a wallet that
    // only ever had a record was unremovable by construction.

    #[test]
    fn removing_a_wallet_takes_its_record_and_its_name_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let keeper = ks.create_unrelated_account("pw", acked()).unwrap();
        ks.forget_derivation(&group).unwrap();
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());

        let out = ks.remove_group(&group).unwrap();
        assert!(out.record_removed && out.name_removed && out.group == group);
        assert!(ks.get_groups().unwrap().is_empty());
        assert!(ks.get_group_labels().unwrap().is_empty());
        assert!(ks.list_groups().unwrap().is_empty(), "the row survived its own removal");

        // Nothing signable went with it, and nothing was left behind to be swept.
        assert_eq!(ks.list_accounts().unwrap(), vec![keeper]);
        assert!(ks.signer_for(&keeper.to_string(), "pw").is_ok());
        assert!(ks.scan().unwrap().stray().is_empty());
    }

    #[test]
    fn a_wallet_that_still_holds_anything_is_refused_rather_than_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let second = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();

        // The key first: removal must never become a second door to deleting key material,
        // and it must not be the one without the acknowledgement.
        let e = ks.remove_group(&group).unwrap_err();
        assert!(format!("{e}").contains("still keeps a derivation key"), "got {e}");
        assert!(ks.group_vault_path(&group).exists(), "a refusal must change nothing");
        ks.forget_derivation(&group).unwrap();

        // Then the accounts, counted: each of them is a spendable key with its own password.
        let e = ks.remove_group(&group).unwrap_err();
        assert!(format!("{e}").contains("still holds 2 account(s)"), "got {e}");
        assert!(ks.get_groups().unwrap().contains_key(&group));
        assert_eq!(ks.get_group_labels().unwrap()[&group], "Main");

        // The premise the whole precondition rests on: with the key gone the wallet cannot
        // grow again, so "holds nothing" is a terminal state and not a moment.
        assert!(ks.derive_next_account(Some(&group), "gp", "pw", 0).is_err());
        assert!(ks.derive_account_at(&group, "gp", "pw", None, 0, 7).is_err());

        assert!(ks.delete_account(&second.address.to_string(), "pw").unwrap());
        assert!(ks.remove_group(&group).is_err(), "one account is still one account");
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());
        assert!(ks.remove_group(&group).is_ok());
    }

    #[test]
    fn a_key_at_the_staging_path_blocks_removal_exactly_as_the_live_one_does() {
        // An interrupted import's copy opens the whole wallet just the same, and it is the
        // one a check of the live path alone would walk straight past.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        assert!(ks.delete_account(&ACCT0.to_string(), "pw").unwrap());
        let stage = dir.path().join("groups").join(format!(".stage-{group}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::rename(ks.group_vault_path(&group), stage.join(format!("{group}.json"))).unwrap();

        let e = ks.remove_group(&group).unwrap_err();
        assert!(format!("{e}").contains("an interrupted import left a copy"), "got {e}");
        ks.forget_derivation(&group).unwrap();
        assert!(ks.remove_group(&group).is_ok());
    }

    #[test]
    fn removing_a_wallet_that_is_not_there_says_so_and_a_half_removed_one_heals() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = emptied(dir.path());
        let e = ks.remove_group(&format!("g_{}", "0".repeat(32))).unwrap_err();
        assert!(format!("{e}").contains("no such group"), "got {e}");
        for hostile in ["g_../../../etc/passwd", "../groups/x", "", "g_"] {
            assert!(ks.remove_group(hostile).is_err(), "{hostile:?}");
        }

        // A name left standing over a record that already went: the operation is total, so
        // it takes what is there and says which half it found.
        lose_records(&ks);
        let out = ks.remove_group(&group).unwrap();
        assert!(!out.record_removed && out.name_removed);
        assert!(ks.get_group_labels().unwrap().is_empty());
        assert!(ks.remove_group(&group).is_err(), "there is nothing left to remove");
    }

    #[test]
    fn an_unreadable_precondition_refuses_the_removal_rather_than_taking_the_record() {
        // Reading a torn file as "nothing here" is the defect this module keeps finding. On
        // this path it would remove the record of a wallet that still had accounts under it.
        for (name, corrupt) in corruptions() {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = emptied(dir.path());
            let saved = std::fs::read_to_string(dir.path().join("index.pending.json")).unwrap();
            corrupt(dir.path());
            assert!(ks.remove_group(&group).is_err(), "{name}");
            std::fs::remove_file(dir.path().join("index.pending.json")).unwrap();
            corrupt_index(dir.path(), &saved);
            assert_eq!(ks.get_group_labels().unwrap()[&group], "Main", "{name}: the name went anyway");
        }

        // The accounts are what say whether anything is still under the wallet.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = emptied(dir.path());
        let saved = std::fs::read_to_string(dir.path().join("index.pending.json")).unwrap();
        corrupt_index(dir.path(), "{\"x\": ");
        assert!(ks.remove_group(&group).is_err());
        corrupt_index(dir.path(), &saved);
        assert!(ks.get_groups().unwrap().contains_key(&group));
    }

    #[test]
    fn a_group_id_cannot_escape_the_keystore_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = with_group(dir.path());
        for hostile in ["g_../../../etc/passwd", "../groups/x", "g_ABCDEF0123456789abcdef0123456789", "", "g_"] {
            assert!(ks.derive_next_account(Some(hostile), "gp", "pw", 0).is_err(), "{hostile:?}");
            assert!(ks.preview_addresses(hostile, "gp", 0, 0, 1).is_err(), "{hostile:?}");
        }
        // A well-formed id that names no group is a plain not-found.
        let e = ks.derive_next_account(Some(&format!("g_{}", "0".repeat(32))), "gp", "pw", 0).unwrap_err();
        assert!(format!("{e}").contains("not found"), "got {e}");
    }

    #[test]
    fn provenance_is_recorded_for_every_way_an_account_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let src = tempfile::tempdir().unwrap();
        let other = Keystore::new(src.path());
        let json = other
            .import_private_key(ACCT0_PK, "pw")
            .and_then(|a| other.export_keystore_json(&a.to_string(), "pw"))
            .unwrap();

        let imported = ks.import_private_key("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "pw").unwrap();
        let from_json = ks.import_keystore_json(&json, "pw", "pw").unwrap();
        let random = ks.create_unrelated_account("pw", acked()).unwrap();

        let origin = |a: Address| {
            ks.provenance_view().unwrap().into_iter().find(|p| p.address == a).unwrap().provenance.origin
        };
        assert_eq!(origin(imported), "imported-key");
        assert_eq!(origin(from_json), "imported-json");
        assert_eq!(origin(random), "random");
        assert!(ks.provenance_view().unwrap().iter().all(|p| !p.derivable));

        // An account that predates all of this is reported unknown, never guessed: a guess
        // about recoverability is the one lie this must not tell.
        // An older build named it by its address; the next keystore to open takes it in.
        let ancient = address!("0000000000000000000000000000000000000001");
        std::fs::copy(vault_file(&ks, &from_json), dir.path().join(format!("{}.json", addr_key(&ancient)))).unwrap();
        let reopened = Keystore::new(dir.path());
        let found = reopened.provenance_view().unwrap().into_iter().find(|p| p.address == ancient).unwrap();
        assert_eq!(found.provenance.origin, "unknown");
        assert!(!dir.path().join(format!("{}.json", addr_key(&ancient))).exists(), "its vault took a random name");
    }

    #[test]
    fn a_group_records_that_a_passphrase_was_used_but_never_its_value() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let d = ks
            .import_mnemonic_ex(&ImportRequest { bip39_passphrase: "TREZOR", ..req(Storage::Extkey, 0) })
            .unwrap();
        // The passphrase forks the whole tree, so this is a different wallet.
        assert_ne!(d.address, ACCT0);
        assert!(ks.list_groups().unwrap()[0].group.used_passphrase);

        // No bookkeeping may carry the phrase or the passphrase, sealed or not.
        let txt = plain_docs(dir.path());
        assert!(!txt.contains("TREZOR"), "the bookkeeping leaked the passphrase");
        assert!(!txt.contains(TEST_MNEMONIC), "the bookkeeping leaked the phrase");
        assert!(!txt.contains("xprv"), "the bookkeeping leaked the derivation key");
    }

    #[cfg(unix)]
    #[test]
    fn the_group_vault_is_never_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("groups")), 0o700);
        assert_eq!(mode(&ks.group_vault_path(&group)), 0o600);
        // And nothing is left staged: the vault is written elsewhere and renamed in.
        let staged: Vec<_> = std::fs::read_dir(dir.path().join("groups"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".stage-"))
            .collect();
        assert!(staged.is_empty());
    }

    #[test]
    fn a_failed_import_leaves_no_half_made_group() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        // Fail the account vault's write, so the failure lands AFTER the group's derivation key
        // has been written.
        FAIL_VAULT_WRITE.with(|f| f.set(true));

        assert!(ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).is_err());
        assert!(ks.get_groups().unwrap().is_empty(), "a group whose account never landed must not survive");
        assert!(ks.get_group_labels().unwrap().is_empty(), "its name must not survive it either");
        let leftover: Vec<_> = std::fs::read_dir(dir.path().join("groups")).unwrap().flatten().collect();
        assert!(leftover.is_empty(), "a live derivation key was left behind");
    }

    #[test]
    fn seed_material_is_built_once_and_wiped_by_every_keystore_entry_point() {
        use crate::hd::probe;
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());

        let before = probe::count();
        let d = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        assert_eq!(probe::count(), before + 1, "an import must wipe its seed");

        // The whole point of keeping the account key: to_seed runs once, ever. Every later
        // account costs no phrase, no IPC trip and no PBKDF2.
        ks.derive_next_account(None, "gp", "pw", 0).unwrap();
        ks.preview_addresses(&d.group, "gp", 0, 0, 2).unwrap();
        assert_eq!(probe::count(), before + 1, "deriving from a stored key must build no seed");

        // A refused import wipes on the way out too, and writes nothing.
        assert!(ks.import_mnemonic_ex(&ImportRequest { index: HARDENED_INDEX, ..req(Storage::Extkey, 0) }).is_err());
        assert!(ks.import_mnemonic_ex(&ImportRequest { phrase: "not a phrase", ..req(Storage::Extkey, 0) }).is_err());
        assert_eq!(ks.get_groups().unwrap().len(), 1);
    }

    /// One past the last valid address index — the level is not hardened, so 2^31 is out
    /// of range rather than "hardened index 0".
    const HARDENED_INDEX: u32 = 0x8000_0000;

    // ---- an unreadable file is not an empty one --------------------------
    // Every new vault is written through `persist_signer`, which reads groups.json and
    // accounts.json FIRST. That read used to swallow every I/O and parse error and carry on
    // with an empty map, so a key could land with no record of where it came from. The
    // refusal is about the provenance record, not about minting — it applies to an imported
    // key and an acknowledged one alike.

    /// One named way of making a file unusable, applied to a keystore directory.
    type Corruption = (&'static str, Box<dyn Fn(&std::path::Path)>);

    /// Every way `groups.json` can exist and be unusable. Each is applied to a keystore
    /// whose derivation key is still on disk.
    fn corruptions() -> Vec<Corruption> {
        let write = |name: &'static str, body: &'static str| -> Corruption {
            (name, Box::new(move |p: &std::path::Path| corrupt_index(p, body)))
        };
        let mut cases = vec![
            // Exactly the measured state: `> file`, or a crash before any byte lands.
            write("truncated", ""),
            // ENOSPC part-way through a non-atomic write.
            write("partial json", "{\"g_0123456789abcdef0123456789abcdef\": {\"storage\": \"extk"),
            // Valid JSON, wrong shape — a hand-edit, or a file from another version.
            write("wrong schema", "[]"),
            write("wrong value type", "{\"g_0123456789abcdef0123456789abcdef\": \"extkey\"}"),
            // Not JSON at all.
            write("not json", "\u{0}\u{0}\u{0}\u{0}"),
        ];
        #[cfg(unix)]
        cases.push(("unreadable", Box::new(|p: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p.join("index.pending.json"), std::fs::Permissions::from_mode(0o000)).unwrap();
        })));
        cases
    }

    #[test]
    fn a_groups_file_that_cannot_be_read_refuses_before_a_vault_lands() {
        for (name, corrupt) in corruptions() {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            corrupt(dir.path());

            // Every way a key can arrive, refused alike: a key on disk that nothing can
            // later explain is the failure, and it does not care how the key was obtained.
            let e = ks.create_unrelated_account("pw", acked()).unwrap_err();
            assert!(
                matches!(e, KeystoreError::Corrupt(..)),
                "{name}: an unreadable index must refuse, got {e}"
            );
            assert!(format!("{e}").contains("index.pending.json"), "{name}: {e}");
            assert!(ks.import_private_key(ACCT0_PK, "pw").is_err(), "{name}");

            assert_eq!(ks.scan().unwrap().vaults.len(), 1, "{name}: a vault landed anyway");
            assert!(ks.group_vault_path(&group).exists(), "{name}");

            // Every other read of that file refuses too, instead of reporting "no wallets".
            assert!(ks.list_groups().is_err(), "{name}");
            assert!(ks.provenance_view().is_err(), "{name}");
            assert!(ks.derive_next_account(None, "gp", "pw", 0).is_err(), "{name}");

            // And the escape hatch stays open: the key is still nameable and still deletable.
            assert_eq!(ks.list_derivation_keys().unwrap(), vec![group.clone()], "{name}");
            assert!(ks.forget_derivation(&group).is_ok(), "{name}");
        }
    }

    #[test]
    fn an_unreadable_accounts_file_refuses_before_the_vault_lands() {
        // The index is read on the way to writing every new vault. Swallowing its errors would
        // leave a key on disk with no record of where it came from.
        for (name, body) in [("truncated", ""), ("wrong schema", "[]")] {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            ks.create_unrelated_account("pw", acked()).unwrap();
            let before = ks.scan().unwrap().vaults;
            corrupt_index(dir.path(), body);

            assert!(matches!(ks.create_unrelated_account("pw", acked()), Err(KeystoreError::Corrupt(..))), "{name}");
            assert!(ks.import_private_key(ACCT0_PK, "pw").is_err(), "{name}");
            assert_eq!(ks.scan().unwrap().vaults, before, "{name}: a vault landed despite the refusal");
            assert!(ks.get_provenance().is_err(), "{name}");
        }
    }

    #[test]
    fn an_unreadable_labels_file_refuses_rather_than_erasing_every_name() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let a = ks.create_unrelated_account("pw", acked()).unwrap();
        ks.set_label(&a.to_string(), "Savings", "pw").unwrap();

        corrupt_index(dir.path(), "{\"x\": ");
        assert!(ks.get_labels().is_err());
        // Naming a second account would otherwise write a fresh map over the torn one,
        // silently losing every name it held. The password is correct on purpose: a wrong
        // one would refuse for the other reason and this would pass having proven nothing.
        let e = ks.set_label(&a.to_string(), "Chequing", "pw").unwrap_err();
        assert!(format!("{e}").contains("unreadable"), "got {e}");
    }

    #[test]
    fn an_absent_sidecar_is_still_empty_and_only_the_unreadable_case_refuses() {
        // The three states must stay apart. Absent means nothing is configured yet, and
        // that path has to keep working exactly as it did.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        assert!(ks.get_groups().unwrap().is_empty());
        assert!(ks.get_provenance().unwrap().is_empty());
        assert!(ks.get_labels().unwrap().is_empty());
        assert!(ks.list_derivation_keys().unwrap().is_empty());
        assert!(ks.list_groups().unwrap().is_empty());
        assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "a green-field keystore must still work");

        // An EMPTY json object is a readable "nothing", and is not the corrupt case.
        let d2 = tempfile::tempdir().unwrap();
        let ks2 = Keystore::new(d2.path());
        std::fs::create_dir_all(d2.path()).unwrap();
        std::fs::write(d2.path().join("groups.json"), "{}").unwrap();
        assert!(ks2.get_groups().unwrap().is_empty());
        assert!(ks2.create_unrelated_account("pw", acked()).is_ok());
    }

    #[test]
    fn a_derivation_key_on_disk_is_reported_even_with_no_record_of_it() {
        // The vault FILE is the authority; deleting groups.json is the one corrupt state
        // that reads as legitimately empty. The scan still NAMES the key — which is what
        // makes it deletable — it just no longer decides anything about creating accounts.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        lose_records(&ks);
        assert!(ks.get_groups().unwrap().is_empty(), "no record is an empty one");

        assert_eq!(ks.list_derivation_keys().unwrap(), vec![group.clone()]);
        assert!(ks.group_store().unwrap().possible_key_material().iter().any(|m| m.contains(&group)));
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0]);
    }

    #[test]
    fn a_failed_sidecar_write_leaves_the_old_bytes_and_nothing_staged() {
        // Replaces a test that forced the failure by occupying `groups.json.tmp`. There is
        // no fixed staging name to occupy any more, so the failure is forced the one way
        // that covers EVERY name: the directory itself. That is strictly the better probe —
        // it no longer depends on knowing our own temp naming.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();

        let before = plain_docs(dir.path());
        let listed = |ks: &Keystore| ks.scan().unwrap();
        assert!(listed(&ks).doc_stages.is_empty(), "left staged: {:?}", listed(&ks).doc_stages);

        restrict_permissions(dir.path(), 0o500).unwrap();
        let failed = ks.update_groups(|g| {
            g.get_mut(&group).unwrap().next_index = 99;
        });
        restrict_permissions(dir.path(), 0o700).unwrap();

        assert!(failed.is_err(), "a failed staging must not report success");
        assert_eq!(plain_docs(dir.path()), before);
        assert_eq!(ks.list_accounts().unwrap().len(), 2);
        assert!(ks.get_groups().is_ok());
        assert!(listed(&ks).doc_stages.is_empty(), "a failed write left a staged copy behind");

        // A staged document that DOES outlive a crash is reported, not silently dropped —
        // the shape the account-half scan exists to close.
        std::fs::write(dir.path().join(format!("{}orphan", crate::atomic::DOC_STAGE_PREFIX)), "{}").unwrap();
        assert_eq!(listed(&ks).doc_stages.len(), 1);
        assert!(listed(&ks).unexplained.is_empty(), "a staged document is explained, not unexplained");
    }

    // ---- a stranded derivation key must stay deletable --------------------

    #[test]
    fn a_derivation_key_whose_record_is_gone_can_still_be_named_and_deleted() {
        // Routing forget_derivation through the bookkeeping meant a group with no record
        // could not be named, so its whole-wallet key stayed on disk forever — and the
        // "extkey → plain is a real downgrade" affordance had no way out.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let derived = ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();
        lose_records(&ks);

        // Nameable: listed as stranded, and reachable without the bookkeeping at all.
        let stranded: Vec<_> = ks.list_groups().unwrap().into_iter().filter(|g| g.stranded).collect();
        assert_eq!(stranded.len(), 1);
        assert_eq!(stranded[0].id, group);
        assert!(!stranded[0].derivable, "with no recorded path prefix it cannot derive");
        assert_eq!(ks.list_derivation_keys().unwrap(), vec![group.clone()]);

        // Deletable on the strength of its file, with no bookkeeping and no password.
        let out = ks.forget_derivation(&group).unwrap();
        assert!(out.was_stranded && !out.record_updated);
        assert!(!ks.group_vault_path(&group).exists());
        assert!(ks.list_derivation_keys().unwrap().is_empty());
        assert!(ks.list_groups().unwrap().is_empty());

        // The accounts already derived are untouched: they keep signing, they simply stop
        // being extendable. That is the promise the UI has to make.
        assert_eq!(ks.list_accounts().unwrap(), vec![derived.address, ACCT0]);
        assert!(ks.signer_for(&derived.address.to_string(), "pw").is_ok());
        assert!(ks.signer_for(&ACCT0.to_string(), "pw").is_ok());
        assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "the store still works");
    }

    #[test]
    fn a_stranded_key_is_deletable_even_when_the_bookkeeping_is_unreadable() {
        for (name, corrupt) in corruptions() {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            corrupt(dir.path());

            // list_groups refuses — but the escape hatch reads the vault directory only.
            assert!(ks.list_groups().is_err(), "{name}");
            assert_eq!(ks.list_derivation_keys().unwrap(), vec![group.clone()], "{name}");

            let out = ks.forget_derivation(&group).unwrap();
            assert!(!out.record_updated, "{name}: the record cannot have been updated");
            assert!(!ks.group_vault_path(&group).exists(), "{name}");
            // The account's key stays in its vault: which account it is waits on the index.
            assert_eq!(ks.scan().unwrap().vaults.len(), 1, "{name}: an account was lost");
        }
    }

    #[test]
    fn forgetting_a_recorded_group_still_downgrades_it_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let out = ks.forget_derivation(&group).unwrap();
        assert_eq!(out.group, group);
        assert!(out.record_updated && !out.was_stranded);
        assert_eq!(ks.list_groups().unwrap()[0].group.storage, Storage::Plain);
        assert!(!ks.list_groups().unwrap()[0].stranded);

        // A well-formed id naming no key at all is a plain not-found, not a silent success.
        let e = ks.forget_derivation(&format!("g_{}", "0".repeat(32))).unwrap_err();
        assert!(format!("{e}").contains("not found"), "got {e}");
        for hostile in ["g_../../../etc/passwd", "../groups/x", "", "g_"] {
            assert!(ks.forget_derivation(hostile).is_err(), "{hostile:?}");
        }
    }

    // ---- every on-disk state a derivation key can be in -------------------
    //
    // The blind spot this table exists to close: one representation of the key
    // (`groups/<id>.json`) was the authority while the key could sit in another
    // (`groups/.stage-<id>/<id>.json`). Every row asserts the same three questions, and the
    // `live` column is measured — the bytes are decrypted and derived from — rather than
    // assumed from a filename.

    /// Puts `groups/` into one state, given the keystore directory and the group id.
    type Mutate = Box<dyn Fn(&Path, &str)>;

    /// One on-disk state, and what `groups/` then holds.
    struct DiskState {
        name: &'static str,
        setup: Mutate,
        /// Paths under the keystore whose bytes still decrypt to the wallet's account key.
        live: fn(&str) -> Vec<String>,
        /// Must `list_derivation_keys` name the id?
        named: bool,
        /// Must the scan REPORT this state as material that could open a whole wallet?
        /// A report, not a gate: the safety property is the acknowledgement, asserted for
        /// every row alike, and it does not care what this column says.
        reports: bool,
        /// Must `forget_derivation` report having removed something?
        forgets: bool,
    }

    fn none(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn group_dir(d: &Path) -> PathBuf {
        d.join("groups")
    }

    /// A 0000 directory a row planted would outlive the tempdir, so every row reopens the
    /// tree before it drops. Best-effort: this is cleanup, not an assertion.
    fn reopen(dir: &Path) {
        let _ = restrict_permissions(dir, 0o700);
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                reopen(&e.path());
            }
        }
    }

    /// Decrypt a group vault and derive its index-0 address. This is what "holds a live
    /// account xprv" means here: not that a file exists, but that its bytes still reach the
    /// wallet's addresses.
    fn reaches_account_zero(path: &Path, password: &str) -> Address {
        let bytes = eth_keystore::decrypt_key(path, password).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        hd::address_in_account(&hd::decode_account_key(&text).unwrap(), 0, 0).unwrap()
    }

    fn state_table() -> Vec<DiskState> {
        vec![
            DiskState {
                name: "final path only",
                setup: Box::new(|_, _| {}),
                live: |id| vec![format!("groups/{id}.json")],
                named: true,
                reports: true,
                forgets: true,
            },
            DiskState {
                // The measured F1 state: same bytes, one directory deeper.
                name: "staging path only",
                setup: Box::new(|d, id| {
                    let stage = group_dir(d).join(format!(".stage-{id}"));
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), stage.join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!("groups/.stage-{id}/{id}.json")],
                named: true,
                reports: true,
                forgets: true,
            },
            DiskState {
                name: "both paths",
                setup: Box::new(|d, id| {
                    let stage = group_dir(d).join(format!(".stage-{id}"));
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::copy(group_dir(d).join(format!("{id}.json")), stage.join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!("groups/{id}.json"), format!("groups/.stage-{id}/{id}.json")],
                named: true,
                reports: true,
                forgets: true,
            },
            DiskState {
                name: "neither — empty key directory",
                setup: Box::new(|d, id| {
                    std::fs::remove_file(group_dir(d).join(format!("{id}.json"))).unwrap();
                }),
                live: none,
                named: false,
                reports: false,
                forgets: false,
            },
            DiskState {
                name: "neither — no key directory at all",
                setup: Box::new(|d, _| std::fs::remove_dir_all(group_dir(d)).unwrap()),
                live: none,
                named: false,
                reports: false,
                forgets: false,
            },
            DiskState {
                // Not live, but indistinguishable from live without the password — so it is
                // treated as a key, and refuses.
                name: "corrupt vault at the final path",
                setup: Box::new(|d, id| std::fs::write(group_dir(d).join(format!("{id}.json")), "").unwrap()),
                live: none,
                named: true,
                reports: true,
                forgets: true,
            },
            DiskState {
                name: "unreadable vault at the final path",
                setup: Box::new(|d, id| {
                    restrict_permissions(&group_dir(d).join(format!("{id}.json")), 0o000).unwrap()
                }),
                live: none, // present and live, but this process cannot read it to prove so
                named: true,
                reports: true,
                forgets: true,
            },
            DiskState {
                // ROW 10 (F2). Empty, and a DIRECTORY — so the classifier that ran on files
                // saw nothing at all at the exact path a key belongs. Reported now.
                name: "an empty directory where the key belongs",
                setup: Box::new(|d, id| {
                    let p = group_dir(d).join(format!("{id}.json"));
                    std::fs::remove_file(&p).unwrap();
                    std::fs::create_dir_all(&p).unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: true,
            },
            DiskState {
                // The same directory, with the key inside it. Unnameable as a key, still live.
                name: "a directory where the file belongs, holding the key",
                setup: Box::new(|d, id| {
                    let p = group_dir(d).join(format!("{id}.json"));
                    let tmp = d.join("moved.json");
                    std::fs::rename(&p, &tmp).unwrap();
                    std::fs::create_dir_all(&p).unwrap();
                    std::fs::rename(&tmp, p.join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!("groups/{id}.json/{id}.json")],
                named: false,
                reports: true,
                forgets: true,
            },
            DiskState {
                name: "a stale staging directory, empty",
                setup: Box::new(|d, id| {
                    std::fs::remove_file(group_dir(d).join(format!("{id}.json"))).unwrap();
                    std::fs::create_dir_all(group_dir(d).join(format!(".stage-{id}"))).unwrap();
                }),
                live: none,
                named: false,
                reports: false,
                forgets: true,
            },
            DiskState {
                name: "a file the layout does not explain",
                setup: Box::new(|d, id| {
                    std::fs::remove_file(group_dir(d).join(format!("{id}.json"))).unwrap();
                    std::fs::write(group_dir(d).join("notes.txt"), "hand-edited").unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // ROW 11 (F2). Any empty directory under `groups/`, not only one at a key
                // path — an unrecognised directory was invisible whatever it was called.
                name: "an empty directory under the key directory",
                setup: Box::new(|d, id| {
                    std::fs::remove_file(group_dir(d).join(format!("{id}.json"))).unwrap();
                    std::fs::create_dir_all(group_dir(d).join("scratch")).unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // ROW 12 (F2). Two levels down, where the walk used to stop classifying.
                name: "a directory two levels under the key directory",
                setup: Box::new(|d, id| {
                    std::fs::remove_file(group_dir(d).join(format!("{id}.json"))).unwrap();
                    std::fs::create_dir_all(group_dir(d).join("a").join("b")).unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // ROW 14 (F6). The key directory is a LINK, so the key lands outside
                // `<ks>/` where no scan of it can reach. Named — with its destination —
                // rather than merely refused, and the write that would put a key there is
                // refused outright (see the symlink test below).
                name: "the key directory is a symlink out of the keystore",
                setup: Box::new(|d, _| {
                    let real = d.parent().unwrap().join("groups-elsewhere");
                    std::fs::rename(group_dir(d), &real).unwrap();
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&real, group_dir(d)).unwrap();
                }),
                live: |id| vec![format!("groups/{id}.json")],
                named: false,
                reports: true,
                forgets: true,
            },
            DiskState {
                // A1, MEASURED. The same 594-byte vault, one directory over — described by
                // the scan and ignored by the guard that keyed on the `groups/` prefix.
                name: "a live key one directory over, under a groups-like name",
                setup: Box::new(|d, id| {
                    let p = d.join("groups.bak");
                    std::fs::create_dir_all(&p).unwrap();
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), p.join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!("groups.bak/{id}.json")],
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // A1, MEASURED. A stage name, at the one position the layout does not
                // explain it — root rather than under `groups/`.
                name: "a live key in a group stage at the root",
                setup: Box::new(|d, id| {
                    let p = d.join(format!(".stage-{id}"));
                    std::fs::create_dir_all(&p).unwrap();
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), p.join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!(".stage-{id}/{id}.json")],
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // A1, MEASURED. Liveness is proved in the setup, while the directory is
                // still readable — afterwards this process cannot read it to prove so, and
                // "could not look" is exactly why it must refuse.
                name: "a live key in an unreadable directory beside groups/",
                setup: Box::new(|d, id| {
                    let p = d.join("locked");
                    std::fs::create_dir_all(&p).unwrap();
                    let k = p.join(format!("{id}.json"));
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), &k).unwrap();
                    assert_eq!(reaches_account_zero(&k, "gp"), ACCT0, "the row planted a dead key");
                    restrict_permissions(&p, 0o000).unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // A1, MEASURED. The same, under a name that says nothing at all: only the
                // fact that this scan could not see inside stands between the user and a
                // random key.
                name: "a live key in an unreadable directory at the root",
                setup: Box::new(|d, id| {
                    let p = d.join("opaque");
                    std::fs::create_dir_all(&p).unwrap();
                    let k = p.join("k.json");
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), &k).unwrap();
                    assert_eq!(reaches_account_zero(&k, "gp"), ACCT0, "the row planted a dead key");
                    restrict_permissions(&p, 0o000).unwrap();
                }),
                live: none,
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // A1's residual shape: renamed so NOTHING in the path says "key". Only the
                // bytes do — a vault is a vault whatever it is called.
                name: "a live key at the root under a name that says nothing",
                setup: Box::new(|d, id| {
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), d.join("k.json")).unwrap();
                }),
                live: |_| vec!["k.json".to_string()],
                named: false,
                reports: true,
                forgets: false,
            },
            DiskState {
                // A2. The key's own path is a LINK, so `Path::exists` found a live key the
                // scan will not name. Deriving from what the report denies is the same
                // contradiction as signing with it.
                name: "the key path is a symlink to a live key outside the keystore",
                setup: Box::new(|d, id| {
                    let real = d.parent().unwrap().join(format!("outside-{id}.json"));
                    std::fs::rename(group_dir(d).join(format!("{id}.json")), &real).unwrap();
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&real, group_dir(d).join(format!("{id}.json"))).unwrap();
                }),
                live: |id| vec![format!("groups/{id}.json")],
                named: false,
                reports: true,
                forgets: true,
            },
            DiskState {
                // Why the row above refuses: the same shape can BE the key.
                name: "a live key under a name the layout does not explain",
                setup: Box::new(|d, id| {
                    std::fs::rename(
                        group_dir(d).join(format!("{id}.json")),
                        group_dir(d).join("backup.json"),
                    )
                    .unwrap();
                }),
                live: |_| vec!["groups/backup.json".to_string()],
                named: false,
                reports: true,
                forgets: false,
            },
        ]
    }

    #[test]
    fn every_on_disk_state_of_a_derivation_key_answers_the_same_three_questions() {
        let table = state_table();
        assert!(table.len() >= 21, "the table lost rows: {}", table.len());
        for state in table {
            // Some rows move key material to `<ks>/..`: keep that inside a directory this row owns.
            let own = tempfile::tempdir().unwrap();
            let dir = tempfile::tempdir_in(own.path()).unwrap();
            let (ks, group) = with_group(dir.path());
            // The records are lost so the directory scan answers alone, with no record to agree
            // with. It is what the scan REPORTS that is measured here; what makes a random key
            // safe is the acknowledgement, asserted below in every row alike.
            lose_records(&ks);
            (state.setup)(dir.path(), &group);
            let name = state.name;

            // Measured, not argued: each `live` path really does reach the wallet.
            let live = (state.live)(&group);
            for rel in &live {
                assert_eq!(
                    reaches_account_zero(&dir.path().join(rel), "gp"),
                    ACCT0,
                    "{name}: {rel} was supposed to hold a live account key"
                );
            }

            let named = ks.list_derivation_keys().unwrap();
            assert_eq!(named, if state.named { vec![group.clone()] } else { vec![] }, "{name}");

            // NO STATE WITH RECOVERABLE KEY MATERIAL IS INVISIBLE. Every path that reaches
            // the wallet is named as a key id, as unidentified material, or as a link and
            // where it points — the last is all a scan of `<ks>/` can say about a key
            // outside it, and saying nothing is what F6 did.
            let scan = ks.scan().unwrap();
            // A row whose key sits where this process cannot read it proved that key live in
            // its own setup, so the same coverage is owed for the directory hiding it.
            let hidden: Vec<String> = ["locked".into(), "opaque".into()]
                .into_iter()
                .filter(|p: &String| dir.path().join(p).exists())
                .collect();
            for rel in live.iter().chain(hidden.iter()) {
                let covered = named.iter().any(|id| rel.contains(id.as_str()) && !rel.contains(".json/"))
                    || scan.possible_keys.iter().any(|u| rel.starts_with(u.as_str()))
                    || scan.links.iter().any(|l| rel.starts_with(l.split(" -> ").next().unwrap_or("")));
                assert!(covered, "{name}: {rel} reaches the wallet and nothing in the scan covers it");
            }

            // THE ONE QUERY, now purely a REPORT. It names what could open a whole wallet;
            // it decides nothing, so it no longer has to be complete to be correct.
            let material = ks.group_store().unwrap().possible_key_material().to_vec();
            assert_eq!(!material.is_empty(), state.reports, "{name}: material {material:?}");
            if !live.is_empty() {
                assert!(!material.is_empty(), "{name}: a live account xprv is on disk and unreported");
            }

            // THE PROPERTY, in every row alike: NO RANDOM KEY WITHOUT AN ACKNOWLEDGEMENT —
            // and, once acknowledged, no on-disk state can withhold one. The predecessor
            // ("no state mints") had to be decided by looking at the disk, which is what
            // could not be made sound; this is decided by the caller and holds by
            // construction. Reverting `Unrecoverable::acknowledged` fails here and in
            // `no_random_key_exists_without_the_acknowledgement`.
            assert!(Unrecoverable::acknowledged(false).is_err(), "{name}");
            assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "{name}");

            let forgotten = ks.forget_derivation(&group);
            assert_eq!(forgotten.is_ok(), state.forgets, "{name}: forget said {forgotten:?}");

            // Every path this id can occupy is clear afterwards. A live key the layout does
            // not explain is NOT one of them — it is named by the refusal instead, and the
            // row above proves that refusal happens.
            let store = ks.group_store().unwrap();
            assert!(!store.keys.contains(&group), "{name}: a key survived at the final path");
            assert!(!store.staged.contains(&group), "{name}: a key survived at the staging path");
            for rel in &live {
                let unexplained = rel.starts_with(&format!("groups/{group}.json/"))
                    || !rel.starts_with(&format!("groups/{group}"));
                assert_eq!(
                    dir.path().join(rel).exists(),
                    unexplained && !state.forgets,
                    "{name}: {rel}"
                );
            }

            // And the accounts already derived are untouched by any of it.
            assert!(ks.signer_for(&ACCT0.to_string(), "pw").is_ok(), "{name}: an account was lost");
            reopen(dir.path());
        }
    }

    #[test]
    fn only_the_parent_directory_changes_and_the_answer_does_not() {
        // A1 at its cleanest. ONE group vault, ONE set of bytes, ONE password; nothing
        // varies but the name of the directory holding it. The guard keyed on a `groups/`
        // PREFIX, so four of these five minted an unrecoverable random key beside a live
        // whole-wallet derivation key — each stranded vault proved live by decrypting it.
        //
        // The records are lost throughout: keystore.rs says the key directory is the authority
        // and the record only describes it, so the authority is tested ALONE.
        for (what, parent) in [
            ("the key directory itself", "groups"),
            ("one directory over", "groups.bak"),
            ("a group stage at the root", ".stage-{id}"),
            ("a name that says nothing", "elsewhere"),
            ("a directory nobody may read", "locked"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            lose_records(&ks);

            let home = dir.path().join(parent.replace("{id}", &group));
            std::fs::create_dir_all(&home).unwrap();
            let key = home.join(format!("{group}.json"));
            if key != group_dir(dir.path()).join(format!("{group}.json")) {
                std::fs::rename(group_dir(dir.path()).join(format!("{group}.json")), &key).unwrap();
            }
            // MEASURED: these bytes still open the whole wallet, wherever they now sit.
            assert_eq!(reaches_account_zero(&key, "gp"), ACCT0, "{what}: planted a dead key");
            let shut = what.contains("nobody may read");
            if shut {
                restrict_permissions(&home, 0o000).unwrap();
            }

            // NOTHING WITH RECOVERABLE KEY MATERIAL IS INVISIBLE.
            let material = ks.group_store().unwrap().possible_key_material().to_vec();
            let rel = key.strip_prefix(dir.path()).unwrap().to_string_lossy().into_owned();
            assert!(
                material.iter().any(|m| rel.starts_with(m.as_str())),
                "{what}: {rel} opens the wallet and the one query missed it: {material:?}"
            );

            // AND THE ACKNOWLEDGEMENT IS WHAT A RANDOM KEY COSTS, in all five — which is
            // exactly why the report above no longer has to be complete to be safe.
            assert!(Unrecoverable::acknowledged(false).is_err(), "{what}");
            assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "{what}");
            if shut {
                restrict_permissions(&home, 0o700).unwrap();
            }
        }
    }

    #[test]
    fn the_use_path_asks_the_authority_rather_than_the_filesystem() {
        // A2. `signer_for`, `has_address`, `delete_account` and `derive_*` all resolved by
        // `Path::exists`, which FOLLOWS SYMLINKS — so material was live and signable while
        // the scan refused to list it (measured: listed=[], has_address=true, signs=true).
        // If the authority does not name it, using it is a contradiction.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());

            // Half one: the account vault's path is a link to a live key elsewhere.
            let donor = Keystore::new(outside.path());
            let acct = donor.import_private_key(ACCT0_PK, "pw").unwrap();
            let real = vault_file(&donor, &acct);
            let linked = vault_file(&ks, &ACCT0);
            let link_name = linked.file_name().unwrap().to_string_lossy().into_owned();
            std::fs::remove_file(&linked).unwrap();
            std::os::unix::fs::symlink(&real, &linked).unwrap();
            assert_eq!(opens_to(&linked, "pw"), ACCT0, "the link does not reach a live key");

            let listed = ks.list_accounts().unwrap();
            assert!(!listed.contains(&ACCT0), "the authority named a link: {listed:?}");
            assert!(!ks.has_address(&ACCT0.to_string()));
            for used in [
                ks.sign_message(&ACCT0.to_string(), "pw", "hi").err(),
                ks.sign_digest(&ACCT0.to_string(), "pw", &format!("0x{}", "11".repeat(32))).err(),
                ks.export_keystore_json(&ACCT0.to_string(), "pw").err(),
                ks.change_password(&ACCT0.to_string(), "pw", "pw2").err(),
                ks.delete_account(&ACCT0.to_string(), "pw").err(),
            ] {
                assert!(used.is_some(), "an unlisted vault was used");
            }
            // Named, and removable by name — refusing without that would be a wedge.
            assert!(ks.scan().unwrap().stray().contains(&link_name));
            assert!(ks.remove_unexplained(&link_name, true).unwrap());
            assert!(std::fs::read_to_string(&real).is_ok(), "removal followed the link");

            // Half two: the derivation key's path is a link to a live key elsewhere.
            let key = group_dir(dir.path()).join(format!("{group}.json"));
            let away = outside.path().join("extkey.json");
            std::fs::rename(&key, &away).unwrap();
            std::os::unix::fs::symlink(&away, &key).unwrap();
            assert_eq!(reaches_account_zero(&key, "gp"), ACCT0, "the link does not reach the wallet");

            assert!(ks.list_derivation_keys().unwrap().is_empty(), "the authority named a link");
            assert!(ks.derive_next_account(Some(&group), "gp", "pw", 0).is_err());
            assert!(ks.derive_account_at(&group, "gp", "pw", None, 0, 5).is_err());
            assert!(ks.preview_addresses(&group, "gp", 0, 0, 2).is_err());
            // Unlisted, but not invisible: the one query still names it, so a reader is told.
            let material = ks.group_store().unwrap().possible_key_material().to_vec();
            assert!(material.contains(&format!("groups/{group}.json")), "{material:?}");
        }
    }

    #[test]
    fn a_key_at_the_staging_path_is_reported_exactly_as_the_live_one_is() {
        // Reproduces F1 by construction: the same bytes at the two paths, and the two
        // answers that used to differ. What they must now agree on is the REPORT.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let stage = dir.path().join("groups").join(format!(".stage-{group}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::rename(ks.group_vault_path(&group), stage.join(format!("{group}.json"))).unwrap();

        assert_eq!(reaches_account_zero(&stage.join(format!("{group}.json")), "gp"), ACCT0);
        assert_eq!(ks.list_derivation_keys().unwrap(), vec![group.clone()]);
        let material = ks.group_store().unwrap().possible_key_material().to_vec();
        assert!(material.iter().any(|m| m.contains(&group)), "the staged key is unreported: {material:?}");

        // It is not promoted to the live key either: a half-written file is not a vault.
        assert!(ks.derive_next_account(Some(&group), "gp", "pw", 0).is_err());
        assert!(!ks.list_groups().unwrap()[0].derivable);
        assert!(ks.list_groups().unwrap()[0].staged, "the UI has to be able to say why");
    }

    #[test]
    fn a_blocked_rename_leaves_no_key_at_the_staging_path() {
        // The deterministic F1 repro: a directory where the vault file goes, so the rename
        // fails with the staged copy already written and already decryptable.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        let encoded = String::from_utf8(
            eth_keystore::decrypt_key(ks.group_vault_path(&group), "gp").unwrap(),
        )
        .unwrap();

        let blocked = format!("g_{}", "a".repeat(32));
        std::fs::create_dir_all(ks.group_vault_path(&blocked)).unwrap();
        let e = ks.write_group_vault(&blocked, &encoded, "gp").unwrap_err().to_string();
        assert!(e.contains("irectory"), "the rename was supposed to fail on the directory: {e}");

        assert!(!ks.stage_dir(&blocked).exists(), "a decryptable account key was left staged");
        let store = ks.group_store().unwrap();
        assert!(store.staged.is_empty(), "left staged: {:?}", store.staged);
        assert_eq!(store.keys, vec![group], "the real key must be untouched");
    }

    #[test]
    fn the_staging_directory_is_removed_even_when_the_write_panics() {
        // The guard covers every path this process can take; the scan covers the one it
        // cannot. Without the guard a panic mid-write leaves a decryptable key behind.
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join(".stage-probe");
        let hit = std::panic::catch_unwind(|| {
            let guard = atomic::Stage::create(stage.clone()).unwrap();
            std::fs::write(guard.path().join("key.json"), "ciphertext").unwrap();
            panic!("ENOSPC");
        });
        assert!(hit.is_err());
        assert!(!stage.exists(), "the staged copy outlived the panic");
    }

    #[test]
    fn a_key_that_cannot_be_opened_is_still_deletable() {
        // F2: gating deletion on decryption made a key whose password is lost permanently
        // undeletable — while it went on refusing every new account. Cannot derive, cannot
        // stop being derivable.
        for (name, break_it) in [
            ("wrong password", Box::new(|_: &Path, _: &str| {}) as Mutate),
            ("corrupt bytes", Box::new(|d: &Path, id: &str| {
                std::fs::write(d.join("groups").join(format!("{id}.json")), "{ not a vault").unwrap()
            })),
            ("unreadable file", Box::new(|d: &Path, id: &str| {
                restrict_permissions(&d.join("groups").join(format!("{id}.json")), 0o000).unwrap()
            })),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            break_it(dir.path(), &group);

            // The key cannot be opened, so nothing can be derived from it.
            assert!(ks.derive_next_account(Some(&group), "LOST", "pw", 0).is_err(), "{name}");

            assert!(ks.forget_derivation(&group).is_ok(), "{name}: the key is undeletable");
            assert!(ks.group_store().unwrap().holds_nothing(), "{name}");
            // And it has stopped being derivable, which is the whole point of forgetting it.
            assert!(!ks.list_groups().unwrap()[0].derivable, "{name}");
            assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "{name}");
            assert!(ks.signer_for(&ACCT0.to_string(), "pw").is_ok(), "{name}: an account was lost");
        }
    }

    // ---- every on-disk state an ACCOUNT vault can be in --------------------
    //
    // The group table, one directory up, in the half that fix never touched. Two shapes had
    // already been fixed under `groups/` and were still here: `change_password` staged a
    // LIVE ACCOUNT KEY at `.rekey-<addr>/<addr>.json`, past two early returns and a panic,
    // and nothing ever removed it — while `list_accounts` dropped anything it did not
    // recognise, that copy included, without a word.
    //
    // Every row asserts the same questions AND the universal properties: no live key is
    // invisible, no state stops the keystore working, and a wrong password never signs.

    /// What `delete_account` does. `Refuses` is the surviving shape of the defect the group
    /// half fixed by dropping its password gate: an account whose vault cannot be decrypted
    /// cannot be removed. Recorded rather than fixed — "the password is the only proof of
    /// ownership of an account" is a policy call, not file management.
    #[derive(PartialEq, Eq, Debug)]
    enum Deletes {
        Yes,
        Nothing,
        Refuses,
    }

    /// One on-disk state of ACCT0's vault, given the keystore directory and its filename.
    struct AccountState {
        name: &'static str,
        setup: Box<dyn Fn(&Path, &str)>,
        /// Paths under the keystore whose bytes still decrypt to ACCT0's key, before
        /// anything settles them. Measured, not assumed from a filename.
        live: fn(&str) -> Vec<String>,
        listed: bool,
        signs: bool,
        rekeys: bool,
        deletes: Deletes,
        /// Must the scan name something under `<ks>/` that this module did not write?
        reports: bool,
        /// Must it name an unfinished document write?
        doc_stage: bool,
        /// Must it name an import scratch copy? F1's leftover was in `$TMPDIR`, under a
        /// name no authority in this module could reach.
        import_stage: bool,
    }

    fn no_paths(_: &str) -> Vec<String> {
        Vec::new()
    }

    /// Decrypt a vault and recover its address. This is what "holds a live account key"
    /// means here: not that a file exists, but that its bytes still sign for ACCT0.
    fn opens_to(path: &Path, password: &str) -> Address {
        let key = Zeroizing::new(eth_keystore::decrypt_key(path, password).unwrap());
        PrivateKeySigner::from_slice(&key).unwrap().address()
    }

    fn account_state_table() -> Vec<AccountState> {
        let vault = |d: &Path, a: &str| d.join(format!("{a}.json"));
        vec![
            AccountState {
                name: "final path only",
                setup: Box::new(|_, _| {}),
                live: |a| vec![format!("{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                // FINDING A's state, reachable by SIGKILL between the write and the rename.
                name: "staging path only",
                setup: Box::new(move |d, a| {
                    let stage = d.join(format!(".stage-{a}"));
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::rename(vault(d, a), stage.join(format!("{a}.json"))).unwrap();
                }),
                live: |a| vec![format!(".stage-{a}/{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                // The rename landed and the cleanup did not. The final vault is intact by
                // construction, so the copy is redundant and is reaped.
                name: "both paths",
                setup: Box::new(move |d, a| {
                    let stage = d.join(format!(".stage-{a}"));
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::copy(vault(d, a), stage.join(format!("{a}.json"))).unwrap();
                }),
                live: |a| vec![format!("{a}.json"), format!(".stage-{a}/{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "neither — no vault at all",
                setup: Box::new(move |d, a| std::fs::remove_file(vault(d, a)).unwrap()),
                live: no_paths,
                listed: false, signs: false, rekeys: false, deletes: Deletes::Nothing,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                // Not live, but indistinguishable from live without the password.
                name: "corrupt vault at the final path",
                setup: Box::new(move |d, a| std::fs::write(vault(d, a), "").unwrap()),
                live: no_paths,
                listed: true, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "unreadable vault at the final path",
                setup: Box::new(move |d, a| restrict_permissions(&vault(d, a), 0o000).unwrap()),
                live: no_paths, // present and live, but this process cannot read it to prove so
                listed: true, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "a directory where the file belongs",
                setup: Box::new(move |d, a| {
                    std::fs::remove_file(vault(d, a)).unwrap();
                    std::fs::create_dir_all(vault(d, a)).unwrap();
                }),
                live: no_paths,
                listed: false, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "a directory where the file belongs, holding the key",
                setup: Box::new(move |d, a| {
                    let moved = d.join("moved");
                    std::fs::rename(vault(d, a), &moved).unwrap();
                    std::fs::create_dir_all(vault(d, a)).unwrap();
                    std::fs::rename(&moved, vault(d, a).join(format!("{a}.json"))).unwrap();
                }),
                live: |a| vec![format!("{a}.json/{a}.json")],
                listed: false, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                // ROW 6 exactly: a live key the name-pattern scan dropped without a word.
                name: "a live key under a name the layout does not explain",
                setup: Box::new(move |d, a| {
                    std::fs::rename(vault(d, a), d.join("backup.json")).unwrap()
                }),
                live: |_| vec!["backup.json".to_string()],
                listed: false, signs: false, rekeys: false, deletes: Deletes::Nothing,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                // FINDING A's actual leftover, written by the code this pass replaced. It is
                // a live account key, and it used to be invisible to every authority.
                name: "the old hand-rolled rekey stage, holding a live key",
                setup: Box::new(move |d, a| {
                    let rekey = d.join(format!(".rekey-{a}"));
                    std::fs::create_dir_all(&rekey).unwrap();
                    std::fs::copy(vault(d, a), rekey.join(format!("{a}.json"))).unwrap();
                }),
                live: |a| vec![format!("{a}.json"), format!(".rekey-{a}/{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "a stale staging directory, empty",
                setup: Box::new(|d, a| std::fs::create_dir_all(d.join(format!(".stage-{a}"))).unwrap()),
                live: |a| vec![format!("{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                // Not reaped: a peer's in-flight document write holds an open descriptor on
                // one of these, and deleting it would break their rename.
                name: "a stale document stage",
                setup: Box::new(|d, _| {
                    std::fs::write(d.join(format!("{}orphan", crate::atomic::DOC_STAGE_PREFIX)), "{").unwrap()
                }),
                live: |a| vec![format!("{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: true, import_stage: false,
            },
            AccountState {
                // ROW 9 (F1). The caller's ciphertext, left by a kill mid-import. It used to
                // land in $TMPDIR at 0600 in a SHARED directory, under a name `layout::scan`
                // could not reach and no restart swept. Inside `<ks>/` it is named and swept.
                name: "an import scratch copy a kill left behind",
                setup: Box::new(move |d, a| {
                    let stage = d.join(format!(".stage-import-{}", "ab".repeat(16)));
                    std::fs::create_dir_all(&stage).unwrap();
                    std::fs::copy(vault(d, a), stage.join("import.json")).unwrap();
                }),
                live: |a| vec![format!("{a}.json"), format!(".stage-import-{}/import.json", "ab".repeat(16))],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: false, doc_stage: false, import_stage: true,
            },
            AccountState {
                // ROW 13 (F3). A vault at another address's filename. The wallet listed the
                // FILENAME's address as a live account, and signing as it used the key
                // inside — a signature attributed to an account whose key never touched it.
                name: "a vault whose key is not the address its filename claims",
                setup: Box::new(move |d, a| {
                    std::fs::rename(vault(d, a), vault(d, &"b".repeat(40))).unwrap()
                }),
                live: |_| vec![format!("{}.json", "b".repeat(40))],
                listed: false, signs: false, rekeys: false, deletes: Deletes::Nothing,
                reports: false, doc_stage: false, import_stage: false,
            },
            AccountState {
                // A2, MEASURED. `Path::exists` FOLLOWS SYMLINKS, so this was live and
                // signable while `list_accounts` reported an empty wallet: has_address=true,
                // signs=true, listed=[]. Signing what the authority will not name is a
                // contradiction, so the use path asks the scan now.
                name: "the vault path is a symlink to a live key outside the keystore",
                setup: Box::new(move |d, a| {
                    let real = d.parent().unwrap().join(format!("outside-{a}.json"));
                    std::fs::rename(vault(d, a), &real).unwrap();
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&real, vault(d, a)).unwrap();
                }),
                live: |a| vec![format!("{a}.json")],
                listed: false, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                // The same shape aimed back INSIDE `<ks>/`: both paths are live, neither is
                // a vault this keystore wrote, and both are named rather than signed for.
                name: "the vault path is a symlink to a live key inside the keystore",
                setup: Box::new(move |d, a| {
                    std::fs::rename(vault(d, a), d.join("backup.json")).unwrap();
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(d.join("backup.json"), vault(d, a)).unwrap();
                }),
                live: |a| vec![format!("{a}.json"), "backup.json".to_string()],
                listed: false, signs: false, rekeys: false, deletes: Deletes::Refuses,
                reports: true, doc_stage: false, import_stage: false,
            },
            AccountState {
                name: "a file the layout does not explain",
                setup: Box::new(|d, _| std::fs::write(d.join("notes.txt"), "hand-edited").unwrap()),
                live: |a| vec![format!("{a}.json")],
                listed: true, signs: true, rekeys: true, deletes: Deletes::Yes,
                reports: true, doc_stage: false, import_stage: false,
            },
        ]
    }

    #[test]
    fn every_on_disk_state_of_an_account_vault_answers_the_same_questions() {
        let table = account_state_table();
        assert!(table.len() >= 17, "the table lost rows: {}", table.len());
        for state in table {
            let name = state.name;
            // Some rows move key material to `<ks>/..`: keep that inside a directory this row owns.
            let own = tempfile::tempdir().unwrap();
            let dir = tempfile::tempdir_in(own.path()).unwrap();
            let ks = Keystore::new(dir.path());
            let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
            assert_eq!(addr, ACCT0);
            let a = vault_file(&ks, &ACCT0).file_stem().unwrap().to_string_lossy().into_owned();
            (state.setup)(dir.path(), &a);

            // Measured, not argued: each `live` path really does sign for ACCT0.
            let live = (state.live)(&a);
            for rel in &live {
                assert_eq!(
                    opens_to(&dir.path().join(rel), "pw"), ACCT0,
                    "{name}: {rel} was supposed to hold a live account key"
                );
            }

            // NO STATE WITH RECOVERABLE KEY MATERIAL IS INVISIBLE — asserted BEFORE anything
            // settles, because a repair that removes the evidence is not a report.
            let before = ks.scan().unwrap();
            assert_eq!(!before.import_stages.is_empty(), state.import_stage, "{name}");
            let before_stray = before.stray();
            for rel in &live {
                let named = rel == &format!("{a}.json")
                    || before.vaults.iter().any(|v| rel == &format!("{v}.json"))
                    || before.staged_vaults.iter().any(|v| rel.starts_with(&format!(".stage-{v}/")))
                    || before.import_stages.iter().any(|n| rel.starts_with(&format!(".stage-import-{n}/")))
                    || before_stray.iter().any(|u| rel.starts_with(u.as_str()));
                assert!(named, "{name}: {rel} holds a live key and nothing in the scan covers it");
            }

            // The listing settles what the layout can settle, then answers.
            let listed = ks.list_accounts().unwrap();
            assert_eq!(listed.contains(&ACCT0), state.listed, "{name}: listed {listed:?}");
            let settled = ks.scan().unwrap();
            let stray = settled.stray();
            assert_eq!(!stray.is_empty(), state.reports, "{name}: stray {stray:?}");
            assert_eq!(!settled.doc_stages.is_empty(), state.doc_stage, "{name}");

            // And still invisible to nothing AFTER the repair: settled onto its real path,
            // swept, or named — as a vault file, as staged, or as unidentified material.
            for rel in &live {
                let settled_away = !dir.path().join(rel).exists();
                let at_the_real_path = rel == &format!("{a}.json");
                let named = stray.iter().any(|u| rel.starts_with(u.as_str()))
                    || settled.vaults.iter().any(|v| rel == &format!("{v}.json"))
                    || settled.staged_vaults.contains(&a);
                assert!(settled_away || at_the_real_path || named,
                        "{name}: {rel} holds a live account key and nothing names it");
            }

            // A2's universal property: NOT LISTED MEANS NOT SIGNABLE. The use path resolved
            // by `Path::exists`, which follows symlinks, so the two could disagree.
            assert_eq!(ks.has_address(&ACCT0.to_string()), listed.contains(&ACCT0), "{name}");
            if !listed.contains(&ACCT0) {
                assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_err(),
                        "{name}: signed for an address the authority does not name");
            }

            // A WRONG PASSWORD NEVER SIGNS, in any state.
            assert!(ks.sign_message(&ACCT0.to_string(), "WRONG", "hi").is_err(), "{name}");
            assert!(ks.change_password(&ACCT0.to_string(), "WRONG", "new").is_err(), "{name}");
            assert_eq!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok(), state.signs,
                       "{name}: signing");

            let mut password = "pw";
            let rekeyed = ks.change_password(&ACCT0.to_string(), "pw", "pw2");
            assert_eq!(rekeyed.is_ok(), state.rekeys, "{name}: change_password said {rekeyed:?}");
            if rekeyed.is_ok() {
                password = "pw2";
                assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_err(), "{name}");
                assert!(ks.sign_message(&ACCT0.to_string(), "pw2", "hi").is_ok(), "{name}");
            }
            // FINDING A's regression: a re-encryption leaves NO copy at the source.
            assert!(ks.scan().unwrap().vault_stages.is_empty(),
                    "{name}: change_password left a live key staged");

            let deleted = ks.delete_account(&ACCT0.to_string(), password);
            let what = match &deleted {
                Ok(true) => Deletes::Yes,
                Ok(false) => Deletes::Nothing,
                Err(_) => Deletes::Refuses,
            };
            assert_eq!(what, state.deletes, "{name}: delete said {deleted:?}");

            // NO STATE STOPS THE KEYSTORE WORKING: a fresh account still lands, still lists
            // and still signs, whatever the row above left behind.
            let fresh = ks.create_unrelated_account("fresh", acked()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(ks.list_accounts().unwrap().contains(&fresh), "{name}");
            assert!(ks.sign_message(&fresh.to_string(), "fresh", "hi").is_ok(), "{name}");
        }
    }

    #[test]
    fn re_encrypting_a_vault_replaces_it_atomically_rather_than_truncating_it() {
        // ROW 1. `eth_keystore::encrypt_key` is one `File::create` straight to the
        // destination, so an in-place write TRUNCATES the live vault and a crash in that
        // window destroys the only copy of the key. Staged-and-renamed is observable
        // WITHOUT a crash: a reader holding the old file still reads the whole old vault,
        // because the rename replaced the name and never those bytes.
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let path = vault_file(&ks, &addr);
        let before = std::fs::read_to_string(&path).unwrap();

        let mut held = std::fs::File::open(&path).unwrap();
        ks.change_password(&addr.to_string(), "pw", "pw2").unwrap();

        let mut seen = String::new();
        held.read_to_string(&mut seen).unwrap();
        assert_eq!(seen, before, "the live vault was written in place, not replaced");
        assert_ne!(std::fs::read_to_string(&path).unwrap(), before, "the new vault never landed");
        assert!(ks.sign_message(&addr.to_string(), "pw2", "hi").is_ok());
        assert!(ks.scan().unwrap().vault_stages.is_empty(), "a copy was left at the source");
    }

    #[test]
    fn an_unreadable_keystore_directory_is_refused_rather_than_reported_as_an_empty_wallet() {
        // Shape 2, one directory up. `list_accounts` swallowed every read_dir error and
        // returned an empty Vec, so a user with a funded wallet was told they had none —
        // and `provenance_view` and the module's account count all repeated it.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0]);

        restrict_permissions(dir.path(), 0o000).unwrap();
        let listed = ks.list_accounts();
        let seen = ks.provenance_view();
        restrict_permissions(dir.path(), 0o700).unwrap();

        assert!(matches!(listed, Err(KeystoreError::Corrupt(..))), "got {listed:?}");
        assert!(seen.is_err(), "provenance repeated the empty answer");
        assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0], "the wallet is still there");
    }

    // ---- F3, F5, F6: the filename, the sweep, and the link -----------------

    #[test]
    fn a_vault_whose_key_is_not_its_filename_is_refused_rather_than_signed_for() {
        // F3. The filename is a CLAIM and the decrypted key is the proof, so the proof wins
        // wherever it is available. Trusting the CONTENTS instead is unimplementable at
        // report time — listing has no password — and at use time the two rules agree, so
        // this refuses the mismatch and does it at every point where it is knowable.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let vault = vault_file(&ks, &ACCT0);
        let wrong = "b".repeat(40);
        // The index names ACCT0's vault for another address.
        ks.update_accounts(|all| {
            let p = all.remove(&addr_key(&ACCT0)).unwrap();
            all.insert(wrong.clone(), p);
        })
        .unwrap();
        let claimed = format!("0x{wrong}");

        // Before: this signed with ACCT0's key and handed back a signature the caller
        // attributed to `wrong`.
        for e in [
            ks.sign_message(&claimed, "pw", "hi").unwrap_err(),
            ks.sign_digest(&claimed, "pw", &format!("0x{}", "11".repeat(32))).unwrap_err(),
            ks.export_keystore_json(&claimed, "pw").unwrap_err(),
            ks.change_password(&claimed, "pw", "pw2").unwrap_err(),
        ] {
            let text = e.to_string();
            assert!(text.contains(&ACCT0.to_string()), "the refusal must name the key it found: {text}");
            assert!(text.contains(&wrong), "and the address that was asked for: {text}");
        }
        // Deleting `wrong` must not destroy ACCT0's only key on the way.
        assert!(ks.delete_account(&claimed, "pw").is_err());
        assert!(vault.exists());

        // The other half: a vault that DECLARES an address disagreeing with its filename is
        // not listed as an account at all — there the mismatch is knowable without a password.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let path = vault_file(&ks, &ACCT0);
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["address"] = serde_json::json!(wrong);
        std::fs::write(&path, v.to_string()).unwrap();

        let report = ks.account_report().unwrap();
        assert!(!report.accounts.contains(&ACCT0), "an address the vault disputes was listed");
        assert_eq!(report.mismatched.len(), 1, "{:?}", report.mismatched);
        assert!(report.mismatched[0].contains(&wrong));
        // Named as unexplained too, so the one removal path reaches it.
        assert!(report.unexplained.contains(&path.file_name().unwrap().to_string_lossy().into_owned()));
        // And the two answers agree: `has_address` used to say yes off the filename alone.
        assert!(!ks.has_address(&ACCT0.to_string()));
    }

    #[test]
    fn a_settled_stage_is_removable_by_name_rather_than_only_by_listing() {
        // F5. `settle` ran only as a side effect of listing, so a stage a crash left behind
        // disappeared when something happened to call `list_accounts` and not otherwise.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let a = vault_file(&ks, &ACCT0).file_stem().unwrap().to_string_lossy().into_owned();
        let stage = dir.path().join(format!(".stage-{a}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::copy(dir.path().join(format!("{a}.json")), stage.join(format!("{a}.json"))).unwrap();
        let import = dir.path().join(format!(".stage-import-{}", "cd".repeat(16)));
        std::fs::create_dir_all(&import).unwrap();
        std::fs::copy(dir.path().join(format!("{a}.json")), import.join("import.json")).unwrap();

        let scan = ks.scan().unwrap();
        assert_eq!(scan.vault_stages, vec![a.clone()]);
        assert_eq!(scan.import_stages, vec!["cd".repeat(16)]);

        // Called by name, with nothing listing first.
        let left = ks.settle().unwrap();
        assert!(!stage.exists() && !import.exists(), "the named sweep left them behind");
        assert_eq!(left.swept.len(), 2, "the sweep must SAY what it removed: {:?}", left.swept);
        assert!(left.left.vault_stages.is_empty() && left.left.import_stages.is_empty());
        assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok(), "the account was lost");
    }

    #[test]
    fn a_symlinked_key_directory_refuses_the_write_and_says_where_it_points() {
        // F6. A link puts the key outside `<ks>/`, where no scan of it can name what landed.
        // So the write is refused rather than followed, the link is named WITH its target,
        // and the link itself is removable like anything else the layout does not explain.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let ks_dir = dir.path().join("ks");
            let elsewhere = dir.path().join("elsewhere");
            std::fs::create_dir_all(&ks_dir).unwrap();
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, ks_dir.join("groups")).unwrap();
            let ks = Keystore::new(&ks_dir);

            let e = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap_err().to_string();
            assert!(e.contains("groups/ is not a directory"), "got {e}");
            assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "a key landed outside");

            let scan = ks.scan().unwrap();
            assert_eq!(scan.links.len(), 1, "{:?}", scan.links);
            assert!(scan.links[0].starts_with("groups -> ") && scan.links[0].contains("elsewhere"));
            assert_eq!(scan.possible_keys, vec!["groups".to_string()]);

            // Nameable and removable, and then the write it was blocking succeeds.
            assert!(ks.remove_unexplained("groups", false).is_err(), "an unacknowledged removal");
            assert!(ks.remove_unexplained("groups", true).unwrap());
            assert!(ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).is_ok());
            assert!(ks.scan().unwrap().links.is_empty());
        }
    }

    #[test]
    fn every_path_the_scan_reports_is_removable_by_name() {
        // The other side of "nothing is dropped in silence": a report nothing can act on is
        // only half an answer. Every shape a crash or a hand-edit can leave is removable,
        // and nothing else is — a path the scan did not produce cannot be named at all.
        let plant: Vec<(&str, Box<dyn Fn(&Path)>)> = vec![
            ("a hand-placed backup", Box::new(|d: &Path| {
                std::fs::write(d.join("backup.json"), "{}").unwrap()
            })),
            ("a directory where a vault belongs", Box::new(move |d: &Path| {
                std::fs::create_dir_all(d.join(format!("{}.json", "0".repeat(40)))).unwrap()
            })),
            ("a directory two levels deep", Box::new(|d: &Path| {
                std::fs::create_dir_all(d.join("a").join("b")).unwrap()
            })),
            ("a leftover document stage", Box::new(|d: &Path| {
                std::fs::write(d.join(format!("{}x", crate::atomic::DOC_STAGE_PREFIX)), "{").unwrap()
            })),
            ("an empty directory where a key belongs", Box::new(|d: &Path| {
                std::fs::create_dir_all(d.join("groups").join(format!("g_{}.json", "0".repeat(32)))).unwrap()
            })),
        ];
        for (name, plant) in plant {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            ks.import_private_key(ACCT0_PK, "pw").unwrap();
            plant(dir.path());

            let reported = ks.scan().unwrap().unexplained_all();
            assert!(!reported.is_empty(), "{name}: nothing was reported to remove");
            assert!(ks.remove_unexplained(&reported[0], false).is_err(), "{name}: removed unacknowledged");
            // Outermost first, so removing a directory takes what is nested inside it.
            for _ in 0..reported.len() {
                match ks.scan().unwrap().unexplained_all().first() {
                    Some(path) => assert!(ks.remove_unexplained(path, true).unwrap(), "{name}"),
                    None => break,
                }
            }
            assert!(ks.scan().unwrap().unexplained_all().is_empty(), "{name}");
            assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok(), "{name}: an account was lost");
        }

        // Only what the scan itself produced. A path it did not report cannot be named,
        // which is what keeps this from being an arbitrary-delete primitive.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        for hostile in ["../../etc/passwd", "/etc/passwd", &format!("{addr:x}.json"), "groups.json", ""] {
            assert!(ks.remove_unexplained(hostile, true).is_err(), "{hostile:?} was accepted");
        }
        assert!(ks.sign_message(&addr.to_string(), "pw", "hi").is_ok());
    }

    // ---- the two tripwires under the authority -----------------------------

    #[test]
    fn every_path_this_module_writes_is_classified() {
        // The forcing function that does not depend on the type system. `Slot` stops a new
        // path being BUILT; this walks what actually landed, so it catches one arriving by
        // any route at all — including one `eth_keystore` writes for us.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());

        let d = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        ks.derive_next_account(None, "gp", "pw", 0).unwrap();
        let at = ks.derive_account_at(&d.group, "gp", "pw", None, 0, 9).unwrap();
        ks.preview_addresses(&d.group, "gp", 0, 0, 2).unwrap();
        let unrelated = ks.create_unrelated_account("pw", acked()).unwrap();
        let json = ks.export_keystore_json(&unrelated.to_string(), "pw").unwrap();
        ks.change_password(&unrelated.to_string(), "pw", "pw2").unwrap();
        ks.set_label(&unrelated.to_string(), "Savings", "pw2").unwrap();
        ks.set_group_label(&rename_as(&d.group, "Cold storage", &d.address.to_string(), "pw")).unwrap();
        ks.remove_group(&d.group).unwrap_err();
        ks.delete_account(&at.address.to_string(), "pw").unwrap();
        ks.forget_derivation(&d.group).unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let ks2 = Keystore::new(d2.path());
        ks2.import_keystore_json(&json, "pw", "pw3").unwrap();
        ks2.import_private_key(ACCT0_PK, "pw").unwrap();
        ks2.create_unrelated_account("pw", acked()).unwrap();

        // The listing is typed as addresses, not as the lowercase filenames it read them
        // from — which is what makes the module render them EIP-55 checksummed over IPC.
        assert!(ks2.list_accounts().unwrap().iter().any(|a| a.to_string().contains(char::is_uppercase)));

        for (label, ks) in [("mutated", &ks), ("imported", &ks2)] {
            let s = ks.scan().unwrap();
            assert!(s.unexplained.is_empty(), "{label}: unexplained {:?}", s.unexplained);
            assert!(s.possible_keys.is_empty(), "{label}: {:?}", s.possible_keys);
            assert!(s.doc_stages.is_empty(), "{label}: {:?}", s.doc_stages);
            assert!(s.vault_stages.is_empty(), "{label}: {:?}", s.vault_stages);
            assert!(s.staged_vaults.is_empty(), "{label}: {:?}", s.staged_vaults);
            assert!(s.staged.is_empty(), "{label}: {:?}", s.staged);
        }
    }

    #[test]
    fn a_stray_path_is_reported_and_wedges_nothing() {
        // THE WEDGE, removed. Every one of these was a path the layout does not explain,
        // and the previous round refused on all of them so that a hidden derivation key
        // could not be missed by the mint guard. An unreadable `groups/` was the worst:
        // `scan` returned an error, so listing, signing, settling AND `remove_unexplained`
        // all failed — the store could not even be repaired. With the acknowledgement
        // carrying the safety property, these are reports.
        let plant: Vec<(&str, Box<dyn Fn(&Path)>, &str)> = vec![
            ("an unreadable key directory", Box::new(|d: &Path| {
                std::fs::create_dir_all(d.join("groups")).unwrap();
                restrict_permissions(&d.join("groups"), 0o000).unwrap();
            }), "groups"),
            ("an unreadable directory at the root", Box::new(|d: &Path| {
                std::fs::create_dir_all(d.join("opaque")).unwrap();
                restrict_permissions(&d.join("opaque"), 0o000).unwrap();
            }), "opaque"),
            ("a vault-shaped file under a name that says nothing", Box::new(|d: &Path| {
                let vault = r#"{"crypto":{"cipher":"aes-128-ctr","ciphertext":"ab","kdf":"scrypt"},"id":"x","version":3}"#;
                std::fs::write(d.join("k.json"), vault).unwrap();
            }), "k.json"),
            ("a plain stray file", Box::new(|d: &Path| {
                std::fs::write(d.join(".DS_Store"), "x").unwrap()
            }), ".DS_Store"),
        ];
        for (name, plant, rel) in plant {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            ks.import_private_key(ACCT0_PK, "pw").unwrap();
            plant(dir.path());

            // REPORTED, by name, in the one place a reader looks.
            assert!(ks.scan().unwrap().unexplained_all().iter().any(|p| p == rel),
                    "{name}: {rel} is not reported");
            // AND NOTHING IS WEDGED: the wallet lists, signs, settles, and still accepts an
            // acknowledged key. Each of these refused before.
            assert!(ks.list_accounts().unwrap().contains(&ACCT0), "{name}");
            assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok(), "{name}");
            assert!(ks.settle().is_ok(), "{name}");
            assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "{name}");
            // And the report is actionable: a reported path is removable by name, which is
            // what turns "your store is in a state I cannot explain" into something a user
            // can act on rather than a dead end.
            assert!(ks.remove_unexplained(rel, false).is_err(), "{name}: unacknowledged");
            assert!(ks.remove_unexplained(rel, true).unwrap(), "{name}");
            assert!(ks.scan().unwrap().unexplained_all().is_empty(), "{name}");
        }
    }

    #[test]
    fn every_shape_a_crash_can_leave_behind_is_reported() {
        // The other half: nothing this module did NOT write may be dropped in silence. Each
        // of these was reachable before and named by nothing.
        let plant: Vec<(&str, Box<dyn Fn(&Path)>, &str)> = vec![
            ("a leftover document stage", Box::new(|d: &Path| {
                std::fs::write(d.join(format!("{}x", crate::atomic::DOC_STAGE_PREFIX)), "{").unwrap()
            }), "doc_stages"),
            ("the old fixed-name sidecar stage", Box::new(|d: &Path| {
                std::fs::write(d.join("groups.json.tmp"), "{}").unwrap()
            }), "unexplained"),
            ("the old rekey stage directory", Box::new(move |d: &Path| {
                std::fs::create_dir_all(d.join(format!(".rekey-{}", format!("{:x}", ACCT0)))).unwrap()
            }), "unexplained"),
            ("a hand-placed backup", Box::new(|d: &Path| {
                std::fs::write(d.join("backup.json"), "{}").unwrap()
            }), "unexplained"),
            ("a directory where a vault belongs", Box::new(move |d: &Path| {
                std::fs::create_dir_all(d.join(format!("{}.json", "0".repeat(40)))).unwrap()
            }), "unexplained"),
            ("a symlink", Box::new(|d: &Path| {
                #[cfg(unix)]
                std::os::unix::fs::symlink("/etc/passwd", d.join("link.json")).unwrap();
            }), "unexplained"),
            ("a vault staging directory", Box::new(move |d: &Path| {
                std::fs::create_dir_all(d.join(format!(".stage-{}", format!("{:x}", ACCT0)))).unwrap()
            }), "vault_stages"),
        ];
        for (name, plant, bucket) in plant {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            ks.import_private_key(ACCT0_PK, "pw").unwrap();
            plant(dir.path());

            let s = ks.scan().unwrap();
            let found = match bucket {
                "doc_stages" => &s.doc_stages,
                "vault_stages" => &s.vault_stages,
                _ => &s.unexplained,
            };
            assert!(!found.is_empty(), "{name}: dropped in silence");
            // Reported, never refused: under `<ks>/` a stray path is at worst one account,
            // and a keystore must not be bricked by a `.DS_Store`.
            assert!(ks.list_accounts().unwrap().contains(&ACCT0), "{name}");
            assert!(ks.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok(), "{name}");
            assert!(ks.create_unrelated_account("pw", acked()).is_ok(), "{name}");
        }
    }

    // ---- the sealed index: a locked wallet lists nothing -----------------------

    fn data_key(byte: u8, generation: u32) -> logos_signer_interface::wallets::DataKey {
        logos_signer_interface::wallets::DataKey {
            key: logos_signer_interface::Secret::new(hex::encode([byte; 32])),
            generation,
        }
    }

    /// Every path under the keystore, as one text.
    fn every_name(dir: &std::path::Path) -> String {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                out.push(e.file_name().to_string_lossy().into_owned());
                if e.file_type().unwrap().is_dir() {
                    todo.push(e.path());
                }
            }
        }
        out.join("\n")
    }

    /// A keystore with an EVM wallet, a Bitcoin wallet of the same phrase, a kept phrase and an
    /// imported key, every seed sealed as the signer manager's keys would seal it.
    fn sealed_keystore(dir: &std::path::Path) -> (Keystore, Vec<String>) {
        let ks = Keystore::new(dir);
        ks.import_mnemonic_ex(&ImportRequest { keep: KeepPhrase::New("phrase-pw"), ..req(Storage::Extkey, 0) }).unwrap();
        bitcoin_import(&ks, Family::Segwit);
        ks.import_private_key(&format!("{:064x}", 7), "pw").unwrap();
        let closed = ks.closed_seeds().unwrap();
        assert_eq!(closed.len(), 2, "one seed for the phrase, one for the key: {closed:?}");
        let mut seeds = Vec::new();
        for (seed, wanted) in closed {
            assert_eq!(wanted, None, "a new seed waits for its first key");
            assert!(ks.open_seed(&seed, &data_key(1, 0), &data_key(1, 0)).unwrap());
            seeds.push(seed);
        }
        (ks, seeds)
    }

    #[test]
    fn a_sealed_seed_lists_nothing_until_its_key_opens_it_again() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, seeds) = sealed_keystore(dir.path());
        assert_eq!(ks.list_accounts().unwrap().len(), 2);
        assert_eq!(ks.locked_wallets().unwrap(), 0);
        assert!(!dir.path().join("index.pending.json").exists() || plain_docs(dir.path()).contains("{}"));

        // Another process, or this one after Basecamp restarts: no key, nothing listed.
        let fresh = Keystore::new(dir.path());
        assert!(fresh.list_accounts().unwrap().is_empty());
        assert!(fresh.list_groups().unwrap().is_empty(), "a locked wallet's keys are not stranded");
        assert!(fresh.kept_phrases().unwrap().is_empty(), "nor is its phrase listed");
        assert!(fresh.list_derivation_keys().unwrap().is_empty(), "nor its derivation keys");
        let key = ks.list_derivation_keys().unwrap();
        let phrase = ks.kept_phrases().unwrap()[0].id.clone();
        assert_eq!(key.len(), 2, "the EVM and the Bitcoin wallet's: {key:?}");
        for k in &key {
            assert!(format!("{}", fresh.forget_derivation(k).unwrap_err()).contains("locked"), "{k}");
            assert!(dir.path().join(format!("groups/{k}.json")).exists(), "a refusal deleted nothing");
        }
        assert!(format!("{}", fresh.forget_phrase(&phrase).unwrap_err()).contains("locked"));
        assert!(fresh.account_report().unwrap().unexplained.is_empty(), "nor its vaults unexplained");
        assert!(fresh.provenance_view().unwrap().is_empty() && fresh.get_labels().unwrap().is_empty());
        assert!(!fresh.has_address(&ACCT0.to_string()));
        assert!(fresh.sign_message(&ACCT0.to_string(), "pw", "hi").is_err());
        assert_eq!(fresh.locked_wallets().unwrap(), 2);
        let mut locked = fresh.locked_seeds().unwrap();
        locked.sort();
        let mut want = seeds.clone();
        want.sort();
        assert_eq!(locked, want, "named as the keystore names them to the manager");
        for v in fresh.scan().unwrap().vaults {
            assert!(fresh.remove_unexplained(&format!("{v}.json"), true).is_err(), "a locked wallet's vault is removable");
        }

        // A wrong key opens nothing; the right one, of the box's generation, opens it again.
        let closed = fresh.closed_seeds().unwrap();
        assert!(closed.iter().all(|(_, g)| *g == Some(0)), "{closed:?}");
        assert!(fresh.open_seed(&seeds[0], &data_key(2, 0), &data_key(2, 0)).is_err());
        for s in &seeds {
            assert!(fresh.open_seed(s, &data_key(1, 0), &data_key(1, 1)).unwrap(), "sealed again under generation 1");
        }
        assert_eq!(fresh.list_accounts().unwrap().len(), 2);
        assert_eq!(fresh.list_derivation_keys().unwrap(), key);
        assert!(fresh.sign_message(&ACCT0.to_string(), "pw", "hi").is_ok());
        assert!(Keystore::new(dir.path()).closed_seeds().unwrap().iter().all(|(_, g)| *g == Some(1)));

        // Locking forgets the keys.
        fresh.lock_seeds();
        assert!(fresh.list_accounts().unwrap().is_empty());
    }

    #[test]
    fn no_file_names_an_account_and_no_plain_document_holds_one() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = sealed_keystore(dir.path());
        let accounts = ks.list_accounts().unwrap();
        let xpub = ks.get_groups().unwrap().values().find_map(|g| g.xpub.clone()).unwrap();
        let names = every_name(dir.path());
        let docs = plain_docs(dir.path());
        for a in &accounts {
            let hexed = addr_key(a);
            assert!(!names.contains(&hexed), "a file is named by {a}: {names}");
            assert!(!docs.to_ascii_lowercase().contains(&hexed), "a document holds {a}");
        }
        assert!(!docs.contains(&xpub) && !docs.contains("tpub") && !docs.contains("Main"), "{docs}");
    }

    #[test]
    fn a_locked_seed_still_gives_its_unlock_key_behind_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, seeds) = sealed_keystore(dir.path());
        let wanted: Vec<[u8; 33]> = seeds.iter().map(|s| ks.unlock_key(s, 0, "pw").unwrap()).collect();
        let fresh = Keystore::new(dir.path());
        for (s, want) in seeds.iter().zip(&wanted) {
            assert_eq!(&fresh.unlock_key(s, 0, "pw").unwrap(), want, "{s}");
            assert!(fresh.unlock_key(s, 0, "wrong").is_err(), "{s}");
        }
    }

    #[test]
    fn a_wallet_here_already_but_locked_is_not_added_twice() {
        let dir = tempfile::tempdir().unwrap();
        sealed_keystore(dir.path());
        let fresh = Keystore::new(dir.path());
        for e in [
            fresh.import_mnemonic_ex(&ImportRequest { index: 3, ..req(Storage::Plain, 0) }).unwrap_err(),
            fresh.import_private_key(&format!("{:064x}", 7), "pw").unwrap_err(),
        ] {
            assert!(format!("{e}").contains("unlock it in the Signer app"), "{e}");
        }
        assert!(fresh.import_private_key(&format!("{:064x}", 8), "pw").is_ok(), "another key is welcome");
        assert_eq!(fresh.scan().unwrap().vaults.len(), 3, "a refusal wrote no vault");
    }

    #[test]
    fn an_older_builds_documents_and_address_named_vaults_move_into_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let d = ks.import_mnemonic_ex(&req(Storage::Extkey, 0)).unwrap();
        let key = ks.import_private_key(&format!("{:064x}", 7), "pw").unwrap();
        ks.set_label(&key.to_string(), "Spare", "pw").unwrap();
        // What an older build left: four documents, and vaults named by their address.
        let doc = ks.view().unwrap().merged();
        for a in [d.address, key] {
            std::fs::rename(vault_file(&ks, &a), dir.path().join(format!("{}.json", addr_key(&a)))).unwrap();
        }
        let strip = |mut p: Provenance| {
            (p.vault, p.seed, p.check) = (String::new(), String::new(), None);
            p
        };
        let accounts: BTreeMap<String, Provenance> = doc.accounts.into_iter().map(|(k, p)| (k, strip(p))).collect();
        for (name, body) in [
            ("groups.json", serde_json::to_string(&doc.groups).unwrap()),
            ("accounts.json", serde_json::to_string(&accounts).unwrap()),
            ("labels.json", serde_json::to_string(&doc.labels).unwrap()),
            ("group-labels.json", serde_json::to_string(&doc.group_labels).unwrap()),
        ] {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        for name in ["seeds.json", "index.pending.json"] {
            std::fs::remove_file(dir.path().join(name)).unwrap();
        }

        let moved = Keystore::new(dir.path());
        let mut want = vec![d.address, key];
        want.sort_by_key(addr_key);
        assert_eq!(moved.list_accounts().unwrap(), want);
        assert_eq!(moved.get_labels().unwrap()[&addr_key(&key)], "Spare");
        assert_eq!(moved.get_group_labels().unwrap()[&d.group], "Main");
        assert!(moved.sign_message(&key.to_string(), "pw", "hi").is_ok());
        assert!(moved.derive_next_account(Some(&d.group), "gp", "pw", 0).is_ok());
        let names = every_name(dir.path());
        for gone in ["groups.json", "accounts.json", "labels.json", "group-labels.json"] {
            assert!(!names.contains(gone), "{gone} is still here");
        }
        assert!(!names.contains(&addr_key(&key)) && !names.contains(&addr_key(&d.address)), "{names}");
        assert!(moved.closed_seeds().unwrap().iter().all(|(s, _)| s.starts_with("g_") || s.starts_with("k_")));
    }

    // ---- a wallet's name is its seed's; an account file's is its own -----------------

    fn seed_of(ks: &Keystore, group: &str) -> String {
        Keystore::seed_of_group(&ks.get_groups().unwrap(), group)
    }

    #[test]
    fn a_new_wallet_takes_its_name_and_each_account_only_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let first = ks
            .import_mnemonic_ex(&ImportRequest { group_label: "", wallet_name: "Main wallet", ..req(Storage::Plain, 0) })
            .unwrap();
        let seed = seed_of(&ks, &first.group);
        assert_eq!(ks.wallet_names().unwrap()[&seed], "Main wallet");
        assert!(ks.get_group_labels().unwrap().is_empty(), "an account file has no name unless given one");
        assert_eq!(ks.enrolment(&first.address.to_string(), "pw").unwrap().name, "Main wallet");

        // Another account of the same phrase: its own name, and the wallet's is untouched.
        let savings = ks
            .import_mnemonic_ex(&ImportRequest { index: 1, group_label: "Savings", wallet_name: "Ignored", ..req(Storage::Plain, 0) })
            .unwrap();
        assert_eq!(seed_of(&ks, &savings.group), seed);
        assert_eq!(ks.wallet_names().unwrap()[&seed], "Main wallet");
        assert_eq!(ks.get_group_labels().unwrap()[&savings.group], "Savings");
        assert!(!ks.get_group_labels().unwrap().contains_key(&first.group));

        // Renaming the wallet needs what naming a file needs.
        let e = ks.set_wallet_name(&rename(&first.group, "Daily")).unwrap_err();
        assert!(format!("{e}").contains("needs the password of one of them"), "{e}");
        ks.set_wallet_name(&rename_as(&first.group, "Daily", &first.address.to_string(), "pw")).unwrap();
        assert_eq!(ks.wallet_names().unwrap()[&seed], "Daily");
        assert_eq!(ks.get_group_labels().unwrap()[&savings.group], "Savings");
        ks.set_wallet_name(&rename(&first.group, "")).unwrap();
        assert!(ks.wallet_names().unwrap().is_empty(), "clearing asks for nothing");
    }

    #[test]
    fn the_name_an_older_keys_app_copied_onto_every_file_becomes_the_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        // What the older keys app wrote: the wallet's name on every file, and on each account.
        let a = ks.import_mnemonic_ex(&ImportRequest { group_label: "Old", ..req(Storage::Plain, 0) }).unwrap();
        let b = ks.import_mnemonic_ex(&ImportRequest { index: 1, group_label: "Old", ..req(Storage::Plain, 0) }).unwrap();
        ks.set_label(&a.address.to_string(), "Old", "pw").unwrap();
        let seed = seed_of(&ks, &a.group);
        assert!(ks.wallet_names().unwrap().is_empty(), "adding an account adopts nothing");

        // Naming the wallet takes the copy off its files and accounts.
        ks.set_wallet_name(&rename_as(&a.group, "New", &a.address.to_string(), "pw")).unwrap();
        assert_eq!(ks.wallet_names().unwrap()[&seed], "New");
        let files = ks.get_group_labels().unwrap();
        assert!(!files.contains_key(&a.group) && !files.contains_key(&b.group), "{files:?}");
        assert!(ks.get_labels().unwrap().is_empty(), "the copy on the account went too");

        // Two different names are names of their own, and stay.
        let d2 = tempfile::tempdir().unwrap();
        let ks2 = Keystore::new(d2.path());
        let x = ks2.import_mnemonic_ex(&ImportRequest { group_label: "One", ..req(Storage::Plain, 0) }).unwrap();
        ks2.import_mnemonic_ex(&ImportRequest { index: 1, group_label: "Two", ..req(Storage::Plain, 0) }).unwrap();
        ks2.set_wallet_name(&rename_as(&x.group, "Both", &x.address.to_string(), "pw")).unwrap();
        assert_eq!(ks2.get_group_labels().unwrap().len(), 2);
    }
}
