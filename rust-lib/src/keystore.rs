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
use crate::hd::{self, Bip44Path, Seed};
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

/// Manages a directory of scrypt vault files. One vault file per account, named
/// `<lowercase-hex-address>.json`.
///
/// There is deliberately NO cache of unlocked signers. Signing *is* vault
/// access: a key is derived from the vault password for one operation and wiped
/// when that operation ends. The previous design kept a `HashMap<Address,
/// Unlocked>` whose entries carried an *optional* deadline, and the only caller
/// passed `None` — so an unlock was an unlimited, process-lifetime signer that
/// any module able to reach this one could spend.
pub struct Keystore {
    root: Root,
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

fn parse_u128(s: &str, what: &str) -> Result<u128> {
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

fn vault_name(addr: &Address) -> String {
    // lowercase hex, no 0x — stable filename + easy listing
    format!("{:x}", addr)
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: Root::new(dir) }
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
                "the vault at {}.json holds the key for {} — refusing to act as {addr} with \
                 another account's key",
                vault_name(&addr),
                signer.address()
            )));
        }
        Ok(signer)
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(self.root.as_path()).map_err(|e| KeystoreError::Io(e.to_string()))?;
        // create_dir_all honours the umask, so the vault directory was 0755. Tightened, not
        // set: setting it outright re-opened a directory an operator had locked down.
        atomic::tighten_dir(self.root.as_path()).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    fn vault_path(&self, addr: &Address) -> PathBuf {
        self.root.path(&Slot::Vault(vault_name(addr)))
    }

    /// The vault the AUTHORITY names for this address.
    ///
    /// The use path used to resolve by `Path::exists`, which follows symlinks — so material
    /// could be live and signable while the scan refused to list it. Signing what the
    /// authority will not name is a contradiction, so the scan decides here too, and
    /// anything else sitting at that path is refused by name rather than taken for the vault.
    fn held_vault(&self, addr: &Address) -> Result<PathBuf> {
        let name = vault_name(addr);
        let scan = self.scan()?;
        if scan.vaults.contains(&name) {
            return Ok(self.vault_path(addr));
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

    /// Addresses the authority names a vault for. Taken once, for a caller asking about
    /// many — a scan per index would be the same answer, read n times.
    fn held_addresses(&self) -> Result<Vec<String>> {
        Ok(self.scan()?.vaults)
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
    fn write_vault(&self, addr: &Address, key: &[u8], password: &str) -> Result<()> {
        self.ensure_dir()?;
        let kind = StageKind::Vault(vault_name(addr));
        let stage = atomic::Stage::create(self.root.path(&Slot::Stage(kind.clone())))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let file = Slot::staged_name(&kind);
        let mut rng = rand::thread_rng();
        eth_keystore::encrypt_key(stage.path(), &mut rng, key, password, Some(&file))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        stage
            .promote(&file, &self.vault_path(addr))
            .map_err(|e| KeystoreError::Vault(e.to_string()))
    }

    fn persist_signer(&self, signer: &PrivateKeySigner, password: &str) -> Result<Address> {
        // The single choke point for a new vault, so this is where an unreadable sidecar is
        // refused: BEFORE the key lands. A vault whose provenance record could not be
        // written is a key nothing can later explain.
        self.get_groups()?;
        self.get_provenance()?;
        let addr = signer.address();
        // `to_bytes()` hands back the raw secp256k1 secret. Own it in a
        // Zeroizing so it is wiped when this scope ends, on every path.
        let key = Zeroizing::new(signer.to_bytes().0);
        self.write_vault(&addr, key.as_slice(), password)?;
        Ok(addr)
    }

    /// Import a raw private key (hex, with or without 0x), persisting a vault.
    pub fn import_private_key(&self, priv_hex: &str, password: &str) -> Result<Address> {
        let signer = signer_from_hex(priv_hex)?;
        let address = self.persist_signer(&signer, password)?;
        self.record_provenance(&address, Provenance::of("imported-key"))?;
        Ok(address)
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
        let address = self.persist_signer(&signer, new_password)?;
        self.record_provenance(&address, Provenance::of("imported-json"))?;
        Ok(address)
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
        self.write_vault(&addr, key.as_slice(), new)?;
        Ok(addr)
    }

    /// Human-readable account names. Kept beside the vaults, never inside them: a label is
    /// not a secret and must not require a password to read.
    fn labels_path(&self) -> PathBuf {
        self.root.path(&Slot::Doc(Doc::Labels))
    }

    pub fn get_labels(&self) -> Result<BTreeMap<String, String>> {
        self.read_json(&self.labels_path())
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
        self.open_group_vault(&path, password).map(drop).map_err(|e| match e {
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
        if !self.has_address(address) {
            return Err(KeystoreError::InvalidParams(format!("no such account: {addr}")));
        }
        let key = vault_name(&addr);
        let label = label.trim().to_string();
        if !label.is_empty() {
            self.prove_custody(address, password)?;
        }
        // Read and write under one lock, so a torn labels.json cannot silently erase every
        // name and a concurrent rename cannot lose one.
        self.update(&self.labels_path(), |labels: &mut BTreeMap<String, String>| {
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
        let addrs = |v: &[String]| v.iter().map(|a| parse_address(a)).collect::<Result<Vec<_>>>();
        let mut report = AccountReport {
            accounts: Vec::new(),
            staged: addrs(&scan.staged_vaults)?,
            unexplained: scan.stray(),
            mismatched: Vec::new(),
        };
        for name in &scan.vaults {
            match self.declared_address(name) {
                // Reported as unexplained too, so the one removal path can reach it.
                Some(declared) if &declared != name => {
                    report.mismatched.push(format!("{name}.json holds 0x{declared}"));
                    report.unexplained.push(format!("{name}.json"));
                }
                _ => report.accounts.push(parse_address(name)?),
            }
        }
        report.unexplained.sort();
        Ok(report)
    }

    /// The address a vault file declares, where it declares one. Vaults this module writes
    /// carry no such field; one that does was placed here by something else, and a
    /// disagreement with the filename means neither claim can be trusted without a password.
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
        let reported = self.scan()?.unexplained_all();
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
        Ok(self.scan()?.stray())
    }

    /// Whether a vault for this address is here. Through the same declared-address rule
    /// `account_report` uses, so the two cannot disagree about what the wallet holds.
    pub fn has_address(&self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => {
                let name = vault_name(&addr);
                self.held_vault(&addr).is_ok()
                    && self.declared_address(&name).is_none_or(|d| d == name)
            }
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

/// A group's record in `groups.json`. Nothing here is a secret: `usedPassphrase` is a
/// boolean so a user restoring elsewhere is told a passphrase was involved, never what it was.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
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
}

/// Where one account came from. Kept beside the vaults for the same reason labels are: a
/// derivation path is not a secret, and an attacker holding the directory already reads
/// the addresses off the filenames.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Provenance {
    /// `derived` | `imported-key` | `imported-json` | `random` | `unknown`.
    pub origin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
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
    pub group_label: &'a str,
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

impl Keystore {
    fn groups_path(&self) -> PathBuf {
        self.root.path(&Slot::Doc(Doc::Groups))
    }

    fn accounts_path(&self) -> PathBuf {
        self.root.path(&Slot::Doc(Doc::Accounts))
    }

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

    pub fn get_groups(&self) -> Result<BTreeMap<String, Group>> {
        self.read_json(&self.groups_path())
    }

    pub fn get_provenance(&self) -> Result<BTreeMap<String, Provenance>> {
        self.read_json(&self.accounts_path())
    }

    fn group_labels_path(&self) -> PathBuf {
        self.root.path(&Slot::Doc(Doc::GroupLabels))
    }

    /// Wallet names, by group id. Their own document rather than a field of `groups.json`,
    /// because the group a reader most needs to name is the stranded one — and its record
    /// is exactly what is missing. Readable when that file is not.
    pub fn get_group_labels(&self) -> Result<BTreeMap<String, String>> {
        self.read_json(&self.group_labels_path())
    }

    /// The ONE writer of a wallet name. Empty clears, like an account label.
    fn write_group_label(&self, id: &str, label: &str) -> Result<()> {
        let label = label.trim().to_string();
        self.update(&self.group_labels_path(), |names: &mut BTreeMap<String, String>| {
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
                    .and_then(|a| provenance.get(&vault_name(&a)))
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
        // A name an older build wrote into the record moves out first, or clearing one here
        // would only reveal the older name still sitting underneath it.
        if recorded.get(id).is_some_and(|g| !g.label.trim().is_empty()) {
            self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
                if let Some(g) = groups.get_mut(id) {
                    g.label = String::new();
                }
            })?;
        }
        self.write_group_label(id, req.label)
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

    /// Everything the keystore directory holds, classified. One scan is the authority for
    /// every question asked of it — what may be minted, what is derivable, what is
    /// deletable, and what is here that this keystore did not write — so those answers
    /// cannot drift apart the way "the final path" and "the staging path" did.
    pub fn scan(&self) -> Result<Scan> {
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
        Ok(self.scan()?.key_ids())
    }

    fn record_provenance(&self, addr: &Address, p: Provenance) -> Result<()> {
        let key = vault_name(addr);
        self.update(&self.accounts_path(), |all: &mut BTreeMap<String, Provenance>| {
            all.insert(key, p);
        })
    }

    /// Record only what is not already recorded, so walking past an existing account never
    /// rewrites how it actually came to be.
    fn record_provenance_if_absent(&self, addr: &Address, p: Provenance) -> Result<()> {
        let key = vault_name(addr);
        self.update(&self.accounts_path(), |all: &mut BTreeMap<String, Provenance>| {
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
        self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
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
            .filter(|(_, g)| g.storage == Storage::Extkey)
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
        let address = self.persist_signer(&signer, password)?;
        self.record_provenance(
            &address,
            Provenance {
                origin: "derived".into(),
                group: id.to_string(),
                path: path.to_string(),
                index: Some(path.index),
            },
        )?;
        self.bump_next_index(id, path.index)?;
        Ok(Derived { address, path: path.to_string(), group: id.to_string(), index: path.index })
    }

    /// Import a mnemonic, optionally keeping the account key so later accounts can be
    /// derived without the phrase. Creates the group.
    pub fn import_mnemonic_ex(&self, req: &ImportRequest) -> Result<Derived> {
        let path = Bip44Path::new(req.bip44_account, req.change, req.index)?;
        if req.storage == Storage::Extkey && req.group_password.is_empty() {
            return Err(KeystoreError::InvalidParams(
                "keeping a derivation key needs a password of its own".into(),
            ));
        }
        let seed = Seed::from_mnemonic(req.phrase, req.bip39_passphrase)?;
        let account_key = seed.account_key(path.account)?;

        let id = new_group_id();
        let record = Group {
                storage: req.storage,
                path_prefix: Bip44Path::account_prefix(path.account),
                next_index: 0,
                retired: Vec::new(),
                used_passphrase: !req.bip39_passphrase.is_empty(),
            // The name lives in its own document; this field is only what older builds wrote.
            label: String::new(),
            created_ms: now_ms(),
        };
        self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
            groups.insert(id.clone(), record)
        })?;

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

        landed.inspect_err(|_| {
            // Both paths the key can occupy, not just the final one: rolling back only the
            // destination left the staged copy alive and invisible.
            let _ = remove_path(&self.group_vault_path(&id));
            let _ = remove_path(&self.stage_dir(&id));
            let _ = self.write_group_label(&id, "");
            let _ = self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
                groups.remove(&id)
            });
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
            if !held.contains(&vault_name(&address)) {
                return self.persist_derived(&key, &id, path, password);
            }
            self.record_provenance_if_absent(
                &address,
                Provenance {
                    origin: "derived".into(),
                    group: id.clone(),
                    path: path.to_string(),
                    index: Some(index),
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
        if self.held_addresses()?.contains(&vault_name(&address)) {
            return Err(KeystoreError::Refused(format!("{path} is already held, as {address}")));
        }
        self.persist_derived(&key, &id, path, password)
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
                present: held.contains(&vault_name(&address)),
            });
        }
        Ok(out)
    }

    /// The ONE way to obtain a random key. `Unrecoverable` is the acknowledgement: it does
    /// not exist unless someone asked for a key no recovery phrase covers, and it carries
    /// the key it generated. Nothing here can mint one without holding it.
    pub fn create_unrelated_account(&self, password: &str, key: Unrecoverable) -> Result<Address> {
        let address = self.persist_signer(key.signer(), password)?;
        self.record_provenance(&address, Provenance::of("random"))?;
        Ok(address)
    }

    /// Stop keeping a group's derivation key. Removes every path the id can occupy, and
    /// needs NO password: gating deletion on decryption left a key nobody could open sitting
    /// there refusing every new account — neither derivable nor removable. The Tier D
    /// custodian gate is the authorisation.
    ///
    /// Accounts already derived are untouched; what ends is adding MORE without the phrase.
    pub fn forget_derivation(&self, group: &str) -> Result<Forgotten> {
        check_group_id(group)?;
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
        let downgraded = self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
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
            self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
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
        let provenance = self.get_provenance()?;
        let recorded = self.get_groups()?;
        let names = self.get_group_labels()?;
        let store = self.group_store()?;
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
                    storage: Storage::Extkey,
                    path_prefix: String::new(),
                    next_index: 0,
                    retired: Vec::new(),
                    used_passphrase: false,
                    label,
                    created_ms: 0,
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
                    .get(&vault_name(&address))
                    .cloned()
                    .unwrap_or_else(|| Provenance::of("unknown"));
                let derivable = groups.get(&provenance.group).is_some_and(|g| {
                    g.storage == Storage::Extkey && keys.contains(&provenance.group)
                });
                AccountProvenance { address, provenance, derivable }
            })
            .collect())
    }

    /// Retire an index so it is never handed out again. A reused path may collide with an
    /// account that still holds funds; a gap costs nothing.
    fn retire(&self, address: &Address) -> Result<()> {
        let key = vault_name(address);
        let removed = self.update(&self.accounts_path(), |all: &mut BTreeMap<String, Provenance>| {
            all.remove(&key)
        })?;
        let (Some(p), ) = (removed, ) else { return Ok(()) };
        let (Some(index), false) = (p.index, p.group.is_empty()) else {
            return Ok(());
        };
        self.update(&self.groups_path(), |groups: &mut BTreeMap<String, Group>| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::eips::eip2718::Decodable2718;
    use alloy::primitives::address;

    // Foundry's canonical test mnemonic → account 0.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ACCT0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const ACCT0_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
        let vault = sub.join(format!("{:x}.json", addr));
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
        assert_eq!(ks.get_labels().unwrap()[&vault_name(&addr)], "Treasury");

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
        assert!(!ks.get_provenance().unwrap().contains_key(&vault_name(&a1.address)));
    }

    #[test]
    fn the_next_index_is_recomputed_from_the_recorded_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        ks.derive_next_account(Some(&group), "gp", "pw", 0).unwrap();

        // Corrupt the cache the way a hand-edit would. It is a high-water mark, not the
        // authority: the worst it can do is skip an index, never collide.
        ks.update(&ks.groups_path(), |g: &mut BTreeMap<String, Group>| {
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
        std::fs::write(dir.path().join("groups.json"), "{}").unwrap();

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
        std::fs::write(dir.path().join("group-labels.json"), "{\"x\": ").unwrap();

        assert!(ks.get_group_labels().is_err());
        assert!(ks.list_groups().is_err(), "an unreadable name is not an unnamed wallet");
        // Naming a wallet would otherwise write a fresh map over the torn one, silently
        // losing every name it held — and an import would quietly land a nameless wallet.
        // Credentialed on purpose: an uncredentialed call would refuse for the other reason.
        let e = ks
            .set_group_label(&rename_as(&group, "Cold storage", &ACCT0.to_string(), "pw"))
            .unwrap_err();
        assert!(format!("{e}").contains("unreadable"), "got {e}");
        assert!(ks.import_mnemonic_ex(&ImportRequest { bip44_account: 1, ..req(Storage::Extkey, 0) }).is_err());
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
        // groups.json carried the name before it had a document of its own. It is still
        // shown, but a rename has to leave nothing underneath that can resurface.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = with_group(dir.path());
        std::fs::remove_file(dir.path().join("group-labels.json")).unwrap();
        let mut groups = ks.get_groups().unwrap();
        groups.get_mut(&group).unwrap().label = "Legacy".into();
        std::fs::write(dir.path().join("groups.json"), serde_json::to_string(&groups).unwrap()).unwrap();
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
        std::fs::write(d2.path().join("groups.json"), "{}").unwrap();
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
        std::fs::write(dir.path().join("groups.json"), "{}").unwrap();
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
        std::fs::write(dir.path().join("groups.json"), "{}").unwrap();

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
        std::fs::write(dir.path().join("groups.json"), "{}").unwrap();
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
            corrupt(dir.path());
            assert!(ks.remove_group(&group).is_err(), "{name}");
            assert_eq!(ks.get_group_labels().unwrap()[&group], "Main", "{name}: the name went anyway");
        }

        // accounts.json is the one that says whether anything is still under the wallet.
        let dir = tempfile::tempdir().unwrap();
        let (ks, group) = emptied(dir.path());
        std::fs::write(dir.path().join("accounts.json"), "{\"x\": ").unwrap();
        assert!(ks.remove_group(&group).is_err());
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
        let ancient = address!("0000000000000000000000000000000000000001");
        std::fs::copy(
            dir.path().join(format!("{}.json", vault_name(&from_json))),
            dir.path().join(format!("{}.json", vault_name(&ancient))),
        )
        .unwrap();
        assert_eq!(origin(ancient), "unknown");
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

        // Neither sidecar may carry the phrase or the passphrase: they are read without a
        // password, by anyone who can read the directory.
        for name in ["groups.json", "accounts.json"] {
            let txt = std::fs::read_to_string(dir.path().join(name)).unwrap();
            assert!(!txt.contains("TREZOR"), "{name} leaked the passphrase");
            assert!(!txt.contains(TEST_MNEMONIC), "{name} leaked the phrase");
            assert!(!txt.contains("xprv"), "{name} leaked the derivation key");
        }
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
        // Make the account vault unwritable by putting a directory where its file goes, so
        // the failure lands AFTER the group's derivation key has been written.
        std::fs::create_dir_all(dir.path().join(format!("{}.json", vault_name(&ACCT0)))).unwrap();

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
            (name, Box::new(move |p: &std::path::Path| std::fs::write(p.join("groups.json"), body).unwrap()))
        };
        let mut cases = vec![
            // Exactly the measured state: `> groups.json`, or a crash before any byte lands.
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
            std::fs::set_permissions(p.join("groups.json"), std::fs::Permissions::from_mode(0o000)).unwrap();
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
                "{name}: an unreadable groups.json must refuse, got {e}"
            );
            assert!(format!("{e}").contains("groups.json"), "{name}: {e}");
            assert!(ks.import_private_key(ACCT0_PK, "pw").is_err(), "{name}");

            assert_eq!(ks.list_accounts().unwrap(), vec![ACCT0], "{name}: a vault landed anyway");
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
        // accounts.json is read on the way to writing every new vault. Swallowing its
        // errors would leave a key on disk with no record of where it came from.
        for (name, body) in [("truncated", ""), ("wrong schema", "[]")] {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            ks.create_unrelated_account("pw", acked()).unwrap();
            let before = ks.list_accounts().unwrap();
            std::fs::write(dir.path().join("accounts.json"), body).unwrap();

            assert!(matches!(ks.create_unrelated_account("pw", acked()), Err(KeystoreError::Corrupt(..))), "{name}");
            assert!(ks.import_private_key(ACCT0_PK, "pw").is_err(), "{name}");
            assert_eq!(ks.list_accounts().unwrap(), before, "{name}: a vault landed despite the refusal");
            assert!(ks.get_provenance().is_err(), "{name}");
        }
    }

    #[test]
    fn an_unreadable_labels_file_refuses_rather_than_erasing_every_name() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let a = ks.create_unrelated_account("pw", acked()).unwrap();
        ks.set_label(&a.to_string(), "Savings", "pw").unwrap();

        std::fs::write(dir.path().join("labels.json"), "{\"x\": ").unwrap();
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
        std::fs::remove_file(dir.path().join("groups.json")).unwrap();
        assert!(ks.get_groups().unwrap().is_empty(), "an absent file is an empty one");

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

        let before = std::fs::read_to_string(dir.path().join("groups.json")).unwrap();
        let listed = |ks: &Keystore| ks.scan().unwrap();
        assert!(listed(&ks).doc_stages.is_empty(), "left staged: {:?}", listed(&ks).doc_stages);

        restrict_permissions(dir.path(), 0o500).unwrap();
        let failed = ks.update(&ks.groups_path(), |g: &mut BTreeMap<String, Group>| {
            g.get_mut(&group).unwrap().next_index = 99;
        });
        restrict_permissions(dir.path(), 0o700).unwrap();

        assert!(failed.is_err(), "a failed staging must not report success");
        assert_eq!(std::fs::read_to_string(dir.path().join("groups.json")).unwrap(), before);
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
        std::fs::write(dir.path().join("groups.json"), "{}").unwrap();

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
            assert!(ks.signer_for(&ACCT0.to_string(), "pw").is_ok(), "{name}: an account was lost");
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
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            // groups.json is removed so the directory scan answers alone, with no record to
            // agree with. It is what the scan REPORTS that is measured here; what makes a
            // random key safe is the acknowledgement, asserted below in every row alike.
            std::fs::remove_file(dir.path().join("groups.json")).unwrap();
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
        // groups.json is deleted throughout: keystore.rs says the key directory is the
        // authority and the record only describes it, so the authority is tested ALONE.
        for (what, parent) in [
            ("the key directory itself", "groups"),
            ("one directory over", "groups.bak"),
            ("a group stage at the root", ".stage-{id}"),
            ("a name that says nothing", "elsewhere"),
            ("a directory nobody may read", "locked"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (ks, group) = with_group(dir.path());
            std::fs::remove_file(dir.path().join("groups.json")).unwrap();

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
            let real = outside.path().join(format!("{acct:x}.json"));
            let linked = dir.path().join(format!("{:x}.json", ACCT0));
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
            assert!(ks.scan().unwrap().stray().contains(&format!("{:x}.json", ACCT0)));
            assert!(ks.remove_unexplained(&format!("{:x}.json", ACCT0), true).unwrap());
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
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::new(dir.path());
            let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
            assert_eq!(addr, ACCT0);
            let a = format!("{:x}", ACCT0);
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
        let path = dir.path().join(format!("{:x}.json", addr));
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
        let wrong = "b".repeat(40);
        std::fs::rename(
            dir.path().join(format!("{:x}.json", ACCT0)),
            dir.path().join(format!("{wrong}.json")),
        )
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
        assert!(dir.path().join(format!("{wrong}.json")).exists());

        // The other half: a vault that DECLARES an address disagreeing with its filename is
        // not listed as an account at all — there the mismatch is knowable without a password.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let path = dir.path().join(format!("{:x}.json", ACCT0));
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["address"] = serde_json::json!(wrong);
        std::fs::write(&path, v.to_string()).unwrap();

        let report = ks.account_report().unwrap();
        assert!(!report.accounts.contains(&ACCT0), "an address the vault disputes was listed");
        assert_eq!(report.mismatched.len(), 1, "{:?}", report.mismatched);
        assert!(report.mismatched[0].contains(&wrong));
        // Named as unexplained too, so the one removal path reaches it.
        assert!(report.unexplained.contains(&format!("{:x}.json", ACCT0)));
        // And the two answers agree: `has_address` used to say yes off the filename alone.
        assert!(!ks.has_address(&ACCT0.to_string()));
    }

    #[test]
    fn a_settled_stage_is_removable_by_name_rather_than_only_by_listing() {
        // F5. `settle` ran only as a side effect of listing, so a stage a crash left behind
        // disappeared when something happened to call `list_accounts` and not otherwise.
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let a = format!("{:x}", ACCT0);
        ks.import_private_key(ACCT0_PK, "pw").unwrap();
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
}
