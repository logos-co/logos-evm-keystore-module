//! Logos module glue for `keystore_module` (rust-first authoring).
//!
//! This file is the contract: the builder derives the `.lidl` from the
//! `KeystoreModule` trait below (`codegen.rust = { trait, source: "src/glue.rs" }`)
//! and injects the generated scaffold at the `include!` point. It is compiled
//! only with the default `logos_module` feature; `cargo test --no-default-features`
//! excludes it so the crypto core (`crate::keystore`) stays testable without the
//! generated scaffold or the Logos runtime.
//!
//! Every structured value crosses the IPC boundary as a JSON string. Methods
//! return `{ "ok": true, ... }` or `{ "ok": false, "error": "..." }`.

use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::keystore::Keystore;

/// The keystore module's IPC contract. Each non-defaulted method is a callable
/// module method. Private keys never appear in any signature — only addresses,
/// signed payloads, and (re-encrypted) keystore JSON cross the boundary.
pub trait KeystoreModule: Send + 'static {
    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24) — `{ ok, phrase }`.
    fn create_mnemonic(&mut self, words: i64) -> String;
    /// Derive + persist an account from a mnemonic. params JSON:
    /// `{ phrase, passphrase?, accountIndex?, password }` → `{ ok, address }`.
    fn import_mnemonic(&mut self, params_json: String) -> String;
    /// Create a new random account, persisted under `password` → `{ ok, address }`.
    fn new_account(&mut self, password: String) -> String;
    /// Import a raw private key (hex), persisted under `password` → `{ ok, address }`.
    fn import_private_key(&mut self, priv_hex: String, password: String) -> String;
    /// Import a scrypt keystore JSON, re-encrypted under `new_password` → `{ ok, address }`.
    fn import_keystore_json(&mut self, key_json: String, password: String, new_password: String) -> String;
    /// Export an account's scrypt keystore JSON (requires its password) → `{ ok, keystore }`.
    fn export_keystore_json(&mut self, address: String, password: String) -> String;
    /// `{ ok, accounts: [address, ...] }`.
    fn list_accounts(&mut self) -> String;
    fn has_address(&mut self, address: String) -> bool;
    fn delete_account(&mut self, address: String, password: String) -> bool;
    fn unlock(&mut self, address: String, password: String) -> bool;
    fn timed_unlock(&mut self, address: String, password: String, seconds: i64) -> bool;
    fn lock(&mut self, address: String) -> bool;
    fn is_unlocked(&mut self, address: String) -> bool;
    /// Sign an unsigned tx (JSON) for `chain_id` → `{ ok, raw }` (signed tx hex).
    fn sign_transaction(&mut self, address: String, unsigned_tx_json: String, chain_id: i64) -> String;
    /// EIP-191 personal_sign → `{ ok, signature }`.
    fn sign_message(&mut self, address: String, message: String) -> String;
    /// Sign a raw 32-byte digest (hex) with `address`'s key → `{ ok, signature }`
    /// (65-byte hex). For protocol digests — an ERC-4337 UserOperation hash or an
    /// EIP-7702 authorization hash — that aren't a transaction or an EIP-191
    /// message. ⚠️ Signs an opaque hash (see `Keystore::sign_digest`); for trusted
    /// in-app callers only. The account must be unlocked.
    fn sign_digest(&mut self, address: String, digest_hex: String) -> String;
    /// Framework hook — defaulted, so it is NOT part of the IPC contract.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

/// Typed events — emitted whenever the set of accounts changes.
pub trait KeystoreModuleEvents {
    fn accounts_changed(&self, count: i64);
}

// The builder injects the generated module-impl scaffold here: `install`,
// `context()`, `RustModuleContext`, the `emit_accounts_changed` emitter, and the
// C-ABI dispatch. No `build.rs`, no `OUT_DIR`.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeystoreModuleImpl {
    ks: Option<Keystore>,
}

impl KeystoreModuleImpl {
    fn ks(&mut self) -> std::result::Result<&mut Keystore, String> {
        self.ks
            .as_mut()
            .ok_or_else(|| "keystore not initialized (context not ready)".to_string())
    }
    fn account_count(&self) -> i64 {
        self.ks.as_ref().map(|k| k.list_accounts().len() as i64).unwrap_or(0)
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

#[derive(Deserialize)]
struct ImportMnemonicParams {
    phrase: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default, alias = "accountIndex")]
    account_index: u32,
    password: String,
}

impl KeystoreModule for KeystoreModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        let dir = std::path::Path::new(&ctx.instance_persistence_path).join("keystore");
        self.ks = Some(Keystore::new(dir));
    }

    fn create_mnemonic(&mut self, words: i64) -> String {
        match Keystore::create_mnemonic(words as u32) {
            Ok(phrase) => json!({ "ok": true, "phrase": phrase }).to_string(),
            Err(e) => err(e),
        }
    }

    fn import_mnemonic(&mut self, params_json: String) -> String {
        let p: ImportMnemonicParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let res = match self.ks() {
            Ok(ks) => ks.import_mnemonic(&p.phrase, &p.passphrase, p.account_index, &p.password),
            Err(e) => return err(e),
        };
        match res {
            Ok(addr) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": addr.to_string() }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn new_account(&mut self, password: String) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.new_account(&password),
            Err(e) => return err(e),
        };
        match res {
            Ok(addr) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": addr.to_string() }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn import_private_key(&mut self, priv_hex: String, password: String) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.import_private_key(&priv_hex, &password),
            Err(e) => return err(e),
        };
        match res {
            Ok(addr) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": addr.to_string() }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn import_keystore_json(&mut self, key_json: String, password: String, new_password: String) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.import_keystore_json(&key_json, &password, &new_password),
            Err(e) => return err(e),
        };
        match res {
            Ok(addr) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": addr.to_string() }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn export_keystore_json(&mut self, address: String, password: String) -> String {
        match self.ks() {
            Ok(ks) => match ks.export_keystore_json(&address, &password) {
                Ok(json_str) => json!({ "ok": true, "keystore": json_str }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn list_accounts(&mut self) -> String {
        match self.ks() {
            Ok(ks) => {
                let accts: Vec<String> = ks.list_accounts().iter().map(|a| a.to_string()).collect();
                json!({ "ok": true, "accounts": accts }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn has_address(&mut self, address: String) -> bool {
        self.ks().map(|ks| ks.has_address(&address)).unwrap_or(false)
    }

    fn delete_account(&mut self, address: String, password: String) -> bool {
        let res = match self.ks() {
            Ok(ks) => ks.delete_account(&address, &password),
            Err(_) => return false,
        };
        match res {
            Ok(true) => {
                emit_accounts_changed(self.account_count());
                true
            }
            _ => false,
        }
    }

    fn unlock(&mut self, address: String, password: String) -> bool {
        self.ks().map(|ks| ks.unlock(&address, &password, None).is_ok()).unwrap_or(false)
    }

    fn timed_unlock(&mut self, address: String, password: String, seconds: i64) -> bool {
        let ttl = Duration::from_secs(seconds.max(0) as u64);
        self.ks().map(|ks| ks.unlock(&address, &password, Some(ttl)).is_ok()).unwrap_or(false)
    }

    fn lock(&mut self, address: String) -> bool {
        self.ks().map(|ks| ks.lock(&address)).unwrap_or(false)
    }

    fn is_unlocked(&mut self, address: String) -> bool {
        self.ks().map(|ks| ks.is_unlocked(&address)).unwrap_or(false)
    }

    fn sign_transaction(&mut self, address: String, unsigned_tx_json: String, chain_id: i64) -> String {
        match self.ks() {
            Ok(ks) => match ks.sign_transaction(&address, &unsigned_tx_json, chain_id as u64) {
                Ok(raw) => json!({ "ok": true, "raw": raw }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn sign_message(&mut self, address: String, message: String) -> String {
        match self.ks() {
            Ok(ks) => match ks.sign_message(&address, &message) {
                Ok(sig) => json!({ "ok": true, "signature": sig }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn sign_digest(&mut self, address: String, digest_hex: String) -> String {
        match self.ks() {
            Ok(ks) => match ks.sign_digest(&address, &digest_hex) {
                Ok(sig) => json!({ "ok": true, "signature": sig }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreModuleImpl>();
}
