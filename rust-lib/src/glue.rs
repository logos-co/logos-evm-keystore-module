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

use crate::approval::Approvals;
use crate::keystore::Keystore;

/// Default approver. Overridden by `approver` in `<persistence>/keystore.json`.
const DEFAULT_APPROVER: &str = "signer_ui";

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
    // ── Tier B: any NAMED module may ask ────────────────────────────────
    /// Ask a human to approve signing. Returns immediately with
    /// `{ ok, handle, receipt }` — it does NOT block on the human. `handle` is
    /// announced on the event plane; `receipt` is returned exactly once and is
    /// what authorises collecting the result.
    fn request_approval(&mut self, intent_json: String) -> String;
    /// Bare state for the requester — never the intent, never the results.
    /// `{ ok, state, reason? }`.
    fn approval_status(&mut self, handle: String, receipt: String) -> String;
    /// Collect the signatures. Idempotent until `ack_result`, so a dropped
    /// reply does not cost the human a second password entry.
    fn fetch_result(&mut self, handle: String, receipt: String) -> String;
    /// The requester has the signatures; erase them.
    fn ack_result(&mut self, handle: String, receipt: String) -> bool;
    /// The requester gave up.
    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool;

    // ── Tier A: the configured approver only ────────────────────────────
    /// Queue summaries — never leg detail. `{ ok, pending: [...] }`.
    fn pending(&mut self) -> String;
    /// Claim a request for display. Returns the lines to show VERBATIM plus the
    /// commitment to echo back. Demotes any other rendered request, so exactly
    /// one thing can be on screen. `{ ok, handle, bundle_id, requester, render_lines }`.
    fn acknowledge(&mut self, handle: String) -> String;
    /// The human said yes. One key derivation, every leg signed, then wiped.
    /// `bundle_id` must be the value that was displayed. `{ ok, signed }`.
    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String;
    /// The human said no.
    fn reject(&mut self, handle: String) -> bool;

    /// Observability: what this module currently sees as its caller. Ungated
    /// and side-effect-free — identity cannot report its own absence.
    fn caller_identity(&mut self) -> String;
    /// Framework hook — defaulted, so it is NOT part of the IPC contract.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

/// Typed events — emitted whenever the set of accounts changes.
pub trait KeystoreModuleEvents {
    fn accounts_changed(&self, count: i64);
    /// A new request is waiting. Payload is the HANDLE ONLY: the event plane
    /// carries no token, so anything richer would publish the intent to every
    /// subscriber.
    fn approval_offered(&self, handle: String);
    /// A request reached a terminal state.
    fn approval_settled(&self, handle: String, state: String);
}

// The builder injects the generated module-impl scaffold here: `install`,
// `context()`, `RustModuleContext`, the `emit_accounts_changed` emitter, and the
// C-ABI dispatch. No `build.rs`, no `OUT_DIR`.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeystoreModuleImpl {
    ks: Option<Keystore>,
    approvals: Approvals,
    /// The one module name permitted to approve. Read from a config file in
    /// `on_context_ready`, i.e. from the loader's own directory — never from a
    /// method, which would make "who may approve a signature" remotely
    /// writable.
    approver: String,
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

/// Refused identically whether the handle is unknown or simply not yours, in
/// content and in shape — a distinct message would answer "does this handle
/// exist?" for a caller that has no business knowing.
fn not_authorized() -> String {
    json!({ "ok": false, "error": "not authorized" }).to_string()
}

impl KeystoreModuleImpl {
    /// Tier A: the configured approver, and nothing else.
    ///
    /// `HostAnchor` is refused deliberately. It is one undifferentiated bag
    /// covering the shells, `core_service` and every relayed CLI token, so
    /// admitting it here would make a plain `logosctl call … approve` a legal
    /// bypass of the human.
    fn is_approver(&self) -> bool {
        logos_rust_sdk::current_caller().is_module(&self.approver)
    }

    /// Tier B: any NAMED module. Returns the name to record against the
    /// request, so results can only be collected by the module that asked.
    fn named_caller(&self) -> Option<String> {
        match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Module { name, .. } => Some(name),
            _ => None,
        }
    }
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
        let base = std::path::Path::new(&ctx.instance_persistence_path);
        self.ks = Some(Keystore::new(base.join("keystore")));

        // Who may approve is configuration, not a method: a `set_approver` call
        // would be a remotely-writable answer to "who may authorise a
        // signature". This file is written by whoever deploys the module.
        self.approver = std::fs::read_to_string(base.join("keystore.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("approver").and_then(|a| a.as_str()).map(str::to_string))
            .unwrap_or_else(|| DEFAULT_APPROVER.to_string());
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

    // ── Tier B ──────────────────────────────────────────────────────────

    fn request_approval(&mut self, intent_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        if self.approver.is_empty() {
            return err("no approver configured");
        }
        match self.approvals.request(&requester, &intent_json) {
            Ok((handle, receipt)) => {
                emit_approval_offered(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn approval_status(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        match self.approvals.status(&handle, &receipt) {
            Ok((state, reason)) => json!({ "ok": true, "state": state, "reason": reason }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn fetch_result(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        match self.approvals.fetch_result(&handle, &receipt) {
            Ok(results) => json!({ "ok": true, "results": results }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn ack_result(&mut self, handle: String, receipt: String) -> bool {
        self.named_caller().is_some() && self.approvals.ack_result(&handle, &receipt).is_ok()
    }

    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool {
        self.named_caller().is_some() && self.approvals.cancel(&handle, &receipt).is_ok()
    }

    // ── Tier A ──────────────────────────────────────────────────────────

    fn pending(&mut self) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        let items: Vec<_> = self
            .approvals
            .pending()
            .into_iter()
            .map(|s| {
                json!({
                    "handle": s.handle, "requester": s.requester, "state": s.state,
                    "purpose": s.purpose, "leg_count": s.leg_count, "age_ms": s.age_ms as u64,
                })
            })
            .collect();
        json!({ "ok": true, "pending": items }).to_string()
    }

    fn acknowledge(&mut self, handle: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        match self.approvals.acknowledge(&handle) {
            Ok(r) => json!({
                "ok": true, "handle": r.handle, "bundle_id": r.bundle_id,
                "requester": r.requester, "render_lines": r.render_lines,
            })
            .to_string(),
            Err(e) => err(e),
        }
    }

    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        let ks = match self.ks.as_ref() {
            Some(k) => k,
            None => return err("keystore not initialized (context not ready)"),
        };
        let out = self.approvals.approve(ks, &handle, &bundle_id, &password);
        crate::approval::scrub(password);
        match out {
            Ok(n) => {
                emit_approval_settled(&handle, "approved");
                json!({ "ok": true, "signed": n }).to_string()
            }
            // Deliberately coarse: a wrong password, an unknown handle and a
            // stale commitment must not be distinguishable to a caller probing
            // the surface. The approver shows the human a generic retry.
            Err(_) => err("approval failed"),
        }
    }

    fn reject(&mut self, handle: String) -> bool {
        if !self.is_approver() {
            return false;
        }
        let ok = self.approvals.reject(&handle).is_ok();
        if ok {
            emit_approval_settled(&handle, "rejected");
        }
        ok
    }

    fn caller_identity(&mut self) -> String {
        let c = logos_rust_sdk::current_caller();
        let (kind, name) = match &c {
            logos_rust_sdk::LogosCaller::Unknown => ("unknown", String::new()),
            logos_rust_sdk::LogosCaller::HostAnchor => ("host", String::new()),
            logos_rust_sdk::LogosCaller::Module { name, .. } => ("module", name.clone()),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => ("derived", format!("{parent}.{leaf}")),
            logos_rust_sdk::LogosCaller::Operator { name } => ("operator", name.clone()),
        };
        json!({ "ok": true, "kind": kind, "identity": name, "approver": self.approver }).to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreModuleImpl>();
}
