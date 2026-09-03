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
use zeroize::Zeroizing;
use std::time::Duration;

use crate::ack::Unrecoverable;
use crate::approval::Approvals;
use crate::gate;
use crate::keystore::{Derived, GroupLabelRequest, ImportRequest, Keystore, Storage};

/// Default approver. Overridden by `approver` in `<persistence>/keystore.json`.
const DEFAULT_APPROVER: &str = "signer_ui";
/// The one module permitted to MUTATE the keystore. Mirrors `DEFAULT_APPROVER`: a wallet
/// requests signatures and reads which accounts exist; creating, importing, exporting and
/// deleting them belongs to one surface, and that surface is the keystore UI.
const DEFAULT_CUSTODIAN: &str = "keystore_ui";

/// The keystore module's IPC contract. Each non-defaulted method is a callable
/// module method. Private keys never appear in any signature — only addresses,
/// signed payloads, and (re-encrypted) keystore JSON cross the boundary.
pub trait KeystoreModule: Send + 'static {
    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24) — `{ ok, phrase }`.
    fn create_mnemonic(&mut self, words: i64) -> String;
    /// Derive + persist an account from a mnemonic, creating its derivation group. params
    /// JSON: `{ phrase, passphrase?, accountIndex?, password, storage?, bip44Account?,
    /// change?, groupPassword?, groupLabel? }` → `{ ok, address, path, group, storage,
    /// index, origin }`. `accountIndex` is the ADDRESS index; `bip44Account` is the
    /// hardened BIP-44 account level. `storage` defaults to `"plain"` — keeping nothing —
    /// so the pre-HD call shape behaves exactly as it did.
    fn import_mnemonic(&mut self, params_json: String) -> String;
    /// Add the next account of a derivation group, without the phrase. params JSON:
    /// `{ group?, groupPassword, password, change? }` → `{ ok, address, path, group,
    /// index, origin }`. `group` may be omitted only when exactly one group can derive.
    fn derive_next_account(&mut self, params_json: String) -> String;
    /// Add one account at a chosen index. params JSON:
    /// `{ group, groupPassword, password, bip44Account?, change?, index }`.
    fn derive_account_at(&mut self, params_json: String) -> String;
    /// Addresses a group would derive, without writing anything and without a network.
    /// params JSON: `{ group, groupPassword, change?, from?, count? }` →
    /// `{ ok, group, addresses: [{ index, path, address, present }] }`.
    fn preview_addresses(&mut self, params_json: String) -> String;
    /// The ONE way to obtain a random key — a key no recovery phrase covers. params JSON:
    /// `{ password, acknowledgeUnrecoverable }`; the refusal says what an unrelated account
    /// IS rather than that a flag is missing.
    ///
    /// It replaced `new_account`, which minted one silently on a keystore that looked empty.
    /// The acknowledgement is enforced by construction: it generates the key, so a path that
    /// skipped it has nothing to persist.
    fn create_unrelated_account(&mut self, params_json: String) -> String;
    /// Stop keeping a group's derivation key. params JSON: `{ group }`.
    /// One-way: the material is gone, and re-importing the phrase is the only way back.
    /// Keyed on the FILES and needing no password — deletion must not require the ability to
    /// READ what it deletes, or a key whose password is lost becomes permanent while it goes
    /// on refusing every new account. Removes every path the id can occupy, the staging one
    /// included. Accounts already derived keep working; they just stop being extendable.
    fn forget_derivation(&mut self, params_json: String) -> String;
    /// Remove a wallet's record and its name. params JSON: `{ group }` →
    /// `{ ok, group, recordRemoved, nameRemoved }`. Tier D.
    ///
    /// Refuses while the wallet holds a derivation key (live or staged) or an account, so it
    /// never deletes key material — `forget_derivation` and `delete_account` stay the only
    /// writers that do, each keeping its own acknowledgement. Because "holds nothing" is the
    /// precondition, nothing signable is at stake and no password is asked for.
    fn remove_group(&mut self, params_json: String) -> String;
    /// Derivation groups, `{ ok, groups: [...] }`. UNGATED, like `get_labels`: none of it
    /// is a secret, and a wallet showing an account picker needs it. Includes STRANDED
    /// groups — a derivation key on disk that no record names.
    fn list_groups(&mut self) -> String;
    /// What the key directory holds: `{ ok, groups, staged, unexplained }`. UNGATED. Reads
    /// the directory ONLY, so a wallet whose bookkeeping is unreadable can still be named —
    /// and therefore still deleted with `forget_derivation`. `staged` are ids an interrupted
    /// import left a copy of; `unexplained` are paths the layout does not account for. That
    /// last list REPORTS; it no longer refuses anything.
    fn list_derivation_keys(&mut self) -> String;
    /// Where each account came from, `{ ok, accounts: { <address>: {...} } }`. UNGATED.
    fn get_provenance(&mut self) -> String;
    /// Bring the keystore directory to a state the layout explains, and report both what it
    /// DID and what is left: `{ ok, swept, promoted, unexplained, links, staged, importStages }`.
    /// Tier D — it removes things. A leftover only named after it has been swept was never
    /// nameable, so the reply says what went.
    /// Callable by name rather than only as a side effect of listing, so a stage a crash
    /// left behind is not waiting on something happening to call `list_accounts`.
    fn settle(&mut self) -> String;
    /// Remove one path `settle`/`list_accounts` reported as unexplained. params JSON:
    /// `{ path, acknowledgeMayBeKeyMaterial }` → `{ ok, removed }`. Tier D. Only a string
    /// the scan itself produced is accepted, so nothing outside `<ks>/` can be named; the
    /// acknowledgement is required because unidentified material may BE a live key.
    fn remove_unexplained(&mut self, params_json: String) -> String;
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
    /// Re-encrypt a vault under a new password. Tier D. Crash-safe: the new vault is staged
    /// and renamed, so a failure cannot leave the account with no readable copy.
    /// `{ ok, address }`, or `{ ok: false }` if the old password is wrong.
    fn change_password(&mut self, address: String, old_password: String, new_password: String) -> String;
    /// Name an account, or clear the name with an empty string. Tier D, plus the account's
    /// own vault password when a name is being SET: a label is what a wallet shows in place
    /// of an address, so writing one is a claim of custody and now has to prove it. Clearing
    /// needs no password — it can only move the display toward the raw address, and it is
    /// the one way to strip a stale name off an account whose password is lost. `{ ok }`.
    fn set_label(&mut self, address: String, label: String, password: String) -> String;
    /// Account names, `{ ok, labels: { <address>: <name> } }`. UNGATED: a label is not a
    /// secret, and a wallet showing an account picker needs it.
    fn get_labels(&mut self) -> String;
    /// Name a wallet, or clear the name with an empty string. params JSON:
    /// `{ group, label, address?, password? }` → `{ ok }`. Tier D, plus the credential of
    /// whatever the wallet HOLDS when a name is being set: one of its own accounts (named by
    /// `address`) where it has accounts, because the name is a claim about them; the
    /// derivation key's password where it has only a key, because the name will come to
    /// stand over what that key mints. Free only where it holds neither. No uniqueness rule.
    fn set_group_label(&mut self, params_json: String) -> String;
    /// Wallet names, `{ ok, labels: { <groupId>: <name> } }`. UNGATED, like `get_labels`,
    /// and answered from its own document — so a wallet whose record is gone is still
    /// nameable on screen.
    fn get_group_labels(&mut self) -> String;
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

/// Typed events.
pub trait KeystoreModuleEvents {
    /// Anything a reader shows about the accounts moved — the set itself, or the names and
    /// wallets it is displayed under. `count` is the account count at that moment and is
    /// ADVISORY: a rename does not move it, so a subscriber that diffs counts sees nothing.
    /// Re-read; the payload is not a change detector.
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
    /// The one module name permitted to mutate the keystore. Read from the same
    /// config file, for the same reason.
    custodian: String,
    /// Why both roles are empty, when they are empty because the config could not be read.
    /// Reported by `caller_identity` so "nothing works" has a stated cause.
    config_error: String,
}

impl KeystoreModuleImpl {
    fn ks(&mut self) -> std::result::Result<&mut Keystore, String> {
        self.ks
            .as_mut()
            .ok_or_else(|| "keystore not initialized (context not ready)".to_string())
    }
    /// `-1` means "unknown", not "none": the listing is fallible now, and reporting a
    /// keystore we could not read as an EMPTY one is the exact defect this pass removed
    /// from the layer below. A subscriber that treats -1 as 0 is wrong on purpose.
    fn account_count(&self) -> i64 {
        match self.ks.as_ref().map(|k| k.list_accounts()) {
            Some(Ok(a)) => a.len() as i64,
            _ => -1,
        }
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
        gate::holds_role(&self.approver, &Self::caller())
    }

    /// Tier D: the configured custodian, for a method `gate::TIER_D_METHODS` names.
    ///
    /// `HostAnchor` is refused for the same reason as Tier A — it is one undifferentiated
    /// bag covering the shells and every relayed CLI token, so admitting it would make a
    /// plain `logosctl call … import_private_key` a legal way in. A method missing from the
    /// registry is refused outright rather than falling through ungated.
    fn may_mutate(&self, method: &str) -> bool {
        gate::tier_d_admits(method, &self.custodian, &Self::caller())
    }

    /// The live caller, reduced to the pure form the gate reasons about.
    fn caller() -> gate::Caller {
        match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Unknown => gate::Caller::Unknown,
            logos_rust_sdk::LogosCaller::HostAnchor => gate::Caller::HostAnchor,
            logos_rust_sdk::LogosCaller::Module { name, .. } => gate::Caller::Module(name),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => {
                gate::Caller::Derived { parent, leaf }
            }
            logos_rust_sdk::LogosCaller::Operator { name } => gate::Caller::Operator(name),
        }
    }

    /// Tier B: any NAMED module. Returns the name to record against the
    /// request, so results can only be collected by the module that asked.
    fn named_caller(&self) -> Option<String> {
        Self::caller().named().map(str::to_string)
    }
}

#[derive(Deserialize)]
struct ImportMnemonicParams {
    phrase: String,
    #[serde(default)]
    passphrase: String,
    /// The ADDRESS index (the fifth path level). Named `accountIndex` since before there
    /// was a BIP-44 account level to confuse it with; `bip44Account` is that one.
    #[serde(default, alias = "accountIndex")]
    account_index: u32,
    password: String,
    #[serde(default)]
    storage: String,
    #[serde(default, alias = "bip44Account")]
    bip44_account: u32,
    #[serde(default)]
    change: u32,
    #[serde(default, alias = "groupPassword")]
    group_password: String,
    #[serde(default, alias = "groupLabel")]
    group_label: String,
}

#[derive(Deserialize)]
struct DeriveNextParams {
    #[serde(default)]
    group: String,
    #[serde(default, alias = "groupPassword")]
    group_password: String,
    password: String,
    #[serde(default)]
    change: u32,
}

#[derive(Deserialize)]
struct DeriveAtParams {
    group: String,
    #[serde(default, alias = "groupPassword")]
    group_password: String,
    password: String,
    #[serde(default, alias = "bip44Account")]
    bip44_account: Option<u32>,
    #[serde(default)]
    change: u32,
    index: u32,
}

#[derive(Deserialize)]
struct PreviewParams {
    group: String,
    #[serde(default, alias = "groupPassword")]
    group_password: String,
    #[serde(default)]
    change: u32,
    #[serde(default)]
    from: u32,
    #[serde(default)]
    count: u32,
}

#[derive(Deserialize)]
struct UnrelatedParams {
    password: String,
    #[serde(default, alias = "acknowledgeUnrecoverable")]
    acknowledge_unrecoverable: bool,
}

/// `{ group }` — the whole body of both calls that act on one wallet by id.
#[derive(Deserialize)]
struct GroupParams {
    group: String,
}

#[derive(Deserialize)]
struct GroupLabelParams {
    group: String,
    #[serde(default)]
    label: String,
    /// One account of this wallet, sent only where an account is what proves the name. What
    /// the wallet HOLDS decides which credential `password` carries — see `set_group_label`.
    #[serde(default)]
    address: String,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct RemoveParams {
    path: String,
    #[serde(default, alias = "acknowledgeMayBeKeyMaterial")]
    acknowledge_may_be_key_material: bool,
}

fn derived_reply(d: &Derived) -> String {
    json!({ "ok": true, "address": d.address.to_string(), "path": d.path,
            "group": d.group, "index": d.index, "origin": "derived" })
    .to_string()
}

/// Parse params that carry a secret. On failure the buffer is scrubbed rather than left to
/// outlive the call — a malformed request still contained a password.
fn parse_secret_params<T: serde::de::DeserializeOwned>(
    params_json: String,
) -> std::result::Result<T, String> {
    let owned = Zeroizing::new(params_json);
    serde_json::from_str(&owned).map_err(err)
}

impl KeystoreModule for KeystoreModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        let base = std::path::Path::new(&ctx.instance_persistence_path);
        self.ks = Some(Keystore::new(base.join("keystore")));

        // Who may approve is configuration, not a method: a `set_approver` call
        // would be a remotely-writable answer to "who may authorise a
        // signature". This file is written by whoever deploys the module.
        //
        // ABSENT means "not configured", and the defaults apply. UNREADABLE means we do not
        // know who was named — and silently reverting to the defaults would hand both roles
        // to modules the deployer may have replaced on purpose. An empty role admits nobody
        // (`gate::holds_role`), so a torn config makes every gated method refuse instead.
        let cfg = match std::fs::read_to_string(base.join("keystore.json")) {
            Ok(t) => serde_json::from_str::<serde_json::Value>(&t).ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(serde_json::Value::Null),
            Err(_) => None,
        };
        let Some(cfg) = cfg else {
            self.approver = String::new();
            self.custodian = String::new();
            self.config_error =
                "keystore.json is present but unreadable, so no module holds the approver or \
                 custodian role"
                    .into();
            return;
        };
        let name_or = |key: &str, fallback: &str| {
            cfg.get(key).and_then(|a| a.as_str()).map(str::to_string).unwrap_or_else(|| fallback.to_string())
        };
        self.approver = name_or("approver", DEFAULT_APPROVER);
        self.custodian = name_or("custodian", DEFAULT_CUSTODIAN);
    }

    fn create_mnemonic(&mut self, words: i64) -> String {
        if !self.may_mutate("create_mnemonic") {
            return not_authorized();
        }
        match Keystore::create_mnemonic(words as u32) {
            Ok(phrase) => json!({ "ok": true, "phrase": phrase }).to_string(),
            Err(e) => err(e),
        }
    }

    fn import_mnemonic(&mut self, params_json: String) -> String {
        if !self.may_mutate("import_mnemonic") {
            // Scrub before returning: the phrase and the password are both in this buffer,
            // and a refusal is exactly when they should not outlive the call.
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: ImportMnemonicParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let storage = match Storage::parse(&p.storage) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let res = match self.ks() {
            Ok(ks) => ks.import_mnemonic_ex(&ImportRequest {
                phrase: &p.phrase,
                bip39_passphrase: &p.passphrase,
                index: p.account_index,
                password: &p.password,
                storage,
                bip44_account: p.bip44_account,
                change: p.change,
                group_password: &p.group_password,
                group_label: &p.group_label,
            }),
            Err(e) => return err(e),
        };
        match res {
            Ok(d) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": d.address.to_string(), "path": d.path,
                        "group": d.group, "storage": storage.as_str(), "index": d.index,
                        "origin": "derived" })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn derive_next_account(&mut self, params_json: String) -> String {
        if !self.may_mutate("derive_next_account") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: DeriveNextParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        // An absent group is "the only one that can derive"; with several, the core
        // refuses and names them rather than picking one.
        let group = (!p.group.is_empty()).then_some(p.group.as_str());
        let res = match self.ks() {
            Ok(ks) => ks.derive_next_account(group, &p.group_password, &p.password, p.change),
            Err(e) => return err(e),
        };
        match res {
            Ok(d) => {
                emit_accounts_changed(self.account_count());
                derived_reply(&d)
            }
            Err(e) => err(e),
        }
    }

    fn derive_account_at(&mut self, params_json: String) -> String {
        if !self.may_mutate("derive_account_at") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: DeriveAtParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let res = match self.ks() {
            Ok(ks) => ks.derive_account_at(
                &p.group,
                &p.group_password,
                &p.password,
                p.bip44_account,
                p.change,
                p.index,
            ),
            Err(e) => return err(e),
        };
        match res {
            Ok(d) => {
                emit_accounts_changed(self.account_count());
                derived_reply(&d)
            }
            Err(e) => err(e),
        }
    }

    fn preview_addresses(&mut self, params_json: String) -> String {
        if !self.may_mutate("preview_addresses") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: PreviewParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match self.ks() {
            Ok(ks) => match ks.preview_addresses(&p.group, &p.group_password, p.change, p.from, p.count) {
                Ok(rows) => {
                    let addresses: Vec<_> = rows
                        .iter()
                        .map(|r| {
                            json!({ "index": r.index, "path": r.path,
                                    "address": r.address.to_string(), "present": r.present })
                        })
                        .collect();
                    json!({ "ok": true, "group": p.group, "addresses": addresses }).to_string()
                }
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn create_unrelated_account(&mut self, params_json: String) -> String {
        if !self.may_mutate("create_unrelated_account") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: UnrelatedParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        // The acknowledgement is taken BEFORE the keystore is reached, because it is what
        // generates the key: without it there is nothing to persist.
        let key = match Unrecoverable::acknowledged(p.acknowledge_unrecoverable) {
            Ok(key) => key,
            Err(e) => return err(e),
        };
        let res = match self.ks() {
            Ok(ks) => ks.create_unrelated_account(&p.password, key),
            Err(e) => return err(e),
        };
        match res {
            Ok(addr) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "address": addr.to_string(), "origin": "random" }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn forget_derivation(&mut self, params_json: String) -> String {
        if !self.may_mutate("forget_derivation") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: GroupParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let res = match self.ks() {
            Ok(ks) => ks.forget_derivation(&p.group),
            Err(e) => return err(e),
        };
        match res {
            Ok(f) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "group": f.group, "storage": "plain",
                        "recordUpdated": f.record_updated, "stranded": f.was_stranded,
                        "stagedRemoved": f.staged_removed })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn remove_group(&mut self, params_json: String) -> String {
        if !self.may_mutate("remove_group") {
            return not_authorized();
        }
        let p: GroupParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let res = match self.ks() {
            Ok(ks) => ks.remove_group(&p.group),
            Err(e) => return err(e),
        };
        match res {
            Ok(r) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "group": r.group, "recordRemoved": r.record_removed,
                        "nameRemoved": r.name_removed })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn list_groups(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.list_groups(),
            Err(e) => return err(e),
        };
        match res {
            Ok(rows) => {
                let groups: Vec<_> = rows
                    .into_iter()
                    .map(|g| {
                        json!({
                            "id": g.id, "storage": g.group.storage.as_str(),
                            "pathPrefix": g.group.path_prefix, "nextIndex": g.group.next_index,
                            "usedIndices": g.used_indices, "retiredIndices": g.group.retired,
                            "usedPassphrase": g.group.used_passphrase, "label": g.group.label,
                            "accountCount": g.account_count, "derivable": g.derivable,
                            "stranded": g.stranded, "staged": g.staged,
                        })
                    })
                    .collect();
                json!({ "ok": true, "groups": groups }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn list_derivation_keys(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.group_store(),
            Err(e) => return err(e),
        };
        match res {
            Ok(store) => json!({ "ok": true, "groups": store.ids(), "staged": store.staged,
                                 "unexplained": store.possible_keys, "links": store.links })
            .to_string(),
            Err(e) => err(e),
        }
    }

    fn get_provenance(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.provenance_view(),
            Err(e) => return err(e),
        };
        match res {
            Ok(rows) => {
                let accounts: serde_json::Map<String, serde_json::Value> = rows
                    .into_iter()
                    .map(|a| {
                        (
                            a.address.to_string(),
                            json!({ "origin": a.provenance.origin, "group": a.provenance.group,
                                    "path": a.provenance.path, "index": a.provenance.index,
                                    "derivable": a.derivable }),
                        )
                    })
                    .collect();
                json!({ "ok": true, "accounts": accounts }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn settle(&mut self) -> String {
        if !self.may_mutate("settle") {
            return not_authorized();
        }
        let res = match self.ks() {
            Ok(ks) => ks.settle(),
            Err(e) => return err(e),
        };
        match res {
            Ok(s) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "swept": s.swept, "promoted": s.promoted,
                        "unexplained": s.left.unexplained_all(), "links": s.left.links,
                        "staged": s.left.staged_vaults, "importStages": s.left.import_stages })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn remove_unexplained(&mut self, params_json: String) -> String {
        if !self.may_mutate("remove_unexplained") {
            return not_authorized();
        }
        let p: RemoveParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let res = match self.ks() {
            Ok(ks) => ks.remove_unexplained(&p.path, p.acknowledge_may_be_key_material),
            Err(e) => return err(e),
        };
        match res {
            Ok(removed) => {
                emit_accounts_changed(self.account_count());
                json!({ "ok": true, "removed": removed }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn import_private_key(&mut self, priv_hex: String, password: String) -> String {
        if !self.may_mutate("import_private_key") {
            let _ = Zeroizing::new(priv_hex);
            let _ = Zeroizing::new(password);
            return not_authorized();
        }
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
        if !self.may_mutate("import_keystore_json") {
            let _ = Zeroizing::new(key_json);
            let _ = Zeroizing::new(password);
            let _ = Zeroizing::new(new_password);
            return not_authorized();
        }
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
        if !self.may_mutate("export_keystore_json") {
            let _ = Zeroizing::new(password);
            return not_authorized();
        }
        match self.ks() {
            Ok(ks) => match ks.export_keystore_json(&address, &password) {
                Ok(json_str) => json!({ "ok": true, "keystore": json_str }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn change_password(&mut self, address: String, old_password: String, new_password: String) -> String {
        if !self.may_mutate("change_password") {
            let _ = Zeroizing::new(old_password);
            let _ = Zeroizing::new(new_password);
            return not_authorized();
        }
        match self.ks() {
            Ok(ks) => match ks.change_password(&address, &old_password, &new_password) {
                Ok(addr) => json!({ "ok": true, "address": addr.to_string() }).to_string(),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn set_label(&mut self, address: String, label: String, password: String) -> String {
        if !self.may_mutate("set_label") {
            let _ = Zeroizing::new(password);
            return not_authorized();
        }
        let password = Zeroizing::new(password);
        match self.ks() {
            Ok(ks) => match ks.set_label(&address, &label, &password) {
                Ok(()) => {
                    emit_accounts_changed(self.account_count());
                    json!({ "ok": true }).to_string()
                }
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn get_labels(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.get_labels(),
            Err(e) => return err(e),
        };
        match res {
            Ok(labels) => json!({ "ok": true, "labels": labels }).to_string(),
            Err(e) => err(e),
        }
    }

    fn set_group_label(&mut self, params_json: String) -> String {
        if !self.may_mutate("set_group_label") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: GroupLabelParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let req = GroupLabelRequest {
            group: &p.group,
            label: &p.label,
            address: &p.address,
            password: &p.password,
        };
        match self.ks() {
            Ok(ks) => match ks.set_group_label(&req) {
                Ok(()) => {
                    emit_accounts_changed(self.account_count());
                    json!({ "ok": true }).to_string()
                }
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    fn get_group_labels(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.get_group_labels(),
            Err(e) => return err(e),
        };
        match res {
            Ok(labels) => json!({ "ok": true, "labels": labels }).to_string(),
            Err(e) => err(e),
        }
    }

    /// Reports what the keystore directory holds that this module did not write. Those
    /// paths used to be dropped without a word by a name-pattern scan; they are at worst one
    /// account each, so they are reported here rather than refused.
    fn list_accounts(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.account_report(),
            Err(e) => return err(e),
        };
        match res {
            Ok(r) => {
                let render = |v: &[_]| v.iter().map(ToString::to_string).collect::<Vec<String>>();
                json!({ "ok": true,
                        "accounts": render(&r.accounts),
                        "staged": render(&r.staged),
                        "unexplained": r.unexplained,
                        "mismatched": r.mismatched })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn has_address(&mut self, address: String) -> bool {
        self.ks().map(|ks| ks.has_address(&address)).unwrap_or(false)
    }

    fn delete_account(&mut self, address: String, password: String) -> bool {
        // Gating this also closes an unmetered password oracle: before, any module could
        // guess at the vault password here, and a correct guess DESTROYED the account.
        if !self.may_mutate("delete_account") {
            let _ = Zeroizing::new(password);
            return false;
        }
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
            return not_authorized();
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
            // `signed`, matching the documented contract and `approve`'s count
            // field name-for-meaning: this is the array the requester collects.
            Ok(results) => json!({ "ok": true, "signed": results }).to_string(),
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
                // A COUNT, not the signatures. The approver authorises a
                // bundle; it never receives what it authorised. Only the
                // requester can collect that, and only with the receipt it was
                // handed at request time. Distinct key from fetch_result's
                // `signed` array so the two can never be confused.
                json!({ "ok": true, "signed_count": n }).to_string()
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
        json!({ "ok": true, "kind": kind, "identity": name,
                "approver": self.approver, "custodian": self.custodian,
                "configError": self.config_error })
        .to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreModuleImpl>();
}
