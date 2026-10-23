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
use crate::btc::{Chain as BtcChain, Family as BtcFamily};
use crate::gate;
use crate::keystore::{Derived, GroupLabelRequest, ImportRequest, KeepPhrase, Keystore, Storage};
use crate::signer::{self as ks_signer, KeystoreSigner, Unlocks};
use crate::{BitcoinImport, WalletStart};
use logos_signer_interface::jobs::{JobTable, KeyJobs};
use logos_signer_interface::{json as signer_json, wire};

/// The keystore module's IPC contract. Each non-defaulted method is a callable
/// module method. Private keys never appear in any signature — only addresses,
/// signed payloads, and (re-encrypted) keystore JSON cross the boundary.
pub trait KeystoreModule: Send + 'static {
    /// Name who holds the three roles: `{ approvers?, custodians?, managers? }` → `{ ok,
    /// approvers, custodians, managers }`. TOTAL — a role the document does not name is held by
    /// nobody — and it takes effect at once, on a module that has been serving the built-in
    /// defaults (`evm_signer_ui`, `evm_keystore_ui`, `signer_manager_module`) since it loaded. A
    /// malformed document is refused and the roles in force are left untouched.
    ///
    /// UNGATED, deliberately and for now: any caller can name itself custodian and then
    /// mutate the keystore. Protecting it is deferred, not refuted — see docs/specs.md.
    fn configure(&mut self, config_json: String) -> String;
    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24) — `{ ok, phrase }`.
    fn create_mnemonic(&mut self, words: i64) -> String;
    /// Derive + persist an account from a mnemonic, creating its derivation group. params
    /// JSON: `{ phrase, passphrase?, accountIndex?, password, storage?, bip44Account?,
    /// change?, groupPassword?, groupLabel? }` → `{ ok, address, path, group, storage,
    /// index, origin }`. `accountIndex` is the ADDRESS index; `bip44Account` is the
    /// hardened BIP-44 account level. `storage` defaults to `"plain"` — keeping nothing —
    /// so the pre-HD call shape behaves exactly as it did.
    fn import_mnemonic(&mut self, params_json: String) -> String;

    /// Add a wallet only after verifying its phrase belongs to sourceGroup.
    fn import_seed_wallet(&mut self, params_json: String) -> String;
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
    /// Read-only recovery-source preview: phrase or keptPhrase + phrasePassword,
    /// passphrase?, sourceGroup?, family, chain, account?, from?, count?. Tier D.
    fn preview_mnemonic(&mut self, params_json: String) -> String;
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
    /// Wallet ownership for account pickers,
    /// `{ ok, wallets: { <address>: { wallet, index? } } }`. UNGATED. This is the
    /// canonical join of account provenance and wallet names, so every consumer groups
    /// accounts the same way.
    fn get_account_wallets(&mut self) -> String;
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
    /// one thing can be on screen. `claim_lines` is the requester's own account of
    /// what this is for; `render_lines` is what is actually signed. An approver must
    /// keep them apart. `{ ok, handle, bundle_id, requester, claim_lines, render_lines }`.
    fn acknowledge(&mut self, handle: String) -> String;
    /// The human said yes. One key derivation, every leg signed, then wiped.
    /// `bundle_id` must be the value that was displayed. `{ ok, signed }`.
    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String;
    /// The human said no.
    fn reject(&mut self, handle: String) -> bool;

    // ── logos.signer/1: the keystore as a signer ─────────────────────────
    /// `{ ok, interface, kind, model, families, requestKinds, showsRequest, collects }`. UNGATED:
    /// it describes this kind of signer, not any account.
    fn signer_info(&mut self) -> String;
    /// Every account as public material, `{ ok, accounts }`. The manager and the custodian only:
    /// a Bitcoin wallet's xpub reveals its whole history.
    fn signer_accounts(&mut self) -> String;
    /// Sign the hashes the manager prepared, with the account's password or inside an unlock.
    /// `{ account, kind: "hash", items, secret? }` → `{ ok, job }`. Tier M.
    fn sign(&mut self, request_json: String) -> String;
    /// `{ ok, job, state, code?, error? }`. Tier M.
    fn sign_status(&mut self, job: String) -> String;
    /// `{ ok, job, signatures }`, repeatable until the job is swept. Tier M.
    fn sign_result(&mut self, job: String) -> String;
    /// `{ ok, job }`. Tier M.
    fn cancel_sign(&mut self, job: String) -> String;
    /// A seed's unlock key, for the signer manager to unlock the wallet's data: `{ seed, index,
    /// secret }`, the secret being the wallet's password → `{ ok, job }`, done at once. Tier M.
    fn unlock_key(&mut self, request_json: String) -> String;
    /// `{ ok, job, state, code?, error? }`. Tier M.
    fn unlock_key_status(&mut self, job: String) -> String;
    /// `{ ok, job, key }`, once: the job forgets it. Tier M.
    fn unlock_key_result(&mut self, job: String) -> String;
    /// `{ ok, job }`. Tier M.
    fn cancel_unlock_key(&mut self, job: String) -> String;
    /// Hold an account's key in memory until `ttlMs` passes or `count` requests are signed.
    /// `{ account, password, ttlMs?, count? }` → `{ ok, account, expiresInMs, countLeft }`. Tier M:
    /// the manager keeps which apps the unlock covers, so nothing else may reach it.
    fn unlock(&mut self, params_json: String) -> String;
    /// `{ account? }` locks one account, `{}` every one → `{ ok, locked }`. Tier M.
    fn lock(&mut self, params_json: String) -> String;
    /// `{ ok, unlocked: [{ account, expiresInMs, countLeft }] }`. The manager and the custodian.
    fn unlocked(&mut self) -> String;
    /// A Bitcoin wallet's database key for an open request the keys app approved: `{ group,
    /// password? }` → `{ ok, group, databaseKey, origin, birthday }`, from its unlock when no
    /// password. Tier M.
    fn database_key(&mut self, params_json: String) -> String;
    /// The database key of a Bitcoin wallet whose key is on a device, for an open the keys app
    /// approved. The first open makes it under the password the person set: `{ signer, account,
    /// password, birthday? }` → `{ ok, signer, account, databaseKey, origin, birthday, created }`. Tier M.
    fn device_database_key(&mut self, params_json: String) -> String;
    /// The device accounts with a database key here: `{ ok, wallets: [{ signer, account,
    /// birthday, createdMs }] }`. The manager and the custodian.
    fn device_wallets(&mut self) -> String;
    /// Forget a device account's database key: `{ signer, account }` → `{ ok, forgotten }`. Tier D.
    fn forget_device_wallet(&mut self, params_json: String) -> String;
    /// A Bitcoin wallet from a phrase: `{ phrase, passphrase?, family, chain, account?, password,
    /// label?, keepPhrase?: { password }, origin?, birthday? }`, or `{ keptPhrase, phrasePassword, … }`
    /// in place of `phrase` → `{ ok, group, family, chain, path, fingerprint, external, internal,
    /// phrase, origin, birthday }`. Tier D.
    fn import_bitcoin(&mut self, params_json: String) -> String;
    /// A kept phrase's words, for the keys app to show: `{ phrase, password }` → `{ ok, phrase,
    /// words }`. Tier D.
    fn show_phrase(&mut self, params_json: String) -> String;
    /// Remove a kept phrase, no password needed: `{ phrase }` → `{ ok, forgotten }`. Tier D.
    fn forget_phrase(&mut self, params_json: String) -> String;
    /// Every kept phrase: `{ ok, phrases: [{ id, groups, staged }] }`. Ungated: ids only.
    fn list_phrases(&mut self) -> String;
    /// A Bitcoin wallet's descriptors, for the keys app to show: `{ group }` → `{ ok, group,
    /// external, internal }`. The custodian and the manager: an xpub shows the whole history.
    fn account_descriptors(&mut self, params_json: String) -> String;

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
    /// The signer interface's account event, sent with every `accounts_changed`.
    fn signer_accounts_changed(&self, count: i64);
    /// The signer interface's device event. The keystore has no device and never sends it.
    fn signer_changed(&self, state: String);
    /// The signer interface's job event. Keystore jobs finish inside `sign` and never send it.
    fn sign_progress(&self, job: String, state: String);
}

// The builder injects the generated module-impl scaffold here: `install`,
// `context()`, `RustModuleContext`, the `emit_accounts_changed` emitter, and the
// C-ABI dispatch. No `build.rs`, no `OUT_DIR`.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

/// The module behind `logos.wallets/1`: the signer manager, bound at runtime, since it depends on
/// this keystore and this keystore can't depend on it.
const WALLETS: &str = "signer_manager_module";

#[derive(Default)]
struct KeystoreModuleImpl {
    ks: Option<Keystore>,
    approvals: Approvals,
    /// Who may approve and who may mutate. Defaults from load, replaced by `configure`.
    roles: gate::Roles,
    /// Keys held by an unlock, in memory only, and the signer interface's jobs.
    unlocks: Unlocks,
    jobs: JobTable,
    /// Unlock-key jobs: read once, by the manager only, and announced nowhere.
    keys: KeyJobs,
}

impl KeystoreModuleImpl {
    fn ks(&mut self) -> std::result::Result<&mut Keystore, String> {
        self.ks
            .as_mut()
            .ok_or_else(|| "keystore not initialized (context not ready)".to_string())
    }
    /// The keystore as a signer, over this module's state for one call.
    fn signer(&mut self) -> std::result::Result<KeystoreSigner<'_>, String> {
        let ks = self.ks.as_ref().ok_or_else(|| "keystore not initialized (context not ready)".to_string())?;
        Ok(KeystoreSigner { ks, unlocks: &mut self.unlocks, jobs: &mut self.jobs, keys: &mut self.keys })
    }

    /// Tell the signer manager about the wallet an import added, while its password is at hand,
    /// so the person never unlocks it a second time. Asked without waiting: the manager answers
    /// in its own time, and without one installed the wallet is added all the same.
    fn enroll(&mut self, account_or_group: &str, password: &str) {
        let Ok(ks) = self.ks() else { return };
        let Ok(e) = ks.enrolment(account_or_group, password) else { return };
        let body = Zeroizing::new(
            json!({ "seed": e.seed, "kind": "keystore", "unlockKey": hex::encode(e.unlock_key), "name": e.name,
                    "origin": e.origin, "birthday": e.birthday })
            .to_string(),
        );
        // Not from this call: the first call to the manager waits for its connection in a nested
        // event loop, where the next call into this module would wait on this one's lock.
        std::thread::spawn(move || {
            wallets::WalletsClient::bind(WALLETS).enroll_seed_async(&body, |_| {});
        });
    }

    /// Both account events: the keystore's own, and the signer interface's.
    fn announce(&self) {
        let count = self.account_count();
        emit_accounts_changed(count);
        emit_signer_accounts_changed(count);
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

/// The words to import, typed or opened from a kept phrase, and what the wallet records of them.
fn words_and_keep<'a>(
    ks: &Keystore,
    typed: Zeroizing<String>,
    kept: Option<&'a str>,
    keep_password: Option<&'a str>,
    phrase_password: &str,
) -> std::result::Result<(Zeroizing<String>, KeepPhrase<'a>), String> {
    match (kept, typed.trim().is_empty(), keep_password) {
        (Some(id), true, None) => {
            ks.show_phrase(id, phrase_password).map(|w| (w, KeepPhrase::Kept(id))).map_err(|e| e.to_string())
        }
        (None, false, keep) => Ok((typed, keep.map_or(KeepPhrase::No, KeepPhrase::New))),
        (Some(_), _, _) => Err("keptPhrase replaces phrase, and is kept already".into()),
        (None, true, _) => Err("name the phrase, or a kept one".into()),
    }
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
        gate::holds_any_role(&self.roles.approvers, &Self::caller())
    }

    /// Tier D: the configured custodian, for a method `gate::TIER_D_METHODS` names.
    ///
    /// `HostAnchor` is refused for the same reason as Tier A — it is one undifferentiated
    /// bag covering the shells and every relayed CLI token, so admitting it would make a
    /// plain `logosctl call … import_private_key` a legal way in. A method missing from the
    /// registry is refused outright rather than falling through ungated.
    fn may_mutate(&self, method: &str) -> bool {
        gate::tier_d_admits(method, &self.roles.custodians, &Self::caller())
    }

    /// Tier M: a configured manager, for a method `gate::TIER_M_METHODS` names.
    fn is_manager(&self, method: &str) -> bool {
        gate::tier_m_admits(method, &self.roles.managers, &Self::caller())
    }

    /// Account listings with xpubs, and what is unlocked: the manager and the custodian.
    fn reads_signer_state(&self) -> bool {
        let caller = Self::caller();
        gate::holds_any_role(&self.roles.managers, &caller) || gate::holds_any_role(&self.roles.custodians, &caller)
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
    #[serde(default, rename = "sourceGroup")]
    source_group: Option<String>,
    #[serde(default)]
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
    /// Keep the phrase in a vault of its own, under this password.
    #[serde(default, rename = "keepPhrase")]
    keep_phrase: Option<PasswordParams>,
    /// Make the wallet from a kept phrase rather than typed words.
    #[serde(default, rename = "keptPhrase")]
    kept_phrase: Option<String>,
    #[serde(default, rename = "phrasePassword")]
    phrase_password: String,
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
#[serde(rename_all = "camelCase")]
struct UnlockParams {
    account: String,
    password: String,
    #[serde(default)]
    ttl_ms: Option<u64>,
    #[serde(default)]
    count: Option<u32>,
}

#[derive(Deserialize, Default)]
struct LockParams {
    #[serde(default)]
    account: Option<String>,
}

#[derive(Deserialize)]
struct DatabaseKeyParams {
    group: String,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize)]
struct DeviceKeyParams {
    signer: String,
    account: String,
    password: String,
    #[serde(default)]
    birthday: Option<String>,
}

#[derive(Deserialize)]
struct DeviceWalletParams {
    signer: String,
    account: String,
}

#[derive(Deserialize)]
struct ImportBitcoinParams {
    #[serde(default, rename = "sourceGroup")]
    source_group: Option<String>,
    #[serde(default)]
    phrase: String,
    #[serde(default)]
    passphrase: String,
    family: String,
    chain: String,
    #[serde(default)]
    account: u32,
    password: String,
    #[serde(default)]
    label: String,
    /// Keep the phrase in a vault of its own, under this password.
    #[serde(default, rename = "keepPhrase")]
    keep_phrase: Option<PasswordParams>,
    /// Make the wallet from a kept phrase rather than typed words.
    #[serde(default, rename = "keptPhrase")]
    kept_phrase: Option<String>,
    #[serde(default, rename = "phrasePassword")]
    phrase_password: String,
    /// `created` when the keys app made the phrase for this wallet; `restored`, the default, otherwise.
    #[serde(default)]
    origin: Option<String>,
    /// A restored wallet's first day of use, `YYYY-MM-DD`, if the person knows it.
    #[serde(default)]
    birthday: Option<String>,
}

#[derive(Deserialize)]
struct PasswordParams {
    password: String,
}

#[derive(Deserialize)]
struct PhraseParams {
    phrase: String,
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
    }

    fn configure(&mut self, config_json: String) -> String {
        match self.roles.configure(&config_json) {
            Ok(()) => json!({ "ok": true, "approvers": self.roles.approvers,
                              "custodians": self.roles.custodians, "managers": self.roles.managers })
            .to_string(),
            Err(e) => err(e),
        }
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

    fn import_seed_wallet(&mut self, params_json: String) -> String {
        let mut params = Zeroizing::new(params_json);
        if !self.may_mutate("import_seed_wallet") {
            return not_authorized();
        }
        #[derive(Deserialize)]
        struct Target {
            #[serde(rename = "sourceGroup")]
            source_group: String,
            family: String,
        }
        let target: Target = match serde_json::from_str(&params) {
            Ok(p) => p,
            Err(_) => return err("sourceGroup and family are required"),
        };
        if target.source_group.is_empty() {
            return err("sourceGroup is required");
        }
        // The import methods verify the source before any writes and announce on success.
        // A distinct API ensures an older backend cannot silently ignore sourceGroup.
        match target.family.as_str() {
            "evm" => self.import_mnemonic(std::mem::take(&mut *params)),
            "bitcoin" | "bitcoin_taproot" => self.import_bitcoin(std::mem::take(&mut *params)),
            _ => err("unsupported wallet family"),
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
        let (typed, passphrase, password) =
            (Zeroizing::new(p.phrase), Zeroizing::new(p.passphrase), Zeroizing::new(p.password));
        let (keep_password, phrase_password, group_password) = (
            Zeroizing::new(p.keep_phrase.map(|k| k.password)),
            Zeroizing::new(p.phrase_password),
            Zeroizing::new(p.group_password),
        );
        let ks = match self.ks() {
            Ok(ks) => ks,
            Err(e) => return err(e),
        };
        let (phrase, keep) = match words_and_keep(
            ks,
            typed,
            p.kept_phrase.as_deref(),
            keep_password.as_deref(),
            &phrase_password,
        ) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if let Some(source) = &p.source_group {
            if let Err(e) = ks.check_seed_source(&phrase, &passphrase, source) {
                return err(e);
            }
        }
        let res = ks.import_mnemonic_ex(&ImportRequest {
            phrase: &phrase,
            bip39_passphrase: &passphrase,
            index: p.account_index,
            password: &password,
            storage,
            bip44_account: p.bip44_account,
            change: p.change,
            group_password: &group_password,
            group_label: &p.group_label,
            keep,
        });
        match res {
            Ok(d) => {
                let kept =
                    ks.get_groups().ok().and_then(|gs| gs.get(&d.group).and_then(|r| r.phrase.clone()));
                self.announce();
                self.enroll(&d.address.to_string(), &password);
                json!({ "ok": true, "address": d.address.to_string(), "path": d.path,
                        "group": d.group, "storage": storage.as_str(), "index": d.index,
                        "origin": "derived", "phrase": kept })
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
                self.announce();
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
                self.announce();
                derived_reply(&d)
            }
            Err(e) => err(e),
        }
    }

    fn preview_mnemonic(&mut self, params_json: String) -> String {
        let params = Zeroizing::new(params_json);
        if !self.may_mutate("preview_mnemonic") { return not_authorized(); }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Preview {
            #[serde(default)] phrase: String,
            #[serde(default)] passphrase: String,
            #[serde(default)] kept_phrase: Option<String>,
            #[serde(default)] phrase_password: String,
            #[serde(default)] source_group: Option<String>,
            family: String, chain: String,
            #[serde(default)] account: u32,
            #[serde(default)] from: u32,
            count: u32,
        }
        let p: Preview = match serde_json::from_str(&params) { Ok(p) => p, Err(_) => return err("invalid preview parameters") };
        let typed = Zeroizing::new(p.phrase);
        let passphrase = Zeroizing::new(p.passphrase);
        let password = Zeroizing::new(p.phrase_password);
        let ks = match self.ks() { Ok(ks) => ks, Err(e) => return err(e) };
        let (words, _) = match words_and_keep(ks, typed, p.kept_phrase.as_deref(), None, &password) {
            Ok(v) => v, Err(e) => return err(e),
        };
        if let Some(group) = p.source_group {
            if let Err(e) = ks.check_seed_source(&words, &passphrase, &group) { return err(e); }
        }
        match ks.preview_mnemonic(&words, &passphrase, &p.family, &p.chain, p.account, p.from, p.count) {
            Ok(addresses) => json!({"ok": true, "addresses": addresses}).to_string(),
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
                self.announce();
                self.enroll(&addr.to_string(), &p.password);
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
                self.announce();
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
                self.announce();
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
                        let preview = if g.group.family.is_some() {
                            match self.ks().and_then(|ks| ks.bitcoin_address_preview(&g.id).map_err(|e| e.to_string())) {
                                Ok((address, path)) => json!({ "address": address, "path": path, "firstReceiving": true }),
                                Err(error) => json!({ "error": error }),
                            }
                        } else { serde_json::Value::Null };
                        json!({
                            "id": g.id, "storage": g.group.storage.as_str(),
                            "pathPrefix": g.group.path_prefix,
                            "seedId": g.group.seed.as_ref().map(|s| &s.id), "nextIndex": g.group.next_index,
                            "usedIndices": g.used_indices, "retiredIndices": g.group.retired,
                            "usedPassphrase": g.group.used_passphrase, "label": g.group.label,
                            "accountCount": g.account_count, "derivable": g.derivable,
                            "stranded": g.stranded, "staged": g.staged,
                            "family": g.group.family, "chain": g.group.chain,
                            "phrase": g.group.phrase, "preview": preview,
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

    fn get_account_wallets(&mut self) -> String {
        let res = match self.ks() {
            Ok(ks) => ks.account_wallets(),
            Err(e) => return err(e),
        };
        match res {
            Ok(wallets) => json!({ "ok": true, "wallets": wallets }).to_string(),
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
                self.announce();
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
                self.announce();
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
                self.announce();
                self.enroll(&addr.to_string(), &password);
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
                self.announce();
                self.enroll(&addr.to_string(), &new_password);
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
                Ok(addr) => {
                    // A new password ends an unlock opened with the old one.
                    self.unlocks.lock(Some(&addr.to_string()));
                    json!({ "ok": true, "address": addr.to_string() }).to_string()
                }
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
                    self.announce();
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
                    self.announce();
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
                self.unlocks.lock(Some(&address));
                self.announce();
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
        if self.roles.approvers.is_empty() {
            return not_authorized();
        }
        // The keystore is lent so a Bitcoin request can be read against its wallet.
        match self.approvals.request_with(self.ks.as_ref(), &requester, &intent_json) {
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
                "requester": r.requester, "claim_lines": r.claim_lines,
                "render_lines": r.render_lines,
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

    fn signer_info(&mut self) -> String {
        wire::ok(serde_json::to_value(ks_signer::info()).unwrap_or_default())
    }

    fn signer_accounts(&mut self) -> String {
        if !self.reads_signer_state() {
            return not_authorized();
        }
        let raw = match self.signer() {
            Ok(mut s) => signer_json::signer_accounts(&mut s),
            Err(e) => return err(e),
        };
        let mut reply: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v, Err(_) => return raw,
        };
        if let Ok(origins) = self.ks().and_then(|ks| ks.account_origins().map_err(|e| e.to_string())) {
            if let Some(rows) = reply["accounts"].as_array_mut() {
                for row in rows {
                    // An EVM account by its address, a Bitcoin wallet by its id.
                    let key = row["address"].as_str().or_else(|| row["id"].as_str()).map(str::to_string);
                    if let Some(origin) = key.and_then(|k| {
                        origins.iter().find(|(key, _)| key.eq_ignore_ascii_case(&k)).map(|(_, v)| v)
                    }) { row["origin"] = origin.clone(); }
                }
            }
        }
        reply.to_string()
    }

    fn sign(&mut self, request_json: String) -> String {
        let request_json = Zeroizing::new(request_json);
        if !self.is_manager("sign") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::sign(&mut s, &request_json),
            Err(e) => err(e),
        }
    }

    fn unlock_key(&mut self, request_json: String) -> String {
        let request_json = Zeroizing::new(request_json);
        if !self.is_manager("unlock_key") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::unlock_key(&mut s, &request_json),
            Err(e) => err(e),
        }
    }

    fn unlock_key_status(&mut self, job: String) -> String {
        if !self.is_manager("unlock_key_status") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::unlock_key_status(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn unlock_key_result(&mut self, job: String) -> String {
        if !self.is_manager("unlock_key_result") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::unlock_key_result(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn cancel_unlock_key(&mut self, job: String) -> String {
        if !self.is_manager("cancel_unlock_key") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::cancel_unlock_key(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn sign_status(&mut self, job: String) -> String {
        if !self.is_manager("sign_status") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::sign_status(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn sign_result(&mut self, job: String) -> String {
        if !self.is_manager("sign_result") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::sign_result(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn cancel_sign(&mut self, job: String) -> String {
        if !self.is_manager("cancel_sign") {
            return not_authorized();
        }
        match self.signer() {
            Ok(mut s) => signer_json::cancel_sign(&mut s, &job),
            Err(e) => err(e),
        }
    }

    fn unlock(&mut self, params_json: String) -> String {
        if !self.is_manager("unlock") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: UnlockParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = Zeroizing::new(p.password);
        let ttl = p.ttl_ms.map(Duration::from_millis);
        match self.signer() {
            Ok(mut s) => match s.unlock(&p.account, &password, ttl, p.count) {
                Ok(v) => json!({ "ok": true, "account": v.account, "expiresInMs": v.expires_in_ms,
                                 "countLeft": v.count_left })
                .to_string(),
                Err(e) => wire::err(&e),
            },
            Err(e) => err(e),
        }
    }

    fn lock(&mut self, params_json: String) -> String {
        if !self.is_manager("lock") {
            return not_authorized();
        }
        let p: LockParams = if params_json.trim().is_empty() {
            LockParams::default()
        } else {
            match serde_json::from_str(&params_json) {
                Ok(p) => p,
                Err(e) => return err(e),
            }
        };
        let locked = self.unlocks.lock(p.account.as_deref());
        json!({ "ok": true, "locked": locked }).to_string()
    }

    fn unlocked(&mut self) -> String {
        if !self.reads_signer_state() {
            return not_authorized();
        }
        let list: Vec<_> = self
            .unlocks
            .list()
            .into_iter()
            .map(|v| json!({ "account": v.account, "expiresInMs": v.expires_in_ms, "countLeft": v.count_left }))
            .collect();
        json!({ "ok": true, "unlocked": list }).to_string()
    }

    fn database_key(&mut self, params_json: String) -> String {
        if !self.is_manager("database_key") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: DatabaseKeyParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = p.password.map(Zeroizing::new);
        let key = match self.signer() {
            Ok(mut s) => match s.database_key(&p.group, password.as_ref().map(|pw| pw.as_str())) {
                Ok(key) => key,
                Err(e) => return wire::err(&e),
            },
            Err(e) => return err(e),
        };
        // Where the wallet core starts scanning travels with the key that opens its database.
        match self.ks().and_then(|ks| ks.bitcoin_start(&p.group).map_err(|e| e.to_string())) {
            Ok((origin, birthday)) => json!({ "ok": true, "group": p.group, "databaseKey": key.as_str(),
                                              "origin": origin, "birthday": birthday })
            .to_string(),
            Err(e) => err(e),
        }
    }

    fn device_database_key(&mut self, params_json: String) -> String {
        if !self.is_manager("device_database_key") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: DeviceKeyParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = Zeroizing::new(p.password);
        let birthday = p.birthday.as_deref().map(str::trim).filter(|b| !b.is_empty());
        let opened = self.ks().map_err(|e| err(e)).and_then(|ks| {
            ks.device_database_key(&p.signer, &p.account, &password, birthday)
                .map_err(|e| wire::err(&crate::signer::from_keystore(e)))
        });
        match opened {
            Ok(k) => {
                // A new vault moves what the keys app shows for that device account.
                if k.created {
                    self.announce();
                }
                json!({ "ok": true, "signer": p.signer, "account": p.account, "databaseKey": k.database_key.as_str(),
                        "origin": "restored", "birthday": k.birthday, "created": k.created })
                .to_string()
            }
            Err(reply) => reply,
        }
    }

    fn device_wallets(&mut self) -> String {
        if !self.reads_signer_state() {
            return not_authorized();
        }
        match self.ks().and_then(|ks| ks.device_wallets().map_err(|e| e.to_string())) {
            Ok(list) => {
                let wallets: Vec<_> = list
                    .into_iter()
                    .map(|(_, w)| {
                        json!({ "signer": w.signer, "account": w.account, "birthday": w.birthday, "createdMs": w.created_ms })
                    })
                    .collect();
                json!({ "ok": true, "wallets": wallets }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn forget_device_wallet(&mut self, params_json: String) -> String {
        if !self.may_mutate("forget_device_wallet") {
            return not_authorized();
        }
        let p: DeviceWalletParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        match self.ks().and_then(|ks| ks.forget_device_wallet(&p.signer, &p.account).map_err(|e| e.to_string())) {
            Ok(forgotten) => {
                self.announce();
                json!({ "ok": true, "forgotten": forgotten }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn import_bitcoin(&mut self, params_json: String) -> String {
        if !self.may_mutate("import_bitcoin") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: ImportBitcoinParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let (typed, passphrase, password) =
            (Zeroizing::new(p.phrase), Zeroizing::new(p.passphrase), Zeroizing::new(p.password));
        let (keep_password, phrase_password) =
            (Zeroizing::new(p.keep_phrase.map(|k| k.password)), Zeroizing::new(p.phrase_password));
        let (family, chain) = match (BtcFamily::parse(&p.family), BtcChain::parse(&p.chain)) {
            (Ok(f), Ok(c)) => (f, c),
            (Err(e), _) | (_, Err(e)) => return err(e),
        };
        let birthday = p.birthday.as_deref().map(str::trim).filter(|b| !b.is_empty());
        let start = match (p.origin.as_deref().map(str::trim), birthday) {
            (Some("created"), None) => WalletStart::Created,
            (Some("created"), Some(_)) => {
                return err("a created wallet's birthday is the day it is made; send none")
            }
            (None | Some("restored"), day) => WalletStart::Restored(day),
            (Some(other), _) => return err(format!("origin must be created or restored, not {other:?}")),
        };
        let ks = match self.ks() {
            Ok(ks) => ks,
            Err(e) => return err(e),
        };
        let (phrase, keep) = match words_and_keep(
            ks,
            typed,
            p.kept_phrase.as_deref(),
            keep_password.as_deref(),
            &phrase_password,
        ) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        if let Some(source) = &p.source_group {
            if let Err(e) = ks.check_seed_source(&phrase, &passphrase, source) {
                return err(e);
            }
        }
        let req = BitcoinImport {
            phrase: &phrase,
            bip39_passphrase: &passphrase,
            family,
            chain,
            account: p.account,
            password: &password,
            label: &p.label,
            keep,
            start,
        };
        match ks.import_bitcoin(&req) {
            Ok(g) => {
                let record = ks.get_groups().ok().and_then(|mut gs| gs.remove(&g.id));
                let kept = record.as_ref().and_then(|r| r.phrase.clone());
                let birthday = record.and_then(|r| r.birthday);
                self.announce();
                self.enroll(&g.id, &password);
                json!({ "ok": true, "group": g.id, "family": family.as_str(), "chain": chain.as_str(),
                        "path": format!("m/{}", g.account.origin().to_string().trim_start_matches("m/")),
                        "fingerprint": g.account.fingerprint.to_string(),
                        "external": g.account.descriptor(0), "internal": g.account.descriptor(1),
                        "phrase": kept,
                        "origin": if start == WalletStart::Created { "created" } else { "restored" },
                        "birthday": birthday })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn show_phrase(&mut self, params_json: String) -> String {
        if !self.may_mutate("show_phrase") {
            let _ = Zeroizing::new(params_json);
            return not_authorized();
        }
        let p: PhraseParams = match parse_secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = Zeroizing::new(p.password);
        match self.ks().and_then(|ks| ks.show_phrase(&p.phrase, &password).map_err(|e| e.to_string())) {
            Ok(words) => {
                let reply = Zeroizing::new(json!({ "ok": true, "phrase": p.phrase, "words": words.as_str() }).to_string());
                reply.to_string()
            }
            Err(e) => err(e),
        }
    }

    fn forget_phrase(&mut self, params_json: String) -> String {
        if !self.may_mutate("forget_phrase") {
            return not_authorized();
        }
        let p: PhraseParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        match self.ks().and_then(|ks| ks.forget_phrase(&p.phrase).map_err(|e| e.to_string())) {
            Ok(forgotten) => {
                self.announce();
                json!({ "ok": true, "forgotten": forgotten }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn account_descriptors(&mut self, params_json: String) -> String {
        if !self.reads_signer_state() {
            return not_authorized();
        }
        #[derive(Deserialize)]
        struct Wire {
            group: String,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(e),
        };
        match self.ks().and_then(|ks| ks.account_descriptors(&w.group).map_err(|e| e.to_string())) {
            Ok((external, internal)) => {
                json!({ "ok": true, "group": w.group, "external": external, "internal": internal }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn list_phrases(&mut self) -> String {
        match self.ks().and_then(|ks| ks.kept_phrases().map_err(|e| e.to_string())) {
            Ok(kept) => {
                let phrases: Vec<_> =
                    kept.into_iter().map(|k| json!({ "id": k.id, "groups": k.groups, "staged": k.staged })).collect();
                json!({ "ok": true, "phrases": phrases }).to_string()
            }
            Err(e) => err(e),
        }
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
                "approvers": self.roles.approvers, "custodians": self.roles.custodians, "managers": self.roles.managers })
        .to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreModuleImpl>();
}
