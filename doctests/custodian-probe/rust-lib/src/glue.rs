//! A Tier D custodian, so the account-mutation gate can be proven from BOTH sides without a
//! GUI: this module is admitted, and everything else — including the CLI — is refused.

use serde_json::{json, Value};

pub trait KeystoreCustodianModule: Send + 'static {
    /// Create an account with a random key — the ONE door to one. Two arguments, because
    /// the acknowledgement is the point: `create <pw> false` must refuse from the custodian
    /// itself, which is what makes the property provable from outside the process.
    fn create(&mut self, password: String, acknowledge: bool) -> String;
    /// Generate a recovery phrase. Tier D, and the only method here that persists nothing —
    /// so it proves the gate admits the custodian without leaving a key behind to prove it.
    fn mnemonic(&mut self, words: i64) -> String;
    /// Import a raw private key — the most sensitive Tier D method there is.
    fn import_key(&mut self, priv_hex: String, password: String) -> String;
    /// Delete an account. Ungated for everyone before Tier D, and an unmetered password
    /// oracle while it was.
    fn delete(&mut self, address: String, password: String) -> String;
    /// Import a recovery phrase, keeping its derivation key. Tier D, and the only way to
    /// put a derivation key on disk from here. `bip44` picks the hardened account level, so
    /// a second wallet can be made from the same phrase without colliding with the first.
    fn import_phrase(&mut self, phrase: String, group_password: String, password: String, bip44: i64) -> String;
    /// Add the next account of a wallet, without the phrase. Tier D. Here to show the other
    /// half of the wedge: a key that cannot be opened cannot derive either.
    fn derive(&mut self, group: String, group_password: String, password: String) -> String;
    /// Stop keeping a derivation key. Tier D — and it takes NO password, which is the whole
    /// point: a key nobody can open is exactly the one that has to stay deletable.
    fn forget(&mut self, group: String) -> String;
    /// Add the account at one chosen index. Tier D. Shows what an account vault that cannot
    /// be opened does to the index it occupies.
    fn derive_at(&mut self, group: String, group_password: String, password: String, index: i64) -> String;
    /// Re-encrypt a vault under a new password. Tier D, and the other staged write in the
    /// module — here so its staging path can be inspected from outside the process.
    fn rekey(&mut self, address: String, old_password: String, new_password: String) -> String;
    /// Re-import a scrypt vault JSON. Tier D — here it answers "whose key is this file?"
    /// for a vault found somewhere the keystore never means to leave one.
    fn import_json(&mut self, key_json: String, password: String, new_password: String) -> String;
    /// Export a vault as JSON. Tier D — and the one place a caller learns that the vault at
    /// an address's filename does not hold that address's key.
    fn export(&mut self, address: String, password: String) -> String;
    /// Sweep the keystore directory BY NAME rather than as a side effect of listing. Tier D.
    fn settle(&mut self) -> String;
    /// Remove one path the scan reported as unexplained. Tier D.
    fn remove(&mut self, path: String) -> String;
    /// Name a wallet. Tier D — the CLI is refused, and the name it would have written is
    /// the one a UI shows in place of an address that moves when an account is deleted.
    /// `address`/`password` are one of the wallet's own accounts, and are what a rename has
    /// to prove when the wallet has any; pass empty strings to show the refusal.
    fn name_wallet(&mut self, group: String, label: String, address: String, password: String) -> String;
    /// Name an account. Tier D plus the account's own password — the string a reader shows
    /// in PLACE of an address is the one an impersonator would most like to write.
    fn name_account(&mut self, address: String, label: String, password: String) -> String;
    /// Remove a wallet's record and its name. Tier D. Refuses while the wallet still holds
    /// a derivation key or an account, so it can never be a second way to delete a key.
    fn remove_wallet(&mut self, group: String) -> String;
    /// Wallet names, UNGATED — proven from here as well as from the CLI.
    fn wallet_names(&mut self) -> String;
    /// An UNGATED read, to show the gate did not simply close the whole module.
    fn accounts(&mut self) -> String;
    /// What `groups/` holds, including where any symlink points. UNGATED.
    fn keys(&mut self) -> String;
    /// What the keystore thinks of this caller — `{ kind, identity, approver, custodian }`.
    fn identity(&mut self) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeystoreCustodianModuleImpl;

fn pass(reply: Result<String, impl std::fmt::Debug>) -> String {
    match reply {
        Ok(s) => s,
        Err(e) => json!({ "ok": false, "error": format!("{e:?}") }).to_string(),
    }
}

impl KeystoreCustodianModule for KeystoreCustodianModuleImpl {
    fn create(&mut self, password: String, acknowledge: bool) -> String {
        let p = json!({ "password": password, "acknowledgeUnrecoverable": acknowledge });
        pass(modules().keystore_module.create_unrelated_account(&p.to_string()))
    }

    fn mnemonic(&mut self, words: i64) -> String {
        pass(modules().keystore_module.create_mnemonic(words))
    }

    fn import_key(&mut self, priv_hex: String, password: String) -> String {
        pass(modules().keystore_module.import_private_key(&priv_hex, &password))
    }

    fn delete(&mut self, address: String, password: String) -> String {
        match modules().keystore_module.delete_account(&address, &password) {
            Ok(v) => json!({ "ok": v }).to_string(),
            Err(e) => json!({ "ok": false, "error": format!("{e:?}") }).to_string(),
        }
    }

    fn import_phrase(&mut self, phrase: String, group_password: String, password: String, bip44: i64) -> String {
        let p = json!({ "phrase": phrase, "password": password, "storage": "extkey",
                        "groupPassword": group_password, "bip44Account": bip44 });
        pass(modules().keystore_module.import_mnemonic(&p.to_string()))
    }

    fn derive(&mut self, group: String, group_password: String, password: String) -> String {
        let p = json!({ "group": group, "groupPassword": group_password, "password": password });
        pass(modules().keystore_module.derive_next_account(&p.to_string()))
    }

    fn forget(&mut self, group: String) -> String {
        pass(modules().keystore_module.forget_derivation(&json!({ "group": group }).to_string()))
    }

    fn derive_at(&mut self, group: String, group_password: String, password: String, index: i64) -> String {
        let p = json!({ "group": group, "groupPassword": group_password, "password": password,
                        "index": index });
        pass(modules().keystore_module.derive_account_at(&p.to_string()))
    }

    fn rekey(&mut self, address: String, old_password: String, new_password: String) -> String {
        pass(modules().keystore_module.change_password(&address, &old_password, &new_password))
    }

    fn import_json(&mut self, key_json: String, password: String, new_password: String) -> String {
        pass(modules().keystore_module.import_keystore_json(&key_json, &password, &new_password))
    }

    fn export(&mut self, address: String, password: String) -> String {
        pass(modules().keystore_module.export_keystore_json(&address, &password))
    }

    fn settle(&mut self) -> String {
        pass(modules().keystore_module.settle())
    }

    fn remove(&mut self, path: String) -> String {
        let p = json!({ "path": path, "acknowledgeMayBeKeyMaterial": true });
        pass(modules().keystore_module.remove_unexplained(&p.to_string()))
    }

    fn name_wallet(&mut self, group: String, label: String, address: String, password: String) -> String {
        let p = json!({ "group": group, "label": label, "address": address, "password": password });
        pass(modules().keystore_module.set_group_label(&p.to_string()))
    }

    fn name_account(&mut self, address: String, label: String, password: String) -> String {
        pass(modules().keystore_module.set_label(&address, &label, &password))
    }

    fn remove_wallet(&mut self, group: String) -> String {
        pass(modules().keystore_module.remove_group(&json!({ "group": group }).to_string()))
    }

    fn wallet_names(&mut self) -> String {
        pass(modules().keystore_module.get_group_labels())
    }

    fn accounts(&mut self) -> String {
        pass(modules().keystore_module.list_accounts())
    }

    fn keys(&mut self) -> String {
        pass(modules().keystore_module.list_derivation_keys())
    }

    fn identity(&mut self) -> String {
        pass(modules().keystore_module.caller_identity())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreCustodianModuleImpl>();
}
