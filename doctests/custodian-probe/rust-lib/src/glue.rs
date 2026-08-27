//! A Tier D custodian, so the account-mutation gate can be proven from BOTH sides without a
//! GUI: this module is admitted, and everything else — including the CLI — is refused.

use serde_json::{json, Value};

pub trait KeystoreCustodianModule: Send + 'static {
    /// Create an account. Admitted only because this module is the configured custodian.
    fn create(&mut self, password: String) -> String;
    /// Import a raw private key — the most sensitive Tier D method there is.
    fn import_key(&mut self, priv_hex: String, password: String) -> String;
    /// Delete an account. Ungated for everyone before Tier D, and an unmetered password
    /// oracle while it was.
    fn delete(&mut self, address: String, password: String) -> String;
    /// An UNGATED read, to show the gate did not simply close the whole module.
    fn accounts(&mut self) -> String;
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
    fn create(&mut self, password: String) -> String {
        pass(modules().keystore_module.new_account(&password))
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

    fn accounts(&mut self) -> String {
        pass(modules().keystore_module.list_accounts())
    }

    fn identity(&mut self) -> String {
        pass(modules().keystore_module.caller_identity())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreCustodianModuleImpl>();
}
