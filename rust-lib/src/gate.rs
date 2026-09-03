//! Who may do what, as a pure decision.
//!
//! The tier gates live in `glue.rs`, which is compiled only with the `logos_module` feature
//! and needs a live runtime to resolve a caller — so the *decision* is extracted here, where
//! it can be tested without one. `glue.rs` resolves the caller and asks this module; it does
//! not decide anything itself.

/// Default approver: the surface that renders an intent to a human and takes the vault
/// password. Stands until `Roles::configure` replaces it.
pub const DEFAULT_APPROVER: &str = "signer_ui";
/// Default custodian. Mirrors `DEFAULT_APPROVER`: a wallet requests signatures and reads
/// which accounts exist; creating, importing, exporting and deleting them belongs to one
/// surface, and that surface is the keystore UI.
pub const DEFAULT_CUSTODIAN: &str = "keystore_ui";

/// Who holds the two roles. Configuration, so it is data rather than a decision — but it
/// lives here because it is the only input the decisions below take besides the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roles {
    pub approver: String,
    pub custodian: String,
}

/// The built-in defaults, in force from load. A module nobody configures is not inert.
impl Default for Roles {
    fn default() -> Self {
        Self { approver: DEFAULT_APPROVER.into(), custodian: DEFAULT_CUSTODIAN.into() }
    }
}

/// `{ approver?, custodian? }`. Unknown keys are refused rather than ignored: under the
/// total rule below a typo'd key would otherwise empty BOTH roles, which fails closed but
/// says nothing about why.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesWire {
    #[serde(default)]
    approver: String,
    #[serde(default)]
    custodian: String,
}

impl Roles {
    /// Replace both roles from a `{ approver?, custodian? }` document.
    ///
    /// TOTAL, not a patch: the document is the whole answer to "who holds these roles", so
    /// one it does not name is held by nobody — `holds_role` refuses an empty name. Half a
    /// configuration inheriting the other half from a default is how a deployer who replaced
    /// one surface goes on granting the old one. A malformed document is refused and the
    /// roles in force are left untouched.
    pub fn configure(&mut self, config_json: &str) -> Result<(), String> {
        let doc: serde_json::Value = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
        // A struct deserializes from a JSON ARRAY as well, defaulting every field — so `[]`
        // would empty both roles instead of being refused. Insist on an object.
        if !doc.is_object() {
            return Err("configuration must be a JSON object".into());
        }
        let wire: RolesWire = serde_json::from_value(doc).map_err(|e| e.to_string())?;
        // Whitespace is not a module name, so it means nobody rather than an unmatchable one.
        self.approver = wire.approver.trim().to_string();
        self.custodian = wire.custodian.trim().to_string();
        Ok(())
    }
}

/// The caller, reduced to what a gate is allowed to care about.
///
/// `HostAnchor` is deliberately distinct from a named module rather than folded into it: it
/// is one undifferentiated bag covering the shells, `core_service` and every relayed CLI
/// token, so a tier that admitted it would admit an unbounded set rather than a party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    HostAnchor,
    Module(String),
    Derived { parent: String, leaf: String },
    Operator(String),
}

impl Caller {
    pub fn is_module(&self, name: &str) -> bool {
        matches!(self, Caller::Module(n) if n == name)
    }

    /// The name a Tier B request is recorded against, so results can only be collected by
    /// the module that asked. Only a plainly-named module has one.
    pub fn named(&self) -> Option<&str> {
        match self {
            Caller::Module(n) => Some(n.as_str()),
            _ => None,
        }
    }
}

/// Does `caller` hold the role configured as `role_holder`?
///
/// An EMPTY configured name admits NOBODY. That is the fail-closed direction and it is
/// deliberate: an unconfigured role means the surface that should hold it has not shipped
/// yet, and the right answer then is that the capability is unavailable — not that it is
/// available to everyone. Tier A behaved exactly this way before `signer_ui` existed.
pub fn holds_role(role_holder: &str, caller: &Caller) -> bool {
    !role_holder.is_empty() && caller.is_module(role_holder)
}

/// Every keystore mutation, by contract name — the Tier D registry.
///
/// A list rather than a per-method `if`, so "which methods are custodian-only" is one
/// value that can be asserted against, and so a method NOT on it is refused outright
/// instead of falling through ungated. Adding a mutating method without adding it here
/// makes that method refuse everyone, loudly; the reverse mistake is silent.
pub const TIER_D_METHODS: &[&str] = &[
    "create_mnemonic",
    "import_mnemonic",
    "import_private_key",
    "import_keystore_json",
    "export_keystore_json",
    "change_password",
    "set_label",
    // Naming a WALLET, like naming an account: it is written by whoever manages the
    // keystore, and it is what a reader shows in place of an address.
    "set_group_label",
    "delete_account",
    // HD derivation. Deriving an account is a mutation, and it opens a vault whose blast
    // radius is a whole wallet rather than one account — so if anything it belongs here
    // more firmly than the rest.
    "derive_next_account",
    "derive_account_at",
    "preview_addresses",
    // The ONE way to obtain a random key. `new_account` used to be another, and sometimes
    // minted one silently; it is gone, so this name has to stay here.
    "create_unrelated_account",
    "forget_derivation",
    // Removes a wallet's RECORD and its name, never its key: it refuses while the wallet
    // holds a key or an account. The row it exists for is the one nothing else could remove.
    "remove_group",
    // Directory repair. Both REMOVE things, so they belong to whoever manages the keystore
    // rather than to whoever reads it.
    "settle",
    "remove_unexplained",
];

/// Tier D: the configured custodian, for a method the registry names.
pub fn tier_d_admits(method: &str, custodian: &str, caller: &Caller) -> bool {
    TIER_D_METHODS.contains(&method) && holds_role(custodian, caller)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(n: &str) -> Caller {
        Caller::Module(n.into())
    }

    #[test]
    fn the_configured_holder_is_admitted_and_nobody_else_is() {
        assert!(holds_role("keystore_ui", &m("keystore_ui")));
        assert!(!holds_role("keystore_ui", &m("wallet_ui")));
        assert!(!holds_role("keystore_ui", &m("eth_wallet_backend")));
    }

    #[test]
    fn an_empty_role_refuses_everyone_including_a_module_named_empty() {
        assert!(!holds_role("", &m("keystore_ui")));
        assert!(!holds_role("", &Caller::HostAnchor));
        assert!(!holds_role("", &Caller::Unknown));
        assert!(!holds_role("", &m("")), "an empty module name must not match an empty role");
    }

    #[test]
    fn the_host_anchor_is_refused_however_the_role_is_configured() {
        // The anchor covers `core`, capability_module and every relayed CLI token under one
        // value, so admitting it would turn `logosctl call … import_private_key` into a
        // legal way in.
        for role in ["keystore_ui", "signer_ui", "core", ""] {
            assert!(!holds_role(role, &Caller::HostAnchor), "role {role}");
        }
    }

    #[test]
    fn unknown_derived_and_operator_callers_are_refused() {
        assert!(!holds_role("keystore_ui", &Caller::Unknown));
        assert!(!holds_role(
            "keystore_ui",
            &Caller::Derived { parent: "keystore_ui".into(), leaf: "child".into() }
        ));
        assert!(!holds_role("keystore_ui", &Caller::Operator("keystore_ui".into())));
    }

    #[test]
    fn only_a_plainly_named_module_can_be_recorded_as_a_requester() {
        assert_eq!(m("eth_wallet_backend").named(), Some("eth_wallet_backend"));
        assert_eq!(Caller::HostAnchor.named(), None);
        assert_eq!(Caller::Unknown.named(), None);
        assert_eq!(Caller::Operator("cli".into()).named(), None);
        assert_eq!(Caller::Derived { parent: "a".into(), leaf: "b".into() }.named(), None);
    }

    #[test]
    fn tier_d_admits_only_the_custodian_for_every_mutation() {
        // Every name, against every shape of caller. A gate that is right for eight of nine
        // methods is a gate that lets an account be created by whoever asks.
        for method in TIER_D_METHODS {
            assert!(tier_d_admits(method, "keystore_ui", &m("keystore_ui")), "{method}");
            for other in [
                m("signer_ui"),
                m("eth_wallet_backend"),
                m("keystore_module"),
                Caller::HostAnchor,
                Caller::Unknown,
                Caller::Operator("cli".into()),
                Caller::Derived { parent: "keystore_ui".into(), leaf: "child".into() },
            ] {
                assert!(!tier_d_admits(method, "keystore_ui", &other), "{method} admitted {other:?}");
            }
            // An unconfigured custodian admits nobody, including the module named "".
            assert!(!tier_d_admits(method, "", &m("keystore_ui")), "{method}");
            assert!(!tier_d_admits(method, "", &m("")), "{method}");
        }
    }

    #[test]
    fn every_hd_derivation_mutation_is_in_the_tier_d_registry() {
        // Named, not counted: a count still passes when a method is dropped and an easier
        // one added. An absent name refuses everyone, which is loud — but only if something
        // asserts the name was meant to be there at all.
        for method in [
            "derive_next_account",
            "derive_account_at",
            "preview_addresses",
            "create_unrelated_account",
            "forget_derivation",
            "remove_group",
            "import_mnemonic",
            "settle",
            "remove_unexplained",
            "set_label",
            "set_group_label",
        ] {
            assert!(TIER_D_METHODS.contains(&method), "{method} is not gated");
        }
    }

    #[test]
    fn a_method_the_registry_does_not_name_is_refused_even_for_the_custodian() {
        // Fail closed on a typo: a misspelled gate must refuse, never fall through.
        // `new_account` is on this list on purpose: it was removed from the contract, and a
        // gate that still admitted the name would let a resurrected one through ungated.
        for unknown in ["derive_nextaccount", "list_accounts", "approve", "", "DERIVE_NEXT_ACCOUNT", "new_account"] {
            assert!(!tier_d_admits(unknown, "keystore_ui", &m("keystore_ui")), "{unknown:?}");
        }
    }

    #[test]
    fn the_built_in_defaults_are_in_force_until_something_configures_them() {
        // A module nobody configures must not be inert: the shipped surfaces work out of
        // the box, and only a deployer replacing one has to say so.
        let r = Roles::default();
        assert!(holds_role(&r.approver, &m("signer_ui")));
        assert!(tier_d_admits("import_private_key", &r.custodian, &m("keystore_ui")));
    }

    #[test]
    fn configuring_both_roles_moves_the_gate_to_the_named_modules() {
        let mut r = Roles::default();
        r.configure(r#"{"approver":"probe_ui","custodian":"probe_custodian"}"#).unwrap();
        assert!(holds_role(&r.approver, &m("probe_ui")));
        assert!(tier_d_admits("import_private_key", &r.custodian, &m("probe_custodian")));
        // And the modules the defaults named lose it in the same call.
        assert!(!holds_role(&r.approver, &m("signer_ui")));
        assert!(!tier_d_admits("import_private_key", &r.custodian, &m("keystore_ui")));
    }

    #[test]
    fn a_role_the_configuration_does_not_name_admits_nobody() {
        // Named empty, omitted entirely, or given whitespace: all three are "nobody holds
        // this", never "fall back to the default the deployer just replaced".
        for doc in [
            r#"{"approver":"","custodian":"probe_custodian"}"#,
            r#"{"custodian":"probe_custodian"}"#,
            r#"{"approver":"   ","custodian":"probe_custodian"}"#,
        ] {
            let mut r = Roles::default();
            r.configure(doc).unwrap();
            assert_eq!(r.approver, "", "{doc}");
            for who in [m("signer_ui"), m(""), Caller::HostAnchor, Caller::Unknown] {
                assert!(!holds_role(&r.approver, &who), "{doc} admitted {who:?}");
            }
            // The role that WAS named is unaffected by its neighbour being empty.
            assert!(tier_d_admits("import_private_key", &r.custodian, &m("probe_custodian")));
        }
    }

    #[test]
    fn a_malformed_configuration_is_refused_and_the_roles_in_force_survive_it() {
        // Refusing has to leave the gate where it was. A partial apply would hand one role
        // to an attacker-chosen name and blame the other half on a parse error.
        let mut r = Roles::default();
        r.configure(r#"{"approver":"probe_ui","custodian":"probe_custodian"}"#).unwrap();
        let good = r.clone();
        for doc in [
            "",
            "not json",
            "[]",
            r#"{"approver":5}"#,
            r#"{"approver":null}"#,
            // A typo'd key, which the total rule would otherwise turn into "nobody holds
            // anything" — fail-closed, but silent about why every method started refusing.
            r#"{"custodain":"probe_custodian"}"#,
        ] {
            assert!(r.configure(doc).is_err(), "{doc:?} was accepted");
            assert_eq!(r, good, "{doc:?} moved the roles");
        }
    }

    #[test]
    fn the_approver_and_custodian_roles_are_independent() {
        // signer_ui may approve a signature; it may NOT import a key. keystore_ui is the
        // mirror image. Neither inherits the other's reach.
        assert!(holds_role("signer_ui", &m("signer_ui")));
        assert!(!holds_role("keystore_ui", &m("signer_ui")));
        assert!(!holds_role("signer_ui", &m("keystore_ui")));
    }
}
