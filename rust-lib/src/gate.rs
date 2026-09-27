//! Who may do what, as a pure decision.
//!
//! The tier gates live in `glue.rs`, which is compiled only with the `logos_module` feature
//! and needs a live runtime to resolve a caller — so the *decision* is extracted here, where
//! it can be tested without one. `glue.rs` resolves the caller and asks this module; it does
//! not decide anything itself.

/// The built-in approver: the surface that renders an intent to a human and takes the vault
/// password. It holds Tier A on any call the runtime did not check against a grant.
pub const DEFAULT_APPROVER: &str = "evm_signer_ui";
/// The built-in custodian. Mirrors `DEFAULT_APPROVER`: a wallet requests signatures and reads
/// which accounts exist; creating, importing, exporting and deleting them belongs to one
/// surface, and that surface is the keystore UI.
pub const DEFAULT_CUSTODIAN: &str = "evm_keystore_ui";

/// Whether the runtime checked this call against a method-list grant: `"scoped": true` in
/// the caller document it pushed. Only the target's own runtime writes that document, so a
/// caller cannot claim it. Absent, unparseable, or anything but `true` is `false`.
pub fn scoped_from_caller_json(caller_json: Option<&str>) -> bool {
    caller_json
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|doc| doc.get("scoped").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// The caller, reduced to what a gate is allowed to care about.
///
/// `HostAnchor` is deliberately distinct from a named module rather than folded into it: it
/// is one undifferentiated bag, so a tier that admitted it would admit an unbounded set
/// rather than a party. Once capability_module is the runtime's token authority it is the
/// runtime alone: shells and `core_service` call as named modules and a CLI session as an
/// `Operator`. Before that it also covers them and every relayed CLI token.
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

/// Does `caller` hold the role `role_holder`?
///
/// An EMPTY name admits NOBODY — the fail-closed direction, kept so that a blank can never
/// match a module named "".
pub fn holds_role(role_holder: &str, caller: &Caller) -> bool {
    !role_holder.is_empty() && caller.is_module(role_holder)
}

/// Tier A. A `scoped` call passed the deployer's method list for this very method, so the
/// policy already named its caller an approver; any other call needs the built-in role.
///
/// Granting `approve` to anything but a signer surface takes the human out of the approval:
/// that is the deployer's call to make, in the policy, and never a caller's.
pub fn approver_admits(caller: &Caller, scoped: bool) -> bool {
    scoped || holds_role(DEFAULT_APPROVER, caller)
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

/// Tier D: a method the registry names, from a `scoped` call (the deployer granted exactly
/// this method) or from the built-in custodian. A `"*"` grant is not scoped: it lets a caller
/// through to this check and no further.
pub fn tier_d_admits(method: &str, caller: &Caller, scoped: bool) -> bool {
    TIER_D_METHODS.contains(&method) && (scoped || holds_role(DEFAULT_CUSTODIAN, caller))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(n: &str) -> Caller {
        Caller::Module(n.into())
    }

    fn every_caller_shape() -> Vec<Caller> {
        vec![
            m("evm_signer_ui"),
            m("evm_keystore_ui"),
            m("eth_wallet_backend"),
            m(""),
            Caller::HostAnchor,
            Caller::Unknown,
            Caller::Operator("cli".into()),
            Caller::Derived { parent: "evm_keystore_ui".into(), leaf: "child".into() },
        ]
    }

    #[test]
    fn the_role_holder_is_admitted_and_nobody_else_is() {
        assert!(holds_role("evm_keystore_ui", &m("evm_keystore_ui")));
        assert!(!holds_role("evm_keystore_ui", &m("wallet_ui")));
        assert!(!holds_role("evm_keystore_ui", &m("eth_wallet_backend")));
    }

    #[test]
    fn an_empty_role_refuses_everyone_including_a_module_named_empty() {
        assert!(!holds_role("", &m("evm_keystore_ui")));
        assert!(!holds_role("", &Caller::HostAnchor));
        assert!(!holds_role("", &Caller::Unknown));
        assert!(!holds_role("", &m("")), "an empty module name must not match an empty role");
    }

    #[test]
    fn the_host_anchor_is_refused_whatever_the_role() {
        // The anchor is one undifferentiated bag, so admitting it would admit an unbounded
        // set of callers rather than a party.
        for role in ["evm_keystore_ui", "evm_signer_ui", "core", ""] {
            assert!(!holds_role(role, &Caller::HostAnchor), "role {role}");
        }
    }

    #[test]
    fn unknown_derived_and_operator_callers_do_not_hold_a_role() {
        assert!(!holds_role("evm_keystore_ui", &Caller::Unknown));
        assert!(!holds_role(
            "evm_keystore_ui",
            &Caller::Derived { parent: "evm_keystore_ui".into(), leaf: "child".into() }
        ));
        assert!(!holds_role("evm_keystore_ui", &Caller::Operator("evm_keystore_ui".into())));
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
    fn unscoped_the_built_in_roles_decide() {
        // Older runtimes, and runtimes with no rule for the keystore, send no mark: the
        // shipped surfaces keep working, and nobody else gets in.
        assert!(approver_admits(&m("evm_signer_ui"), false));
        for method in TIER_D_METHODS {
            assert!(tier_d_admits(method, &m("evm_keystore_ui"), false), "{method}");
        }
        for other in every_caller_shape() {
            if other != m("evm_signer_ui") {
                assert!(!approver_admits(&other, false), "approver admitted {other:?}");
            }
            if other != m("evm_keystore_ui") {
                for method in TIER_D_METHODS {
                    assert!(!tier_d_admits(method, &other, false), "{method} admitted {other:?}");
                }
            }
        }
    }

    #[test]
    fn a_scoped_call_is_admitted_by_the_grant_it_passed() {
        // The deployer named this caller for this method: a terminal signer, a headless
        // custodian, or an operator. The runtime refused every other method already.
        for caller in every_caller_shape() {
            assert!(approver_admits(&caller, true), "{caller:?}");
            for method in TIER_D_METHODS {
                assert!(tier_d_admits(method, &caller, true), "{method} {caller:?}");
            }
        }
    }

    #[test]
    fn a_method_the_registry_does_not_name_is_refused_even_scoped() {
        // Fail closed on a typo: a misspelled gate must refuse, never fall through — and a
        // grant naming a method the keystore does not gate here does not open it.
        // `new_account` is here on purpose: it was removed from the contract.
        for unknown in ["derive_nextaccount", "list_accounts", "approve", "", "DERIVE_NEXT_ACCOUNT", "new_account"] {
            assert!(!tier_d_admits(unknown, &m("evm_keystore_ui"), false), "{unknown:?}");
            assert!(!tier_d_admits(unknown, &m("evm_keystore_ui"), true), "{unknown:?}");
        }
    }

    #[test]
    fn every_hd_derivation_mutation_is_in_the_tier_d_registry() {
        // Named, not counted: a count still passes when a method is dropped and an easier
        // one added.
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
    fn only_the_runtimes_true_mark_counts_as_scoped() {
        assert!(scoped_from_caller_json(Some(r#"{"kind":"module","name":"x","scoped":true}"#)));
        assert!(scoped_from_caller_json(Some(r#"{"kind":"operator","name":"alice","scoped":true}"#)));
        for doc in [
            None,
            Some(""),
            Some("not json"),
            Some(r#"{"kind":"module","name":"x"}"#),
            Some(r#"{"kind":"module","name":"x","scoped":false}"#),
            Some(r#"{"kind":"module","name":"x","scoped":"true"}"#),
            Some(r#"{"kind":"module","name":"x","scoped":1}"#),
            Some(r#"[true]"#),
        ] {
            assert!(!scoped_from_caller_json(doc), "{doc:?}");
        }
    }

    #[test]
    fn the_approver_and_custodian_roles_are_independent() {
        // evm_signer_ui may approve a signature; it may NOT import a key. evm_keystore_ui is the
        // mirror image. Neither inherits the other's reach.
        assert!(approver_admits(&m("evm_signer_ui"), false));
        assert!(!tier_d_admits("import_private_key", &m("evm_signer_ui"), false));
        assert!(!approver_admits(&m("evm_keystore_ui"), false));
        assert!(tier_d_admits("import_private_key", &m("evm_keystore_ui"), false));
    }
}
