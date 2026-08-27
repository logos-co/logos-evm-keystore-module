//! Who may do what, as a pure decision.
//!
//! The tier gates live in `glue.rs`, which is compiled only with the `logos_module` feature
//! and needs a live runtime to resolve a caller — so the *decision* is extracted here, where
//! it can be tested without one. `glue.rs` resolves the caller and asks this module; it does
//! not decide anything itself.

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
    fn the_approver_and_custodian_roles_are_independent() {
        // signer_ui may approve a signature; it may NOT import a key. keystore_ui is the
        // mirror image. Neither inherits the other's reach.
        assert!(holds_role("signer_ui", &m("signer_ui")));
        assert!(!holds_role("keystore_ui", &m("signer_ui")));
        assert!(!holds_role("signer_ui", &m("keystore_ui")));
    }
}
