# logos-evm-keystore-module

A Logos `core` module (Rust, rust-first cdylib) that is the **keystore** for the
Logos multi-chain EVM wallet: scrypt-encrypted vaults, BIP39/BIP32 HD derivation,
and secp256k1 signing. It does **no networking**, and private keys never cross the
module boundary — only addresses, signed payloads, and (re-encrypted) keystore
JSON do.

Built on well-established crates: [`alloy`](https://github.com/alloy-rs/alloy)
(signing, tx encoding), [`eth-keystore`](https://crates.io/crates/eth-keystore)
(Web3 Secure Storage scrypt vaults), and `coins-bip39`/`coins-bip32` (HD wallets).

## Contract (`KeystoreModule`)

**Configuration:** `configure` names who holds the two roles —
`{ approvers?, custodians? }` → `{ ok, approvers, custodians }`. Each role is a **set**, so
a terminal signer can approve alongside `signer_ui` rather than by displacing it; write one
name or a list of them. It is **total**: a role the document does not name is held by
nobody, and an empty set admits no caller. Until it is called the built-in defaults stand
(`signer_ui` approves, `keystore_ui` mutates), so a deployment that configures nothing still
works. A malformed document is refused whole and
leaves the roles in force untouched.

Configuration arrives by **method call**, never as a file in the module's persistence
directory: that directory belongs to the module instance, may be sandboxed away from every
other process, and does not exist until the module has written to it. `configure` is
**ungated for now** — any caller can name itself custodian — which is a deliberate,
temporary exposure rather than an oversight; see
[`docs/specs.md`](docs/specs.md#configureconfig_json-string---string).

**Accounts (Tier D — the custodian only):** `create_mnemonic`, `import_mnemonic`,
`create_unrelated_account`, `import_private_key`, `import_keystore_json`,
`export_keystore_json`, `change_password`, `set_label`, `set_group_label`,
`delete_account`.

`create_unrelated_account` is the only way this crate **generates** a key from randomness,
and it requires an explicit `acknowledgeUnrecoverable`. It is not the only way to end up
with a key no recovery phrase restores — `import_private_key` and `import_keystore_json`
take caller-supplied material and carry no acknowledgement. Provenance keeps the three
apart (`random`, `imported-key`, `imported-json`) so a UI can say which it is. The
acknowledgement *generates* the key (`ack::Unrecoverable`), so a path that skipped it has
nothing to persist and does not compile. `new_account` is removed: it minted such a key
silently on a keystore that looked empty, and whether that was safe rested on a directory
scan being complete — which is not decidable by inspection.

**HD derivation (Tier D):** `derive_next_account`, `derive_account_at`,
`preview_addresses`, `forget_derivation`, `remove_group`.

**Reads (ungated):** `list_accounts`, `has_address`, `get_labels`, `get_group_labels`,
`list_groups`, `list_derivation_keys`, `get_provenance`, `caller_identity` — the last of
which also reports the two role names in force.

A wallet is named like an account is: `set_group_label` writes, an empty string clears,
and `get_group_labels` answers from `group-labels.json` alone — so the name survives the
record and the key it belonged to, which is the row a UI most needs to name. Duplicates
are storable on purpose; uniqueness is the reader's problem.

**Setting a name proves custody; clearing one does not.** A label is what a reader shows
*in place of* an address, so writing one is a claim — naming an account needs that
account's vault password, and naming a wallet that has accounts needs the password of one
of them (the *group* password is refused there: it proves you can make accounts, not that
you own the ones the header speaks for). A wallet with no accounts but a key on disk is
named by that key's password instead: it has no account to hold, and the name will come to
stand over whatever the key mints. Only a wallet that **holds nothing** — the precondition
`remove_group` refuses on — names nothing and is free. Clearing needs no secret either: it
can only move the display back toward the raw address, and it is the one way to strip a
stale name off a vault whose password is lost.

`remove_group` removes a wallet's **record** and its **name**, and refuses while the
wallet still holds a derivation key or an account — so it is never a second way to delete
a key. It exists because `forget_derivation` removes the *key* and reports not-found when
there is none, which left a wallet that is not derivable and holds no accounts listed and
unremovable by anything. Five accounts therefore cost six calls to remove, and that is
correct: five of them are spendable keys. Re-parenting them to "origin not recorded"
instead would rewrite a true `derived` provenance to `unknown` to make a row disappear.

Every read of a keystore *sidecar* keeps three states apart: **absent** is "nothing
configured yet", **readable** is its contents, and **present-but-unreadable refuses** —
no vault lands with no record of where it came from. The keystore *directory* is the same
for its root, and everywhere below it a directory that cannot be read is **reported**
rather than refused: the scan describes what is on disk, it does not gate anything, so
one bad directory no longer makes the store unlistable, unsignable and unrepairable.

One authority decides where anything may be written and what everything found there
is (`rust-lib/src/layout.rs`): `Slot` is the only path builder — for scratch space as
much as for a vault, so a writer cannot dodge it by taking a path from the shared temp
directory — and the scan that classifies the directory is total over *entries* rather
than over files, so an unrecognised directory is as visible as an unrecognised file.
Nothing lands where a guard is not looking, and nothing is dropped in silence. Every
guard asks that same authority — signing, deleting and deriving resolve through the
scan rather than through `Path::exists`, which follows symlinks, so material can never
be live and usable while the wallet reports it absent. What the scan reports it can
also remove, by name: `settle` for what the layout explains and `remove_unexplained`
for what it does not — including a directory nobody may read, which is the shape that
used to wedge the store. Whether unexplained material could be a whole-wallet derivation
key is judged from its name, its bytes and whether it could be looked inside at all —
never from which directory holds it. That judgement is a **report**; nothing refuses on
it, which is why it no longer has to be complete to be correct. Every write goes
through the same shapes (`rust-lib/src/atomic.rs`) — a document is staged under a
random name and renamed, a vault is encrypted into a named staging directory and
renamed out of it, because
`eth_keystore::encrypt_key` writes straight to its destination and an in-place write
would truncate a live vault. The staging guard drops on every exit this process can
take; the scan covers the one it cannot.

**Signing** goes through the human-approval tiers — `request_approval` /
`approval_status` / `fetch_result` / `ack_result` / `cancel_approval` for any named
module, and `pending` / `acknowledge` / `approve` / `reject` for the configured
approver. There is no `unlock`, no signer cache, and no method that signs on demand.

Events: `accounts_changed`, `approval_offered`, `approval_settled`. All structured
values cross the IPC boundary as JSON strings. `accounts_changed` fires after every
mutation that changes what a reader displays — a rename included — and its `count` is
advisory, because a rename does not move it.

See [`docs/specs.md`](docs/specs.md) for the full reference, including the BIP-32 /
BIP-44 derivation contract and what an `extkey` derivation group does and does not
reach.

## Build & test

```bash
# crypto core (no Logos runtime needed)
cd rust-lib && cargo test --no-default-features

# full module (Qt plugin) + .lgx package
nix build .#install   # -> result/modules/keystore_module/
nix build .#lgx
```

The crypto core is feature-gated away from the Logos glue so it stays
`cargo test`-able on its own; the builder compiles the glue via the default
`logos_module` feature. See the wallet plan for the full architecture.
