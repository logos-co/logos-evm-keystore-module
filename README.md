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

`create_mnemonic`, `import_mnemonic`, `new_account`, `import_private_key`,
`import_keystore_json`, `export_keystore_json`, `list_accounts`, `has_address`,
`delete_account`, `unlock`/`timed_unlock`/`lock`/`is_unlocked`,
`sign_transaction` (legacy EIP-155 + EIP-1559), `sign_message` (EIP-191). Event:
`accounts_changed`. All structured values cross the IPC boundary as JSON strings.

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
