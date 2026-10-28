# `logos-evm-keystore-module` — Reference Specification

## Purpose

`logos-evm-keystore-module` is the **keystore** for the Logos multi-chain EVM
wallet. It is a Rust **cdylib Logos module** (`type: core`, `interface: cdylib`)
that owns everything to do with private keys: generating and importing them,
encrypting them at rest as scrypt vaults, and producing **secp256k1 signatures**
**only when a human has approved them** — both EIP-191
`personal_sign` messages and signed EIP-1559 / legacy (EIP-155) transactions.

Its defining property is **isolation**: the module does **no networking**, and a
raw private key never crosses the module's IPC boundary. The only values that
leave the module are **addresses**, **signed payloads** (signature hex / raw
signed-transaction hex), and **(re-)encrypted keystore JSON**. The crypto core is
built on well-established crates — [`alloy`](https://github.com/alloy-rs/alloy)
(signing + transaction encoding), [`eth-keystore`](https://crates.io/crates/eth-keystore)
(Web3 Secure Storage scrypt vaults), and `coins-bip39` / `coins-bip32` (BIP-39 /
BIP-32 HD derivation, consumed through alloy's re-export).

### Where it sits in the EVM wallet system

The EVM wallet and the apps beside it are built from repositories that talk to each
other as process-isolated Logos modules over a typed RPC bridge. The ones around this
module:

| Repo | Role | Talks to |
|------|------|----------|
| `logos-evm-net-proxy` | Fail-closed HTTP/RPC client **library crate** (not a module) | — |
| **`logos-evm-keystore-module`** | **Key management + signing (this repo)** | **nothing — leaf module** |
| `logos-evm-eth-rpc-module` | Multi-chain JSON-RPC transport (`concurrency: multi`) | net-proxy |
| `logos-evm-token-list-module` | Token-list fetch/merge per chain | net-proxy |
| `logos-evm-uniswap-module` | Uniswap V2/V3/V4 price oracle + swap building (`concurrency: multi`) | eth-rpc |
| `logos-evm-tx-sender-module` | Prices, signs through this module, broadcasts and follows every send (the requester) | keystore, eth-rpc, fee |
| `logos-eth-wallet-backend` | The wallet's backend: accounts, balances, history, sends | keystore (accounts), eth-rpc, token-list, evm-assets, fee, tx-sender |
| `logos-uniswap-backend` | The Uniswap app's backend | keystore (accounts), eth-rpc, token-list, evm-assets, fee, uniswap, tx-sender |
| `logos-eth-wallet-ui`, `logos-uniswap-ui` | Universal C++ `ui_qml` apps | their backend |
| `logos-evm-signer-ui` | The approver: renders an approval and takes the vault password | keystore |
| `logos-evm-keystore-ui` | The custodian: creates, imports and exports keys | keystore |

This module is a **leaf**: it declares **no dependencies** (`"dependencies": []`)
and calls no other module. It is driven *by* `tx_sender_module`, which *requests* an
approval as the signing leg of every send and never handles a vault password; by the app
backends, which read accounts and labels; by the approver and the custodian; or directly
by the headless `logosctl` runtime. Keeping the keystore a dependency-free leaf is deliberate: the component
that holds private keys has the smallest possible attack surface and pulls in no
network-capable code.

---

## Overall architecture

The module is two layers that are deliberately decoupled by a Cargo feature:

* **The crypto core** (`rust-lib/src/keystore.rs`) — pure, offline, Logos-free
  Rust. The `Keystore` struct manages a directory of scrypt vault files. It holds **no**
  decrypted keys: a signer is derived per approval and zeroized before the call
  returns. Unit-tested on its own with
  `cargo test --no-default-features`.
* **The Logos glue** (`rust-lib/src/glue.rs`) — the `KeystoreModule` contract
  trait and its implementation, compiled only behind the default `logos_module`
  feature. It marshals every structured value across the IPC boundary as a JSON
  string, wires the on-context-ready hook to a persistence path, and emits
  `accounts_changed` after every mutation that changes what a reader displays.

```mermaid
flowchart TB
    subgraph Callers["Callers (over Logos bridge)"]
        BE["tx_sender_module<br/>(requester: request_approval)"]
        SU["evm_signer_ui<br/>(the ONLY approver)"]
        LC["logosctl daemon<br/>(Tier C only)"]
    end

    subgraph Module["keystore_module (Rust cdylib, type: core)"]
        direction TB
        DISP["Generated C-ABI dispatch + install()<br/>(injected from generated/provider_gen.rs)"]
        subgraph Glue["Logos glue — src/glue.rs (feature logos_module)"]
            TRAIT["trait KeystoreModule<br/>(the IPC contract)"]
            IMPL["KeystoreModuleImpl<br/>{ ks, approvals, roles }"]
            GATE["Tier gate<br/>current_caller() → A / B / C"]
            EV["KeystoreModuleEvents::accounts_changed<br/>→ emit_accounts_changed(count)"]
            CTX["on_context_ready(ctx)<br/>ks = Keystore::new(ctx.instance_persistence_path/keystore)"]
        end
        subgraph Core["Crypto core — src/keystore.rs (no network, no Logos)"]
            KS["struct Keystore { dir }<br/>(no signer cache)"]
            VAULTS["scrypt vault files<br/>a_&lt;random id&gt;.json"]
            MEM["signer: a LOCAL inside approve()<br/>derived per approval, then zeroized"]
        end
    end

    subgraph Deps["External crates (all offline)"]
        ALLOY["alloy<br/>signers / consensus / eips / k256"]
        ETHKS["eth-keystore<br/>(scrypt encrypt/decrypt)"]
        BIP39["coins-bip39 / coins-bip32<br/>(via alloy re-export)"]
    end

    BE -->|Tier B: request_approval| DISP
    SU -->|Tier A: acknowledge / approve| DISP
    LC -->|Tier C only| DISP
    DISP --> TRAIT
    TRAIT --> GATE
    GATE --> IMPL
    IMPL --> KS
    IMPL -.->|on account set change| EV
    EV -.->|event| Callers
    CTX --> KS
    KS --> VAULTS
    KS --> MEM
    KS --> ALLOY
    KS --> ETHKS
    KS --> BIP39

    classDef boundary fill:#1f2937,stroke:#60a5fa,color:#e5e7eb;
    class Module boundary;
```

**Key isolation, restated against the diagram:** raw private-key bytes exist only
inside `Core` — encrypted in the vault files, and decrypted **only into a local
variable inside `approve()`**, which zeroizes it before returning. There is no
map, no cache and no TTL, so there is no window during which some *other* caller
could reach a live signer. Keys are never returned through `TRAIT`. Only
`Address` strings, signature/transaction hex, and re-encrypted keystore JSON
travel back across the `DISP` boundary — and a signature only ever leaves as the
result of a `Rendered` request a human approved.

---

## Communication with dependencies

This module is a **leaf** — it makes **no outbound calls** to any other module
and opens no sockets. The interesting flow is therefore how a **caller drives it**.
The canonical flow has **three** parties, not two: a **requester** that may ask
but never approve, the **approver** (`evm_signer_ui`) that renders and takes the vault
password, and the human. `logosctl` can reach Tier C only.

```mermaid
sequenceDiagram
    autonumber
    participant BE as tx_sender_module (requester)
    participant KS as keystore_module (this repo)
    participant SU as evm_signer_ui (the ONLY approver)
    participant H as the human
    participant DISK as scrypt vault dir

    Note over KS: on_context_ready(ctx) → Keystore::new(...)<br/>roles default to evm_signer_ui / evm_keystore_ui until configure() names them

    BE->>KS: request_approval({ address, purpose, legs })
    Note right of KS: caller must be a NAMED module (Tier B)
    KS-->>BE: { ok, handle, receipt }   %% receipt returned exactly once
    KS--)SU: event approval_offered(handle)   %% handle only — no token, no intent

    SU->>KS: acknowledge(handle)
    Note right of KS: Tier A — refuses anyone but the approver.<br/>Demotes any other Rendered record.
    KS-->>SU: { bundle_id, requester, claim_lines, render_lines }
    SU->>H: both lists VERBATIM, kept apart + bundle_id
    Note over H: no timeout on the human

    H->>SU: vault password
    SU->>KS: approve(handle, bundle_id, password)
    KS->>DISK: decrypt vault (scrypt) → signer (a local)
    Note right of KS: re-parse intent, re-derive commitment,<br/>compare to bundle_id, sign every leg, ZEROIZE
    KS-->>SU: { ok, signed_count: n }   %% a COUNT — the approver never gets the signatures
    KS--)BE: event approval_settled(handle, "approved")   %% tx_sender polls approval_status instead

    BE->>KS: fetch_result(handle, receipt)
    KS-->>BE: { ok, signed: [...] }   %% idempotent until ack_result
    BE->>KS: ack_result(handle, receipt)

    Note over BE: tx_sender broadcasts the raw tx via eth_rpc_module<br/>(keystore never touches the network)
```

The signed values tx_sender collects are what it hands to `eth_rpc_module` for
`eth_sendRawTransaction`. The keystore itself never performs that broadcast — it
has no network code at all. Note the password crosses **only** the `evm_signer_ui` →
`keystore` edge: the requester never sees it, never sees `render_lines`, and
cannot produce a signature.

---

## Full API reference

The contract is the `KeystoreModule` trait in `rust-lib/src/glue.rs`. The builder
derives the module's `.lidl` interface from this trait (`codegen.rust =
{ crate: "rust-lib", trait: "KeystoreModule", source: "src/glue.rs" }`); every
**non-defaulted** trait method becomes a callable module method. `on_context_ready`
is *defaulted*, so it is a framework hook and **not** part of the IPC contract.

### Conventions

* **Structured returns are JSON strings.** Methods that return `String` return a
  JSON object that is either `{ "ok": true, … }` on success or
  `{ "ok": false, "error": "<message>" }` on failure. The `err()` helper produces
  the error shape; the message text comes from `KeystoreError` (`Display`).
* **Boolean methods** (`has_address`, `delete_account`, `ack_result`,
  `cancel_approval`, `reject`) return a bare `bool` and are **fail-soft**: any internal
  error (bad address, wrong password, keystore not yet initialized) maps to
  `false` rather than an error object.
* **Addresses** are accepted with or without a `0x` prefix, in any case; no EIP-55
  checksum is required (`parse_address` decodes the 20 raw bytes directly). The
  `logosctl` CLI auto-types a `0x…` argument as a number, so in CLI examples
  addresses are passed as **bare hex**.
* **Numeric transaction fields** cross as hex (`0x…`) **or** decimal strings to
  avoid precision loss over JSON; empty/missing numeric fields default to `0`.
* **`logosctl call` argument typing:** `true`/`false` → bool, integers → int,
  else string; `@file` loads file contents as the argument.

### Method index

| Method | Params | Returns | Mutates accounts? |
|--------|--------|---------|-------------------|
| `configure` | `config_json: String` | `{ ok, approvers, custodians, managers }` | no — sets who may |
| `create_mnemonic` | `words: i64` | `{ ok, phrase }` | no |
| `import_mnemonic` | `params_json: String` | `{ ok, address, path, group, storage, index, origin, phrase }` | yes → event |
| `derive_next_account` | `params_json: String` | `{ ok, address, path, group, index, origin }` | yes → event |
| `derive_account_at` | `params_json: String` | `{ ok, address, path, group, index, origin }` | yes → event |
| `import_seed_wallet` | `params_json: String` | `import_mnemonic`'s reply for `family: "evm"`, `import_bitcoin`'s for a Bitcoin family. The phrase must be `sourceGroup`'s, checked before anything is written | yes → event |
| `preview_addresses` | `params_json: String` | `{ ok, group, addresses: [..] }` | no |
| `preview_mnemonic` | `params_json: String` | `{ ok, addresses: [..] }`: what a phrase (or a kept one with its password) would derive for a family and chain, written nowhere. Tier D | no |
| `create_unrelated_account` | `params_json: String` | `{ ok, address, origin }`, or a refusal without the acknowledgement | yes → event |
| `forget_derivation` | `params_json: String` | `{ ok, group, storage, recordUpdated, stranded, stagedRemoved }` | no |
| `remove_group` | `params_json: String` | `{ ok, group, recordRemoved, nameRemoved }` | no — refuses while the wallet holds a key or an account |
| `list_groups` | — | `{ ok, groups: [..] }` | no |
| `list_derivation_keys` | — | `{ ok, groups: [id, ..], staged: [id, ..], unexplained: [path, ..], links: [..] }` | no |
| `get_provenance` | — | `{ ok, accounts: {..} }` | no |
| `get_account_wallets` | — | `{ ok, wallets: { <address>: { wallet, index? } } }` | no |
| `settle` | — | `{ ok, swept, promoted, unexplained, links, staged, importStages }` | removes leftovers |
| `remove_unexplained` | `params_json: String` | `{ ok, removed }` | removes one reported path |
| `import_private_key` | `priv_hex: String, password: String` | `{ ok, address }` | yes → event |
| `import_keystore_json` | `key_json, password, new_password: String` | `{ ok, address }` | yes → event |
| `export_keystore_json` | `address, password: String` | `{ ok, keystore }` | no |
| `list_accounts` | — | `{ ok, accounts: [..], staged: [..], unexplained: [path, ..], mismatched: [..] }` | no |
| `has_address` | `address: String` | `bool` | no |
| `delete_account` | `address, password: String` | `bool` | yes → event |
| `set_label` | `address, label, password: String` | `{ ok }` | no |
| `get_labels` | — | `{ ok, labels: { <address>: <name> } }` | no |
| `set_group_label` | `params_json: String` | `{ ok }` | no |
| `set_wallet_name` | `params_json: String` | `{ ok }` | no |
| `get_group_labels` | — | `{ ok, labels: { <groupId>: <name> } }` | no |
| `request_approval` | `intent_json: String` | `{ ok, handle, receipt, state }` | no |
| `approval_status` | `handle, receipt: String` | `{ ok, state, reason? }` | no |
| `fetch_result` | `handle, receipt: String` | `{ ok, signed: [..] }` | no |
| `ack_result` | `handle, receipt: String` | `bool` | no |
| `cancel_approval` | `handle, receipt: String` | `bool` | no |
| `pending` | — | `{ ok, pending: [..] }` | no |
| `acknowledge` | `handle: String` | `{ ok, bundle_id, requester, claim_lines, render_lines }` | no |
| `approve` | `handle, bundle_id, password: String` | `{ ok, signed_count: n }` | no |
| `reject` | `handle: String` | `bool` | no |
| `caller_identity` | — | `{ ok, kind, identity, approvers, custodians, managers }` | no |
| `signer_info` | — | `{ ok, interface, kind, model, families, requestKinds, showsRequest, collects }` | no |
| `signer_accounts` | — | `{ ok, accounts: [..] }` | no |
| `sign` | `request_json: String` | `{ ok, job }` | no |
| `sign_status` | `job: String` | `{ ok, job, state, code?, error? }` | no |
| `sign_result` | `job: String` | `{ ok, job, signatures: [..] }` | no |
| `cancel_sign` | `job: String` | `{ ok, job }` | no |
| `unlock_key` | `request_json: String` | `{ ok, job }` | no |
| `unlock_key_status` | `job: String` | `{ ok, job, state, code?, error? }` | no |
| `unlock_key_result` | `job: String` | `{ ok, job, key }`, once | no |
| `cancel_unlock_key` | `job: String` | `{ ok, job }` | no |
| `unlock` | `params_json: String` | `{ ok, account, expiresInMs, countLeft }` | no |
| `lock` | `params_json: String` | `{ ok, locked }` | no |
| `unlocked` | — | `{ ok, unlocked: [..] }` | no |
| `database_key` | `params_json: String` | `{ ok, group, databaseKey, origin, birthday }` | no |
| `device_database_key` | `params_json: String` | `{ ok, signer, account, databaseKey, origin, birthday, created }` | the first open makes a vault → event |
| `device_wallets` | — | `{ ok, wallets: [{ signer, account, birthday, createdMs }] }` | no |
| `forget_device_wallet` | `params_json: String` | `{ ok, forgotten }` | yes → event |
| `import_bitcoin` | `params_json: String` | `{ ok, group, family, chain, path, fingerprint, external, internal, phrase, origin, birthday }` | yes → event |
| `show_phrase` | `params_json: String` | `{ ok, phrase, words }` | no |
| `forget_phrase` | `params_json: String` | `{ ok, forgotten }` | yes → event |
| `list_phrases` | — | `{ ok, phrases: [{ id, groups, staged }] }` | no |
| `account_descriptors` | `params_json: String` | `{ ok, group, external, internal }` | no |

---

### `configure(config_json: String) -> String`

Name who holds the three roles. `config_json` is `{ approvers?, custodians?, managers? }`; the
reply is `{ ok, approvers, custodians, managers }` echoing what is now in force, or the usual
`{ ok: false, error }`. It takes effect on the next call — nothing is reloaded.

**A role is a set.** Each key takes one name or a list of them, because a terminal signer
has to approve *alongside* `evm_signer_ui` rather than by displacing it. Blanks and repeats are
normalised out, so `is_empty()` and "admits nobody" can never disagree. The pre-list
`approver`/`custodian` spelling is refused as an unknown key — the right way for a stale
configuration to fail, since accepting it silently would empty both roles.

**Total, not a patch.** The document is the whole answer to who holds these roles, so one
it does not name is held by **nobody**: `gate::holds_any_role` refuses an empty set, and
every method of that tier then refuses everyone. Half a configuration inheriting the other half
from a default is how a deployer who replaced one surface goes on granting the old one.
Whitespace is not a module name, so a blank string means nobody rather than an unmatchable
somebody.

**Refusals leave the gate where it stood.** A document that is not a JSON object, carries an
unknown key, or types a role as anything but a string is refused whole and the roles in
force are untouched — there is no partial apply. The unknown-key rule exists because under
the total rule a typo (`custodain`) would otherwise empty **both** roles: fail-closed, but
silent about why everything started refusing.

**Until it is called, the built-in defaults stand** — `evm_signer_ui` approves, `evm_keystore_ui`
mutates, `signer_manager_module` asks for signatures. A module nobody configures is not inert.

#### It is deliberately ungated, for now

Any caller can call `configure`, name **itself** custodian, and then mutate the keystore.
That is a real exposure and it is a deliberate, temporary one: protecting this call is
**deferred, not refuted**.

The design this replaced put the two role names in `<persistence>/keystore.json`, read once
in `on_context_ready`, on the stated ground that *who may mutate the keystore is
configuration, not a method — a `set_custodian` call would be a remotely-writable answer to
"who may import a key."* That reasoning still holds; what did not hold was the delivery. A
module's persistence directory is owned by the module instance and may be sandboxed with no
other process able to reach it, so configuration cannot be **placed** there from outside —
and in practice it did not even exist until the module had written to it, which put the
config out of reach at exactly the moment it was needed. Configuration has to arrive by
method call.

What is still owed is the protection the file gave for free: an answer to "who may set
policy" that is not simply "whoever calls first". Claim-once semantics, a caller gate, or a
platform-level configuration channel are all candidates; none is implemented here. Until one
is, treat the roles as advisory against a hostile co-resident module and load-bearing against
an honest one.

---

### `create_mnemonic(words: i64) -> String`

Generate a fresh BIP-39 English mnemonic. **Does not persist anything** — the
caller decides whether to import the phrase. The phrase is produced from
`rand::thread_rng()` and returned in cleartext (it is *not* a private key per se,
but it is seed material — treat it as a secret).

* **`words`** — word count. Must be one of `12 | 15 | 18 | 21 | 24`; any other
  value returns an error.

**Success:** `{ "ok": true, "phrase": "word1 word2 … wordN" }`
**Error:** `{ "ok": false, "error": "word count must be 12/15/18/21/24, got 13" }`

```bash
logosctl call keystore_module create_mnemonic 12
# → {"ok":true,"phrase":"… twelve words …"}
```

---

### `import_mnemonic(params_json: String) -> String`

Derive an account from a mnemonic along the BIP-44 Ethereum path
`m/44'/60'/<bip44Account>'/<change>/<accountIndex>`, persist its scrypt vault, and
create the account's **derivation group**. The argument is a **JSON object**
(`ImportMnemonicParams`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `phrase` | string | yes, unless `keptPhrase` | The BIP-39 mnemonic |
| `passphrase` | string | no (default `""`) | BIP-39 passphrase (the "25th word"). ASCII only — see below |
| `accountIndex` (alias `account_index`) | u32 | no (default `0`) | The **address** index — the fifth path level |
| `password` | string | yes | Vault password used to scrypt-encrypt the derived key on disk |
| `storage` | string | no (default `"plain"`) | `"plain"` keeps nothing; `"extkey"` keeps the account key so later accounts can be derived without the phrase |
| `bip44Account` | u32 | no (default `0`) | The **hardened BIP-44 account** level — the third |
| `change` | u32 | no (default `0`) | `0` external, `1` change |
| `groupPassword` | string | required when `storage` is `"extkey"` | Password for the group's own derivation-key vault |
| `groupLabel` | string | no | Human name for the wallet |
| `keepPhrase` | `{ password }` | no | Keep the phrase in a vault of its own, under this password. See [Kept recovery phrases](#kept-recovery-phrases) |
| `keptPhrase` | string | no | Make the wallet from a phrase kept earlier, in place of `phrase` |
| `phrasePassword` | string | with `keptPhrase` | The kept phrase's own password |

`accountIndex` and `bip44Account` are **different levels** and the names are a
trap worth reading twice: `accountIndex` predates the BIP-44 account level and
still means the address index.

`storage` defaults to `"plain"`, so a pre-HD call shape behaves exactly as it did
— nothing is retained and the group is recorded as not derivable. On success emits
`accounts_changed`.

**Success:** `{ "ok": true, "address": "0x…", "path": "m/44'/60'/0'/0/0", "group": "g_…", "storage": "plain", "index": 0, "origin": "derived", "phrase": null }`; `phrase` is the kept phrase's id when one is kept or used
**Error:** `{ "ok": false, "error": "<parse / derivation error>" }`

```bash
logosctl call keystore_module import_mnemonic \
  @mnemonic.json   # {"phrase":"test test … junk","accountIndex":0,"password":"pw"}
# → {"ok":true,"address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", …}
```

**The BIP-39 passphrase is part of the secret.** Same phrase, different passphrase
⇒ a completely disjoint account tree. It is **not stored** and **not recoverable**;
losing it loses the accounts as completely as losing the phrase. It is also **not
trimmed** — a trailing space is a different passphrase, and trimming would derive
accounts no other wallet recovers.

**Non-ASCII passphrases are refused.** BIP-39 salts with the NFKD form of the
passphrase; `coins-bip39` salts with the raw bytes it is handed, so `"café"` typed
NFC and NFD would derive different accounts here and a normalizing wallet would
disagree with both. ASCII is NFKD-invariant, so refusing now keeps the option of
normalizing later **without changing any address that is derivable today**.

---

### `new_account` — **removed**

`new_account(password)` created an account from a random key. It has no replacement of
the same shape, on purpose: [`create_unrelated_account`](#create_unrelated_accountparams_json-string---string)
is now the only way to obtain a random key, and it requires an explicit acknowledgement.

The method was safe only where the keystore held no recovery phrase, so it grew a guard
that scanned the directory and refused when it found derivation material. Seven rounds of
fix-and-review could not make that guard sound, and the reason is structural rather than a
missing case:

* every name the layout recognises becomes a hiding place — material wearing a recognised
  name (`labels.json`, `.lock`) skipped the content check entirely and minted;
* every name it does **not** recognise has to count as possible key material, so any stray
  file wedged the store;
* an account key and a derivation key **are the same shape**, and telling them apart needs
  the password.

"Is there live key material anywhere under this store" is not decidable by inspection. The
danger was never "a key exists on disk" — it was "a user got an unrecoverable key without
knowing". That is made impossible directly: a random key may only be obtained through a
door that says what it does and requires the acknowledgement, and no on-disk state either
grants or withholds one.

Callers that were calling `new_account` on an HD wallet want
[`derive_next_account`](#derive_next_accountparams_json-string---string); callers that
really wanted a random key want `create_unrelated_account` and now have to say so.

---

### `import_private_key(priv_hex: String, password: String) -> String`

Import a raw secp256k1 private key and persist its scrypt vault. The key is
consumed and immediately re-encrypted — it is not retained in cleartext beyond the
call, and it is never returned. Emits `accounts_changed`.

* **`priv_hex`** — 32-byte private key in hex, with or without a `0x` prefix.
* **`password`** — vault password.

**Success:** `{ "ok": true, "address": "0x…" }`
**Error:** `{ "ok": false, "error": "invalid private key: …" }`

```bash
logosctl call keystore_module import_private_key \
  ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 pw
# → {"ok":true,"address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
```

---

### `import_keystore_json(key_json: String, password: String, new_password: String) -> String`

Import an existing scrypt **keystore JSON** (Web3 Secure Storage format),
decrypting it with `password` and **re-encrypting** it under `new_password` into a
fresh local vault. The decrypted key never leaves the module. Emits
`accounts_changed`.

* **`key_json`** — the source keystore JSON (a string; written to a short-lived
  temp file because `eth-keystore` is path-based, then decrypted).
* **`password`** — password that decrypts the *incoming* keystore JSON.
* **`new_password`** — password used to re-encrypt the vault stored locally.

**Success:** `{ "ok": true, "address": "0x…" }`
**Error:** `{ "ok": false, "error": "vault error: …" }` (wrong `password`, malformed JSON, etc.)

---

### `export_keystore_json(address: String, password: String) -> String`

Export an account as scrypt keystore JSON **without touching the on-disk vault**.
The password is **verified** (the vault is decrypted to prove the password is
correct) and then the canonical on-disk JSON contents are returned. The exported
JSON is itself scrypt-encrypted — it is *not* a cleartext key.

* **`address`** — account to export (with/without `0x`, any case).
* **`password`** — the vault password (must decrypt, else error).

**Success:** `{ "ok": true, "keystore": "<keystore JSON string>" }`
**Error:** `{ "ok": false, "error": "vault error: …" }` (wrong password or missing vault)

---

### `list_accounts() -> String`

List the addresses of all persisted vaults, through the one directory scan (see
[Directory layout](#directory-layout)). The list is sorted.

Two fields beyond the addresses, both of which used to be dropped in silence:

* **`staged`** — a vault an interrupted write left at `.stage-<addr>/`. Normally
  empty: the call settles the directory first, promoting such a copy to its real
  path (it is the ONLY copy of that key) or reaping it when the real vault is
  already there. It is non-empty only when the repair itself could not run.
* **`unexplained`** — paths under the keystore directory that this module did not
  write: a hand-placed `backup.json`, a `.DS_Store`, a leftover from an older
  version. **Reported, not refused** — listing and signing keep working whatever
  is here, and a wallet must not be bricked by a stray file. Both severities appear
  (see *possible key material* below): a bucket is a severity, never a filter on
  what a reader is shown.

* **`mismatched`** — vault files whose own `address` field disagrees with their
  filename, as `<file> holds 0x<address>`. They are **not listed as accounts**: the
  two claims cannot both be true, and the wallet must not report an address whose
  vault disputes it. They also appear in `unexplained`, so `remove_unexplained`
  reaches them.

A filename is a **claim**, never a proof. Where a vault declares no address — the
ones this module writes do not — the mismatch is not knowable without a password, so
it is caught at every *use* instead: `sign_message`, `sign_digest`,
`export_keystore_json`, `change_password`, `delete_account` and `approve` all
re-derive the address from the decrypted key and refuse if it is not the one that
was asked for. Before that check, a vault renamed onto another address's filename
signed as that address, with a key that was never its own.

**Success:** `{ "ok": true, "accounts": ["0x…"], "staged": [], "unexplained": [], "mismatched": [] }`
**Error:** `{ "ok": false, "error": "keystore not initialized (context not ready)" }`,
or `{ "ok": false, "error": "<dir> is unreadable, and an unreadable file is not an
empty one …" }`. An UNREADABLE keystore directory refuses. It used to return an
empty array, so a user with a funded wallet was told they had none.

```bash
logosctl call keystore_module list_accounts
# → {"ok":true,"accounts":["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"],"staged":[],"unexplained":[],"mismatched":[]}
```

---

### `has_address(address: String) -> bool`

Return `true` iff a vault file exists for `address`. Fail-soft: an invalid address
or uninitialized keystore returns `false`.

* **`address`** — address to check.

```bash
logosctl call keystore_module has_address f39fd6e51aad88f6f4ce6ab8827279cfffb92266
# → true
```

---

### `delete_account(address: String, password: String) -> bool`

Permanently delete an account's vault. **Password-gated**: the vault is decrypted
with `password` first; only on success is the file removed. Emits `accounts_changed`. Returns `true` only when a vault existed, the
password was correct, and the file was removed; `false` otherwise (missing vault,
wrong password, parse error).

* **`address`** — account to delete.
* **`password`** — its vault password (required to authorize deletion).

```bash
logosctl call keystore_module delete_account <address> pw
# → true
```

---

### Naming accounts and wallets

Four methods: the two `set_` calls are **Tier D** *and* need a password (below), and the
two `get_` calls are **ungated** (a name is not a secret, and a picker needs it). Both
`set_` calls emit `accounts_changed` on success — a rename changes what every picker on
the machine is showing, and the count in the payload does not move.

| Method | Params | Returns |
|--------|--------|---------|
| `set_label` | `address: String, label: String, password: String` | `{ ok: true }` |
| `get_labels` | — | `{ ok: true, labels: { "<address>": "<name>" } }` |
| `set_group_label` | `params_json: String` — `{ group, label, address?, password? }` | `{ ok: true }` |
| `set_wallet_name` | `params_json: String` — `{ group, label, address?, password? }` | `{ ok: true }` |
| `get_group_labels` | — | `{ ok: true, labels: { "<groupId>": "<name>" } }` |

**A wallet's name is its seed's; an account file's is its own.** `set_wallet_name` names the
wallet — every account file of one seed, shown as the header over them — with `group` any file of
it, priced as `set_group_label` prices a name. `list_groups` gives each file's `walletName`, and
the imports take `walletName`, kept for a seed that has none yet. A file's `label` is its own name,
empty unless the person gives one. An older keys app copied the wallet's name onto every file and
account: the first `set_wallet_name` of that seed takes the copy off them.

```bash
logosctl call keystore_module set_group_label \
  '{"group":"g_0123456789abcdef0123456789abcdef","label":"Cold storage","address":"f39F…","password":"pw"}'
# → {"ok":true}
logosctl call keystore_module get_group_labels
# → {"ok":true,"labels":{"g_0123456789abcdef0123456789abcdef":"Cold storage"}}
```

**Setting a name needs a password; clearing one never does.** A label is what a reader
shows *in place of* an address, so writing one is a claim of custody — and until this
landing it was the one keystore mutation with no proof behind it, while delete, export
and change-password each had one. What is required depends on what the name speaks for:

| What is named | To SET a name | To CLEAR one |
|---------------|---------------|--------------|
| an account | that account's own vault password | nothing |
| a wallet with ≥1 account | `address` + `password` of **one of its own accounts** | nothing |
| a wallet with no accounts but a key on disk | `password` of that **derivation key** (no `address`) | nothing |
| a wallet that holds nothing | nothing — no accounts and no key, so it names nothing and can never gain anything to name | nothing |

The wallet is priced by what it **holds**, from the one `Holdings` predicate `remove_group`
refuses on — not by whether it happens to have accounts *today*. Holding any account is
precisely the claim "this wallet is mine", and where there are accounts the **group**
password is still *not* accepted: it proves you can *make* accounts, not that you own the
ones the header speaks for. With **no** accounts that rejection has nothing to reach — there
are none to own, and the only thing the name will come to stand for is the accounts that key
mints — so the key's own password is exactly the right proof.

This costs the free rename of a **stranded** key, which an earlier landing exempted as "the
row you most need to name before deleting it, and the one whose password is most likely
lost". The exemption rested on a stranded key never gaining a record, which is a promise
made by the very bookkeeping that is already damaged — and this module's rule is that the
*file* is the fact. Nothing that matters is lost: `forget_derivation` still deletes such a
key with **no** password, and clearing a stale name still needs none.

Refusals: `the password for this account is not correct` (identical for a wrong password
and for an unreadable vault — a name is not worth an oracle that tells them apart),
`naming a wallet that has accounts needs the password of one of them`, `that account
does not belong to this wallet` (identical whether the address is unknown, malformed, or
another wallet's, and it never echoes the value it was given — a swapped
`(address, password)` pair must not put the password into an error string), `naming a
wallet that keeps a derivation key needs that key's password`, and `the password for this
wallet's derivation key is not correct`. The staged copy an interrupted import left opens
the wallet just as the live key does, so it is proved against just the same.

**This is defence in depth, not the boundary.** Tier D already admits exactly one caller,
so an attacker able to call `set_label` at all *is* the custodian UI. What the password
buys is parity with the other destructive mutations, against a different adversary: a
human at an unlocked machine, or anything that can drive the UI without knowing a secret.
The larger part of the impersonation risk is not here at all — it is that a reader renders
a name *instead of* an address. The mitigation that removes it is showing both
(`Treasury · 0x7099…79C8`) wherever an account is chosen.

An empty or whitespace-only `label` **clears** the name; anything else is stored
trimmed. `set_group_label` refuses a group nothing on disk knows about
(`{"ok":false,"error":"invalid parameters: no such group: g_…"}`), and an id that is
not a well-formed group id (`invalid parameters: invalid group id …`) — but it accepts
a group named by *any* of the four facts the keystore holds: its record in the index, its key under
`groups/`, an account whose provenance points at it, or a name already standing over it in
the wallet names. A wallet a reader can see is one it can name, and a **stranded** key,
a lost record or a leftover name is exactly when it needs to.

`get_group_labels` answers from the wallet names alone, so it stays readable when the
record is gone — which is what lets a UI name the wallet it is asking the user
whether to delete. The same name is also mirrored onto each row of `list_groups` as
`label`, stranded rows included; a name a build before this one wrote into
the record is still shown, and the first rename moves it out of the record so a
cleared name cannot resurface.

**No uniqueness rule.** Two wallets may carry one name. Which of them a reader is
looking at is a question for whatever renders them — refusing the write would only
stop it showing what the user actually did.

**Refuses rather than reads as empty.** A present-but-unreadable index
fails every one of these calls, and `list_groups` with it — see *Three states, not
two*. Writing over it would silently erase every name it held.

---

## HD account derivation (BIP-32 / BIP-44)

### The path, and why it is not configurable

```
m / 44' / 60' / account' / change / index
    │     │      │          │        └── address index.   NOT hardened. 0 ≤ index < 2^31
    │     │      │          └─────────── 0 = external, 1 = change. NOT hardened.
    │     │      └────────────────────── BIP-44 account.  HARDENED.  0 ≤ account < 2^31
    │     └───────────────────────────── coin type 60 = Ethereum (SLIP-44). HARDENED.
    └─────────────────────────────────── purpose 44 (BIP-44). HARDENED.
```

Hardening breaks the relation `k_parent = k_child − IL` at that level, because a
hardened child's `IL` is derived from the parent *private* key. BIP-44 hardens the
three levels whose compromise crosses a boundary a user cares about (purpose, coin,
account) and leaves the two below open. Ethereum wallets rarely use `change = 1`,
but **the level must be present**: `m/44'/60'/0'/0` is a different key from
`m/44'/60'/0'/0/0`.

**Purpose and coin type are never editable through the API.** A "custom path" that
can change them is a way to make funds unrecoverable, dressed as a feature.

**Paths are parsed by this module, never handed to the crate's parser**
(`rust-lib/src/hd.rs`). `coins-bip32` filters an `m` segment *anywhere* in the
string, so `"m/44'/60'/m/0/0"` parses there as a four-level path; and its
`harden_index` is a bare `index + 2^31`, so `2147483648'` panics in debug and wraps
in release. Both produce addresses no other wallet recovers. This module parses five
components itself, checks each level, and reconstructs the canonical string.

### Derivation groups

A **group** is one `(mnemonic, BIP-39 passphrase, BIP-44 account)` triple. The
storage choice is made once, at import, for the whole group — it cannot be per
account, because the account key that derives index 3 derives index 5 as well.
Claiming otherwise would be a lie about what is recoverable.

| `storage` | What is kept | What that reaches |
|-----------|--------------|-------------------|
| `plain` (default) | nothing | — adding an account later needs the phrase again |
| `extkey` | the **account** key `m/44'/60'/<account>'`, in its own scrypt vault | every address under that one Ethereum account: both chains, every index, past and future |

**The root key is never stored, returned, or accepted** — unless the person chose to keep the
recovery phrase, which is the root by another name ([Kept recovery phrases](#kept-recovery-phrases)).
No method emits a root key, and
`decode_account_key` refuses any extended key that is not at depth 3 — a group
opened from a root would silently reach every SLIP-44 coin and every BIP-44
account. The account key produces exactly the addresses this module can ever
produce, and nothing else.

**No xpub is exposed, in any tier.** Below the account level BIP-44 is
non-hardened, so an account xpub *plus any one derived private key* yields the
parent xprv and with it every sibling — including addresses the user has not created
yet. `export_keystore_json` makes exporting one account's vault easy and legitimate;
today that costs one account, and an xpub in circulation would silently make it cost
the whole account tree. There is also no consumer: this module has no network, and
balance lookup lives in `eth_rpc_module`, which is handed explicit addresses.

**The trade, stated in both directions.** `plain` has the smaller *at-rest*
footprint: someone who copies the directory and guesses one account's password gets
one account. `extkey` has the smaller *in-use* footprint: it runs `to_seed` exactly
once, ever, while `plain` sends the phrase back through the UI and the IPC boundary
for every future account, and `coins-bip39::to_seed` leaks two un-wiped heap strings
per call. The default is `plain`, because the `extkey` benefit is a convenience and
its cost is a security property.

**Changing your mind.** `extkey` → `plain` is supported (`forget_derivation`) and is
a real, cheap reduction in exposure. It stays reachable even when the group's record
is missing or unreadable, because it is keyed on the key files rather than on the
bookkeeping — and even when the key itself can no longer be opened, because deletion
does not require reading what it deletes. `plain` → `extkey` is **impossible** — the material is not there — and
the module does not pretend otherwise: the only honest offer is importing the phrase
again with `storage: "extkey"`, which re-derives the same addresses.

**Residual, stated rather than papered over.** The extended key cannot be fully
wiped: `coins-bip32`'s `XKeyInfo` is `Copy` and carries an un-zeroized 32-byte chain
code, so every derivation step leaves copies behind. A chain code alone is not a key;
a chain code plus any child private key is the parent xprv. The base58 form is held
in `Zeroizing` and live `XPriv` values are kept to a minimum.

### Index tracking

`nextIndex` lives per group in its record and is a **cache, not the authority**.
It is recomputed on every use as
`max(nextIndex, 1 + max index recorded among the accounts of this group)`, so a
corrupted or hand-edited sidecar can only *skip* an index — never hand out one
already in use. A gap costs nothing; a collision is two vaults claiming one address.

**Deleting an account retires its index; it is never reused.** A reused path may
collide with an account that still holds funds, and re-deriving it under a fresh
password creates two vaults' worth of ambiguity about which password opens what.
Gaps are what every other wallet produces.

**Gap scanning against the chain is deliberately absent.** Knowing whether an
address has history requires an RPC, and this module has no network by construction
(see [Security model](#security-model--invariants)). The shape that keeps the network
where it already is:

```
keystore_module.preview_addresses  → addresses only, no keys, no writes, no network
eth_rpc_module                     → "which of these have history?"
keystore_module.derive_account_at  → create the ones the user picked
```

---

### `derive_next_account(params_json: String) -> String`

Add the next account of a derivation group, without the phrase. **Tier D.**

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `group` | string | no | Group id. May be omitted **only** when exactly one group can derive; with several the error names the candidates rather than picking one |
| `groupPassword` | string | yes | Password for the group's derivation-key vault |
| `password` | string | yes | Vault password for the **new** account (its own, not the group's) |
| `change` | u32 | no (default `0`) | `0` external, `1` change |

Walks past any index whose address is already held — an earlier raw-key import can
occupy one — recording what it is on the way, and never overwriting a vault.

**Success:** `{ "ok": true, "address": "0x…", "path": "m/44'/60'/0'/0/1", "group": "g_…", "index": 1, "origin": "derived" }`
**Error:** `{ "ok": false, "error": "wallet g_… did not keep a derivation key — import its recovery phrase again to add an account" }`

---

### `derive_account_at(params_json: String) -> String`

Add one account at an index the caller chose. **Tier D.**

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `group` | string | yes | Group id |
| `groupPassword` | string | yes | Password for the derivation-key vault |
| `password` | string | yes | Vault password for the new account |
| `bip44Account` | u32 | no | Asserted against the group's own account level |
| `change` | u32 | no (default `0`) | |
| `index` | u32 | yes | Address index |

A `bip44Account` different from the group's is refused **with the reason**: the
stored key cannot reach another account because that level is hardened. An index
already held is refused rather than overwriting the vault.

---

### `preview_mnemonic(params_json: String) -> String`

Tier D, read-only. Accepts `phrase` or `keptPhrase` plus `phrasePassword`, optional
`passphrase` and `sourceGroup`, and `family`, `chain`, `account`, `from`, `count`.
A named source group must match the recovered seed before any addresses are returned.
Counts are bounded by `MAX_PREVIEW`; ranges cannot enter hardened child indices.
Returns `{ ok, addresses: [{ family, chain, account, index, path, address, present }] }`.
Ethereum rows advance the address index at `m/44'/60'/account'/0/index`. Bitcoin rows
advance the hardened account index and show the first receiving address, preserving the
account's receive/change semantics. Preview writes no vaults or metadata and uses no network.
It opens a kept phrase only inside the backend; the words are not returned to the UI.

### `preview_addresses(params_json: String) -> String`

What a group would derive — **addresses only**. No keys, no vaults written, no
network. **Tier D**, because it enumerates the user's future addresses, which is a
linkability leak even though it produces no key.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `group` | string | yes | Group id |
| `groupPassword` | string | yes | Password for the derivation-key vault |
| `change` | u32 | no (default `0`) | |
| `from` | u32 | no (default `0`) | First index |
| `count` | u32 | no (default `10`, max **50**) | How many. Capped so this is not a free scrypt-plus-EC-multiply oracle |

**Success:** `{ "ok": true, "group": "g_…", "addresses": [ { "index": 0, "path": "m/44'/60'/0'/0/0", "address": "0x…", "present": true }, … ] }`

---

### `create_unrelated_account(params_json: String) -> String`

**The one door to a key this crate generates from randomness**, opened only when the
caller says so. Not the only door to a key no phrase restores: `import_private_key` and
`import_keystore_json` accept caller-supplied material and require no acknowledgement.
**Tier D.**
| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `password` | string | yes | Vault password |
| `acknowledgeUnrecoverable` | bool | yes | Must be `true`. This is the safety property, not a formality |

**Success:** `{ "ok": true, "address": "0x…", "origin": "random" }`
**Refusal:** `{ "ok": false, "error": "an unrelated account is a key your recovery phrase will not restore — its only backup is a vault file you export and keep yourself. Pass acknowledgeUnrecoverable: true to create it anyway" }`

**Enforced by construction.** The acknowledgement produces a value of type
`ack::Unrecoverable`, and *generating the random key is what that constructor does*. The
type's field is private to its module, so nothing else in the crate can build one, and the
only function that persists a random key takes one by value. A code path that skipped the
acknowledgement has no key to persist and does not compile. A unit test
(`the_only_random_key_in_this_crate_is_the_acknowledged_one`) reads this crate's own source
to assert `PrivateKeySigner::random()` appears in exactly one file: `ack.rs`.

This is the property that replaced "no on-disk state mints". The predecessor had to be
decided by looking at the directory, which is not decidable; this one is decided by the
caller.

**No on-disk state can withhold it either.** A stray file, an unreadable directory or a
half-written key does not refuse this method. That is deliberate: refusing left the user
with a keystore that could neither derive nor create, and nothing on disk changes what the
caller was told.

---

### `forget_derivation(params_json: String) -> String`

Stop keeping a group's derivation key: delete every path that id can occupy —
`groups/<id>.json` and `groups/.stage-<id>/` — and flip the group to `plain`.
**Tier D.** One-way — re-importing the phrase is the only way back. Emits
`accounts_changed`.

The accounts already derived are **untouched**: they keep signing exactly as before.
What ends is adding *more* of them without the recovery phrase.

**No password.** Deletion does not require the ability to *open* what it deletes. It
used to: a vault whose password was lost, or whose bytes were corrupt, could then
never be removed — and while it sat on disk it went on refusing every new account.
The user could neither derive nor stop being derivable. Authorisation is the Tier D
custodian gate, which is where it belongs; a password proves knowledge of the key,
not intent to destroy it.

Keyed on the key **files**, not on the records. Routing it through the bookkeeping
meant a group whose record was lost or unreadable could not be named at all, so its
whole-wallet key stayed on disk with no way to delete it — and the `extkey → plain`
downgrade below had no way out. `list_derivation_keys` names such a key.

| Field | Type | Required |
|-------|------|----------|
| `group` | string | yes |

**Success:** `{ "ok": true, "group": "g_…", "storage": "plain", "recordUpdated": true,
"stranded": false, "stagedRemoved": false }`

`recordUpdated` is false when the key was deleted but the index could not be
read or rewritten to downgrade the record. `ok: true` means exactly one thing — the
key is gone — and `recordUpdated` says whether the bookkeeping followed. Reporting a
deletion that *did* happen as a failure would invite a retry that finds nothing.
`stranded` means there was no record to update. `stagedRemoved` means a copy left by
an interrupted import was removed as well as, or instead of, the vault.

---

### `remove_group(params_json: String) -> String`

Remove a wallet's **record** and its **name** — and nothing else. **Tier D.** Emits
`accounts_changed`.

This exists because a wallet could be listed and not be removable by anything. A group
consists of up to four things: a record, a name among the wallet names,
a derivation key at `groups/<id>.json` (and/or a staged copy), and zero or more accounts.
`forget_derivation` removes the **key** and reports not-found when there is none — so a
wallet that is not derivable and holds no accounts had only a record, and no method
anywhere could take it off the screen.

| Field | Type | Required |
|-------|------|----------|
| `group` | string | yes |

**Success:** `{ "ok": true, "group": "g_…", "recordRemoved": true, "nameRemoved": true }`

Both booleans are **reported rather than assumed**, in the shape of `forget_derivation`'s
reply, so a half-completed removal is visible instead of reading as a clean one. If only a
name entry survives from an earlier partial write, it is cleared and `recordRemoved` is
`false`: the operation is total and self-healing. The record goes first and the name
second — a name left over a vanished record is invisible cruft, while a vanished name over
a row still on screen is a user-visible surprise.

**It refuses while the wallet still holds anything.**

| The wallet | Result |
|------------|--------|
| keeps a derivation key (live **or** staged) | `this wallet still keeps a derivation key — stop keeping it first` |
| holds ≥1 account | `this wallet still holds N account(s); removing its record would leave them with nothing to name them — delete them first` |
| has neither a record nor a name | `account not found: no such group: g_…` |
| id is malformed | `invalid parameters: invalid group id "…"` |
| the index / the scan is unreadable | the `Corrupt` refusal — never remove on an unread precondition |

So a five-account derivable wallet takes six calls to remove, and that is the correct
cost: five of those are spendable keys, each with its own password. The alternative —
re-parenting the accounts to "origin not recorded" — would rewrite each one's provenance
from `derived` to `unknown` and drop its path, deleting a true fact (that a phrase covers
that account, and at which path) to make a row disappear. This module does not guess about
recoverability, and rewriting `derived` to `unknown` is worse than a guess.

**No password, and no acknowledgement.** Because "holds nothing" is the *precondition*,
nothing signable can be destroyed here — so a password would protect nothing, and a third
acknowledgement flag would devalue the two that mean something (`acknowledgeUnrecoverable`
and `acknowledgeMayBeKeyMaterial` exist where key material is genuinely at stake).
`forget_derivation` and `delete_account` remain the only writers in this module that
delete key material, each keeping its own acknowledgement.

What is lost is exactly: the wallet's name, its recorded path prefix (`m/44'/60'/N'`) and
its `nextIndex`/`retired` bookkeeping. Re-importing the phrase does **not** bring the row
back — it mints a new group id, so it makes a new wallet with no name.

```bash
logosctl call keystore_module remove_group '{"group":"g_0123456789abcdef0123456789abcdef"}'
# → {"ok":true,"group":"g_…","recordRemoved":true,"nameRemoved":true}
```

---

### `list_groups() -> String`

**Ungated**, like `get_labels`: none of it is a secret, and a wallet showing an
account picker needs it.

```json
{ "ok": true, "groups": [ { "id": "g_…", "storage": "extkey",
  "pathPrefix": "m/44'/60'/0'", "nextIndex": 4, "usedIndices": [0, 2, 3],
  "retiredIndices": [1], "usedPassphrase": true, "label": "Main",
  "accountCount": 3, "derivable": true, "stranded": false } ] }
```

`usedPassphrase` is a **boolean, never the value**. A Bitcoin wallet's row also carries `family`
and `chain`, and any wallet made from a kept phrase carries its id as `phrase`
([Kept recovery phrases](#kept-recovery-phrases)). `derivable` checks the vault
*file*, not just the recorded choice, so a deleted key reads as "not derivable"
rather than as a promise.

`stranded` marks a derivation key on disk that **no record names**. It is listed
rather than hidden: it cannot derive (there is no recorded path prefix to derive
against) but it is live whole-wallet material, and hiding it is what made it
undeletable. Its `pathPrefix` is empty; its `label` is whatever the wallet names hold
for it, and its `accountCount` is the accounts whose provenance still points at it — a key
loses its record while the accounts it derived are still here, and both removal and renaming
read that count as "does this wallet hold anything".

`staged` marks a group whose key an interrupted import left at `groups/.stage-<id>/`.
It is **not** promoted to the live key — a half-written file is not a vault — so it
reads as not derivable, but it opens the whole wallet just the same: it refuses a
random key, and `forget_derivation` removes it.

**Refuses** if the index is present but unreadable — see
*Three states, not two* below.

---

### `list_derivation_keys() -> String`

What the `groups/` directory holds. **Ungated.** Reads that directory **only**, never
`groups.json`, so it stays answerable when the bookkeeping is unreadable — which is
what keeps a stranded key nameable, and therefore deletable.

```json
{ "ok": true, "groups": ["g_0123456789abcdef0123456789abcdef"],
  "staged": [], "unexplained": [], "links": [] }
```

`groups` names every key on disk, at either the final path or the staging one — the
set `forget_derivation` can reach. `staged` is the subset an interrupted import left
behind. `unexplained` lists everything else this module did not write that **could be
a derivation key**, anywhere under the keystore directory and relative to it — not
only what sits under `groups/` (see *possible key material* below); the scan is total
over ENTRIES — files, directories, symlinks and sockets alike — so every path is
accounted for. `links` names any symlink as `<rel> -> <target>`: a link
at `groups/` would put the key outside the keystore, so the write is refused and the
link is reported with its destination, which is the only thing a scan of `<ks>/` can
still say about material that left it.

**The scan is the authority for every question asked of `groups/`** — what is derivable,
what is deletable, and what is here that this keystore did not write. Those answers used
to come from different reads, and a key at the staging path was invisible to one of them
while being just as live. It no longer answers "may a random key be created": that is the
caller's acknowledgement, not a property of the directory.

---

### `get_provenance() -> String`

Where each account came from, for **every** account the keystore holds. **Ungated**,
same reasoning as `list_groups`.

```json
{ "ok": true, "accounts": { "0xf39F…2266": { "origin": "derived", "group": "g_…",
  "path": "m/44'/60'/0'/0/0", "index": 0, "derivable": true } } }
```

`origin` is one of `derived` | `imported-key` | `imported-json` | `random` |
`unknown`. Accounts that predate this feature are reported **`unknown`, never
guessed** — a guess about recoverability is the one lie this must not tell.

---

### `get_account_wallets() -> String`

The canonical account-to-wallet join for account pickers. **Ungated.** It combines
the account provenance and wallet-name documents inside the Keystore, so each consumer
does not have to recreate ownership rules independently.

```json
{ "ok": true, "wallets": { "0xf39F…2266": { "wallet": "Main", "index": 0 } } }
```

Only accounts whose provenance names a derivation group with a non-empty wallet label
appear. Imported, unknown, and unnamed accounts are omitted rather than assigned a
guessed wallet. `index` is omitted when provenance does not carry one. An unreadable
provenance or wallet-name document returns an error instead of pretending there are no
wallets.

---

### `settle() -> String`

Bring the keystore directory to a state the layout explains and report what is left.
**Tier D** — it removes things. Emits `accounts_changed`.

* Promotes a vault an interrupted write left at `.stage-<addr>/` when the real vault
  is gone (the staged copy is then the ONLY copy of that key), reaps it when the real
  vault is there.
* Sweeps import scratch at `.stage-import-<nonce>/` — the caller's ciphertext, left
  by a process killed mid-`import_keystore_json`.

`list_accounts` settles as a side effect, but that is not enough on its own: a stage
a crash left behind must not be waiting on something happening to list first.

`swept` names the staging directories it removed and `promoted` the vaults it brought
to their real path — what it *did*, not only what is left. A leftover that is only
named after it has been swept was never nameable.

```json
{ "ok": true, "swept": [".stage-import-422cd79c…"], "promoted": [],
  "unexplained": [], "links": [], "staged": [], "importStages": [] }
```

---

### `remove_unexplained(params_json: String) -> String`

Remove one path the scan reported as unexplained. **Tier D.** Emits `accounts_changed`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `path` | string | yes | Exactly a string `list_accounts`/`settle`/`list_derivation_keys` reported |
| `acknowledgeMayBeKeyMaterial` | bool | yes | Refuses without it |

Only a string the scan itself produced is accepted, so nothing outside the keystore
directory can be named — this is not an arbitrary-delete primitive. The
acknowledgement is required because unidentified material may **be** a live key:
this module cannot read it, so it cannot promise otherwise.

This is what makes the report actionable. Every shape a crash or a hand-edit leaves
— a stray `backup.json`, a directory where a vault belongs, an empty directory where
a derivation key belongs, a `groups/` that is a symlink — is nameable **and**
removable by the same one call.

**Success:** `{ "ok": true, "removed": true }`
**Refusal:** `{ "ok": false, "error": "backup.json is material this keystore did not write and cannot read, so it may be a live key — acknowledge that to remove it anyway" }`

```bash
logosctl call keystore_module remove_unexplained '{"path":"backup.json","acknowledgeMayBeKeyMaterial":true}'
```

---

## Bitcoin wallets (BIP84, BIP86)

*Phase K0 of the Shared Keystore Plan built the core; K1 and K2 added creating Bitcoin wallets over
IPC (`import_bitcoin`), opening them for a wallet core through the signer manager, and unlocking
them.*

A Bitcoin wallet is a derivation group of one **family**, on one **chain**:

| Family | Path | Script | Descriptor |
|---|---|---|---|
| `bitcoin` | `m/84'/c'/a'` (BIP84) | P2WPKH, native segwit | `wpkh([fp/84'/c'/a']xpub/0/*)` and `/1/*` |
| `bitcoin_taproot` | `m/86'/c'/a'` (BIP86) | P2TR, key path only | `tr([fp/86'/c'/a']xpub/0/*)` and `/1/*` |

`c` is 0 on the `main` chain and 1 on `test`, which covers testnet, testnet4, signet and
regtest. Like the EVM path, neither is editable: `btc::parse_account_path` refuses any other
purpose, coin type or depth, so a hand-edited record cannot redirect derivation. A request names
its network, and a test wallet never signs for mainnet or the other way round.

**What is kept.** The group's vault, at `groups/<id>.json` like an EVM group's derivation key,
holds a JSON document inside the same scrypt envelope:
`{ v: 1, family, accountKey, databaseKey }`. `accountKey` is the account-level xprv or tprv,
the deepest key the wallet keeps; the root is never stored. `databaseKey` is 32 random bytes,
generated with the group and derived from nothing, for the wallet core's encrypted database.
The record gains `family`, `chain`, `fingerprint` and `xpub`. They are public,
but the xpub reveals the wallet's whole history, as an EVM vault's filename reveals its address.
An EVM record gains only `fingerprint`, the master fingerprint of the phrase it was made from,
recorded while the seed is in memory; a Bitcoin import from the same phrase fills it in on older
records.

**Where its history starts.** The record also keeps `origin` and `birthday`, for the wallet core
to know where to start scanning:
- `created`: the keys app made the phrase for this wallet, so no coin can have reached it before
  the day it is made. `birthday` is that day, by the keystore's clock, in UTC.
- `restored`: the phrase came from elsewhere, or was kept earlier. `birthday` is the day the
  person gave, if they knew it.

A birthday is a real day as `YYYY-MM-DD`, from 2009-01-03 to tomorrow in UTC, since the person's
day may run ahead of it. A wallet from a kept phrase is always `restored`, since the phrase is older
than the wallet. A record from before these were kept reads `restored`, with no birthday.

`account_descriptors` (`{ group }`, for the configured manager or custodian, so the keys app can
show a wallet's descriptor with its warning) returns both descriptors with their BIP380
checksums. A Bitcoin wallet never exports a child key, which is what keeps showing its xpub
safe; EVM groups still expose no xpub. EVM derivation refuses a Bitcoin group by name, and
`forget_derivation` refuses one, because its vault holds the wallet's only key.

**What the keystore checks before showing a PSBT.** Every input must be this wallet's: an
entry in `bip32_derivation` (or `tap_key_origins` with the internal key) carrying this
wallet's master fingerprint and a path under its account, whose derived key is the one named
and whose script is the one spent. Refused, whole:

* an input of another wallet, or one naming this wallet's keys twice;
* a native segwit input without its previous transaction, a previous transaction that is not
  the one spent, or an amount that disagrees with it. A segwit v0 signature commits only to
  its own input's amount, which is the 2020 fee attack; a taproot signature commits to every
  input's, so a false amount there signs nothing that can spend;
* a sighash other than ALL, or DEFAULT for taproot;
* a script path, a redeem or witness script, or an input already signed;
* outputs worth more than the inputs, or a coin spent twice, which the fee would count twice.

An output counts as this wallet's only if deriving the path it claims gives its script;
anything else is shown as a send. The fee is the keystore's own sum, inputs minus outputs,
and the rate beside it assumes the largest signatures, so it is never above the real one.

```
Wallet: "Savings"
Commitment: 3b0c…
1 item(s) to sign:
  [1] Bitcoin signet · wallet "Savings", native segwit, account 0
      Send 0.01500000 BTC to tb1q…
      Change 0.00481234 BTC back to this wallet (m/84'/1'/0'/1/7, checked)
      Fee 2,190 sats, about 14.1 sat/vB, computed from the inputs
      Spends 2 coins worth 0.01983424 BTC · replaceable (RBF)
```

**Commitment and signing.** The commitment is SHA-256 over the consensus encoding of the
unsigned transaction and, per input, the amount, script, path and sighash shown, and per
output whether it is this wallet's and at which path. `approve` reads the PSBT again, checks
the commitment, opens the vault with the password, refuses a vault whose key is not the one
the record's xpub describes, and signs with rust-bitcoin's `Psbt::sign`: ECDSA for native
segwit, BIP340 Schnorr with auxiliary randomness for taproot. The key lookup is our own,
because rust-bitcoin's lookup for an `Xpriv` matches only a master key or the level below.

**Residual.** rust-bitcoin's `Xpriv` is `Copy` and has no `Zeroize`, so derivation leaves
copies of keys and chain codes the module cannot wipe; `AccountSecret` wipes its own on drop.

## The keystore as a signer (`logos.signer/1`)

The keystore implements [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface),
the contract every signer module implements, so the signer manager (`signer_manager_module`) can
list its accounts and have it sign beside each hardware wallet's module. It signs **hashes only**:
the manager reads, renders and commits to every request, computes each digest, and checks every
signature against the account's public material before anything settles. The keystore parses no
request on this path. The approval flow below keeps working until its last caller has moved to the
manager. `rust-lib/src/signer.rs` holds the code; it passes the interface's conformance suite.

### Who may call

| Methods | Admits |
|---|---|
| `signer_info` | anyone: it describes the kind of signer, not an account |
| `signer_accounts`, `unlocked` | a configured **manager** or **custodian**: a Bitcoin xpub reveals the wallet's whole history |
| `sign`, `sign_status`, `sign_result`, `cancel_sign`, `unlock_key`, `unlock_key_status`, `unlock_key_result`, `cancel_unlock_key`, `unlock`, `lock`, `database_key`, `device_database_key` | a configured **manager** (Tier M, default `signer_manager_module`) |
| `import_bitcoin`, `show_phrase`, `forget_phrase`, `forget_device_wallet` | a configured **custodian** (Tier D) |
| `device_wallets` | a configured **manager** or **custodian** |
| `list_phrases` | anyone: ids and the wallets that name them, never words |
| `account_descriptors` | a configured **manager** or **custodian**: a descriptor's xpub shows the wallet's whole history |

Tier M is a registry like Tier D (`gate::TIER_M_METHODS`). It matters most for `unlock`: the
manager keeps which apps an unlock covers and whether each signature is still confirmed, so a
module that could reach `sign` past it would sign inside an unlock it was never granted.

### `signer_info() -> String`

`{ ok, interface: "logos.signer/1", kind: "keystore", model: "scrypt key files", families: ["evm",
"bitcoin", "bitcoin_taproot"], requestKinds: ["hash"], showsRequest: false, collects: "password",
unlockKey: true }`.

### `signer_accounts() -> String`

Every account as public material. An EVM account: `{ id: <address>, family: "evm", address, path?,
fingerprint?, label?, origin?, available: true }`, `path` only for a derived one, and `fingerprint`
the master fingerprint of the phrase it was derived from, when known. A Bitcoin wallet: `{ id:
<group>, family: "bitcoin" | "bitcoin_taproot", chain: "main" | "test", path: "m/84'/1'/0'",
fingerprint, xpub, label?, origin?, available: true }`. `origin` is `{ devices, phrase: { id, name },
kind, path }`, the signer interface's extension: `phrase.id` is the same for every account of one
phrase, and `name` is one of their wallet names, the same for each.

Every account names its `seed`: the seed link every group of one phrase shares, else its group's id;
a key imported on its own (by its key, a JSON vault, or at random) is a seed of its own, `k_` + 16
random bytes in hex, never its address: the name shows while the wallet is locked. The signer
manager unlocks that seed's data across every app (see below).

### A seed's unlock key

The signer manager unlocks a wallet's data, in every app, with the public key at
`m/1280263247'/n'` of its seed, which every holder of the seed gives. The keystore keeps the
extended key at `m/1280263247'` of each seed it imports, sealed under the password given with it
(scrypt 2^15, XChaCha20-Poly1305, bound to the group), as the group record's `unlock`, so any index
derives behind that password and the phrase isn't needed again. Nothing signs under that purpose:
an item under it is refused. A key imported on its own derives its unlock key from itself.
`change_password` reseals the root under the new password.

- **`unlock_key`** (`{ seed, index, secret }`, Tier M) answers at once: a job that is `done`, whose
  `unlock_key_result` gives the 33-byte key, hex, once. No secret is `locked`; a wrong password
  `wrong_secret`; a seed it doesn't hold `wrong_seed`. A group imported before it kept a root is
  refused: the person adds it again from its phrase.
- **Enrolment.** After every import (`import_mnemonic`, `import_seed_wallet`, `import_bitcoin`,
  `import_private_key`, `import_keystore_json`, `create_unrelated_account`) the keystore tells the
  manager of the seed, while the password is at hand, so the person never unlocks it twice:
  `enroll_seed({ seed, kind: "keystore", unlockKey, name, origin?, birthday? })` through
  `logos.wallets/1` (`wallets.lidl`), bound to `signer_manager_module` at runtime. It is asked
  without waiting; with no manager installed, the import succeeds all the same.

### `sign(request_json: String) -> String`

`{ account, kind: "hash", items: [{ path?, scheme, digest }], secret? }` → `{ ok, job }`. Every item
is checked against the account **before any vault opens**: an EVM account takes scheme `evm` and
no path, and signs with its own key; a native segwit wallet takes `ecdsa` and a Bitcoin wallet's
receive or change path (`m/84'/c'/a'/0|1/i`); a taproot wallet takes `bip86`. With `secret`, the
vault opens with that password for this request only; without it, the account's unlock answers,
and one request counts once against it however many items it carries. A wrong password is
`wrong_secret`, one message for every way a vault fails to open, as `set_label` gives; no secret
and no unlock is `locked`. Signatures are 64 bytes `r‖s` with low S, `recoveryId` for EVM, and
the signing key (33 bytes, or 32 x-only for taproot) as `pubkey`.

### `sign_status(job: String) -> String`, `sign_result(job: String) -> String`, `cancel_sign(job: String) -> String`

A keystore job finishes inside `sign`, so `sign_status` answers `done` (or `failed` with its
`code`) at once, and `sign_result` returns the signatures until the job is swept, ten minutes
after it settled. `cancel_sign` is harmless on a settled job.

### `unlock(params_json: String) -> String`, `lock(params_json: String) -> String`, `unlocked() -> String`

`unlock` takes `{ account, password, ttlMs?, count? }` and holds the account's key in memory until
`ttlMs` passes or `count` requests are signed — whichever comes first; neither means until it is
locked. It answers `{ ok, account, expiresInMs, countLeft }`. `lock` takes `{ account? }` and locks
that account, or every account for `{}`, answering `{ ok, locked: <how many> }`. `unlocked` lists
`{ account, expiresInMs, countLeft }`.

These are **not** the methods keystore#6 deleted. That `unlock` was callable by any module and
its only caller passed `ttl: None`, so it never expired and nobody had chosen that. This one
answers the manager alone, which takes the terms from a person in the keys app; the keystore
enforces the time and the count, the manager the apps and the confirmation. A new password and a
deleted account end the account's unlock, and nothing about an unlock is written to disk.

### `database_key(params_json: String) -> String`

`{ group, password? }` → `{ ok, group, databaseKey, origin, birthday }`: a Bitcoin wallet's 32
random bytes for the wallet core's database, for an open request the keys app approved, with where
its history starts (`birthday` is `null` when unknown). With `password` the vault opens; without
it, the wallet's unlock answers, and opening uses no count.

### Device wallets' database keys

A Bitcoin wallet whose key is on a device, such as a Keycard Shell, still needs a key for its
wallet core's encrypted database. The keystore keeps one per device account, in a vault of its
own under a password the person sets the first time the wallet is opened for an app. It opens the
wallet core's records and nothing else: no coin, no signature. The device signs.

- **`device_database_key`** (`{ signer, account, password, birthday? }`, Tier M): the manager
  calls it for an open the keys app approved, naming the signer module that offers the account
  and the account's id there.
  - The first open makes the vault: 32 random bytes under `password`, with the `birthday` the
    person gave, if any.
  - Every later open needs that password, and keeps the first birthday.
  - A wrong password is `wrong_secret`, with one message for every way the vault fails to open.
  - The reply is `{ ok, signer, account, databaseKey, origin: "restored", birthday, created }`.
    A device account is always `restored`: a device keeps no record of when its seed was made.
- **`device_wallets`** (the manager and the custodian): which device accounts have a vault, with
  their birthdays. Never a key.
- **`forget_device_wallet`** (`{ signer, account }`, Tier D): removes the vault and its record
  without a password, the escape from a forgotten one. What the old key opened can no longer be
  read, so a wallet core starts its records over. The next open makes a new vault.

**What is kept.** The vault sits at `groups/<device id>.json`, where the id is `d_` plus 16 random
bytes, never derived from the account. It is staged and renamed like a group key, and holds
`{ v: 1, databaseKey }` in the same scrypt envelope. `device-wallets.json` maps each id to its
signer, account, creation time and birthday. The scan explains both paths, staged and live. A
database key is not key material: it is never counted among what could open a whole wallet.

A record whose vault never landed, from an interrupted first open, is no wallet: the next open
removes it and makes the vault afresh. The same account id under another signer module is
another wallet.

### `import_bitcoin(params_json: String) -> String`

`{ phrase, passphrase?, family: "bitcoin" | "bitcoin_taproot", chain: "main" | "test", account?,
password, label?, keepPhrase?: { password }, origin?: "created" | "restored", birthday? }` →
`{ ok, group, family, chain, path, fingerprint, external, internal, phrase, origin, birthday }`,
the two descriptors with their checksums. Tier D. See [Bitcoin wallets](#bitcoin-wallets-bip84-bip86).

`origin` defaults to `restored`, which takes an optional `birthday`. `created` takes none: its
birthday is the day it is made. A birthday that isn't a real day from 2009-01-03 on, or a created
wallet from a kept phrase, is refused and records nothing.

`keepPhrase` keeps the phrase in a vault of its own under that password, and `phrase` in the
reply is its id. `{ keptPhrase, phrasePassword }` in place of `phrase` makes another wallet from
a phrase kept earlier: the vault opens with its own password, and the new wallet names it too.
The passphrase is asked for again; it is never kept.

### Kept recovery phrases

Keeping the phrase is the person's choice, off unless asked for. What the keys app says next to
it: *you can see the phrase again and add wallets without typing it. Someone with a copy of this
keystore and this password gets every account of every coin this phrase makes, including ones
never created here. Keep it only if you would keep the paper copy on this computer too.*

- **One vault per phrase,** at `groups/<phrase id>.json`, beside the group keys and staged the
  same way. Its own scrypt password, the same Web3 Secure Storage envelope, the words alone with
  their whitespace normalized. The id is `p_` and 16 random bytes, never derived from the phrase.
  The scan names it, at either path, as key material: `possible_key_material` includes it, and it
  is never stray.
- **Every wallet made from it names it** in its record (`phrase`). Deleting those wallets leaves
  the phrase; `list_phrases` still lists it, and the keys app offers to forget it.
- **The BIP39 passphrase is never kept.** A wallet made with one records only that one was used.
- `show_phrase` (`{ phrase, password }` → `{ ok, phrase, words }`, Tier D) answers the keys app
  alone, and only the live vault: a copy an interrupted write left at the staging path is listed
  and forgettable, never shown.
- `forget_phrase` (`{ phrase }` → `{ ok, forgotten }`, Tier D) removes the vault at either path
  without a password, as `forget_derivation` removes a key, and clears it from every wallet's
  record. It announces, because what `list_groups` shows moved.
- `list_phrases` (ungated) lists every kept phrase with the wallets that name it and whether it
  sits only at the staging path. Ids only; the words never leave `show_phrase`.

### Events

`signer_accounts_changed` goes out with every `accounts_changed`, with the same count, from one helper, so the
two cannot drift; `rust-lib/tests/every_displayed_mutation_announces_itself.rs` checks both.
`signer_changed` and `sign_progress` are part of the interface; the keystore has no device and
finishes its jobs inside `sign`, so it never sends them.

---

## Human-approved signing

There is **no way to make this module sign anything except by a person's approval**: of the
request, or of an unlock whose terms cover it. The methods that used to sign on demand —
`timed_unlock`, `is_unlocked`, `sign_transaction`, `sign_message`, `sign_digest`, and the
`unlock` and `lock` keystore#6 removed — are **deleted from the contract**, not merely gated. On
this path the signing key is derived from the vault password *inside* `approve()`, used, and
zeroized before the call returns. The signer interface's `unlock` (above) answers the manager
alone, on terms a person set.

### The three tiers

Every request is classified by the **caller identity** the platform reports
(`logos_rust_sdk::current_caller()`).

| Tier | Methods | Admits |
|------|---------|--------|
| **A** | `pending`, `acknowledge`, `approve`, `reject` | a configured **approver** (default `evm_signer_ui`) |
| **B** | `request_approval`, `approval_status`, `fetch_result`, `ack_result`, `cancel_approval` | any **named module**; `fetch`/`ack`/`cancel`/`status` additionally require the **receipt** |
| **C** | reads: `list_accounts`, `has_address`, `get_labels`, `get_group_labels`, `list_groups`, `list_derivation_keys`, `get_provenance`, `get_account_wallets`, `caller_identity`, `list_phrases` — and, for now, `configure` | ungated |
| **D** | account mutation: `create_mnemonic`, `import_mnemonic`, `import_private_key`, `import_keystore_json`, `export_keystore_json`, `delete_account`, `change_password`, `set_label`, `set_group_label`, `derive_next_account`, `derive_account_at`, `preview_addresses`, `create_unrelated_account`, `forget_derivation`, `import_bitcoin`, `show_phrase`, `forget_phrase`, `forget_device_wallet` | a configured **custodian** (default `evm_keystore_ui`) |
| **M** | the signer interface's signing calls and the keys an unlock holds — see [the keystore as a signer](#the-keystore-as-a-signer-logossigner1) | a configured **manager** (default `signer_manager_module`) |

Tier D is a **registry**, not a per-method `if`: `gate::TIER_D_METHODS` lists the
names and `gate::tier_d_admits(method, custodian, caller)` is the only decision.
A method **missing** from that list is refused outright rather than falling through
ungated — so the failure mode of forgetting to gate a new mutation is that it
refuses everyone, loudly, instead of admitting everyone, silently.

Tiers A, B and D all return the identical string `{"ok":false,"error":"not authorized"}`
on refusal, so a caller cannot use the error text to probe which tier it failed.
`delete_account` returns a bare `false`, which is what it already returned for a wrong
password — a refusal is indistinguishable from a failure there by construction.

The Tier D gate runs **before the arguments are parsed**, and every secret a refused call
carried — a mnemonic, a private key, a vault JSON, a password — is zeroized rather than left
for the allocator. Gating `delete_account` also closes an unmetered password oracle: before,
any module could guess at the vault password there, and a correct guess DESTROYED the account.

An **empty** custodian admits nobody. That is the same fail-closed direction Tier A took
before `evm_signer_ui` shipped: an unconfigured role means the surface that should hold it does
not exist yet, and the capability is then unavailable rather than universal.

**Who sets the roles is itself ungated.** `configure` names both, and nothing stops a caller
naming itself — so Tier D currently keeps an honest deployer's policy rather than enforcing
one against a hostile co-resident module. See [`configure`](#configureconfig_json-string---string).

### Caller identity — live, and what it reports

Caller identity **works**. Measured 2026-08-26 against a `logoscore` daemon built from
master, with `keystore_module` and a purpose-built `caller_probe` module:

| call | `caller_identity()` reports |
|------|------------------------------|
| `logosctl` → keystore | `{"kind":"host","identity":""}` |
| `logosctl` → probe (`current_caller()` directly) | `HostAnchor` |
| **probe module → keystore** (real module plane) | **`{"kind":"module","identity":"caller_probe"}`** |
| **probe → keystore `request_approval`** (Tier B) | **`{"ok":true,"handle":"ksh_…","receipt":"ksc_…"}`** |

Row 3 is the positive path: a named module is named correctly. Row 4 is the **first
end-to-end proof that the tier gate admits a legitimate caller** rather than merely
refusing everyone.

The host now carries the accessor the plugin pulls (`currentCallerJson` present in
`logos_host_qt`, and exactly **one** `logos-qt-host` in the closure), and the
`No such method LogosAPI::currentCallerJson` warning that used to fire on every
dispatch is **gone**. Three defects had to be fixed for this, in this order — the
sequencing is worth keeping because it looked like unrelated work:

1. **qt-host provenance.** `logos-qt-sdk` exported the `logos-qt-host` it was itself
   built against — by propagation, by a baked absolute-store-path `HINTS`, and by
   forwarding headers containing literal `#include "/nix/store/…"`. So the module host
   linked a stale `LogosAPI` with no `Q_INVOKABLE currentCallerJson`, the plugin's
   cross-image `invokeMethod` failed, and the pushed caller document was empty.
2. **The announced origin.** `logos-rust-sdk` hardcoded `"core"` as the origin of a
   module's *outbound* client. `lidl-gen` now emits `LOGOS_MODULE_NAME` from the
   contract and latches it before the install hook. (C++ was never affected.)
3. **Naming the anchor.** `authorize()` enforced "an anchor key is never a module name"
   on the credential store but not on the caller-keyed one, so `"core"` arriving there
   would have been spelled as a module.

**`HostAnchor` is refused at Tier A and Tier B, and that is deliberate.** The CLI now
reports honestly as the host rather than as `unknown`, and is still refused — which is
the intended property, not a gap. The rule does not depend on any past defect:
`"core"` and `"capability_module"` hold **one token value under two keys**, so nothing
presenting it is distinguishable from anything else presenting it. **A tier admitting
`HostAnchor` admits an unbounded set, not a trusted party.** It must not be relaxed on
the reasoning that "the host is trusted anyway".

### Impersonation of the approver: closed upstream

An earlier revision of this document recorded a live exposure: any loaded module could
reach Tier A by naming `signer_ui`, because `capability_module.requestModule` took the
requesting identity as a **plain argument** and checked only that the name was loaded.
**That is fixed** (`capability_module_impl.cpp:77-92`):

```cpp
const logos::LogosCaller caller = logos::currentCaller();
std::string callerName;
if (caller.isHost())                                    callerName = "core";
else if (caller.isModule() && !caller.name.empty())     callerName = caller.name;
else { /* unnamed / unknown / derived / operator -> REFUSE */ return {}; }
if (!fromModuleName.empty() && fromModuleName != callerName) {
    warn("ignoring leftover fromModuleName='%s' (token-bound caller is '%s')", …);
}
```

Three properties matter here, and all three hold:

* The identity comes from the platform's caller document, **not** the argument. The
  argument is dead ABI — it survives only to be warned about.
* It **fails closed** when there is no named caller. A fallback to the argument on an
  unnameable dispatch would have re-opened the hole entirely; there is none.
* The **binding** uses the derived name: the token is delivered as
  `informModuleTokenTo(…, /*moduleName=*/callerName, …)`. `fromModuleName` appears
  nowhere in the binding path.

**Why it is closed in principle, not merely in this code path.** Ignoring the argument
would be worth little if an attacker could instead poison the map the name is recovered
from. It cannot. To be named `Y`, attacker `X` would have to make the naming scan match
`X`'s presented token against key `Y` — and that caller-keyed map has exactly two
writers: the host, which files each module's root token under its real name
(`module_manager.cpp:226`, whose comment states the purpose: *"capability stores
(name, token) so authorize can name the caller from the presented token rather than from
a self-asserted fromModuleName"*), and `capability_module` itself. Writing to it via
`informModuleToken` is gated on the **target's own credential**
(`module_proxy.cpp:413-421`), which no API hands out — `requestModule` returns a fresh
UUID, never the target's token. And the anchor role labels are masked out of the naming
fold (`module_proxy.cpp:332-337`, `out.fold.offer(match & ~isAnchor, …)`), so a caller
filed under `core`/`capability_module` resolves to `Unknown` and is refused rather than
being spelled as a module.

The fail-closed behaviour is pinned by tests, and was contested during development:
`requestModule_rejects_unnamed_caller` asserts an empty result even when
`fromModuleName` names a seeded, loaded module, and
`requestModule_denies_spoofed_fromModuleName` covers the spoof directly. A commit that
added *"fall back when mocks/old hosts omit the caller"* was **reverted** in favour of
simulating identity in the test harness — which is the right call, and exactly the
fallback that would have re-opened this.

Confirmed live — the mechanism firing, verbatim from the daemon log:

```
[capability_module] ignoring leftover fromModuleName='signer_ui' (token-bound caller is 'core')
```

That is a `logosctl` request to be minted as `signer_ui`, overridden to the CLI's real
token-bound identity. Measured in two composing halves: a module's `currentCaller()` is
its own name (row 3 above), and `requestModule` binds to `currentCaller()`, not to its
argument (source, all paths). A forged argument therefore cannot change the binding.

### The access policy is now a real control — with one residual gap

A previous revision of this document said `--access-policy enforce` was **not** a
mitigation, because the policy arm filtered the same self-asserted name. **That is no
longer true** and the correction matters: the allowlist is now consulted against the
derived `callerName`:

```cpp
auto it = m_restrictions.find(moduleName);
if (it != m_restrictions.end() && it->second.count(callerName) == 0) { /* deny */ }
```

The residual gap is documented in the code and is a rollout decision, not an oversight:

> `TODO(access-policy): still fail-OPEN — a target with no registered restriction is
> unrestricted. Intentional for back-compat during rollout.`

So a policy that is *registered* is now enforced against a real identity; a target with
**no** policy remains reachable by any named module.

**Why keystore does not simply register one.** `registerRestriction` is **per-target,
not per-method**. This module deliberately needs a *wide* Tier B (any named module may
*request*) and a *narrow* Tier A (exactly one may *approve*). A blanket allowlist
naming only `evm_signer_ui` would lock out every legitimate requester —
`tx_sender_module` among them. So the tier gate inside this module stays the
mechanism that separates asking from approving, and the access policy is a coarse
complement for deployments that want to bound the requester set. Operators who want
both should register the requester set as the restriction and leave the approver
distinction to the tier gate.

### What identity still does not guarantee

Identity being live changes what the gate can *do*; it does not make the name a
cryptographic fact. Five residuals, each of which bounds a claim this document makes.

**1. The name is *token-bound*, not verified.** `logos_caller_scope.h` says so in its
own words — token-bound is *"the strongest honest word … chosen over 'verified' or
'authenticated' deliberately"*, because the name is the key under which **this module**
recorded the token the caller presented. It is exactly as strong as that recording. It
is not a signature, and nothing here should be read as authentication.

**2. Only the QtRO path yields a caller at all.** Identity is resolved from the
meta-object dispatch. `plain` tcp / tcp_ssl operator tokens carry no name (the validator
returns a bool), and in-process paths do not go through the proxy. Because
`requestModule` now **fails closed** on an unnamed dispatch, a deployment on those
transports does not degrade to a weaker check — it stops working. That is the right
direction for a signer, but it is a deployment constraint, not a detail: **this module
requires the QtRO transport to be usable at all.**

**3. Same-process impersonation is not closed, and this is the one that matters here.**
`TokenManager::isolateIdentity` is idempotent and `LogosAPI::forIdentity` hands back the
*same* store for an already-isolated name, so native code running inside the host
process can obtain another plugin's identity. In Basecamp every `ui_qml` plugin — this
module's approver among them — lives in **one process**. So the Tier A boundary is a
**code-authority boundary enforced by a name, not a process boundary**: it holds against
another *module* (which is a separate process), and it does not hold against hostile
**native code already inside the shell**. An attacker who has that has already won more
than this gate was defending.

**4. A lying `fromModuleName` is warned about, not refused.** `capability_module` logs
*"ignoring leftover fromModuleName=…"* and proceeds. The binding is unaffected — that is
what matters — but there is no counter and no event, so an operator cannot observe
attempts programmatically. Worth a metric upstream.

**5. `registerRestriction` was not converted.** It still authenticates by a
self-presented `authToken` compared against the trust-root tokens rather than by
`currentCaller()`. That is a *secret*, not a name, so it is a different class from the
hole that was closed — but it means the policy-writing path did not move with the
policy-checking path.

One quieter failure mode is worth knowing because it is *not* the one that was fixed:
the `Q_INVOKABLE currentCallerJson` **declaration** is unguarded while its **body** is
`#if`-guarded on protocol ≥ 0.6. Under a sub-0.6 protocol the old symptom would not
reappear as `No such method` — `invokeMethod` would succeed and return an **empty
string**, which collapses to `unknown`. The loud failure is the one that has been fixed;
a silent one remains reachable on an old protocol. And the check that would catch it
(`caller-invokable`, the only one that actually calls `invokeMethod` by name against a
real `LogosAPI`) is exposed as a flake check but is **not wired into CI**, so the
property is not continuously verified.

### What the gate does and does not guarantee

With identity live and impersonation closed, Tier A means what it is meant to mean: the
caller *is* the configured approver package. Two limits remain worth stating plainly.

**`module:evm_signer_ui` names a plugin package, not a human.** A `ui_qml` plugin's QML view
and its `ui-host` backend are one identity by design, and this module cannot distinguish
them — it must not pretend to. What the entry asserts is that *the operator designated
this package as the code permitted to approve*. It does not assert that a human saw
anything, and no token check can make it. (This design routes **all** keystore calls
through the backend, so it is the backend's identity that is checked.)

**Defence in depth is not resting on identity alone**, and this was tested rather than
asserted. While the impersonation hole was open, the design degraded to *intent
disclosure and denial of service* — never to unauthorised signing — because the
properties that stop signing do not depend on who the caller is:

* `approve()` requires the **vault password**, and no signer is cached; impersonating
  the approver does not produce one.
* The single-`Rendered` rule plus the echoed `bundle_id` mean demoting the human's
  render makes their `approve()` **fail**, not misapply.
* `fetch_result`/`ack_result` authorise on the per-request **receipt**, so requesters
  cannot collect each other's signatures even if they share a name.

Those choices are why a premise failure cost confidentiality and availability rather
than integrity, and they should survive any future change to how identity is delivered.

### Lifecycle

```
request_approval ──▶ Offered ──acknowledge──▶ Rendered ──approve──▶ Settled(Approved)
       │                 │                        │           └────▶ Settled(Rejected)
       │                 └──(no ack in 60 s)─────▶ Settled(ExpiredNoAck)
       └──cancel_approval─────────────────────────────────────────▶ Settled(Cancelled)
```

* **`handle` vs `receipt`.** `request_approval` returns both, and the **receipt is
  returned exactly once**. The handle is what the event plane announces (it carries
  no token, so anything richer would publish the intent to every subscriber); the
  **receipt is what authorises collecting the result**. A module that learns a
  handle from the event plane still cannot fetch someone else's signatures.
* **At most one record is `Rendered`.** `acknowledge` demotes any other rendered
  request, so exactly one thing can be on screen — this is what binds the text the
  human read to the `approve` call that follows.
* **The 60 s window is garbage collection, not flow control.** It is on the
  *event* path only: it bounds how long an unacknowledged offer lingers, not how
  long the human has to decide — once acknowledged, there is **no timeout on the
  human**. It was 3 s while the approver was always already open; an app-to-app
  intent puts a shell confirmation and a provider launch in front of the ack, and
  no timer here can tell "nobody is coming" from "someone is coming, slowly".
  Prompt cleanup is the requester's, which knows — it calls `cancel_approval`
  the moment its dispatch fails — and the TTL covers the one case it cannot: its
  own death. Shortening it to chase a crashed *approver* would re-introduce the
  bug; that case is the requester's to report. Being demoted by another
  acknowledge does not put a record back in the window.
* **Settled records are retained** for 120 s so a requester polling `approval_status`
  learns *why* a request ended (`expired_no_ack`, `rejected`, `cancelled`) rather
  than getting `not_found`.
* **Results are idempotent until `ack_result`**, so a dropped reply does not cost
  the human a second password entry.

### `request_approval(intent_json: String) -> String`

**Tier B.** Returns immediately — it does **not** block on the human.

The intent is `{ address, purpose, legs: [...] }`, where each leg is one of:

```jsonc
{ "kind": "tx",         "chain_id": 1, "tx": { …UnsignedTx… } }
{ "kind": "message",    "text": "…" }
{ "kind": "digest",     "digest": "0x…32 bytes…", "purpose": "…" }
{ "kind": "typed_data", "typed_data": { "types": …, "primaryType": "…", "domain": …, "message": … } }
```

A Bitcoin request names a `group` instead of an `address` and carries exactly one leg:

```jsonc
{ "group": "g_…", "purpose": "…", "legs": [ { "kind": "psbt", "network": "regtest", "psbt": "cHNidP8B…" } ] }
```

The keystore reads the PSBT against that wallet before anything is shown, and refuses it whole
on any input it would not sign; see [Bitcoin wallets](#bitcoin-wallets-bip84-bip86). An intent
names exactly one of `address` and `group`, and a `psbt` leg never rides with an EVM leg.

A `typed_data` leg is EIP-712, in the standard's own JSON. It is **not** opaque: the
module parses it with alloy's implementation of the standard, computes the signing
hash itself — never trusting one from the requester — and renders the domain, the
primary type and every field of the message, nested structs and arrays indented
under their field. A document the standard cannot type (a field the declared type
does not have, a missing type) is refused at `request_approval`, before anything is
rendered or committed to, and so is a field carrying a control or bidi character.
The commitment covers the signing hash, so two documents that hash alike commit
alike whatever their key order. The result is the 65-byte signature over that hash
(what Permit2 and the Universal Router take), which `fetch_result` returns like any
other leg's.

A **bundle** of several legs is **one human decision**: all legs are signed, or
none are. `purpose` is requester-supplied and is always rendered as *claimed by the
requester*, never as fact.

```bash
# → {"ok":true,"handle":"ksh_…","receipt":"ksc_…","state":"offered"}
```

Limits: at most 4 pending per requester, 16 total, 64 KiB of intent.

### `approval_status(handle: String, receipt: String) -> String`

**Tier B.** Bare state for the requester — never the intent, never the results.
`{ ok, state, reason? }`.

### `fetch_result(handle: String, receipt: String) -> String`

**Tier B.** Collect the signatures: `{ ok, signed: [ … ] }`, one entry per leg in
request order. Idempotent until `ack_result`. For a `psbt` leg the entry is the PSBT, base64,
with this wallet's signatures added and its unsigned transaction untouched.

### `ack_result(handle: String, receipt: String) -> bool`

**Tier B.** The requester has the signatures; erase them.

### `cancel_approval(handle: String, receipt: String) -> bool`

**Tier B.** The requester gave up.

### `pending() -> String`

**Tier A.** Queue **summaries** — never leg detail. `{ ok, pending: [...] }`.

### `acknowledge(handle: String) -> String`

**Tier A.** Claim a request for display:
`{ ok, handle, bundle_id, requester, claim_lines, render_lines }`.

The lines come in **two lists an approver must not merge**. `claim_lines` is the
requester's own account of what the request is for — its text, carried for the human
and worth nothing as evidence. `render_lines` is what is actually signed, plus the
commitment over it. The split is structural rather than a prefix an approver could
drop, and it is made here because this module is the only party that parsed the
intent. `requester` is authoritative: it is the caller's identity, not a field it
filled in.

`render_lines` are authored **by this module** from the parsed intent and **must be
displayed verbatim** — not reformatted, elided, truncated or re-ordered. keystore is
the only party that parsed the intent and therefore the only one that can tell
requester-supplied text from its own; it escapes control characters, bidi controls
and zero-width characters before they enter a line.

A transaction leg shows the fee it signs: the max fee and max priority fee per gas (or the
legacy gas price), read by the parser signing uses, in wei and gwei, and `Fee at most`, the gas
limit times that price. A zero priority fee is flagged, and so is a fee signing would refuse.

The full calldata is always shown in full and **never elided**. A `digest` leg
renders an explicit admission that the signer cannot show what it authorises; a
`typed_data` leg shows the whole document instead, and its signing hash beside it.

### `approve(handle: String, bundle_id: String, password: String) -> String`

**Tier A.** The human said yes. `bundle_id` must be the value that was displayed;
a mismatch is refused. The intent is **re-parsed and the commitment re-derived
inside this call** before anything is signed, so what is signed is what was
committed to.

One key derivation, every leg signed, then wiped → `{ ok, signed_count: n }`.

**The approver never receives what it authorised.** `approve()` answers with a
**count**, not the signatures. Only the requester can collect those, and only
with the receipt it was handed at request time — so a compromised approver can
cause a signature to exist but cannot walk away with it. That is also why this
field is named differently from `fetch_result`'s `signed` array: the two must
never be mistaken for one another.

**At most once per handle:** a second `approve` for a handle that has left
`Rendered` returns the recorded outcome and never re-signs. Because a scrypt
derivation runs inside the call, callers must use an async entry point with a
timeout comfortably above worst-case KDF — a dispatched call that times out still
executes here.

The `bundle_id` is SHA-256 over this module's **own canonical re-encoding** of the
parsed intent — deliberately **not** keccak256, so a bundle id can never be
mistaken for a signable Ethereum digest.

### `reject(handle: String) -> bool`

**Tier A.** The human said no.

### `caller_identity() -> String`

Ungated observability: `{ ok, kind, identity, approvers, custodians, managers }` where `kind`
is one of `unknown` | `host` | `module` | `derived` | `operator`.

`approvers`, `custodians` and `managers` are the names currently in force — the built-in
defaults, or whatever `configure` last set. They are everything a total `configure` has to
repeat: a document built from the first two alone would leave the manager unable to sign. An **empty** list means that role is held by nobody and every
method of its tier refuses, which is what this field exists to make visible. (It used to
carry a `configError` naming an unreadable `keystore.json`; there is no config file any
more, so that state cannot occur and the field is gone.)

### Events

The module declares a typed event contract:

```rust
pub trait KeystoreModuleEvents {
    fn accounts_changed(&self, count: i64);
    fn approval_offered(&self, handle: String);
    fn approval_settled(&self, handle: String, state: String);
}
```

`accounts_changed(count)` is emitted (via the generated `emit_accounts_changed`)
**after every mutation that changes what a reader displays** — the account set
(`import_mnemonic`, `derive_next_account`, `derive_account_at`,
`create_unrelated_account`, `import_private_key`, `import_keystore_json`,
`delete_account`) and equally the names and wallets it is displayed under
(`set_label`, `set_group_label`, `remove_group`, `forget_derivation`,
`remove_unexplained`, `settle`). Only on the success path: a refusal changed
nothing. `change_password` is deliberately silent — it re-encrypts a vault and moves
nothing any reader shows.

`count` is ADVISORY, not a change detector: a rename does not move it, so a
subscriber that diffs counts sees nothing and must re-read. It is the total vaults
(`Keystore::list_accounts()?.len()`), or **`-1` for "unknown"** when that listing
failed. `-1` is not `0`: reporting a keystore we could not read as an empty one is
exactly the defect removed from the layer below, and a subscriber that treats -1 as
0 reintroduces it. Subscribers (`evm_keystore_ui`, and `eth_wallet_backend`, which relays
it to the wallet view) re-read their account list on it instead of polling. All event
params are std-typed (`i64`, `String`).

`approval_offered` announces that a new request is waiting, and carries the **handle
only** — the event plane has no token, so a richer payload would publish the intent to
every subscriber (see *`handle` vs `receipt`* above). `approval_settled` announces that
one reached a terminal state, with `state` being `approved` or `rejected`. The other two
terminal states in the lifecycle above, `expired_no_ack` and `cancelled`, are **not**
announced — nothing emits for them, so a subscriber waiting on a settlement event for a
request the human never saw waits forever. Poll `approval_status` for those.

The rule is held by `rust-lib/tests/every_displayed_mutation_announces_itself.rs`,
which reads `glue.rs` and fails if a listed mutator's success path stops emitting —
the silent `set_label` that left the wallet showing a renamed account under its old
name was exactly that.

---

## Configuration & data model

### Module manifest (`metadata.json`)

| Field | Value | Notes |
|-------|-------|-------|
| `name` | `keystore_module` | Module id used by `logosctl`/`lgpm` |
| `version` | `1.0.0` | |
| `type` | `core` | Core (non-UI) module |
| `interface` | `cdylib` | Rust-first cdylib module |
| `category` | `wallet` | |
| `main` | `keystore_module_plugin` | Plugin entry name |
| `dependencies` | `[]` | **Leaf** — no module deps |
| `capabilities` | `[]` | Declares no capability requirements |
| `codegen.rust` | `{ crate: "rust-lib", trait: "KeystoreModule", source: "src/glue.rs" }` | The contract source for the builder's code generator |
| `nix` | empty `external_libraries` / `packages` / `cmake` | No external system libs — the crypto is pure-Rust crates |

There is **no `concurrency` field**, so the keystore runs in the **default
(single-handler) dispatch mode** — calls are processed one at a time. (Contrast
with `eth_rpc_module` / `uniswap_module`, which set `concurrency: "multi"`.) See
[Concurrency](#concurrency).

### Persistence location & on-context-ready

On `on_context_ready(ctx)` the glue computes the keystore directory as
`ctx.instance_persistence_path / "keystore"` and constructs `Keystore::new(dir)`.
Until that hook runs, `self.ks` is `None` and `String`-returning methods report
`keystore not initialized (context not ready)` while bool methods return `false`.
The `instance_persistence_path` is supplied by the Logos runtime
(`RustModuleContext`), so each module instance gets its own isolated vault
directory.

**Nothing is read from that directory as configuration.** It is owned by the module
instance and may be sandboxed away from every other process, so nothing outside can be
relied on to write there — and it does not exist until this module has written to it.
The two role names arrive by method call
([`configure`](#configureconfig_json-string---string)); everything else the module needs it
either defaults or computes.

### Directory layout

`rust-lib/src/layout.rs` is the single authority for **every path this module may
write**, and for the classification of everything found under the keystore
directory. `Slot` is the only path builder and `Slot::rel` matches exhaustively, so
a new path does not compile until it has been named; the scan is total, so a path
that arrives by any other route is still reported rather than dropped.

Two properties make that total rather than nearly total:

* **`Root` is the only source of a path, including a temporary one.** A writer that
  never *asks* for a path is not bound by "a new path must add a variant", and
  `import_keystore_json` was exactly that: it took `std::env::temp_dir()`, so the
  caller's ciphertext sat in a shared directory under a name no authority here could
  reach and no restart ever swept. Scratch space is now a `Slot` like anything else,
  and a unit test reads this crate's own source to assert nothing else can mint one.
* **The classifier is total over ENTRIES, not over files.** Every entry reaching it
  carries its kind — file, directory, symlink, socket — and a name recognised for one
  kind is unexplained for the other three. A directory that is not recognised used to
  be invisible, so an **empty directory** at `groups/<id>.json` was reported by
  nothing at all.

| Path | What it is |
|------|------------|
| `a_<32 hex>.json` | one account's scrypt vault, named at random; older builds named it `<addr>.json` |
| `groups/<id>.json` | one group's derivation key |
| `groups/<phrase id>.json` | a kept recovery phrase, when the person chose to keep one |
| `groups/<device id>.json` | a device wallet's database key, once it was opened for an app |
| `index.sealed.json` | every seed's records, accounts and names, one box per seed under its key |
| `index.pending.json` | the same, plain, for seeds whose key hasn't come yet |
| `seeds.json` | what a locked seed needs: its unlock roots, its files' ids, its check |
| `device-wallets.json` | which device account each database-key vault belongs to |
| `groups.json`, `accounts.json`, `labels.json`, `group-labels.json` | an older build's bookkeeping, moved into the index on first use |
| `.stage-<vault id>/` | an account vault mid-write |
| `groups/.stage-<id>/` | a derivation key, a kept phrase, or a device wallet's database key, mid-write |
| `.stage-import-<nonce>/import.json` | the caller's vault, mid-`import_keystore_json` |
| `.ks-stage-*` | a document mid-write (random name, so two processes cannot collide) |
| `.lock` | cross-process exclusion for the bookkeeping read-modify-write |

Anything else is **unexplained**, and reported by `list_accounts` whatever its
severity.

**Exactly one refusal is left in the scan, and it is about the report's honesty.** An
unreadable **root** means the scan saw nothing at all, and answering "no accounts" to
someone holding a funded wallet is a lie rather than a gap — so it fails as `Corrupt`.
Every directory *below* the root is reported when it cannot be read (as *possible key
material*, since a key could be inside) and the rest of the keystore is still answered.
`groups/` used to refuse there too, which meant one unreadable directory made the store
unlistable, unsignable and unrepairable at once — `remove_unexplained`, the way out, went
through the same scan. That was the wedge, and it was only ever load-bearing for the mint
guard that no longer exists.

#### Possible key material

The two severities are **a judgement about the material, never about the directory
holding it**. They are a REPORT: since the acknowledgement became the safety property,
nothing refuses on them, and the split is what a reader is shown. Without a password the
evidence is:

* its **name** — `g_<32 hex>.json`, a bare `g_<32 hex>`, or `.stage-g_<32 hex>`: a
  name this module could only have written for a derivation key;
* its **bytes** — a Web3 Secure Storage vault, which is the shape of an account key
  and a derivation key alike, and telling the two apart needs the password;
* whether it could be **looked inside at all** — a directory that cannot be
  enumerated, or one deeper than the layout explains, is not an empty one.

Sitting under `groups/` adds to that and never subtracts. Keying the split on that
prefix alone was a defect: the same 594-byte vault one directory over
(`groups.bak/g_<id>.json`, `.stage-g_<id>/g_<id>.json`, an unreadable directory, or
renamed to `k.json`) was described by the scan and ignored by the decision that read it.
Nothing reads it as a decision any more, which is why it no longer has to be complete to
be correct — and why a stray path can be reported without wedging the store.

The **use path asks the same authority**. `signer_for`, `has_address`,
`delete_account`, `open_group_key` and every `derive_*` resolve through the scan
rather than through `Path::exists`, which follows symlinks — so material can no
longer be live and signable while the wallet reports it absent. If the authority does
not name it, using it is refused and `remove_unexplained` names it instead.

Staging directories are named after what they hold rather than randomly, so a copy
a SIGKILL leaves behind is nameable, and therefore classifiable and deletable. A
`.stage-<addr>` holding a vault is settled on the next read: **promoted** when the
real vault is gone (it is the only copy of that key, and it goes through the same
`check_kdf_params` ceiling first) and **reaped** when the real vault is present
(`change_password` only reaches staging after the old vault has been proved
intact). `.stage-import-<nonce>` is swept, never promoted: the vault it was being
re-encrypted into either landed or did not. A `.ks-stage-*` document is reported but
never reaped — a peer mid-write holds an open descriptor on one.

The sweep runs as a side effect of listing **and** by name, as `settle()`. Anything
it cannot explain is removable by name too, with `remove_unexplained()` — including a
`groups/` that turned out to be a symlink, which is refused at the write (a key
through it would land outside the keystore, where no scan of it could ever name what
landed) and reported with its destination.

### Concurrent access

Mutations of the sidecars take an exclusive `flock` (`LockFileEx` on Windows, where
it is mandatory rather than advisory) on `<keystore>/.lock` for the duration of one
read-modify-write. Without it, two processes each adding an account both read, both
insert, both rename, and one record is lost. It is a **refusal, not a wait**: after
a second it gives up and says which lock it could not get, because blocking behind a
hung peer while a user waits on a wallet is worse than a legible refusal. It is
never held across a scrypt derivation, and never nested (`std` documents that
re-locking one file from a single process may deadlock, so nesting is a hard error).

Note this guards the keystore *directory*, which is separate from a runtime
single-instance guard: two `logoscore` daemons with different `--config-dir` values
can still point at one absolute data directory.

### On-disk vault files

* **One file per account**, named at random: `a_` + 16 random bytes in hex, e.g.
  `a_3f0c1d9e8b7a6f5e4d3c2b1a09f8e7d6.json`. Which account it is, is in the index (below).
  An older build named it by its address; the first use moves it to a random name.
* Each file is a **scrypt-encrypted keystore JSON** (Web3 Secure Storage format)
  produced by `eth-keystore::encrypt_key`. The 32-byte secp256k1 private key is
  the encrypted payload; the password is the scrypt secret.
* No vault is decrypted to enumerate accounts. Enumeration is one scan of the
  directory (below), not a name-pattern filter with a silent else.
* **Written staged-then-renamed**, like the group key. `eth_keystore::encrypt_key`
  is one `File::create` straight to its destination — its whole public surface is
  path-based, there is no encrypt-to-string — so an in-place write leaves a window
  where a crash TRUNCATES the live vault. The only handle on that write is the
  directory it writes into, so the module encrypts into `.stage-<vault id>/` inside the
  keystore directory (one filesystem, so the rename is atomic) and renames out. The
  file is chmod 0600 while still inside the 0700 stage, so it is never briefly
  world-readable at its real path.
* **`groups/<group-id>.json`** — one scrypt vault per **derivation group**, holding
  that group's account key `m/44'/60'/<account>'` as base58 `xprv…` text. Present
  only for `storage: "extkey"` groups. Written staged-then-renamed (like
  `change_password`, unlike `persist_signer`): `encrypt_key` writes through
  `File::create` at the default umask, so restricting afterwards would leave a
  window at 0644 at the real path. Directory 0700, file 0600. Its KDF parameters
  are checked (`check_kdf_params`) before decryption, because it is still a file on
  disk that a local attacker can swap for a scrypt bomb.
* **The index** — wallet records, account records and both kinds of name, one document per
  seed; see *The sealed index*. Read through **ungated** methods, for the seeds unlocked in
  this process. It never contains a phrase, a passphrase or a key.
* The group id is `g_` + 16 random bytes in hex. Deliberately **not** the extended
  key's fingerprint, which is public-key-derived and would be a stable cross-machine
  correlator for the same phrase. It is validated as an id before it reaches the
  filesystem, so it cannot escape the keystore directory.
* One honest admission: the *existence* of `groups/<id>.json` tells an attacker with
  the directory which wallet is worth cracking. That is unavoidable — the file must
  exist for the feature to exist.

### The sealed index

What older builds kept in four plain documents, and in the vault filenames, says which
accounts and wallets this keystore holds: addresses, xpubs, derivation paths, names. It now
lives one document per **seed**, each sealed (XChaCha20-Poly1305) under this module's key for
that seed from the signer manager, `data_key(seed, "index")`. The manager gives that key once
the person unlocks the wallet in the Signer app, and the module forgets it when the wallet
locks, so **a locked wallet's accounts are not listed**: not by `list_accounts`, `list_groups`
(which counts them as `lockedWallets` and names them as `lockedSeeds`, by the keystore's own
names for them, for an app's `wallets.unlock` with `signer: "keystore_module"`), `get_provenance`,
`get_labels`, `kept_phrases`,
`list_derivation_keys`, nor the account the keystore offers the manager. Its vaults and keys are
not unexplained or stranded either: `remove_unexplained`, `forget_derivation` and `forget_phrase`
refuse them until it unlocks.

* **`index.sealed.json`** — `{ v: 1, seeds: { <seed>: <box> } }`, 0600, the box format of
  `logos.wallets/1`, bound to `keystore_module index` and the seed. Opened with the key of its
  box's generation and sealed again under the current one.
* **`seeds.json`** — plain, and only what a locked seed needs: each group's sealed unlock root
  (so `unlock_key` answers behind the wallet's password while it is locked), the random ids of
  its vaults, keys and kept phrases, and a check of its unlock key, salted by the seed's id. The
  check finds a seed that is here and locked when the same phrase or key is imported again, which
  is refused ("unlock it in the Signer app first") rather than made a second wallet. It is over a
  key that is never public, so it can't be tested against addresses on a chain.
* **`index.pending.json`** — a seed's document before its first key: just added (the manager
  enrols and unlocks it, and the module seals it within a second), or kept by a keystore with no
  signer manager (the CLI, the tests), where it stays plain as before. `""` holds entries no seed
  claims, such as a stranded key's name.

The module asks for its keys from threads of its own, on the manager's `wallets_changed` and
`wallets_locked`, never inside a call the manager made, and announces `accounts_changed` when a
wallet opens or locks. **A trade-off:** a vault's name no longer says whose it is, so an
unreadable index refuses signing until it is repaired; the keys themselves are untouched in
their vaults.

**From an older build.** On first use the four documents move into the index (pending until
each seed's key comes), every address-named vault takes a random name, and the documents go.
Each step can be repeated, so a crash part-way finishes on the next start. A key imported on its
own takes a new `k_` seed, which the manager learns when it is next enrolled.

### Three states, not two

Every JSON this module reads has **three** states, and they must stay distinct:

| State | Meaning | Behaviour |
|-------|---------|-----------|
| **absent** | nothing configured yet | treated as empty — the green-field path |
| **present and readable** | its contents | used |
| **present and unreadable** | I/O error, truncation, malformed JSON, wrong schema | **refuses**, as `KeystoreError::Corrupt` |

Collapsing the third into the first is how a guard fails open. `get_groups` used to
do exactly that (`.ok().and_then(…ok()).unwrap_or_default()`), and the guard that used
to stop an unrecoverable key being minted beside an HD wallet read the result — so
truncating `groups.json` turned the refusal off. That guard is gone, but the rule it
depended on stands on its own: `persist_signer` reads `groups.json` and `accounts.json`
before **any** vault lands, so no key reaches disk with no record of where it came from.
No attacker is needed; a crash or `ENOSPC` mid-write reaches that state on its own.

Four reads had that shape, and all four now refuse:

| Read | File | What treating it as empty would have said |
|------|------|-------------------------------------------|
| `Keystore::get_groups` | the index | "no wallets here" → a vault lands with no provenance, and `list_groups` hides a live wallet |
| `Keystore::get_provenance` | the index | "this account came from nowhere" |
| `Keystore::get_labels` | the index | "no names" → the next `set_label` erases them all |
| `Keystore::get_group_labels` | the index | "no wallet names" → the next `set_group_label` erases them all, and every wallet frame falls back to an address that moves |

A fifth read used to sit in this table: `on_context_ready` read the role names from
`<persistence>/keystore.json`, and an unreadable one emptied both roles rather than
reverting to defaults. That read is gone — the roles arrive by
[`configure`](#configureconfig_json-string---string) — and with it the whole class: a call
either parses or is refused, and a refused one changes nothing.

**Writes are staged and renamed.** `write_json` writes `<name>.json.tmp`, `sync_all`s
it, restricts it to 0600 and renames it into place, so a crash or a full disk leaves
the previous file intact rather than a truncated one. The same rule `write_group_vault`
and `change_password` already followed.

**The file is a cache; the material is the authority.** `list_derivation_keys` names a
`groups/<id>.json` that no record names — deleting `groups.json` outright is legitimately
"empty", and the key is still right there, so it stays nameable and therefore deletable.
`nextIndex` is the same principle stated for indices (see [Index tracking](#index-tracking)).

### In-memory state

```rust
pub struct Keystore {
    dir: PathBuf,     // that is the whole of it — no signer cache
}
```

**Unlocked keys live in one place: `signer::Unlocks`.** An unlock the manager asked for holds the
account's private key, or a Bitcoin wallet's account key and database key, in a buffer locked into
RAM where the system allows it (`mlock`, `VirtualLock`), and on Linux the process stops writing core
dumps once one exists. The buffer is wiped when the unlock ends: on its time or count, on `lock`,
on a password change, or when the account is deleted. Each signature rebuilds the key from it for
that one call. Nothing about an unlock is written to disk, and a restart locks everything. The
signer interface's job table holds signatures, never keys, and forgets them ten minutes after a
job settles.

**Outside an unlock there is no signer cache, by construction.** A decrypted key exists only
as a local inside `approve()`: derived from the vault password, used to sign every
leg of the bundle, then zeroized (`Zeroizing` wraps the password, the derived key
and the signer's key bytes) before the call returns. Nothing outside that call
frame can reach a key, so there is no TTL to get wrong and no "unlocked forever"
state to leak — the defect this design replaced was exactly an `unlock` that passed
`ttl: None` and therefore never expired.

The only cross-call state is the approval ledger (`approval.rs`), which holds
intents, render text and — briefly — signed *outputs*, never keys.

**Seed and extended-key material is bounded the same way.** A BIP-39 seed exists only
as an `hd::Seed`, which zeroizes on drop — so every path that builds one wipes it,
including the error paths, because nothing else ever owns it. A group's extended key
is decrypted for one call and dropped with it; there is no cached `XPriv`.

**Residual, named rather than papered over:** `coins-bip32`'s `XKeyInfo` is `Copy`
and holds an un-zeroized 32-byte `ChainCode`, so each derivation step leaves chain-code
copies in memory, and `coins-bip39::to_seed` builds two heap strings of its own (the
phrase, and `"mnemonic"` + passphrase) which it does not wipe. A chain code alone is
not a key; a chain code plus any child private key is the parent xprv.

### Unsigned-transaction JSON (`UnsignedTx`)

The `tx` object of a `tx` leg (and the transaction the human is shown)
deserializes into:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `to` | string? | `null`/empty → contract `Create` | recipient address; empty/absent ⇒ contract creation (`TxKind::Create`) |
| `value` | string | `"0"` | wei value (hex `0x…` or decimal), parsed as `U256` |
| `nonce` | string | (required field) | account nonce (hex/decimal `u64`) |
| `gas_limit` | string | `"0"` | gas limit (`u64`) |
| `data` | string | `""` | calldata hex (`0x…`), parsed to `Bytes` |
| `fee_mode` | string | `""` → EIP-1559 | `"eip1559"` (default) or `"legacy"` (case-insensitive) |
| `max_fee_per_gas` | string | `"0"` | EIP-1559 only (`u128`) |
| `max_priority_fee_per_gas` | string | `"0"` | EIP-1559 only (`u128`) |
| `gas_price` | string | `"0"` | legacy only (`u128`) |

Numeric parsing accepts `0x`/`0X` hex or plain decimal; empty strings parse to `0`
/ `U256::ZERO`.

Example (EIP-1559, the one used by the doc-test's `tx.json`):

```json
{
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "0xde0b6b3a7640000",
  "nonce": "0x0",
  "gas_limit": "0x5208",
  "max_fee_per_gas": "0x77359400",
  "max_priority_fee_per_gas": "0x3b9aca00",
  "fee_mode": "eip1559"
}
```

---

## Build, run & test

### Build

```bash
# Crypto core only — no Logos runtime, no generated scaffold needed.
cd rust-lib && cargo test --no-default-features

# Full module (Qt plugin) + installable .lgx package, via nix.
nix build .#install   # → result/modules/keystore_module/
nix build .#lgx       # → result/*.lgx
```

The `flake.nix` is ~15 lines: it delegates to
`logos-module-builder.lib.mkLogosModule { src; configFile = ./metadata.json; … }`,
which reads `metadata.json`, runs the Rust code generator on the `KeystoreModule`
trait, injects the generated scaffold at the `include!(.../generated/provider_gen.rs)`
point in `glue.rs`, and compiles the `staticlib` into the Qt plugin. `CMakeLists.txt`
is the thin bridge (`logos_module(NAME keystore_module)` via `LogosModule.cmake`).

The crate is `crate-type = ["staticlib", "rlib"]` with `resolver = "3"` and
`rust-version = "1.89"` so the MSRV-aware resolver picks dependency versions that
compile under the builder's `rustc 1.89`. The Logos SDK
(`logos-rust-sdk`) is an **optional** dependency enabled by the default
`logos_module` feature, so `cargo test --no-default-features` builds the crypto
core in isolation without the SDK or generated scaffold.

### Run / drive via `logosctl`

The module is loaded into a headless `logosctl` daemon and called over IPC.
End-to-end, as the doc-test does it:

```bash
# 1. Build logosctl + lgpm from their flakes
nix build 'github:logos-co/logos-logoscore-cli#cli' --out-link ./logos
nix build 'github:logos-co/logos-package-manager#cli' -o lgpm

# 2. Build this module's .lgx, seed the capability module, install
nix build '.#lgx' -o keystore-lgx
mkdir -p modules && cp -RL ./logos/modules/. ./modules/   # bundled capability_module
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file keystore-lgx/*.lgx

# 3. Start the daemon, load, and drive
logosctl --config-dir . daemon start --detach
sleep 3
logosctl module load keystore_module
logosctl module show keystore_module        # note: no unlock/sign_* methods exist
logosctl call keystore_module caller_identity          # → {"kind":"host", ...}
logosctl call keystore_module list_accounts            # ungated read

# Tier D is UNREACHABLE from the CLI too: it is the host anchor, not a named module,
# and admitting it would make `logosctl call` a legal way to import a key.
logosctl call keystore_module create_mnemonic 12                # → {"ok":false,"error":"not authorized"}
logosctl call keystore_module import_private_key <privkey> pw   # → {"ok":false,"error":"not authorized"}

# Mutation goes through a configured custodian — here the doc-test's fixture
# (doctests/custodian-probe). configure is TOTAL, so the approver is restated.
logosctl call keystore_module configure '{"approvers":"evm_signer_ui","custodians":"keystore_custodian"}'
logosctl module load keystore_custodian
logosctl call keystore_custodian import_key <privkey> pw        # → {address}
logosctl call keystore_module list_accounts                     # now lists it

# Tier A and Tier B are UNREACHABLE from the CLI, by design:
logosctl call keystore_module pending                  # → {"ok":false,"error":"not authorized"}
logosctl daemon stop
```

The bundled `capability_module` (shipped with `logosctl`) handles the load-time
auth handshake, which is why it is seeded into `./modules` before installing this
module.

Outside the doc-test the custodian is `evm_keystore_cli`
([logos-co/logos-evm-keystore-cli](https://github.com/logos-co/logos-evm-keystore-cli)),
which relays every Tier D method under its own identity with the keystore's own
names and parameters — so the admitted spelling of the refused line above is
`logosctl call evm_keystore_cli import_private_key <privkey> pw`, after a
`configure` that names it custodian.

### How the doc-test exercises it

`doctests/keystore-module-runtime.test.yaml` (rendered to
`doctests/outputs/keystore-module-runtime.md`, run by `doctests/run.sh` and CI in
`.github/workflows/doctests.yml` on `ubuntu-latest` + `macos-latest`) runs the
flow above end-to-end. It is **fully offline and deterministic**: it uses
Foundry's canonical test mnemonic / account 0
(`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, private key
`ac0974…ff80`) and asserts:

* `create_mnemonic 12` output contains `phrase`;
* `import_private_key` returns the expected address (`f39Fd6e51aad…`), proving the
  key stayed inside while only the address came out;
* `list_accounts` then contains that address;
* `caller_identity` reports `"kind":"host"` — the CLI is the host anchor, named
  honestly;
* every Tier A / Tier B method refuses the CLI with the identical
  `{"ok":false,"error":"not authorized"}` — asserted rather than assumed, and now
  for the *right* reason: the caller is named and is not admitted, rather than
  unnameable.

Signing cannot be exercised from `logosctl` — that is the point, and it is the
property to guard. The **Tier B** half of the positive path is now reachable
headlessly, since a named module calling `request_approval` is admitted and gets a
handle and receipt (measured). The **Tier A** half still needs a real approver
plugin, so the full request → acknowledge → approve → broadcast proof remains a
**Basecamp** doctest — not because `logoscore` cannot name callers (it can), but
because `approve()` requires a human at a rendered surface, and `ui-host` is a
`QCoreApplication` that cannot face one.

The CI workflow resolves the commit under test and passes
`--release-for logos-evm-keystore-module=<sha>` so the spec's `{release}`
placeholder builds the PR's own code, then publishes a two-column HTML report to
GitHub Pages.

### Exported symbols

On macOS and Linux the plugin exports only `qt_plugin_instance` and
`qt_plugin_query_metadata_v2`, as it does on Windows (`exports/`, applied in `CMakeLists.txt`).
Without the list it exported about 7,000 symbols, the Rust core's and the statically linked
SDK's among them, and rust-bitcoin added libsecp256k1's 69 C functions.

```bash
nix build .#lib && nm -gU result/lib/keystore_module_plugin.dylib   # 2 symbols
```

### Regtest proof (Bitcoin)

`tools/regtest` is its own crate and lock, so BDK never enters the module's build. It starts a
regtest `bitcoind`, builds a BDK wallet from the keystore's descriptors, funds it, has BDK build
a send, and runs it through `request_approval`, `acknowledge`, `approve` and `fetch_result`. It
checks the fee line against BDK's fee, that a forged change output is shown as a send, that a
false input amount is refused (native segwit) or produces a signature `bitcoind` rejects
(taproot), and that `bitcoind` accepts and mines the honest send, for both families.

```bash
cd tools/regtest
BITCOIND_EXE=$(nix build nixpkgs#bitcoind --no-link --print-out-paths)/bin/bitcoind cargo run --release
```

### Unit tests (crypto core)

`rust-lib/src/keystore.rs` carries `#[cfg(test)]` tests runnable with
`cargo test --no-default-features`, covering:

* `hd_derivation_matches_known_vector` — BIP-44 derivation of accounts 0/1 from
  the Foundry mnemonic matches known addresses.
* `private_key_import_matches_address` — imported PK yields the expected address.
* `create_mnemonic_lengths` — 12/24 words succeed, 13 fails.
* `vault_roundtrip_and_listing` — import → `has_address`/`list_accounts`.
* `every_on_disk_state_of_an_account_vault_answers_the_same_questions` — the
  account half of the state table: thirteen on-disk states, each asserting what
  `list_accounts`, signing, `change_password` and `delete_account` do, that every
  path holding a live key is either at its real path or named in the report, that a
  wrong password never signs, and that no state stops the keystore working.
* `every_path_this_module_writes_is_classified` — drive one of every public
  mutation, then walk the result: nothing unexplained, nothing staged, nothing left.
* `every_shape_a_crash_can_leave_behind_is_reported` — the other half: a leftover
  document stage, the old `groups.json.tmp`, the old `.rekey-<addr>/`, a hand-placed
  backup, a directory where a vault belongs, a symlink. None may vanish.
* `re_encrypting_a_vault_replaces_it_atomically_rather_than_truncating_it` — a
  reader holding the old vault still reads it whole after a re-encryption, which is
  only true of a rename.
* `an_unreadable_keystore_directory_is_refused_rather_than_reported_as_an_empty_wallet`
  — and its counterpart
  `an_unreadable_directory_below_the_root_is_reported_rather_than_refusing_the_scan`,
  which is the wedge this round removed.
* `a_stray_path_is_reported_and_wedges_nothing` — an unreadable `groups/`, an unreadable
  directory at the root, a vault-shaped file under a name that says nothing, and a plain
  `.DS_Store`: each is reported by name, each leaves listing, signing, `settle` and an
  acknowledged account working, and each is removable by name.
* `there_is_no_unlocked_state_to_reuse` — the structural guarantee: nothing
  survives a signing call that a later caller could reuse.
* `sign_message_recovers_signer` — EIP-191 signature recovers to the signer.
* `a_wrong_password_cannot_sign` — the password is the only key to the vault.
* `nonce_that_overflows_u64_is_rejected_not_truncated`,
  `unknown_tx_fields_are_rejected`,
  `absent_to_is_refused_rather_than_deploying_a_contract`,
  `an_access_list_is_refused_rather_than_silently_dropped`,
  `fee_mode_is_a_closed_set_and_is_trimmed` — the parser refuses what it cannot
  faithfully render, instead of silently dropping or truncating it.
* `sign_message_refuses_text_that_renders_differently_than_it_signs` — no bidi,
  control or zero-width characters may enter a rendered line.
* `hostile_kdf_params_are_rejected_before_any_derivation`,
  `the_vault_directory_and_files_are_not_group_or_world_readable`,
  `importing_a_vault_leaves_no_temp_copy_behind`.

**HD derivation** (`rust-lib/src/hd.rs`, pure — no I/O, no runtime). Every expected
value is from a published document, not from `coins-bip32`: a derivation that agrees
only with itself is exactly the bug that makes funds unrecoverable elsewhere.

* `bip32_published_vectors_reproduce_exactly` — BIP-32 test vectors **1, 2 and 3**
  from the BIP-32 document, every listed chain, compared as serialized `xprv`
  strings so the version bytes are covered too. Vectors 2 and 3 are not optional:
  vector 1's root is verbatim the crate's own doc-string, so a suite containing only
  it is the crate agreeing with itself.
* `bip39_published_vectors_reproduce_seed_and_root` — eight rows of the reference
  BIP-39 vector set (12/18/24 words), asserting the 64-byte seed **and** the root
  xprv with passphrase `"TREZOR"`.
* `ethereum_addresses_at_consecutive_indices_match_the_published_keys` — four
  consecutive Anvil accounts, plus the private key at index 0, which is the anchor
  tying the path to a *published key* rather than to our own arithmetic.
* `a_bip39_passphrase_yields_a_completely_different_wallet` — a disjoint tree, and
  a trailing space in the passphrase is a different wallet again.
* `bip44_hardens_purpose_coin_and_account_and_nothing_below` — moving the hardening
  by one level in either direction yields a different key.
* `an_account_key_reaches_every_index_under_it` /
  `an_account_key_cannot_reach_another_bip44_account` — the two halves of the
  `extkey` blast-radius claim, made executable rather than prose.
* `a_stored_account_key_is_an_xprv_never_a_zprv` — invisible in every address-level
  test: the key bytes are identical and only the four version bytes differ.
* `a_root_extended_key_is_refused_where_an_account_key_is_expected`.
* `paths_that_would_derive_something_plausible_and_wrong_are_refused` — the `m`-anywhere
  trap, the `2^31` hardening overflow, a missing root marker, another coin, hardening
  in the wrong place, and the wrong number of levels.
* `a_non_ascii_bip39_passphrase_is_refused_rather_than_silently_diverging`.
* `an_empty_passphrase_derives_what_the_pre_hd_import_derived` — accounts imported
  before this feature existed must not move.
* `seed_material_is_wiped_on_success_and_on_every_error_path` — a thread-local drop
  probe, so the wipe is observed rather than assumed, without reading freed memory.

**Groups and provenance** (`rust-lib/src/keystore.rs`):

* `an_extkey_group_derives_the_next_accounts_without_the_phrase` — and what is
  stored is an account key at depth 3, not the root.
* `the_only_door_to_a_random_key_requires_an_acknowledgement` — on an empty keystore,
  a derivable wallet and a plain one alike: the refusal says what an unrelated account
  IS, creates nothing, and the acknowledged call always succeeds.
* `the_only_random_key_in_this_crate_is_the_acknowledged_one` — reads this crate's own
  production source and asserts `PrivateKeySigner::random()` appears only in `ack.rs`.
* `a_plain_group_cannot_derive_and_says_so` — and re-importing the phrase with the
  key kept derives the **same** addresses, which is what makes that an honest offer.
* `the_derivation_key_never_reaches_a_different_bip44_account`.
* `a_deleted_index_is_retired_and_never_reused`.
* `the_next_index_is_recomputed_from_the_recorded_accounts` — a corrupted cache can
  skip, never collide; and an index occupied by a raw-key import is walked past.
* `preview_writes_nothing_and_marks_what_is_already_held`.
* `a_wrong_group_password_derives_nothing` — and does not destroy the key.
* `forgetting_a_recorded_group_still_downgrades_it_and_says_so`,
  `forget_derivation_downgrades_the_group_and_cannot_be_undone`.
* `every_on_disk_state_of_a_derivation_key_answers_the_same_three_questions` — the
  state table: final path, staging path, both, neither, corrupt, unreadable, wrong
  password, a directory where the file belongs (empty, and holding the key), a stale
  staging directory, an unexplained file, and a live key under an unexplained name.
  Every `live` row is *measured* — the bytes are decrypted and derived from — and every
  row asserts the same property: no random key without an acknowledgement, and no
  on-disk state withholds one that was acknowledged.
* `a_key_at_the_staging_path_is_reported_exactly_as_the_live_one_is`,
  `a_blocked_rename_leaves_no_key_at_the_staging_path`,
  `the_staging_directory_is_removed_even_when_the_write_panics`,
  `a_key_that_cannot_be_opened_is_still_deletable`.
* `a_group_id_cannot_escape_the_keystore_directory`.
* `provenance_is_recorded_for_every_way_an_account_arrives` — and a pre-existing
  account reads `unknown`, never a guess.
* `a_group_records_that_a_passphrase_was_used_but_never_its_value` — neither sidecar
  may carry the phrase, the passphrase or the key.
* `the_group_vault_is_never_readable_by_anyone_else`,
  `a_failed_import_leaves_no_half_made_group`,
  `seed_material_is_built_once_and_wiped_by_every_keystore_entry_point`.

**Wallet names** (`rust-lib/src/keystore.rs`):

* `a_wallet_name_round_trips_and_clears_like_an_account_name` — the name given at import
  lands in the document rather than the record, is trimmed, is mirrored onto `list_groups`,
  reads back as neither an account nor a stray, and clears with an empty string.
* `a_wallet_name_outlives_both_the_key_and_the_record_that_named_it` — a stranded row
  still carries its name, and once the key is gone too the name is still readable and
  still settable, because the accounts it derived are still on screen.
* `a_name_for_a_wallet_that_never_existed_is_refused` — and no hostile id reaches the
  filesystem.
* `two_wallets_may_carry_one_name` — the duplicate is storable; distinguishing them is
  the reader's job.
* `a_name_an_older_build_left_in_the_record_is_read_and_then_moved_out_of_it` — a
  cleared name cannot resurface from `groups.json`.

**An unreadable file is not an empty one** (`rust-lib/src/keystore.rs`):

* `a_groups_file_that_cannot_be_read_refuses_before_a_vault_lands` — driven over every
  corrupt state in turn: truncated, partial JSON, wrong schema, wrong value type, not
  JSON at all, and (unix) mode `0000`. Each asserts that both an acknowledged random key
  and a raw-key import refuse, no vault landed, the derivation key survives, and the key
  is still nameable and deletable.
* `an_unreadable_accounts_file_refuses_before_the_vault_lands` — the refusal is in
  `persist_signer`, so no key reaches disk without a record of where it came from.
* `an_unreadable_labels_file_refuses_rather_than_erasing_every_name`.
* `an_unreadable_wallet_names_file_refuses_rather_than_erasing_every_name` — the same
  for `group-labels.json`, plus: `list_groups` refuses with it, and an import refuses
  rather than landing a wallet it could not name.
* `an_absent_sidecar_is_still_empty_and_only_the_unreadable_case_refuses` — the
  green-field path is unchanged, and `{}` is a readable "nothing".
* `a_derivation_key_on_disk_is_reported_even_with_no_record_of_it` — deleting
  `groups.json` outright reads as legitimately empty, and the key must still be named.
* `a_sidecar_is_replaced_atomically_so_a_crash_cannot_truncate_it` — a blocked
  staging path leaves the destination byte-identical.
* `a_derivation_key_whose_record_is_gone_can_still_be_named_and_deleted` and
  `a_stranded_key_is_deletable_even_when_the_bookkeeping_is_unreadable` — the
  stranded-key escape hatch, over every corrupt state; and the accounts already
  derived keep signing afterwards.

**Tier D gate** (`rust-lib/src/gate.rs`):

* `tier_d_admits_only_the_custodian_for_every_mutation` — every name in the registry
  against every shape of caller.
* `every_hd_derivation_mutation_is_in_the_tier_d_registry`.
* `a_method_the_registry_does_not_name_is_refused_even_for_the_custodian` — a
  misspelled gate refuses; it never falls through.

**Approval state machine** (`rust-lib/src/approval.rs`, pure and offline):

* `approve_refuses_a_handle_that_is_not_the_one_being_rendered` — the
  at-most-one-`Rendered` rule, which is what binds what the human read to what
  gets signed.
* `approve_requires_the_bundle_id_that_was_displayed`.
* `the_commitment_covers_the_parsed_value_not_the_requesters_bytes` — a requester
  cannot get one thing rendered and another signed.
* `the_receipt_not_the_handle_is_what_authorises_collection` — knowing a handle
  from the event plane does not let you collect someone else's signatures.
* `a_wrong_password_neither_signs_nor_settles_the_record`.
* `results_are_idempotent_until_acked_then_erased`.
* `a_bundle_is_one_decision_over_several_legs`.
* `an_unacknowledged_request_expires_and_says_why` — a requester learns the
  reason, rather than seeing the record vanish.
* `a_displaced_record_is_not_collected_as_an_abandoned_offer` — a record another
  acknowledge demotes stays approvable; only an offer nobody came for expires.
* `the_render_shows_full_calldata_and_flags_contract_creation`,
  `an_opaque_digest_is_rendered_as_opaque`.
* `a_requester_cannot_flood_the_queue`,
  `an_oversize_or_empty_intent_is_refused_before_parsing`.
* `sign_eip1559_recovers_signer` / `sign_legacy_recovers_signer` — decode the
  raw signed tx (EIP-2718) and recover the original signer; the EIP-1559 envelope
  starts with `0x02`.

---

## Security model & invariants

This module is the wallet's **secret-holding boundary**. Its security properties:

1. **Private keys never cross the IPC boundary.** No method takes or returns a raw
   private key *out* of the module. The only inbound key material is
   `import_private_key`'s `priv_hex` and `import_keystore_json`'s decrypt path;
   both are immediately re-encrypted into a vault and never echoed back. Outbound
   values are limited to addresses, signature/transaction hex, and re-encrypted
   keystore JSON. This is asserted by the doc-test (import returns only the
   address) and by the `keystore.rs` doc comments.

2. **No network.** The crate pulls in **narrow alloy features only** (`consensus`,
   `eips`, `rlp`, `signers`, `signer-local`, `signer-mnemonic`, `k256`) — no
   `provider`/`rpc`/`network`. There is no HTTP client, no socket, no net-proxy.
   The module cannot exfiltrate a key over the wire because it has no wire.
   (Network access in the wallet is concentrated in `eth_rpc`/`token_list`, which
   are fail-closed through `logos-evm-net-proxy`; the keystore deliberately stays
   out of that path.)

3. **At rest: scrypt vaults.** Keys live on disk only as `eth-keystore`
   scrypt-encrypted JSON, one file per account, in the module's isolated
   `instance_persistence_path`.

4. **In memory: bounded by one call.** A decrypted key exists in RAM only as a
   local inside `approve()` — derived from the vault password, used for every leg
   of the bundle, then zeroized before the call returns. There is no signer cache,
   so there is no TTL to misconfigure and no "unlocked" state another caller could
   ride. The defect this replaced was precisely an `unlock` that passed
   `ttl: None` unconditionally while eviction only ever fired for `Some`, making
   every unlock a permanent, unattributable signing oracle.

5. **A signature requires a human.** No method signs outside `approve()`, and
   `approve()` is reachable only by the configured approver. `render == sign` is
   enforced rather than assumed: the intent is re-parsed and its commitment
   re-derived *inside* `approve()` and compared against the `bundle_id` that was
   displayed, so a requester cannot get one thing rendered and another signed.
   The `bundle_id` is SHA-256 over the module's own canonical re-encoding —
   deliberately **not** keccak256, so it can never be mistaken for a signable
   Ethereum digest.

6. **Password-gated destructive ops.** `delete_account` and `export_keystore_json`
   both require the correct vault password (they decrypt to verify) before acting,
   so neither can be abused by a caller that doesn't already hold the password.
   **Known gap, tracked:** `delete_account` is an *uncounted password oracle* that
   destroys the vault on a correct guess. Rate limiting on vault-decrypting methods
   is a named follow-up, deliberately out of scope for this landing.

   **Deleting key material has exactly two writers**, and neither is reachable by
   accident: `delete_account` (the account's own password) and `forget_derivation` (Tier D,
   no password, because a key nobody can open is the one that most has to stay removable).
   `remove_group` is deliberately *not* a third: it refuses while the wallet holds a key or
   an account, so the only state it can act on is one where nothing signable exists.

7. **Replay protection.** Every signed transaction binds the `chain_id` (EIP-155
   for legacy, the `chainId` field for EIP-1559), so a signed tx cannot be replayed
   on another chain. The chain is also shown to the human on its own render line.

8. **The derivation blast radius is bounded and stated.** An `extkey` group stores
   the **account** key `m/44'/60'/<account>'`, never the root: it reaches every
   address under one Ethereum account and nothing else, because the account level is
   hardened. No xpub is exposed in any tier — an account xpub plus any one derived
   private key yields the parent xprv, which would silently turn
   `export_keystore_json` from a one-account loss into a whole-tree loss. The choice
   between `plain` and `extkey` is per **group**, never per account, because the same
   key derives every index under it.

9. **A random key is never created without an acknowledgement.**
   `create_unrelated_account` is the only way to obtain one, and the acknowledgement
   produces the key — so a path that skipped it has nothing to persist and does not
   compile. `new_account`, which minted one silently on a keystore that looked empty, is
   removed: whether it was safe rested on a directory scan being complete, and that is
   not decidable by inspection.

11. **Known gap, tracked:** `acknowledgeUnrecoverable` is a *caller* assertion, not a *user*
    one. Nothing here distinguishes "the human ticked a box" from "the caller wrote `true`" —
    measured on the sibling `acknowledgeMayBeKeyMaterial`, which the custodian probe hardcodes,
    so a command carrying no acknowledgement deleted a whole key directory. It holds today only
    because Tier D admits exactly one module and that module *is* the screen
    (`AddAccountSheet.qml` gates the button on the checkbox and passes that same value). That is
    a trust assumption about the custodian, not a property of this crate.

10. **Known gap, tracked:** `derive_next_account`, `derive_account_at` and
    `preview_addresses` verify the group password by decrypting, so each is a second
    *uncounted password oracle* alongside `delete_account` (item 6). It matters more
    here: the group vault is a higher-value target than any single account vault.
    Rate limiting on vault-decrypting methods stays the same named follow-up — named,
    not silently inherited. `forget_derivation` left this list: it no longer decrypts
    at all, which removes it as an oracle and makes an unopenable key deletable.

    **`set_label` and `set_group_label` joined this list** when naming was made to prove
    custody: both decrypt a vault, so both confirm a guessed password. Weaker than the rest
    and stated rather than assumed — a correct guess writes a label, it does not destroy or
    spend anything. But they are unmetered confirmations like the others, and a wallet
    rename is reachable on *any* account of that wallet rather than only the one being
    named, so an attacker holding the custodian surface can choose whichever vault has the
    weakest password. Naming a wallet that has **no** accounts and a key decrypts the
    **group** vault, which puts that one arm in the same class as the three calls above
    rather than in the weaker account-vault class; it is the price of the name not being
    settable by proving nothing. Clearing a name decrypts nothing and is therefore not an
    oracle at all — which is one more reason it is exempt.

11. **The gate fails closed, and that was load-bearing while it had to be.** Where a
   caller cannot be named, Tiers A and B refuse *everyone* — the failure mode is
   "nothing can be signed", never "anyone can sign". Identity is live now, so the
   gate admits legitimate callers rather than refusing all of them; the fail-closed
   direction stays because it is what makes a future regression in the identity path
   an availability problem instead of a signing one.

---

## Concurrency

The keystore declares **no `concurrency` field** in `metadata.json`, so it runs in
the framework's **default single-handler dispatch**: the runtime processes one
call at a time. This is appropriate here because the operations mutate shared
state (the approval ledger, vault files) and are fast (local scrypt + signing, no
network latency), so there is no benefit to concurrent dispatch and serial
execution avoids data races on the ledger without extra locking.

Serial dispatch is also what lets cleanup be a **lazy sweep** rather than a
reaper thread: an offer nobody came for is settled `expired_no_ack` on the next
Tier A/Tier B call — precisely the call it would otherwise block — and a settled
record is dropped once its retention passes and any signatures in it have been
collected. A `Rendered` record has no timer; only another acknowledge demotes it.
That is why `concurrency: "multi"` is *not* needed here, despite `approve()`
running a deliberately slow scrypt derivation inside the call.

This contrasts with the wallet's `concurrency: "multi"` modules
(`eth_rpc_module`, `uniswap_module`), which fan out network-bound RPC calls
concurrently and resolve them via a pending-sentinel. The keystore has no
network-bound work to overlap, so it stays single — the simplest model for the
component that must be the most careful with shared secret state.
