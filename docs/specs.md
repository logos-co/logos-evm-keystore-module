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

The EVM wallet is built from seven repositories that talk to each other as
process-isolated Logos modules over a typed RPC bridge:

| Repo | Role | Talks to |
|------|------|----------|
| `logos-evm-net-proxy` | Fail-closed HTTP/RPC client **library crate** (not a module) | — |
| **`logos-evm-keystore-module`** | **Key management + signing (this repo)** | **nothing — leaf module** |
| `logos-evm-eth-rpc-module` | Multi-chain JSON-RPC transport (`concurrency: multi`) | net-proxy |
| `logos-evm-token-list-module` | Token-list fetch/merge per chain | net-proxy |
| `logos-evm-uniswap-module` | Uniswap V2/V3/V4 price oracle + swap building (`concurrency: multi`) | eth-rpc |
| `logos-evm-wallet-backend-module` | Coordinator + tx builder (alloy) | keystore, eth-rpc, token-list, uniswap |
| `logos-evm-wallet-ui` | Universal C++ `ui_qml` app | wallet-backend |

This module is a **leaf**: it declares **no dependencies** (`"dependencies": []`)
and calls no other module. It is driven *by* the `logos-evm-wallet-backend-module`
coordinator (which *requests* an approval as the signing leg of its
send pipeline, and never handles a vault password) or directly by the headless `logosctl`
runtime. Keeping the keystore a dependency-free leaf is deliberate: the component
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
  string, wires the on-context-ready hook to a persistence path, and emits the
  `accounts_changed` event.

```mermaid
flowchart TB
    subgraph Callers["Callers (over Logos bridge)"]
        BE["wallet_backend_module<br/>(requester: request_approval)"]
        SU["signer_ui<br/>(the ONLY approver)"]
        LC["logosctl daemon<br/>(Tier C only)"]
    end

    subgraph Module["keystore_module (Rust cdylib, type: core)"]
        direction TB
        DISP["Generated C-ABI dispatch + install()<br/>(injected from generated/provider_gen.rs)"]
        subgraph Glue["Logos glue — src/glue.rs (feature logos_module)"]
            TRAIT["trait KeystoreModule<br/>(the IPC contract)"]
            IMPL["KeystoreModuleImpl<br/>{ ks, approvals, approver }"]
            GATE["Tier gate<br/>current_caller() → A / B / C"]
            EV["KeystoreModuleEvents::accounts_changed<br/>→ emit_accounts_changed(count)"]
            CTX["on_context_ready(ctx)<br/>ks = Keystore::new(ctx.instance_persistence_path/keystore)"]
        end
        subgraph Core["Crypto core — src/keystore.rs (no network, no Logos)"]
            KS["struct Keystore { dir }<br/>(no signer cache)"]
            VAULTS["scrypt vault files<br/>&lt;lowercase-hex-addr&gt;.json"]
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
but never approve, the **approver** (`signer_ui`) that renders and takes the vault
password, and the human. `logosctl` can reach Tier C only.

```mermaid
sequenceDiagram
    autonumber
    participant BE as wallet_backend_module (requester)
    participant KS as keystore_module (this repo)
    participant SU as signer_ui (the ONLY approver)
    participant H as the human
    participant DISK as scrypt vault dir

    Note over KS: on_context_ready(ctx) → Keystore::new(...)<br/>approver read from keystore.json (default "signer_ui")

    BE->>KS: request_approval({ address, purpose, legs })
    Note right of KS: caller must be a NAMED module (Tier B)
    KS-->>BE: { ok, handle, receipt }   %% receipt returned exactly once
    KS--)SU: event approval_offered(handle)   %% handle only — no token, no intent

    SU->>KS: acknowledge(handle)
    Note right of KS: Tier A — refuses anyone but the approver.<br/>Demotes any other Rendered record.
    KS-->>SU: { bundle_id, requester, render_lines }
    SU->>H: render_lines VERBATIM + bundle_id
    Note over H: no timeout on the human

    H->>SU: vault password
    SU->>KS: approve(handle, bundle_id, password)
    KS->>DISK: decrypt vault (scrypt) → signer (a local)
    Note right of KS: re-parse intent, re-derive commitment,<br/>compare to bundle_id, sign every leg, ZEROIZE
    KS-->>SU: { ok, signed: [...] }
    KS--)BE: event approval_settled(handle, "approved")

    BE->>KS: fetch_result(handle, receipt)
    KS-->>BE: { ok, signed: [...] }   %% idempotent until ack_result
    BE->>KS: ack_result(handle, receipt)

    Note over BE: backend broadcasts raw tx via eth_rpc_module<br/>(keystore never touches the network)
```

The signed values the backend collects are what it hands to `eth_rpc_module` for
`eth_sendRawTransaction`. The keystore itself never performs that broadcast — it
has no network code at all. Note the password crosses **only** the `signer_ui` →
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
| `create_mnemonic` | `words: i64` | `{ ok, phrase }` | no |
| `import_mnemonic` | `params_json: String` | `{ ok, address }` | yes → event |
| `new_account` | `password: String` | `{ ok, address }` | yes → event |
| `import_private_key` | `priv_hex: String, password: String` | `{ ok, address }` | yes → event |
| `import_keystore_json` | `key_json, password, new_password: String` | `{ ok, address }` | yes → event |
| `export_keystore_json` | `address, password: String` | `{ ok, keystore }` | no |
| `list_accounts` | — | `{ ok, accounts: [..] }` | no |
| `has_address` | `address: String` | `bool` | no |
| `delete_account` | `address, password: String` | `bool` | yes → event |
| `request_approval` | `intent_json: String` | `{ ok, handle, receipt, state }` | no |
| `approval_status` | `handle, receipt: String` | `{ ok, state, reason? }` | no |
| `fetch_result` | `handle, receipt: String` | `{ ok, signed: [..] }` | no |
| `ack_result` | `handle, receipt: String` | `bool` | no |
| `cancel_approval` | `handle, receipt: String` | `bool` | no |
| `pending` | — | `{ ok, pending: [..] }` | no |
| `acknowledge` | `handle: String` | `{ ok, bundle_id, requester, render_lines }` | no |
| `approve` | `handle, bundle_id, password: String` | `{ ok, signed: [..] }` | no |
| `reject` | `handle: String` | `bool` | no |
| `caller_identity` | — | `{ ok, kind, identity, approver }` | no |

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

Derive a single account from a mnemonic along the BIP-44 Ethereum path
`m/44'/60'/0'/0/<accountIndex>` and persist its scrypt vault. The argument is a
**JSON object** (`ImportMnemonicParams`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `phrase` | string | yes | The BIP-39 mnemonic |
| `passphrase` | string | no (default `""`) | Optional BIP-39 passphrase (the "25th word"); applied only if non-empty |
| `accountIndex` (alias `account_index`) | u32 | no (default `0`) | HD index to derive |
| `password` | string | yes | Vault password used to scrypt-encrypt the derived key on disk |

Both `accountIndex` and `account_index` are accepted (serde alias). On success
emits `accounts_changed`.

**Success:** `{ "ok": true, "address": "0x…" }`
**Error:** `{ "ok": false, "error": "<parse / derivation error>" }`

```bash
logosctl call keystore_module import_mnemonic \
  @mnemonic.json   # {"phrase":"test test … junk","accountIndex":0,"password":"pw"}
# → {"ok":true,"address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
```

---

### `new_account(password: String) -> String`

Create a brand-new random account (`PrivateKeySigner::random()`) and persist its
scrypt vault under `password`. Emits `accounts_changed`.

* **`password`** — vault password.

**Success:** `{ "ok": true, "address": "0x…" }`
**Error:** `{ "ok": false, "error": "vault error: …" }` (e.g. I/O failure)

```bash
logosctl call keystore_module new_account hunter2
```

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

List the addresses of all persisted vaults. Vaults are discovered by reading the
keystore directory and parsing each `<addr>.json` filename back into an address;
the list is sorted.

**Success:** `{ "ok": true, "accounts": ["0x…", "0x…"] }` (empty array if none)
**Error:** `{ "ok": false, "error": "keystore not initialized (context not ready)" }`

```bash
logosctl call keystore_module list_accounts
# → {"ok":true,"accounts":["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]}
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

## Human-approved signing

There is **no way to make this module sign anything except by a human approving
it.** The methods that used to sign on demand — `unlock`, `timed_unlock`, `lock`,
`is_unlocked`, `sign_transaction`, `sign_message`, `sign_digest` — are **deleted
from the contract**, not merely gated. There is no unlocked-signer cache: the
signing key is derived from the vault password *inside* `approve()`, used, and
zeroized before the call returns.

### The three tiers

Every request is classified by the **caller identity** the platform reports
(`logos_rust_sdk::current_caller()`).

| Tier | Methods | Admits |
|------|---------|--------|
| **A** | `pending`, `acknowledge`, `approve`, `reject` | the configured **approver only** (default `signer_ui`) |
| **B** | `request_approval`, `approval_status`, `fetch_result`, `ack_result`, `cancel_approval` | any **named module**; `fetch`/`ack`/`cancel`/`status` additionally require the **receipt** |
| **C** | account management (`create_mnemonic` … `delete_account`) | ungated / password-gated |

Tiers A and B both return the identical string `{"ok":false,"error":"not authorized"}`
on refusal, so a caller cannot use the error text to probe which tier it failed.

### Caller identity — and which hosts can actually supply it

The caller is populated by a `logos::CallerScope` opened around the inbound
dispatch. The callee names it by finding the presented token in
`ModuleProxy::m_tokens` — its **caller-keyed inbound record**, written by
`informModuleToken`. That is the only store that can honestly name anyone;
`m_store` is direction-mixed and contributes no name, and a validator-accepted
operator token carries none at all.

**Under `logoscore` today, nothing can be named — not even a module.** Measured
against a live daemon at protocol 0.6.0 with a purpose-built probe module:

| call | `caller_identity()` reports |
|------|------------------------------|
| `logosctl` → keystore | `unknown` |
| **probe module → keystore** (real module plane) | **`unknown`** |

Unchanged by `--access-policy enforce`. What the verbose handshake shows is that
the capability exchange announces `requestModule for origin: "core"` — the
bootstrap anchor — rather than `caller_probe`. Only `ModuleProxy::m_tokens`, keyed
by the announced caller, can name anyone, and `authorize()` deliberately refuses
to name an anchor: `"core"` and `"capability_module"` share one value, so naming a
module from it would assert an identity that ambiguity forbids.

**The cause of that `"core"`: fixed upstream (Rust SDK).** `logos-rust-sdk`'s
`src/plugin.rs` hardcoded `CString::new("core")` as the origin when building a
module's **outbound** client. That is why it never contradicted
`logos-module-loader-qt`'s `module_initializer.cpp:103` (`new LogosAPI(moduleName, …)`)
— that line constructs the **provider**-side API, while the outbound client is built
separately. The SDK has no way to learn its own name at runtime (there is no
self-name export in the module-impl C ABI, and `set_context`'s `instance_id` is a
per-instance id that is often absent), so `lidl-gen` now emits `LOGOS_MODULE_NAME`
from the LIDL contract and latches it into a set-once cell before the install hook;
unset yields an empty string rather than a guess. **C++ was never affected** —
`logos_lp_client.h` passes a real origin — which is exactly why the symptom looked
host-shaped. Measured RED→GREEN: `requestModule for origin: "core"` became
`requestModule for origin: "<the module's real name>"`, with no `"core"` anywhere.

**What this means in practice, and it is deliberate:**

* The gate is **fail-closed**. Where identity is unavailable, Tiers A and B refuse
  *everyone* rather than admitting anyone. `{"ok":false,"error":"not authorized"}`
  is the correct answer to an unnameable caller, not a bug.
* **The CLI can never approve a signature**, on any host. `logosctl`'s relayed
  operator token is one undifferentiated bag shared with the shells and
  `core_service`; admitting it at Tier A would make the human bypassable by anyone
  who can reach the daemon socket.
* **Tier C is unaffected**, so account management still works headlessly under
  `logoscore`.
* Consequently the end-to-end proof of approved signing must be **hosted in
  Basecamp or standalone**, never in `logoscore`.

**Naming a caller and naming it *correctly* were separate milestones, and the gap
between them is worth keeping on record.** Before the origin fix, repairing the
pull alone would have produced `{"kind":"module","name":"core"}` — populated, and
wrong — rather than `unknown`, because `authorize()` would have found the announced
anchor name sitting in its caller-keyed store. The consequences were asymmetric,
and they are the reason this module refuses rather than guesses:

* **Tier A stays safe.** `"core"` is not the configured approver, so it is still
  refused and no signature becomes reachable.
* **Result collection stays safe, and this is why the blast radius is bounded.**
  `fetch_result` / `ack_result` authorise on the **receipt**, not on the caller
  name. That single choice is what keeps a misattributed identity a problem of
  *attribution* rather than one of *collection*: requesters that collapse into one
  name still cannot fetch each other's signatures, because the receipt is returned
  exactly once to the requester that asked. Had collection been authorised by
  caller name, the same bug would have let any module collect any other's signed
  payloads.
* **Tier B becomes wrongly permissive.** Every requester collapses into one
  identity: `MAX_PENDING_PER_REQUESTER` stops being per-requester, and — the part
  that matters — `acknowledge()` reports `requester` into the render lines, so **the
  human is shown the wrong requester**. A prompt that says *requested by `core`*
  when it was `wallet_backend_module` is a misattribution in the one surface whose
  entire job is to tell the human what they are authorising.

The rule this leaves behind: a *populated but wrong* identity is worse for this
module than an absent one, because only the wrong one puts a confident falsehood in
front of the human. Tier B is usable when the caller is named **correctly**, not
when it is merely named.

**Both halves are now fixed, and they close different layers.** The origin fix above
stops a module announcing itself as an anchor. The host-side half applies the
anchor-key rule to the *caller-keyed* store as well: `authorize()` already enforced
"an anchor key is never a module name" on the credential store, but the caller-keyed
store offered its key unconditionally — so anything that ever lands an anchor name
there gets suppressed, the `moduleHits == 1 && keyLen > 0` test fails, and the
verdict falls through to `unknown`. `unknown` rather than `host` is the honest
answer: we know we cannot name this caller, we do not know it is the host. Either
half alone leaves a gap, so both are load-bearing.

**Why that mattered more than misattribution — the escalation this prevented.**
`"core"` is not merely a wrong name; it is a `bootstrapKeys()` name. On a pre-0.8
module the provider's `saveToken("core", …)` therefore lands in the **outbound**
namespace, which is precisely where the credential check reads. An ordinary
capability-minted pair token thus became the provider's *own credential*, and the
measured consequences went well past a bad label: the caller reported
`caller_kind=host` — **a module authorizing as the host** — and the victim module's
own anchor was destroyed, locking the host itself out of it.

This is what `HostAnchor` being refused at **both** Tier A and Tier B was actually
protecting against. Tier A held throughout regardless — `"core"` is not the
configured approver — so no signature was ever reachable, but "refuses everyone"
was doing more work than it appeared to.

**The rule, stated so it does not decay into a mitigation.** `HostAnchor` is
refused at every gated tier not because the historical bug existed, and not merely
because the anchor is a bag shared with the shells and `core_service`, but because
**the anchor is not an identity at all.** `core` and `capability_module` share one
token *value*, so nothing presenting it can be distinguished from anything else
presenting it — including a module that came by it legitimately. `authorize()`
already encodes this by refusing to name an anchor. **A tier that admits
`HostAnchor` is admitting an unbounded set, not a trusted party.** That holds
whether or not any module currently claims `core`, which is what makes it a
standing rule rather than a fix for a defect that has since been repaired — and
why it must not be relaxed on the reasoning that "the host is trusted anyway".

The generalisable rule worth stating, because it is what keeps this fixed: **a
store may only name a caller with a key it alone can write.** Ordinary module names
have that property in the caller-keyed store; anchor keys do not, because another
writer puts them there with another meaning.

### The gate's premise is violable by any loaded module — and what survives

This module was built on an explicit scope decision: **caller identity as delivered
by the platform is treated as authoritative**, and validating that a token holder is
who it claims is `capability_module`'s job, not the keystore's. That decision stands.
What follows is the precise, measured statement of what it costs, so nobody reads the
tier table as a stronger guarantee than it is.

`capability_module.requestModule(fromModuleName, moduleName)` takes the requesting
identity as a **plain argument**. Its only check is that the asserted name is one the
image holds a token for — the source says so directly: *"fail closed on an unknown
name rather than mint a token for a self-asserted identity that was never loaded"*
(`capability_module_impl.cpp:65-93`). It verifies the name **is loaded**, not that the
caller **is** it. Be precise about what it *does* provide: a gate on **existence**,
not on identity — a name that was never loaded is refused, so a reserved or invented
namespace cannot be forged. What is not checked is the only thing that would matter
here.

**`--access-policy enforce` is not a mitigation, and this is the trap.** The natural
first response to everything below is "turn the access policy on". It does not work.
The policy arm filters on the *same self-asserted argument*
(`capability_module_plugin.cpp:99-100`):

```cpp
if (auto it = m_restrictions.constFind(moduleName); it != m_restrictions.constEnd()) {
    if (!it->contains(fromModuleName)) { … return {}; }
}
```

A module that asserts the name of an **allowed** caller passes the allowlist. So a
fully populated policy under `enforce` provides no protection against any loaded
module, because the input it filters on is chosen by the requester. The `TODO` there
documents the fail-**open** case when the restriction map is empty; this — the
populated case failing open to anyone who names an allowed caller — is documented
nowhere else, so it is easy to deploy `enforce` and believe it closed this.

Measured on shipped tooling, no harness: a request naming an arbitrary origin mints a
token and the victim records it under that name —

```
$ logoscore call capability_module requestModule core caller_probe
{"result":"b4b5632a-…","status":"ok"}
[caller_probe] ModuleProxy: Token saved for module: "core"
```

Substitute `signer_ui` for `core` and any loaded module can present a token this
keystore will name `signer_ui`, i.e. **reach Tier A**. Every primitive needed is
ordinary public SDK surface.

**What that gets an attacker, and what it does not:**

* **It does NOT get a signature.** `approve()` requires the **vault password**, which
  exists only in the human's head and in `signer_ui`'s hands for the duration of one
  call. Impersonating the approver does not produce one.
* **It cannot redirect a human's approval onto another payload.** `approve()` is
  refused unless the handle is the one currently `Rendered` *and* the echoed
  `bundle_id` matches what was displayed. An attacker who demotes the human's render
  by acknowledging something else causes the human's `approve()` to be **refused**,
  not misapplied.
* **It cannot collect someone else's signatures.** `fetch_result`/`ack_result`
  authorise on the per-request **receipt**, which is returned exactly once to the
  requester that asked — not on the caller name.
* **It does get intent disclosure.** `acknowledge()` returns `render_lines` and the
  requester for a pending request, so an impersonator learns what the user is about
  to sign — amounts, addresses, calldata.
* **It does get denial of service.** `reject()` on any pending request, and repeated
  `acknowledge()` to demote whatever the human is looking at, so approvals fail.

So the design **degrades to disclosure and denial of service, not to unauthorised
signing**, and it does so because of choices that do not depend on identity at all:
per-approval password derivation with no cached signer, the `bundle_id` echo, the
single-`Rendered` rule, and receipt-based collection. That is the property worth
keeping — the tier gate is the part that rests on a premise the platform does not yet
enforce, and it is deliberately *not* the only thing standing between a hostile module
and a signature.

**Closing it is one upstream change**, named here rather than worked around:
`requestModule` deriving the requester from the platform's own caller identity instead
of the `fromModuleName` argument.

That change has a hard prerequisite, which is worth stating because it reorders what
looks like unrelated work: `currentCaller()` answers `unknown` on **every host in the
fleet today** (see above), so `requestModule` has nothing trustworthy to switch to
yet. The chain is **qt-host provenance → caller identity live fleet-wide →
`requestModule` stops trusting its argument.** The qt-host defect is therefore not
merely a broken feature; it is the thing gating a real authorization improvement.

Until that lands, treat Tier A as *"the operator designated this package as the
approver"*, never as *"only that package can reach this"* — and rank **intent
disclosure** first among what remains, since `acknowledge()` returns `render_lines`
with no password and no race.

**A "correctly refused" result on such a host proves less than it looks like.** It
evidences that identity was *absent*, not that the authorization path is sound —
those are different claims, and only the first is established here. (Work on
`logos-protocol#72`, which splits the token store into direction-pure
inbound/outbound/credential halves, reports that an old-host + old-module pairing
authorizes *wrongly* — the same store confusion this section describes from the
naming side, seen from the access side.) Read refusals here as "identity is
missing", never as "the gate was tested".

Use `caller_identity()` to see what this module currently observes. It is ungated
and side-effect-free on purpose: an identity mechanism must not be able to report
its own absence only to the party it would refuse.

### Lifecycle

```
request_approval ──▶ Offered ──acknowledge──▶ Rendered ──approve──▶ Settled(Approved)
       │                 │                        │           └────▶ Settled(Rejected)
       │                 └──(no ack in 3000 ms)──▶ Settled(ExpiredNoAck)
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
* **The 3000 ms window is on the *event* path only.** It bounds how long the
  approver has to acknowledge receipt, not how long the human has to decide. Once
  `Rendered`, there is **no timeout on the human**.
* **Settled records are retained** for 120 s so a requester polling `approval_status`
  learns *why* a request ended (`expired_no_ack`, `rejected`, `cancelled`) rather
  than getting `not_found`.
* **Results are idempotent until `ack_result`**, so a dropped reply does not cost
  the human a second password entry.

### `request_approval(intent_json: String) -> String`

**Tier B.** Returns immediately — it does **not** block on the human.

The intent is `{ address, purpose, legs: [...] }`, where each leg is one of:

```jsonc
{ "kind": "tx",      "chain_id": 1, "tx": { …UnsignedTx… } }
{ "kind": "message", "text": "…" }
{ "kind": "digest",  "digest": "0x…32 bytes…", "purpose": "…" }
```

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
request order. Idempotent until `ack_result`.

### `ack_result(handle: String, receipt: String) -> bool`

**Tier B.** The requester has the signatures; erase them.

### `cancel_approval(handle: String, receipt: String) -> bool`

**Tier B.** The requester gave up.

### `pending() -> String`

**Tier A.** Queue **summaries** — never leg detail. `{ ok, pending: [...] }`.

### `acknowledge(handle: String) -> String`

**Tier A.** Claim a request for display:
`{ ok, handle, bundle_id, requester, render_lines }`.

`render_lines` are authored **by this module** from the parsed intent and **must be
displayed verbatim** — not reformatted, elided, truncated or re-ordered. keystore is
the only party that parsed the intent and therefore the only one that can tell
requester-supplied text from its own; it escapes control characters, bidi controls
and zero-width characters before they enter a line.

The full calldata is always shown in full and **never elided**. A `digest` leg
renders an explicit admission that the signer cannot show what it authorises.

### `approve(handle: String, bundle_id: String, password: String) -> String`

**Tier A.** The human said yes. `bundle_id` must be the value that was displayed;
a mismatch is refused. The intent is **re-parsed and the commitment re-derived
inside this call** before anything is signed, so what is signed is what was
committed to.

One key derivation, every leg signed, then wiped → `{ ok, signed: [...] }`.

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

Ungated observability: `{ ok, kind, identity, approver }` where `kind` is one of
`unknown` | `host` | `module` | `derived` | `operator`.

### Events

The module declares a typed event contract:

```rust
pub trait KeystoreModuleEvents {
    fn accounts_changed(&self, count: i64);
}
```

`accounts_changed(count)` is emitted (via the generated `emit_accounts_changed`)
**whenever the set of persisted accounts changes** — after a successful
`import_mnemonic`, `new_account`, `import_private_key`, `import_keystore_json`, or
`delete_account`. `count` is the new total number of vaults
(`Keystore::list_accounts().len()`). Subscribers (e.g. the wallet UI/backend) can
use it to refresh their account list without polling. All event params are
std-typed (`i64`).

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

### On-disk vault files

* **One file per account**, named `<lowercase-hex-address>.json` (no `0x`
  prefix), e.g. `f39fd6e51aad88f6f4ce6ab8827279cfffb92266.json`.
* Each file is a **scrypt-encrypted keystore JSON** (Web3 Secure Storage format)
  produced by `eth-keystore::encrypt_key`. The 32-byte secp256k1 private key is
  the encrypted payload; the password is the scrypt secret.
* `list_accounts` works purely by listing the directory and parsing filenames; no
  vault is decrypted to enumerate accounts.

### In-memory state

```rust
pub struct Keystore {
    dir: PathBuf,     // that is the whole of it — no signer cache
}
```

**There is no unlocked-signer cache, by construction.** A decrypted key exists only
as a local inside `approve()`: derived from the vault password, used to sign every
leg of the bundle, then zeroized (`Zeroizing` wraps the password, the derived key
and the signer's key bytes) before the call returns. Nothing outside that call
frame can reach a key, so there is no TTL to get wrong and no "unlocked forever"
state to leak — the defect this design replaced was exactly an `unlock` that passed
`ttl: None` and therefore never expired.

The only cross-call state is the approval ledger (`approval.rs`), which holds
intents, render text and — briefly — signed *outputs*, never keys.

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
logosctl call keystore_module create_mnemonic 12
logosctl call keystore_module import_private_key <privkey> pw   # → {address}
logosctl call keystore_module list_accounts
logosctl call keystore_module caller_identity          # → {"kind":"unknown", ...}

# Tier A and Tier B are UNREACHABLE from the CLI, by design:
logosctl call keystore_module pending                  # → {"ok":false,"error":"not authorized"}
logosctl daemon stop
```

The bundled `capability_module` (shipped with `logosctl`) handles the load-time
auth handshake, which is why it is seeded into `./modules` before installing this
module.

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
* every Tier A / Tier B method refuses the CLI with the identical
  `{"ok":false,"error":"not authorized"}` — the fail-closed property, asserted
  rather than assumed.

Signing itself cannot be exercised from `logosctl` (that is the point). The
end-to-end request → acknowledge → approve → broadcast proof is a **Basecamp**
doctest, because only a host that assigns per-plugin identity via
`LogosAPI::forIdentity` can name the approver.

The CI workflow resolves the commit under test and passes
`--release-for logos-evm-keystore-module=<sha>` so the spec's `{release}`
placeholder builds the PR's own code, then publishes a two-column HTML report to
GitHub Pages.

### Unit tests (crypto core)

`rust-lib/src/keystore.rs` carries `#[cfg(test)]` tests runnable with
`cargo test --no-default-features`, covering:

* `hd_derivation_matches_known_vector` — BIP-44 derivation of accounts 0/1 from
  the Foundry mnemonic matches known addresses.
* `private_key_import_matches_address` — imported PK yields the expected address.
* `create_mnemonic_lengths` — 12/24 words succeed, 13 fails.
* `vault_roundtrip_and_listing` — import → `has_address`/`list_accounts`.
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

7. **Replay protection.** Every signed transaction binds the `chain_id` (EIP-155
   for legacy, the `chainId` field for EIP-1559), so a signed tx cannot be replayed
   on another chain. The chain is also shown to the human on its own render line.

8. **The gate fails closed.** Where the host cannot name a caller, Tiers A and B
   refuse *everyone*. This is why the module is safe to run under `logoscore` even
   though identity is unavailable there: the failure mode is "nothing can be
   signed", never "anyone can sign".

---

## Concurrency

The keystore declares **no `concurrency` field** in `metadata.json`, so it runs in
the framework's **default single-handler dispatch**: the runtime processes one
call at a time. This is appropriate here because the operations mutate shared
state (the approval ledger, vault files) and are fast (local scrypt + signing, no
network latency), so there is no benefit to concurrent dispatch and serial
execution avoids data races on the ledger without extra locking.

Serial dispatch is also what lets the lease be a **lazy sweep** rather than a
reaper thread: a stale `Rendered` record is demoted on the next Tier A/Tier B
call — precisely the call it would otherwise block. That is why
`concurrency: "multi"` is *not* needed here, despite `approve()` running a
deliberately slow scrypt derivation inside the call.

This contrasts with the wallet's `concurrency: "multi"` modules
(`eth_rpc_module`, `uniswap_module`), which fan out network-bound RPC calls
concurrently and resolve them via a pending-sentinel. The keystore has no
network-bound work to overlap, so it stays single — the simplest model for the
component that must be the most careful with shared secret state.
