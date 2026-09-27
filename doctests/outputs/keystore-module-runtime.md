# Running the Keystore Module Against logoscore

`logos-evm-keystore-module` is the keystore for the Logos multi-chain EVM
wallet: scrypt-encrypted vaults, BIP39/BIP32 HD derivation, and secp256k1
signing, built on [`alloy`](https://github.com/alloy-rs/alloy) and
[`eth-keystore`](https://crates.io/crates/eth-keystore). It does **no
networking** and private keys never cross the module boundary.

This doc-test exercises the module end-to-end through the headless `logoscore`
runtime — every step is **offline and deterministic**, so it needs no network
and reproduces in CI:

1. Build `logoscore` and `lgpm` from their published flakes.
2. Build this module's installable `.lgx` from its `#lgx` output.
3. Install it into a `./modules` directory with `lgpm`.
4. Start a `logoscore` daemon under an access policy that grants a custodian
   fixture the keystore's account methods, load `keystore_module`, and drive
   it: generate a mnemonic, import a known private key, and then
   **demonstrate that the CLI cannot make it sign anything** — signing
   requires a human approving through the dedicated signer UI.

**What you'll build:** This `keystore_module`, packaged as `.lgx`, installed with `lgpm`, and called through a `logoscore` daemon.

**What you'll learn:**

- How a Rust (rust-first cdylib) Logos module is packaged as an installable `.lgx`
- How an access policy grants a caller individual methods, and why a `"*"` grant does not make it an approver or a custodian
- How to install it with `lgpm` and load it into a `logoscore` daemon
- Why a signature cannot be obtained from the CLI, and what refuses it
- How the keystore keeps private keys inside the module (only addresses and signed payloads come out)

## Prerequisites

- **Nix** with flakes enabled. Install from [nixos.org](https://nixos.org/download.html), then enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

Verify: `nix flake --help >/dev/null 2>&1 && echo "Flakes enabled"`

- **A Linux or macOS machine.** Everything here is offline.

---

## Step 1: Build logoscore and lgpm

`logoscore` is the headless frontend for `logos-liblogos` (it brings in the
whole module-runtime stack), and `lgpm` installs `.lgx` packages into a
modules directory.

### 1.1 Build logoscore

```bash
nix build 'github:logos-co/logos-logoscore-cli/feat/method-scopes#cli' --out-link ./logos
```

### 1.2 Prove the CLI actually runs

```bash
logoscore --version
```

### 1.3 Build lgpm

```bash
nix build 'github:logos-co/logos-package-manager#cli' -o lgpm
```

---

## Step 2: Build and install the keystore module

Build this module's `.lgx` from its flake's `#lgx` output and install it
into a local `./modules` directory. The bundled `capability_module` (shipped
with `logoscore`) handles the load-time auth handshake, so seed it first.

### 2.1 Build the module's .lgx

```bash
# From inside the clone this is simply: nix build '.#lgx'
nix build 'github:logos-co/logos-evm-keystore-module#lgx' -o keystore-lgx
```

```bash
ls keystore-lgx/*.lgx
```

### 2.2 Seed the capability module

```bash
mkdir -p modules
cp -RL ./logos/modules/. ./modules/

```

### 2.3 Install the .lgx with lgpm

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file keystore-lgx/*.lgx
```

### 2.4 Build the custodian fixture

Account mutation is gated on a **custodian**. In production that is
`evm_keystore_ui`; here it is a small fixture module that the access policy grants
the account methods, so the gate can be exercised from both sides headlessly. A
fixture is a real caller with a real name — the gate does not care what a module
is *for*.

```bash
# From inside the clone this is simply:
nix build './doctests/custodian-probe#lgx' -o custodian-lgx
```

### 2.5 Install both

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file custodian-lgx/*.lgx
```

### 2.6 Confirm the install

```bash
./lgpm/bin/lgpm --modules-dir ./modules list
```

---

## Step 3: Run the daemon and drive the keystore

Start `logoscore` pointed at `./modules`, load the module, and call it. We
use Foundry's well-known test key (account 0,
`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`). Note that `logoscore`'s `call`
auto-types a `0x…` argument as a number, so addresses are passed as **bare
hex** — the keystore accepts either form.

### 3.1 Write the access policy

Who may approve and who may mutate comes from the deployer's **access policy**,
which the runtime takes before any module loads; the keystore itself takes no
configuration for it, and no method changes it.

A version 2 policy grants methods per caller. The runtime checks every call to
`keystore_module` against it before the keystore runs, and marks a call it
checked against a method list as `scoped`: that is what admits a caller other
than the built-in approver (`evm_signer_ui`) and custodian (`evm_keystore_ui`).
Here the fixture is granted exactly the methods it calls, and operators — this
CLI — get `"*"`: that lets them reach the keystore, but it is not a grant of any
method in particular, so the keystore's own check still decides, and it refuses.

```bash
cat > policy.json <<'EOF'
{"version": 2, "mode": "explicit",
 "restrictions": {"keystore_module": {"allowedCallers": {
   "keystore_custodian": ["create_mnemonic", "import_mnemonic", "import_private_key", "...",
                          "list_accounts", "caller_identity"],
   "@op:*": "*"}}}}
EOF
```

### 3.2 Start the daemon

```bash
logoscore -D -m ./modules --access-policy ./policy.json > logs.txt &
```

```bash
sleep 3
```

### 3.3 Load the module

```bash
logoscore load-module keystore_module
```

### 3.4 Introspect the module

```bash
logoscore module-info keystore_module
```

### 3.5 Load the custodian fixture

```bash
./logos/bin/logoscore load-module keystore_custodian
```

### 3.6 The CLI cannot mutate the keystore

The CLI calls as an **operator**. The policy lets operators reach the keystore
(`"*"`), but grants them no method in particular, so the call is not `scoped` and
the keystore's own check decides: an operator is not the custodian, so Tier D
refuses it. Admitting it would make `logoscore call` a legal way to import a key.
The refusal string is identical to Tier A's and Tier B's, so a caller cannot use
the error text to work out which tier it failed.

```bash
logoscore call keystore_module import_private_key <privkey> pw
```

### 3.7 …and it cannot derive an account either

HD derivation is account mutation, so it sits behind the same gate. It also opens a
vault whose blast radius is a whole wallet rather than one account — an `extkey`
group's stored key reaches every address under one BIP-44 account, past and future.
The refusal is byte-identical to the one above.

```bash
logoscore call keystore_module derive_next_account '{"groupPassword":"gp","password":"pw"}'
```

### 3.8 …but the ungated reads still work

The gate closed account *mutation*, not the module. A wallet must still be able to
show which accounts exist — that is exactly the line Tier D draws.

```bash
logoscore call keystore_module list_accounts
```

### 3.9 Generate a BIP-39 mnemonic, through the custodian

The other side of the refusal two steps up: the same Tier D method, from the module
the policy granted it. It persists nothing, so what it proves is the gate and only
the gate.

```bash
logoscore call keystore_custodian mnemonic 12
```

### 3.10 Import a known private key

Import Foundry's account-0 private key under a passphrase. The module
returns only the **address** — the key stays inside the scrypt vault.

```bash
logoscore call keystore_custodian import_key <privkey> pw
```

### 3.11 List accounts

```bash
logoscore call keystore_module list_accounts
```

### 3.12 A key no recovery phrase covers needs an acknowledgement

`create_unrelated_account` is the **one** way to obtain a key generated from
randomness rather than derived from a phrase. There used to be a second,
`new_account`, which minted one silently on a keystore that looked empty — whether
that was safe rested on a directory scan being complete, and "is there live key
material anywhere under this store" is not decidable by inspection.

The acknowledgement is. Note who is refused here: the **custodian**, the one caller
Tier D admits. The acknowledgement is a property of the call, not of the caller, so
there is no identity that skips it.

```bash
logoscore call keystore_custodian create pw false
```

### 3.13 …and with it, the key lands

Same caller, same password, one argument different. The refusal above is not a
rate limit or a retry — the key does not exist until it is acknowledged.

```bash
logoscore call keystore_custodian create pw true
```

### 3.14 A file the keystore did not write is reported, not a wedge

Drop a `.DS_Store` into the keystore directory. The scan cannot explain it, and it
says so — but it no longer refuses anything: listing, creating and sweeping all
keep working, and the reported path is removable by name. When the scan was the
safety gate this was a brick, because anything it could not name might have been a
hidden derivation key.

This is the one step that reaches into the module's own directory, and it is not
configuration: it stands in for the operating system putting a file there, which no
method call can simulate. It is what the module has to survive, not how it is told
anything.

```bash
echo x > <module-data>/keystore/.DS_Store
logoscore call keystore_module list_accounts
logoscore call keystore_custodian remove .DS_Store
```

### 3.15 Name a wallet — and prove you hold one of its accounts

A derivation group has no name of its own to fall back on: what a UI shows is its
first account's address, and deleting that account moves it. `set_group_label`
gives it one. It is Tier D, so the CLI is refused and the custodian is not.

Tier D is not the whole story here. A name is the one string in this keystore that
an attacker chooses and a human reads — it is rendered *in place of* an address —
so setting one now also needs the vault password of **one of the wallet's own
accounts**. Holding an account is precisely the claim "this wallet is mine". The
*group* password is not accepted here: it proves you can make accounts, not that
you own the ones the header speaks for. Where the wallet has **no** accounts and
only a key, it is the credential — see the next step.

`get_group_labels` is **ungated**, and answers from its own document rather than
from the group record — so the name outlives the record and the key it belonged to,
which is exactly the row a UI has to name while asking whether to delete it. Two
wallets may carry one name: telling them apart is the reader's job, and refusing
the write would only stop it showing what the user actually did.

```bash
logoscore call keystore_module set_group_label '{"group":"<g>","label":"Cold storage"}'   # refused: Tier D
logoscore call keystore_custodian name_wallet <g> "Cold storage" <address> wrong-password # refused: password
logoscore call keystore_custodian name_wallet <g> "Cold storage" "" ""                    # refused: no account named
logoscore call keystore_custodian name_wallet <g> "Cold storage" <address> pw2            # written
logoscore call keystore_module get_group_labels
```

### 3.16 A wallet that can still mint accounts is named by its derivation key

"No accounts" is not "holds nothing". A wallet that keeps a derivation key and has
no accounts *yet* will have them, and they will be shown under whatever name is on
the header — so a name written here with no proof comes to stand over a real
account the moment one is derived. The exemption is therefore for a wallet that
holds **nothing**: no accounts *and* no key at either path, which is the same
precondition `remove_group` refuses on.

With a key and no accounts there is no account to hold, so what proves the name is
the thing that will mint them: the **derivation key's** own password. Clearing a
name still asks for nothing, and `forget_derivation` still takes no password — a
key you cannot open stays deletable.

```bash
logoscore call keystore_custodian delete <address> pw4          # the wallet now has no accounts
logoscore call keystore_custodian name_wallet <g> "Cold storage" "" ""              # refused: needs the key
logoscore call keystore_custodian name_wallet <g> "Cold storage" "" wrong-password  # refused: password
logoscore call keystore_custodian name_wallet <g> "Cold storage" "" gp4             # written
logoscore call keystore_custodian derive <g> gp4 pw4            # and now the name stands over an account
logoscore call keystore_module list_groups
```

### 3.17 Naming an account proves you hold that account

The same rule, one level down, and this is the sharper case: `set_label` writes the
string a wallet renders *instead of* an address in its account picker. Renaming
"Savings" to something a user would fund is exactly the attack, so setting a name
needs that account's own vault password.

**Clearing a name needs nothing.** It can only move the display back toward the raw
address, which is ground truth — it cannot impersonate anyone — and it is the one
way to strip a stale name off an account whose password is lost. Without that
exemption we would rebuild the wedge `forget_derivation` exists to avoid: a thing
you cannot open and therefore cannot manage.

The account below is Foundry's account 0, imported near the top of this run under
the password `pw`.

```bash
logoscore call keystore_custodian name_account <address> Treasury wrong-password  # refused
logoscore call keystore_custodian name_account <address> Treasury pw              # written
logoscore call keystore_custodian name_account <address> "  " nonsense            # cleared, no password
logoscore call keystore_module get_labels
```

### 3.18 A wallet with nothing left in it can finally be removed

A wallet is up to four things: a record in `groups.json`, a name in
`group-labels.json`, a derivation key, and its accounts. `forget_derivation`
removes the **key** and reports not-found when there is none — so a wallet that is
not derivable and holds no accounts had only a record, and nothing in this module
could take its row off the screen. `remove_group` is that method.

It removes the record and the name, and it **refuses while the wallet still holds
anything** — a derivation key (live or staged) or an account. So it is never a
second door to deleting a key, and because "holds nothing" is the precondition it
needs no password: there is nothing signable left for one to protect. The ladder
below is the whole cost, and it is the correct cost — every rung that is refused is
refused because a spendable key is still under that row.

```bash
logoscore call keystore_custodian name_wallet <g> "Old phone" <address> pw3
logoscore call keystore_module remove_group '{"group":"<g>"}'  # refused: Tier D
logoscore call keystore_custodian remove_wallet <g>            # refused: it still keeps a key
logoscore call keystore_custodian forget <g>
logoscore call keystore_custodian remove_wallet <g>            # refused: it still holds an account
logoscore call keystore_custodian delete <address> pw3
logoscore call keystore_custodian remove_wallet <g>            # the row goes
logoscore call keystore_module list_groups
```

### 3.19 Ask the module who it thinks is calling

The runtime names the CLI as what it is, an **operator**, with the name of its
token, and reports that the call was not `scoped`: the policy's `"*"` for operators
is not a grant of any method. That is the whole reason the next two steps refuse:
the caller is named, and is not admitted.

```bash
logoscore call keystore_module caller_identity
```

### 3.20 Request a signature from the CLI — refused

`request_approval` is Tier B: any **named module** may ask for a
signature. The CLI is not a named module, so it cannot even ask.

```bash
logoscore call keystore_module request_approval '{...intent...}'
```

### 3.21 Approve a signature from the CLI — refused

`approve` is Tier A: **only** the approver (`evm_signer_ui`, or a surface the
deployer's policy grants Tier A's methods) may approve, and it must be a human
doing it. There is no flag, token or argument that makes this succeed from a
shell — which is the property this module exists to provide.

```bash
logoscore call keystore_module pending
```

### 3.22 Stop the daemon

```bash
logoscore stop
```

```bash
sleep 2
```

### 3.23 Confirm the daemon has stopped

```bash
logoscore status
```
