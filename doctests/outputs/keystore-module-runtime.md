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
4. Start a `logoscore` daemon, load `keystore_module`, and drive it: generate a
   mnemonic, import a known private key, unlock the account, and produce a real
   EIP-191 signature and a signed EIP-1559 transaction.

**What you'll build:** This `keystore_module`, packaged as `.lgx`, installed with `lgpm`, and called through a `logoscore` daemon.

**What you'll learn:**

- How a Rust (rust-first cdylib) Logos module is packaged as an installable `.lgx`
- How to install it with `lgpm` and load it into a `logoscore` daemon
- How to import a key, unlock it, and sign a message and a transaction over IPC
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
nix build 'github:logos-co/logos-logoscore-cli#cli' --out-link ./logos
```

### 1.2 Build lgpm

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

### 2.4 Confirm the install

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

### 3.1 Write an unsigned transaction

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

### 3.2 Start the daemon

```bash
logoscore -D -m ./modules > logs.txt &
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

### 3.5 Generate a BIP-39 mnemonic

```bash
logoscore call keystore_module create_mnemonic 12
```

### 3.6 Import a known private key

Import Foundry's account-0 private key under a passphrase. The module
returns only the **address** — the key stays inside the scrypt vault.

```bash
logoscore call keystore_module import_private_key <privkey> pw
```

### 3.7 List accounts

```bash
logoscore call keystore_module list_accounts
```

### 3.8 Unlock the account

```bash
logoscore call keystore_module unlock <address> pw
```

### 3.9 Sign a message (EIP-191)

```bash
logoscore call keystore_module sign_message <address> hello-logos
```

### 3.10 Sign an EIP-1559 transaction

`sign_transaction` signs the unsigned tx in `tx.json` for chain 1 and
returns the raw, broadcast-ready signed transaction (a `0x02…` typed
envelope).

```bash
logoscore call keystore_module sign_transaction <address> @tx.json 1
```

### 3.11 Stop the daemon

```bash
logoscore stop
```

```bash
sleep 2
```

### 3.12 Confirm the daemon has stopped

```bash
logoscore status
```
