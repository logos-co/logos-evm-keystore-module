//! Regtest proof for the Shared Keystore Plan's spike: BDK builds PSBTs from the keystore's
//! descriptors, the keystore reads, shows and signs them, and bitcoind accepts the result.
//!
//! BITCOIND_EXE=$(nix build nixpkgs#bitcoind --print-out-paths)/bin/bitcoind cargo run --release

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use bdk_wallet::bitcoin::{consensus, Address, Amount, Block, FeeRate, Network, Psbt};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use keystore_module::approval::Approvals;
use keystore_module::btc::{Chain, Family};
use keystore_module::{BitcoinImport, Keystore};
use serde_json::{json, Value};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const PHRASE: &str = "test test test test test test test test test test test junk";

struct Node {
    child: Child,
    url: String,
    auth: String,
    _dir: tempfile::TempDir,
}

impl Node {
    fn start(exe: &str) -> Res<Node> {
        let dir = tempfile::tempdir()?;
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let child = Command::new(exe)
            .args([
                "-regtest",
                &format!("-datadir={}", dir.path().display()),
                &format!("-rpcport={port}"),
                "-listen=0",
                "-server=1",
                "-txindex=1",
                "-fallbackfee=0.0002",
                "-printtoconsole=0",
            ])
            .stdout(Stdio::null())
            .spawn()?;
        let cookie: PathBuf = dir.path().join("regtest").join(".cookie");
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut node = Node { child, url: format!("http://127.0.0.1:{port}"), auth: String::new(), _dir: dir };
        loop {
            if let Ok(c) = std::fs::read_to_string(&cookie) {
                node.auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(c.trim()));
                if node.rpc("getblockchaininfo", json!([])).is_ok() {
                    return Ok(node);
                }
            }
            if Instant::now() > deadline {
                return Err("bitcoind did not answer within 60 s".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn call(&self, path: &str, method: &str, params: Value) -> Res<Value> {
        let body = json!({ "jsonrpc": "1.0", "id": "k0", "method": method, "params": params }).to_string();
        let text = match ureq::post(&format!("{}{path}", self.url)).set("Authorization", &self.auth).send_string(&body) {
            Ok(r) => r.into_string()?,
            Err(ureq::Error::Status(_, r)) => r.into_string()?,
            Err(e) => return Err(e.into()),
        };
        let v: Value = serde_json::from_str(&text)?;
        if !v["error"].is_null() {
            return Err(format!("{method}: {}", v["error"]).into());
        }
        Ok(v["result"].clone())
    }

    fn rpc(&self, method: &str, params: Value) -> Res<Value> {
        self.call("/", method, params)
    }

    fn miner(&self, method: &str, params: Value) -> Res<Value> {
        self.call("/wallet/miner", method, params)
    }

    fn mine(&self, n: u64) -> Res<()> {
        let to = self.miner("getnewaddress", json!([]))?;
        self.rpc("generatetoaddress", json!([n, to]))?;
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.rpc("stop", json!([]));
        let _ = self.child.wait();
    }
}

/// Feed the wallet every block it hasn't seen, the way a block-based client would.
fn sync(node: &Node, wallet: &mut Wallet) -> Res<()> {
    let tip = node.rpc("getblockcount", json!([]))?.as_u64().ok_or("no height")? as u32;
    for h in wallet.latest_checkpoint().height() + 1..=tip {
        let hash = node.rpc("getblockhash", json!([h]))?;
        let raw = node.rpc("getblock", json!([hash, 0]))?;
        let block: Block = consensus::encode::deserialize_hex(raw.as_str().ok_or("no block")?)?;
        wallet.apply_block(&block, h)?;
    }
    Ok(())
}

fn grouped(n: u64) -> String {
    let d = n.to_string();
    d.chars().enumerate().fold(String::new(), |mut s, (i, c)| {
        if i > 0 && (d.len() - i) % 3 == 0 {
            s.push(',');
        }
        s.push(c);
        s
    })
}

fn intent(group: &str, psbt: &Psbt) -> String {
    json!({ "group": group, "purpose": "regtest send",
            "legs": [{ "kind": "psbt", "network": "regtest", "psbt": psbt.to_string() }] })
    .to_string()
}

fn run(node: &Node, family: Family) -> Res<()> {
    println!("\n== {} ==", family.describe());
    let dir = tempfile::tempdir()?;
    let ks = Keystore::new(dir.path());
    let g = ks.import_bitcoin(&BitcoinImport {
        phrase: PHRASE,
        bip39_passphrase: "",
        family,
        chain: Chain::Test,
        account: 0,
        password: "pw",
        label: "Regtest",
        wallet_name: "",
        keep: keystore_module::KeepPhrase::No,
        start: keystore_module::WalletStart::Restored(None),
    })?;
    let (external, internal) = ks.account_descriptors(&g.id)?;
    println!("descriptor: {external}");
    for d in [&external, &internal] {
        let (body, sum) = d.split_once('#').ok_or("no checksum")?;
        let info = node.rpc("getdescriptorinfo", json!([body]))?;
        assert_eq!(info["checksum"], sum, "Bitcoin Core computes another checksum for {body}");
    }

    let mut wallet = Wallet::create(external.clone(), internal.clone())
        .network(Network::Regtest)
        .create_wallet_no_persist()?;
    for btc in [0.5, 0.25] {
        let to = wallet.reveal_next_address(KeychainKind::External).address;
        node.miner("sendtoaddress", json!([to.to_string(), btc]))?;
    }
    node.mine(1)?;
    sync(node, &mut wallet)?;
    assert_eq!(wallet.balance().total(), Amount::from_sat(75_000_000), "the wallet sees both coins");

    let dest: Address = node
        .miner("getnewaddress", json!([]))?
        .as_str()
        .ok_or("no address")?
        .parse::<Address<_>>()?
        .require_network(Network::Regtest)?;
    let mut builder = wallet.build_tx();
    builder.add_recipient(dest.script_pubkey(), Amount::from_sat(60_000_000));
    builder.fee_rate(FeeRate::from_sat_per_vb_u32(7));
    let psbt = builder.finish()?;
    let bdk_fee = wallet.calculate_fee(&psbt.unsigned_tx)?;

    let mut ap = Approvals::new();
    let (h, r) = ap.request_with(Some(&ks), "bitcoin_wallet_core_module", &intent(&g.id, &psbt))?;
    let v = ap.acknowledge(&h)?;
    for line in &v.render_lines {
        println!("  | {line}");
    }
    let lines = v.render_lines.join("\n");
    assert!(lines.contains(&format!("Fee {} sats,", grouped(bdk_fee.to_sat()))), "fee line disagrees with BDK's {bdk_fee}");
    assert!(lines.contains("back to this wallet") && lines.contains(", checked)"), "change not recognised");
    println!("(4) fee line equals BDK's fee: {} sats", bdk_fee.to_sat());

    assert!(ap.approve(&ks, &h, &v.bundle_id, "pw")? == 1);
    let mut signed: Psbt = ap.fetch_result(&h, &r)?.remove(0).parse()?;
    assert_eq!(signed.unsigned_tx, psbt.unsigned_tx, "signing changed the transaction");
    assert!(wallet.finalize_psbt(&mut signed, SignOptions::default())?, "BDK could not finalize");
    // (3) on a real BDK PSBT: change that pays a key outside the group shows as a send...
    let change = psbt
        .outputs
        .iter()
        .position(|o| !o.bip32_derivation.is_empty() || !o.tap_key_origins.is_empty())
        .ok_or("BDK added no change output")?;
    let mut forged = psbt.clone();
    forged.unsigned_tx.output[change].script_pubkey = dest.script_pubkey();
    let (fh, _) = ap.request_with(Some(&ks), "bitcoin_wallet_core_module", &intent(&g.id, &forged))?;
    let shown = ap.acknowledge(&fh)?.render_lines.join("\n");
    assert!(!shown.contains("back to this wallet") && shown.matches("Send ").count() == 2, "{shown}");
    // ...and a false input amount is refused before anything is shown.
    let mut lying = psbt.clone();
    let w = lying.inputs[0].witness_utxo.as_mut().ok_or("no witness utxo")?;
    w.value = w.value + Amount::from_sat(1);
    let refused = ap.request_with(Some(&ks), "bitcoin_wallet_core_module", &intent(&g.id, &lying));
    match family {
        // The amount is checked against the previous transaction BDK includes.
        Family::Segwit => {
            assert!(refused.is_err(), "a false amount was accepted");
            println!("(3) forged change shown as a send; a false input amount refused");
        }
        // BDK sends no previous transaction for taproot. Every input's amount is in the sighash,
        // so a signature over a false one can never spend: bitcoind must refuse it.
        Family::Taproot => {
            let (lh, lr) = refused?;
            let lv = ap.acknowledge(&lh)?;
            ap.approve(&ks, &lh, &lv.bundle_id, "pw")?;
            let mut bad: Psbt = ap.fetch_result(&lh, &lr)?.remove(0).parse()?;
            wallet.finalize_psbt(&mut bad, SignOptions::default())?;
            let hex = consensus::encode::serialize_hex(&bad.extract_tx_unchecked_fee_rate());
            let verdict = node.rpc("testmempoolaccept", json!([[hex]]))?;
            assert_eq!(verdict[0]["allowed"], false, "{verdict}");
            println!("(3) forged change shown as a send; a false amount signs nothing that spends: {}", verdict[0]["reject-reason"]);
        }
    }

    // The honest transaction last: the doctored ones share its txid, so judge them while it is unknown.
    let tx = signed.extract_tx()?;
    let hex = consensus::encode::serialize_hex(&tx);
    let accept = node.rpc("testmempoolaccept", json!([[hex]]))?;
    assert_eq!(accept[0]["allowed"], true, "{accept}");
    let txid = node.rpc("sendrawtransaction", json!([hex]))?;
    node.mine(1)?;
    let seen = node.rpc("getrawtransaction", json!([txid, true]))?;
    assert!(seen["confirmations"].as_u64().unwrap_or(0) >= 1, "{seen}");
    println!("(2) bitcoind accepted and mined {txid}");
    Ok(())
}

fn main() -> Res<()> {
    let exe = std::env::var("BITCOIND_EXE").map_err(|_| "set BITCOIND_EXE to a bitcoind binary")?;
    let node = Node::start(&exe)?;
    let version = node.rpc("getnetworkinfo", json!([]))?["subversion"].clone();
    println!("bitcoind {version} on regtest");
    node.rpc("createwallet", json!(["miner"]))?;
    node.mine(101)?;
    run(&node, Family::Segwit)?;
    run(&node, Family::Taproot)?;
    println!("\nall passed");
    Ok(())
}
