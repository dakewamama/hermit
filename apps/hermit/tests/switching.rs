//! Both ways of switching a wallet, against a real chain:
//!
//! * device to device: capsule, pair, restore (no rescan of history), and
//! * app to app: ZeWIF export, then zcash_client_sqlite's own importer.
//!
//! Each resulting wallet must sync to exactly the original's transactions.
//! Needs a running regtest chain behind a lightwalletd-compatible server and
//! a synced zcash-devtool wallet on it, so it is ignored by default:
//!
//!   HERMIT_TEST_WALLET=/path/to/wallet \
//!   HERMIT_TEST_SERVER=127.0.0.1:8137 \
//!   HERMIT_TEST_DEVTOOL=/path/to/zcash-devtool \
//!   cargo test -p hermit --test switching -- --ignored

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Env {
    wallet: PathBuf,
    server: String,
    devtool: PathBuf,
}

fn env() -> Env {
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}; see the module docs"));
    Env {
        wallet: var("HERMIT_TEST_WALLET").into(),
        server: var("HERMIT_TEST_SERVER"),
        devtool: var("HERMIT_TEST_DEVTOOL").into(),
    }
}

fn hermit(home: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hermit"))
        .arg("--home")
        .arg(home)
        .args(args)
        .output()
        .expect("hermit runs");
    assert!(
        out.status.success(),
        "hermit {args:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn devtool(e: &Env, wallet: &Path, args: &[&str]) -> String {
    let out = Command::new(&e.devtool)
        .arg("wallet")
        .arg("-w")
        .arg(wallet)
        .args(args)
        .output()
        .expect("zcash-devtool runs");
    assert!(
        out.status.success(),
        "devtool {args:?} on {} failed:\n{}",
        wallet.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Sync, then the set of transaction ids the wallet knows.
fn synced_txids(e: &Env, wallet: &Path) -> BTreeSet<String> {
    devtool(e, wallet, &["sync", "-s", &e.server]);
    txids(e, wallet)
}

/// The transaction ids the wallet knows right now, without touching the chain.
fn txids(e: &Env, wallet: &Path) -> BTreeSet<String> {
    devtool(e, wallet, &["list-tx"])
        .lines()
        .map(str::trim)
        .filter(|l| l.len() == 64 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
        .collect()
}

fn default_address(e: &Env, wallet: &Path) -> String {
    devtool(e, wallet, &["list-addresses"])
        .lines()
        .find_map(|l| l.trim().strip_prefix("Default Address:"))
        .expect("a default address")
        .trim()
        .to_string()
}

#[test]
#[ignore = "needs a regtest chain; see module docs"]
fn device_to_device_and_app_to_app_carry_the_same_wallet() {
    let e = env();
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let server_url = format!("http://{}", e.server);
    let original = synced_txids(&e, &e.wallet);
    assert!(!original.is_empty(), "test wallet has no transactions");

    let laptop = t.join("laptop");
    let phone = t.join("phone");
    let store = format!("dir://{}", t.join("store").display());
    hermit(&laptop, &["device", "init", "--name", "laptop"]);
    let phone_pub = hermit(&phone, &["device", "init", "--name", "phone"]);
    std::fs::write(t.join("phone.json"), phone_pub).unwrap();
    hermit(
        &laptop,
        &[
            "create",
            "--wallet",
            e.wallet.to_str().unwrap(),
            "--store",
            &store,
        ],
    );
    hermit(
        &laptop,
        &["device", "add", t.join("phone.json").to_str().unwrap()],
    );

    // Device to device.
    let out = hermit(&laptop, &["pair"]);
    let uri = out
        .lines()
        .find(|l| l.starts_with("hermit:"))
        .expect("pair prints a hermit: URI");
    hermit(&phone, &["join", uri]);
    let restored = t.join("restored");
    hermit(
        &phone,
        &[
            "restore",
            "--into",
            restored.to_str().unwrap(),
            "--server",
            &server_url,
        ],
    );
    assert_eq!(
        default_address(&e, &restored),
        default_address(&e, &e.wallet)
    );
    // The history arrived with the capsule: before any sync, the restored
    // wallet already knows every transaction. A seed restore would know none.
    assert_eq!(
        txids(&e, &restored),
        original,
        "device to device, before sync"
    );
    assert_eq!(synced_txids(&e, &restored), original, "device to device");

    // App to app, through the standard format and upstream's importer.
    let doc = t.join("wallet.zewif");
    hermit(&phone, &["zewif", "--out", doc.to_str().unwrap()]);
    let adopted = t.join("adopted");
    hermit(
        &phone,
        &[
            "adopt",
            doc.to_str().unwrap(),
            "--into",
            adopted.to_str().unwrap(),
        ],
    );
    assert_eq!(
        default_address(&e, &adopted),
        default_address(&e, &e.wallet)
    );
    assert_eq!(synced_txids(&e, &adopted), original, "app to app");
}
