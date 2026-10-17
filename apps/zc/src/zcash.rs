//! Zcash adapter for wallets built on `zcash_client_sqlite` (zcash-devtool,
//! Zallet, the mobile SDKs). A wallet directory is split by continuity class:
//!
//! | file                        | section          | class    |
//! |-----------------------------|------------------|----------|
//! | data.sqlite                 | `zcash.wallet`   | Progress |
//! | keys.toml minus mnemonic    | `zcash.wallet`   | Progress |
//! | keys.toml `mnemonic`        | `zcash.spendkey` | Secret   |
//! | (ours) labels/contacts      | `labels`         | Metadata |
//! | fsblockdb cache             | dropped: re-derivable from the chain |

use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zc_kernel::hash::{cbor, from_cbor};
use zc_kernel::{Anchor, Hash};

pub const WALLET: &str = "zcash.wallet";
pub const SPENDKEY: &str = "zcash.spendkey";
pub const LABELS: &str = "labels";

/// `ScanPriority::Scanned` in zcash_client_sqlite's `scan_queue`.
const PRIORITY_SCANNED: i64 = 10;

#[derive(Serialize, Deserialize)]
pub struct WalletBundle {
    /// keys.toml with the mnemonic removed (network, birthday, heights).
    pub config: String,
    /// A consistent `VACUUM INTO` copy of data.sqlite.
    #[serde(with = "serde_bytes_vec")]
    pub db: Vec<u8>,
}

pub struct Capture {
    pub bundle: Vec<u8>,
    /// The age-encrypted mnemonic exactly as the wallet stored it. It stays
    /// encrypted to the wallet's own identity file even inside the capsule.
    pub mnemonic: Option<String>,
    pub anchor: Anchor,
    pub scan: ScanState,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanState {
    pub birthday: u32,
    pub tip_seen: u32,
    /// Every block at or below this height has been scanned.
    pub fully_scanned: u32,
}

fn network_and_birthday(config: &toml::Table) -> Result<(String, u32)> {
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("main")
        .to_string();
    let birthday = config
        .get("birthday")
        .and_then(|v| v.as_integer())
        .ok_or_else(|| anyhow!("keys.toml has no birthday"))? as u32;
    Ok((network, birthday))
}

pub fn capture(wallet_dir: &Path, scratch: &Path) -> Result<Capture> {
    let keys_path = wallet_dir.join("keys.toml");
    let mut config: toml::Table = fs::read_to_string(&keys_path)
        .with_context(|| format!("reading {}", keys_path.display()))?
        .parse()?;
    let mnemonic = config
        .remove("mnemonic")
        .and_then(|v| v.as_str().map(str::to_string));
    let (network, birthday) = network_and_birthday(&config)?;

    let db_path = wallet_dir.join("data.sqlite");
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", db_path.display()))?;
    let (height, hash): (u32, Vec<u8>) = conn
        .query_row(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("wallet has not scanned any block yet; run sync first")?;
    let scan = scan_state(&conn, birthday, height)?;

    let snap = scratch.join("snapshot.sqlite");
    let _ = fs::remove_file(&snap);
    conn.execute("VACUUM INTO ?1", [snap.to_str().unwrap()])?;
    let db = fs::read(&snap)?;
    fs::remove_file(&snap)?;

    let bundle = cbor(&WalletBundle { config: toml::to_string(&config)?, db });
    Ok(Capture {
        bundle,
        mnemonic,
        anchor: Anchor {
            network,
            height,
            block_hash: Hash(hash.try_into().map_err(|_| anyhow!("block hash is not 32 bytes"))?),
        },
        scan,
    })
}

fn scan_state(conn: &Connection, birthday: u32, tip_seen: u32) -> Result<ScanState> {
    let first_gap: Option<u32> = conn.query_row(
        "SELECT MIN(block_range_start) FROM scan_queue WHERE priority > ?1",
        [PRIORITY_SCANNED],
        |r| r.get(0),
    )?;
    let fully_scanned = match first_gap {
        Some(h) => h.saturating_sub(1).max(birthday),
        None => tip_seen,
    };
    Ok(ScanState { birthday, tip_seen, fully_scanned })
}

pub fn decode_bundle(bytes: &[u8]) -> Result<WalletBundle> {
    from_cbor(bytes)
}

/// Materialize a wallet directory. Without `mnemonic` the wallet can sync and
/// view but cannot spend.
pub fn restore(bundle: &WalletBundle, mnemonic: Option<&str>, into: &Path) -> Result<ScanState> {
    anyhow::ensure!(
        !into.join("data.sqlite").exists(),
        "{} already contains a wallet",
        into.display()
    );
    fs::create_dir_all(into)?;
    let mut config: toml::Table = bundle.config.parse()?;
    if let Some(m) = mnemonic {
        config.insert("mnemonic".into(), toml::Value::String(m.to_string()));
    }
    let (_, birthday) = network_and_birthday(&config)?;
    fs::write(into.join("keys.toml"), toml::to_string(&config)?)?;
    fs::write(into.join("data.sqlite"), &bundle.db)?;

    let conn = Connection::open(into.join("data.sqlite"))?;
    let tip: u32 = conn.query_row("SELECT MAX(height) FROM blocks", [], |r| r.get(0))?;
    scan_state(&conn, birthday, tip)
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v: ciborium::Value = Deserialize::deserialize(d)?;
        v.into_bytes()
            .map_err(|_| serde::de::Error::custom("expected bytes"))
    }
}
