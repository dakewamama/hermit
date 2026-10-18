//! Export the verified head of a capsule as a ZeWIF document.
//!
//! The export is view-only by construction: accounts carry their UFVKs, never
//! spending keys or seeds. Chain-derivable data (addresses, notes, trees) is
//! left to the importer to re-derive from the UFVKs and scanned ranges.
//! Hermit's own state rides in the `hermit` extension namespace: the capsule
//! lineage the export was taken from, and transaction labels, which ZeWIF has
//! no native field for. `contact:` labels become address-book entries.

use anyhow::{bail, Context, Result};
use hermit_kernel::metadata::Labels;
use hermit_kernel::{Anchor, Hash};
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeMap;
use std::path::Path;
use zewif::{
    Account, AccountViewingKey, AddressBookEntry, BlockHash, BlockHeight, Data, Network,
    RegtestParams, ScanRange, UnifiedFullViewingKey, Zewif, ZewifWallet,
};

const VENDOR: &str = "hermit";

/// `ScanPriority::Scanned` in zcash_client_sqlite's `scan_queue`.
const PRIORITY_SCANNED: i64 = 10;

pub struct Lineage {
    pub capsule_id: Hash,
    pub head: Hash,
    pub seq: u64,
}

fn cbor_item<T: serde::Serialize>(v: &T) -> Data {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    Data::from_vec(out)
}

/// `db` is a path to a copy of the wallet's data.sqlite.
/// `config` is the wallet's keys.toml (without the mnemonic); regtest
/// wallets carry their activation schedule there.
pub fn export(
    db: &Path,
    config: &str,
    anchor: &Anchor,
    labels: &Labels,
    lineage: &Lineage,
) -> Result<Vec<u8>> {
    let network = match anchor.network.as_str() {
        "main" => Network::Mainnet,
        "test" => Network::Testnet,
        "regtest" => Network::Regtest(regtest_params(config)?),
        other => bail!("ZeWIF export for network '{other}' is not supported"),
    };
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut scanned = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT block_range_start, block_range_end FROM scan_queue
         WHERE priority = ?1 ORDER BY block_range_start",
    )?;
    for r in stmt.query_map([PRIORITY_SCANNED], |r| {
        Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?))
    })? {
        let (start, end) = r?;
        scanned.push(ScanRange::new(
            BlockHeight::from(start),
            BlockHeight::from(end),
        ));
    }

    let mut wallet = ZewifWallet::new(network);
    let mut stmt = conn.prepare(
        "SELECT name, ufvk, birthday_height, recover_until_height FROM accounts ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, u32>(2)?,
            r.get::<_, Option<u32>>(3)?,
        ))
    })?;
    for row in rows {
        let (name, ufvk, birthday, recover_until) = row?;
        let ufvk = ufvk.context("account has no UFVK; only UFVK accounts are exported")?;
        let mut account = Account::new(AccountViewingKey::Ufvk(UnifiedFullViewingKey::new(ufvk)));
        if let Some(n) = name {
            account.set_name(n);
        }
        account.set_birthday_height(BlockHeight::from(birthday));
        if let Some(h) = recover_until {
            account.set_recover_until_height(BlockHeight::from(h));
        }
        for r in &scanned {
            account.add_scanned_range(*r);
        }
        wallet.add_account(account);
    }

    let mut tx_labels = BTreeMap::new();
    for (key, value) in labels.live() {
        if let Some(name) = key.strip_prefix("contact:") {
            let mut entry = AddressBookEntry::new(value.clone());
            entry.set_label(name);
            wallet.add_address_book_entry(entry);
        } else {
            tx_labels.insert(key.clone(), value.clone());
        }
    }

    let mut doc = Zewif::new(
        BlockHeight::from(anchor.height),
        BlockHash::from_bytes(anchor.block_hash.0),
    );
    doc.add_wallet(wallet);
    let ext = doc.extensions_mut();
    ext.add(VENDOR, "capsule_id", cbor_item(&lineage.capsule_id.hex()));
    ext.add(VENDOR, "head", cbor_item(&lineage.head.hex()));
    ext.add(VENDOR, "seq", cbor_item(&lineage.seq));
    if !tx_labels.is_empty() {
        ext.add(VENDOR, "labels", cbor_item(&tx_labels));
    }
    Ok(doc.to_bytes()?)
}

/// A regtest network is defined by its activation schedule, keyed in ZeWIF
/// by consensus branch ID. Upgrades set to "never" are simply absent.
fn regtest_params(config: &str) -> Result<RegtestParams> {
    use zcash_protocol::consensus::NetworkUpgrade as Nu;
    const UPGRADES: [(&str, Nu); 11] = [
        ("overwinter", Nu::Overwinter),
        ("sapling", Nu::Sapling),
        ("blossom", Nu::Blossom),
        ("heartwood", Nu::Heartwood),
        ("canopy", Nu::Canopy),
        ("nu5", Nu::Nu5),
        ("nu6", Nu::Nu6),
        ("nu6_1", Nu::Nu6_1),
        ("nu6_2", Nu::Nu6_2),
        ("nu6_3", Nu::Nu6_3),
        ("nu7", Nu::Nu7),
    ];
    let config: toml::Table = config.parse()?;
    let heights = config
        .get("activation_heights")
        .and_then(|v| v.as_table())
        .context("regtest wallet config has no [activation_heights]")?;
    let mut activations = BTreeMap::new();
    for (name, value) in heights {
        let (_, nu) = UPGRADES
            .iter()
            .find(|(n, _)| n == name)
            .with_context(|| format!("unknown network upgrade '{name}' in activation heights"))?;
        if let Some(h) = value.as_integer() {
            activations.insert(u32::from(nu.branch_id()), u32::try_from(h)?);
        }
    }
    Ok(RegtestParams::new(activations))
}

/// Parse a ZeWIF document with the reference decoder and summarize it.
pub fn describe(bytes: &[u8]) -> Result<String> {
    let doc = Zewif::from_bytes(bytes)?;
    let mut out = format!(
        "ZeWIF v1, export height {}, {} wallet(s)",
        u32::from(doc.export_height()),
        doc.wallets_len()
    );
    for w in doc.wallets() {
        out += &format!(
            "\n  {:?}: {} account(s), {} address-book entr{}",
            w.network(),
            w.accounts().len(),
            w.address_book().len(),
            if w.address_book().len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
        for a in w.accounts() {
            let AccountViewingKey::Ufvk(k) = a.viewing_key() else {
                continue;
            };
            out += &format!(
                "\n    account '{}' birthday {} ufvk {}… scanned ranges {}",
                a.name(),
                a.birthday_height().map(u32::from).unwrap_or(0),
                k.encoding().chars().take(20).collect::<String>(),
                a.scanned_ranges().len()
            );
        }
    }
    if doc.secrets().is_some() {
        out += "\n  WARNING: document carries secrets";
    } else {
        out += "\n  no secrets (view-only)";
    }
    let lineage: Vec<&str> = doc
        .extensions()
        .iter()
        .filter(|(v, _, _)| *v == VENDOR)
        .map(|(_, k, _)| k)
        .collect();
    out += &format!("\n  hermit extensions: {}", lineage.join(", "));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_schedule_is_keyed_by_branch_id() {
        let config = r#"
            network = "regtest"
            birthday = 1
            [activation_heights]
            canopy = 1
            nu5 = 2
            nu7 = "never"
        "#;
        let params = regtest_params(config).unwrap();
        let expected = BTreeMap::from([(0xe9ff_75a6, 1), (0xc2d6_d0b4, 2)]);
        assert_eq!(params.activations(), &expected);
    }

    #[test]
    fn unknown_upgrades_are_rejected_not_dropped() {
        let config = "[activation_heights]\nnu99 = 5\n";
        assert!(regtest_params(config).is_err());
        assert!(regtest_params("network = \"regtest\"\n").is_err());
    }
}
