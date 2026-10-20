//! Export the verified head of a capsule as a ZeWIF document.
//!
//! The export is view-only by construction: accounts carry their UFVKs, never
//! spending keys or seeds. What a seed phrase alone does not carry goes with
//! them: the ZIP 32 derivation (seed fingerprint and account index) and every
//! address the wallet has handed out, with its diversifier index. Wallets that
//! restore from a seed and look only at default addresses miss funds sent to
//! the others; this is the state that gets lost when a wallet app dies.
//! Notes and trees are left to the importer to re-derive from the UFVKs.
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
    sapling, transparent, Account, AccountViewingKey, Address, AddressBookEntry, BlockHash,
    BlockHeight, Data, DerivedKeySource, DiversifierIndex, KeyScope, KeySource, Network,
    ProtocolAddress, RegtestParams, ScanRange, SeedFingerprint, UnifiedAddress,
    UnifiedFullViewingKey, Zewif, ZewifWallet,
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
        // scan_queue ranges end exclusive; ZeWIF's are inclusive.
        let (start, end) = r?;
        if end > start {
            scanned.push(ScanRange::new(
                BlockHeight::from(start),
                BlockHeight::from(end - 1),
            ));
        }
    }

    let mut wallet = ZewifWallet::new(network);
    let mut stmt = conn.prepare(
        "SELECT id, name, ufvk, birthday_height, recover_until_height,
                hd_seed_fingerprint, hd_account_index
         FROM accounts ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, u32>(3)?,
            r.get::<_, Option<u32>>(4)?,
            r.get::<_, Option<Vec<u8>>>(5)?,
            r.get::<_, Option<u32>>(6)?,
        ))
    })?;
    for row in rows {
        let (id, name, ufvk, birthday, recover_until, seed_fp, account_index) = row?;
        let ufvk = ufvk.context("account has no UFVK; only UFVK accounts are exported")?;
        let mut account = Account::new(AccountViewingKey::Ufvk(UnifiedFullViewingKey::new(ufvk)));
        if let Some(n) = name {
            account.set_name(n);
        }
        account.set_birthday_height(BlockHeight::from(birthday));
        if let Some(h) = recover_until {
            account.set_recover_until_height(BlockHeight::from(h));
        }
        if let (Some(fp), Some(index)) = (seed_fp, account_index) {
            account.set_key_source(KeySource::Derived(DerivedKeySource::new(
                seed_fingerprint(&fp)?,
                index,
                None,
            )));
        }
        for r in &scanned {
            account.add_scanned_range(*r);
        }
        for address in exposed_addresses(&conn, id)? {
            account.add_address(address);
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

/// Every address of an account that has been handed out, i.e. could have
/// received funds.
fn exposed_addresses(conn: &Connection, account: i64) -> Result<Vec<Address>> {
    let mut stmt = conn.prepare(
        "SELECT key_scope, diversifier_index_be, address, exposed_at_height
         FROM addresses
         WHERE account_id = ?1 AND exposed_at_height IS NOT NULL
         ORDER BY diversifier_index_be",
    )?;
    let rows = stmt.query_map([account], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<Vec<u8>>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, u32>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (scope, index_be, encoded, exposed_at) = row?;
        let index = index_be.map(diversifier_index).transpose()?;
        let mut address = Address::new(protocol_address(encoded, index));
        if let Some(scope) = key_scope(scope) {
            address.set_scope(scope);
        }
        address.set_exposed_at_height(BlockHeight::from(exposed_at));
        out.push(address);
    }
    Ok(out)
}

/// zcash_client_sqlite's `KeyScope::encode`.
fn key_scope(code: i64) -> Option<KeyScope> {
    match code {
        0 => Some(KeyScope::External),
        1 => Some(KeyScope::Internal),
        2 => Some(KeyScope::Ephemeral),
        -1 => Some(KeyScope::Foreign),
        _ => None,
    }
}

/// The wallet stores diversifier indices big-endian so they sort; ZIP 32 (and
/// so ZeWIF) represents them little-endian.
fn diversifier_index(big_endian: Vec<u8>) -> Result<DiversifierIndex> {
    let mut b: [u8; 11] = big_endian
        .try_into()
        .map_err(|_| anyhow::anyhow!("diversifier index is not 11 bytes"))?;
    b.reverse();
    Ok(DiversifierIndex::new(b))
}

/// The protocol of an encoded address, from its Human-Readable Part.
fn protocol_address(encoded: String, index: Option<DiversifierIndex>) -> ProtocolAddress {
    const UNIFIED: [&str; 3] = ["u1", "utest1", "uregtest1"];
    const SAPLING: [&str; 3] = ["zs1", "ztestsapling1", "zregtestsapling1"];
    if UNIFIED.iter().any(|p| encoded.starts_with(p)) {
        let mut ua = UnifiedAddress::new(encoded);
        if let Some(d) = index {
            ua.set_diversifier_index(d);
        }
        ProtocolAddress::Unified(Box::new(ua))
    } else if SAPLING.iter().any(|p| encoded.starts_with(p)) {
        let mut a = sapling::Address::new(encoded);
        if let Some(d) = index {
            a.set_diversifier_index(d);
        }
        ProtocolAddress::Sapling(Box::new(a))
    } else {
        ProtocolAddress::Transparent(transparent::Address::new(encoded))
    }
}

/// ZIP 32's canonical seed fingerprint encoding, exactly as zcash_client_sqlite
/// decodes it: Bech32m with the Human-Readable Part "zip32seedfp".
fn seed_fingerprint(bytes: &[u8]) -> Result<SeedFingerprint> {
    anyhow::ensure!(bytes.len() == 32, "seed fingerprint is not 32 bytes");
    let hrp = bech32::Hrp::parse("zip32seedfp").expect("valid HRP");
    let encoded = bech32::encode::<bech32::Bech32m>(hrp, bytes)
        .map_err(|e| anyhow::anyhow!("encoding seed fingerprint: {e:?}"))?;
    Ok(SeedFingerprint::new(encoded))
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
            if let Some(KeySource::Derived(d)) = a.key_source() {
                out += &format!(
                    "\n      derived: {}… account {}",
                    d.seed_fingerprint()
                        .encoding()
                        .chars()
                        .take(24)
                        .collect::<String>(),
                    d.account_index()
                );
            }
            out += &format!("\n      exposed addresses: {}", a.addresses().len());
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
    fn diversifier_indices_become_little_endian() {
        let mut be = vec![0u8; 11];
        be[10] = 5; // index 5, big-endian as zcash_client_sqlite stores it
        let d = diversifier_index(be).unwrap();
        let mut le = [0u8; 11];
        le[0] = 5;
        assert_eq!(d, DiversifierIndex::new(le));
        assert!(diversifier_index(vec![0; 10]).is_err());
    }

    #[test]
    fn key_scopes_follow_zcash_client_sqlite() {
        assert_eq!(key_scope(0), Some(KeyScope::External));
        assert_eq!(key_scope(1), Some(KeyScope::Internal));
        assert_eq!(key_scope(2), Some(KeyScope::Ephemeral));
        assert_eq!(key_scope(-1), Some(KeyScope::Foreign));
        assert_eq!(key_scope(7), None);
    }

    #[test]
    fn seed_fingerprint_decodes_the_way_the_importer_decodes_it() {
        let fp = [0x42u8; 32];
        let enc = seed_fingerprint(&fp).unwrap();
        assert!(enc.encoding().starts_with("zip32seedfp1"));
        // zcash_client_sqlite::zewif::decode_seed_fingerprint, step for step.
        let checked =
            bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(enc.encoding())
                .unwrap();
        assert_eq!(checked.hrp().to_lowercase(), "zip32seedfp");
        assert_eq!(checked.byte_iter().collect::<Vec<_>>(), fp);
        assert!(seed_fingerprint(&[0; 31]).is_err());
    }

    #[test]
    fn address_protocols_follow_their_prefix() {
        assert!(protocol_address("uregtest1abc".into(), None).is_unified());
        assert!(protocol_address("utest1abc".into(), None).is_unified());
        assert!(protocol_address("ztestsapling1abc".into(), None).is_sapling());
        assert!(protocol_address("tmJymvc".into(), None).is_transparent());
    }

    #[test]
    fn unknown_upgrades_are_rejected_not_dropped() {
        let config = "[activation_heights]\nnu99 = 5\n";
        assert!(regtest_params(config).is_err());
        assert!(regtest_params("network = \"regtest\"\n").is_err());
    }
}
