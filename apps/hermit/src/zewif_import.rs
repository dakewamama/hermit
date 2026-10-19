//! Adopt a ZeWIF document into a fresh `zcash_client_sqlite` wallet.
//!
//! The import itself is upstream's: `zcash_client_sqlite::zewif::import_wallet`,
//! the path Zallet uses. Hermit only prepares the database the way
//! zcash-devtool does and writes the small config such a wallet expects, so a
//! document produced by Hermit (or by zewif-zcashd from an old zcashd
//! wallet.dat) becomes a wallet another program can open and sync.
//!
//! Adoption is view-only: secret material in the document is discarded.

use crate::zcash;
use anyhow::{bail, Context, Result};
use rand_wallet::{rand_core::UnwrapErr, rngs::SysRng};
use std::fs;
use std::path::Path;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::zewif::{import_wallet, DiscardSecrets, ZewifImportReport};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::{self, BranchId, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

pub struct Adopted {
    pub network: &'static str,
    pub birthday: u32,
    pub report: ZewifImportReport,
}

pub fn adopt(document: &[u8], into: &Path) -> Result<Adopted> {
    let doc = zewif::Zewif::from_bytes(document).context("not a ZeWIF document")?;
    let wallets = doc.wallets();
    anyhow::ensure!(
        wallets.len() == 1,
        "expected one wallet in the document, found {}",
        wallets.len()
    );
    let birthday = wallets[0]
        .accounts()
        .iter()
        .filter_map(|a| a.birthday_height().map(u32::from))
        .min()
        .unwrap_or(1);
    anyhow::ensure!(
        !into.join("data.sqlite").exists(),
        "{} already contains a wallet",
        into.display()
    );
    fs::create_dir_all(into)?;
    let db = into.join("data.sqlite");

    let (network, report, heights) = match wallets[0].network() {
        zewif::Network::Mainnet => (
            "main",
            import(consensus::Network::MainNetwork, &db, &doc)?,
            None,
        ),
        zewif::Network::Testnet => (
            "test",
            import(consensus::Network::TestNetwork, &db, &doc)?,
            None,
        ),
        zewif::Network::Regtest(rp) => {
            let net = local_network(rp)?;
            ("regtest", import(net, &db, &doc)?, Some(net))
        }
    };

    let mut config = toml::Table::new();
    config.insert("network".into(), network.into());
    config.insert("birthday".into(), i64::from(birthday).into());
    if let Some(net) = heights {
        config.insert("activation_heights".into(), activation_table(&net).into());
    }
    fs::write(into.join("keys.toml"), toml::to_string(&config)?)?;
    zcash::init_block_cache(into)?;
    Ok(Adopted {
        network,
        birthday,
        report,
    })
}

fn import<P: Parameters + Clone + 'static>(
    params: P,
    db: &Path,
    doc: &zewif::Zewif,
) -> Result<ZewifImportReport> {
    let mut wdb = WalletDb::for_path(db, params, SystemClock, UnwrapErr(SysRng))?;
    init_wallet_db(&mut wdb, None).map_err(|e| anyhow::anyhow!("initializing wallet: {e}"))?;
    import_wallet(&mut wdb, doc, &mut DiscardSecrets)
        .map_err(|e| anyhow::anyhow!("ZeWIF import failed: {e}"))
}

/// Rebuild a regtest network from its ZeWIF activation schedule (consensus
/// branch ID → height).
fn local_network(rp: &zewif::RegtestParams) -> Result<LocalNetwork> {
    let mut net = LocalNetwork {
        overwinter: None,
        sapling: None,
        blossom: None,
        heartwood: None,
        canopy: None,
        nu5: None,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        nu7: None,
    };
    for (&branch, &height) in rp.activations() {
        let Ok(id) = BranchId::try_from(branch) else {
            bail!("unknown consensus branch ID {branch:#010x} in the document");
        };
        let Some(nu) = id.network_upgrade() else {
            continue; // Sprout: active from genesis, nothing to set.
        };
        let h = Some(consensus::BlockHeight::from(height));
        match nu {
            NetworkUpgrade::Overwinter => net.overwinter = h,
            NetworkUpgrade::Sapling => net.sapling = h,
            NetworkUpgrade::Blossom => net.blossom = h,
            NetworkUpgrade::Heartwood => net.heartwood = h,
            NetworkUpgrade::Canopy => net.canopy = h,
            NetworkUpgrade::Nu5 => net.nu5 = h,
            NetworkUpgrade::Nu6 => net.nu6 = h,
            NetworkUpgrade::Nu6_1 => net.nu6_1 = h,
            NetworkUpgrade::Nu6_2 => net.nu6_2 = h,
            NetworkUpgrade::Nu6_3 => net.nu6_3 = h,
            NetworkUpgrade::Nu7 => net.nu7 = h,
        }
    }
    Ok(net)
}

/// The `[activation_heights]` table zcash-devtool keeps for regtest wallets;
/// an upgrade that is not scheduled is written as "never".
fn activation_table(net: &LocalNetwork) -> toml::Table {
    let entries = [
        ("overwinter", net.overwinter),
        ("sapling", net.sapling),
        ("blossom", net.blossom),
        ("heartwood", net.heartwood),
        ("canopy", net.canopy),
        ("nu5", net.nu5),
        ("nu6", net.nu6),
        ("nu6_1", net.nu6_1),
        ("nu6_2", net.nu6_2),
        ("nu6_3", net.nu6_3),
        ("nu7", net.nu7),
    ];
    entries
        .into_iter()
        .map(|(name, h)| {
            let v: toml::Value = match h {
                Some(h) => i64::from(u32::from(h)).into(),
                None => "never".into(),
            };
            (name.to_string(), v)
        })
        .collect()
}
