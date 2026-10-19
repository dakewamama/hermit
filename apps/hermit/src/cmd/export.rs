//! Handing the verified state to other wallets.

use crate::ctx::Ctx;
use crate::{zcash, zewif_export, zewif_import};
use anyhow::{Context, Result};
use hermit_kernel::metadata::Labels;
use std::fs;
use std::path::Path;

pub fn zewif(ctx: &Ctx, out: &Path) -> Result<()> {
    let (_, head) = ctx.head()?;
    let anchor = head
        .body
        .anchor
        .as_ref()
        .context("capsule has no chain anchor")?;
    let wref = head
        .body
        .section(zcash::WALLET)
        .context("capsule has no wallet section")?;
    let bundle = zcash::decode_bundle(&ctx.read_section(wref)?)?;
    let labels = match head.body.section(zcash::LABELS) {
        Some(s) => Labels::decode(&ctx.read_section(s)?)?,
        None => Labels::default(),
    };
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("data.sqlite");
    fs::write(&db, &bundle.db)?;
    let lineage = zewif_export::Lineage {
        capsule_id: ctx.mem.capsule_id,
        head: head.id(),
        seq: head.body.seq,
    };
    let bytes = zewif_export::export(&db, &bundle.config, anchor, &labels, &lineage)?;
    fs::write(out, &bytes)?;
    println!(
        "✓ wrote {} ({} bytes) from S{} {}",
        out.display(),
        bytes.len(),
        head.body.seq,
        head.id().short()
    );
    // Read it back with the reference decoder before calling it done.
    println!("{}", zewif_export::describe(&fs::read(out)?)?);
    Ok(())
}

pub fn adopt(document: &Path, into: &Path) -> Result<()> {
    let a = zewif_import::adopt(&fs::read(document)?, into)?;
    println!(
        "✓ adopted {} into {} ({} network, birthday {})",
        document.display(),
        into.display(),
        a.network,
        a.birthday
    );
    for acct in &a.report.imported_accounts {
        println!(
            "  account '{}' imported ({:?})",
            acct.name, acct.birthday_basis
        );
    }
    for skipped in &a.report.skipped_accounts {
        println!("  ✗ account skipped: {skipped:?}");
    }
    println!("  view-only: secret material, if any, was discarded");
    Ok(())
}
