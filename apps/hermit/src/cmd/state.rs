//! Wallet state: recording it, labelling it, verifying it, restoring it and
//! reading its history.

use crate::cli::Net;
use crate::ctx::{describe, print_scan, refuse_verdict, verify_anchor, wallet_sections, Ctx};
use crate::zcash;
use anyhow::{Context, Result};
use hermit_kernel::assess::Verdict;
use hermit_kernel::metadata::Labels;
use hermit_kernel::{Body, Class};
use std::path::Path;

pub fn snapshot(
    ctx: &Ctx,
    wallet: &Path,
    include_secret: bool,
    note: &str,
    net: &Net,
) -> Result<()> {
    let (_, head) = ctx.head()?;
    let tmp = tempfile::tempdir()?;
    let cap = zcash::capture(wallet, tmp.path())?;
    // Never sign state built on a chain that doesn't exist.
    verify_anchor(Some(&cap.anchor), net)?;
    // A snapshot continues *this* wallet; never swap in another one.
    if let Some(w) = head.body.section(zcash::WALLET) {
        let theirs = zcash::decode_bundle(&ctx.read_section(w)?)?;
        anyhow::ensure!(
            zcash::bundle_accounts(&theirs, tmp.path())? == cap.accounts,
            "{} holds a different wallet (its accounts don't match the capsule's); refusing to replace it",
            wallet.display()
        );
    }
    if let Some(prev) = &head.body.anchor {
        anyhow::ensure!(
            cap.anchor.height >= prev.height,
            "wallet is at height {} but capsule is at {}: snapshot would regress progress",
            cap.anchor.height,
            prev.height
        );
    }
    let devices = head.body.devices.clone();
    let put = |n: &str, c: Class, pt: &[u8]| ctx.put_section(n, c, pt, &devices);
    let mut sections = wallet_sections(&put, &cap, include_secret)?;
    for s in &head.body.sections {
        if !sections.iter().any(|x| x.name == s.name) {
            sections.push(s.clone());
        }
    }
    let body = Body::child(
        &[&head],
        &ctx.keys,
        devices,
        sections,
        Some(cap.anchor.clone()),
        note,
    )?;
    ctx.commit(body)?;
    print_scan(&cap);
    Ok(())
}

pub fn label(ctx: &Ctx, key: &str, value: Option<&str>) -> Result<()> {
    let (_, head) = ctx.head()?;
    let sref = head
        .body
        .section(zcash::LABELS)
        .context("capsule has no labels section")?;
    let mut labels = Labels::decode(&ctx.read_section(sref)?)?;
    labels.set(key, value.map(str::to_string), ctx.keys.public().sign_pk);
    let new = ctx.put_section(
        zcash::LABELS,
        Class::Metadata,
        &labels.encode(),
        &head.body.devices,
    )?;
    let mut sections: Vec<_> = head
        .body
        .sections
        .iter()
        .filter(|s| s.name != zcash::LABELS)
        .cloned()
        .collect();
    sections.push(new);
    let note = match value {
        Some(v) => format!("label {key} = {v}"),
        None => format!("unlabel {key}"),
    };
    let body = Body::child(
        &[&head],
        &ctx.keys,
        head.body.devices.clone(),
        sections,
        head.body.anchor.clone(),
        &note,
    )?;
    ctx.commit(body)?;
    Ok(())
}

pub fn labels(ctx: &Ctx) -> Result<()> {
    let (_, head) = ctx.head()?;
    let sref = head
        .body
        .section(zcash::LABELS)
        .context("capsule has no labels section")?;
    for (k, v) in Labels::decode(&ctx.read_section(sref)?)?.live() {
        println!("{k}\t{v}");
    }
    Ok(())
}

pub fn status(ctx: &Ctx, net: &Net) -> Result<()> {
    let a = ctx.assess()?;
    let Verdict::Ok { head } = a.verdict else {
        return Err(refuse_verdict(&a.verdict));
    };
    let m = &a.valid[&head];
    println!(
        "✓ lineage OK: S{} {} by {} ({} manifests verified)",
        m.body.seq,
        head.short(),
        m.author_name(),
        a.valid.len()
    );
    if let Some((_, tip)) = verify_anchor(m.body.anchor.as_ref(), net)? {
        let h = m.body.anchor.as_ref().map(|x| x.height).unwrap_or(0);
        println!(
            "  chain tip {tip}; capsule is {} blocks behind",
            tip.saturating_sub(h)
        );
    }
    ctx.accept(m)
}

pub fn restore(ctx: &Ctx, into: &Path, with_secret: bool, net: &Net) -> Result<()> {
    let (_, head) = ctx.head()?;
    println!(
        "✓ lineage OK: S{} {} by {}",
        head.body.seq,
        head.id().short(),
        head.author_name()
    );
    let chain = verify_anchor(head.body.anchor.as_ref(), net)?;
    let wref = head
        .body
        .section(zcash::WALLET)
        .context("capsule has no wallet section")?;
    let bundle = zcash::decode_bundle(&ctx.read_section(wref)?)?;
    let mnemonic = if with_secret {
        let s = head
            .body
            .section(zcash::SPENDKEY)
            .context("capsule carries no spend key (created without --include-secret)")?;
        Some(String::from_utf8(ctx.read_section(s)?)?)
    } else {
        None
    };
    let scan = zcash::restore(&bundle, mnemonic.as_deref(), into)?;
    println!("✓ wallet restored to {}", into.display());
    println!(
        "  spend authority: {}",
        if mnemonic.is_some() {
            "restored (still locked to the wallet's age identity)"
        } else {
            "NOT restored — view-only"
        }
    );
    if let Some((_, tip)) = chain {
        let delta = tip.saturating_sub(scan.fully_scanned);
        let full = tip.saturating_sub(scan.birthday);
        let vs = match delta {
            0 => "already at the tip".to_string(),
            d => format!("{}× fewer", full / d),
        };
        println!(
            "  rescan needed: {delta} blocks instead of {full} from birthday {} ({vs})",
            scan.birthday
        );
    }
    ctx.accept(&head)
}

pub fn log(ctx: &Ctx) -> Result<()> {
    let a = ctx.assess()?;
    let mut ms: Vec<_> = a.valid.values().collect();
    ms.sort_by_key(|m| (m.body.seq, m.id()));
    for m in ms {
        let parents: Vec<String> = m.body.parents.iter().map(|p| p.short()).collect();
        let h = m
            .body
            .anchor
            .as_ref()
            .map(|x| x.height.to_string())
            .unwrap_or("-".into());
        println!(
            "S{:<3} {}  ← [{}]  by {:<8} @{:<8} {}",
            m.body.seq,
            m.id().short(),
            parents.join(","),
            m.author_name(),
            h,
            ctx.note(m)
        );
    }
    println!("verdict: {}", describe(&a.verdict));
    Ok(())
}
