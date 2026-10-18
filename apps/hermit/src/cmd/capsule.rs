//! Capsule membership: creating one, pairing and joining devices, changing
//! who holds authority, and exchanging state with other stores.

use crate::ctx::{describe, print_scan, wallet_sections, Ctx};
use crate::home::{Home, Membership, Pairing};
use crate::store::{self, Store};
use crate::{witness, zcash};
use anyhow::Result;
use hermit_kernel::assess::HighWater;
use hermit_kernel::metadata::Labels;
use hermit_kernel::{seal, Body, Class, Device, DeviceKeys, Hash, SectionRef};
use std::fs;
use std::path::Path;

pub fn device_init(home: &Home, name: &str) -> Result<()> {
    let k = DeviceKeys::generate(name);
    home.save_keys(&k)?;
    println!("{}", serde_json::to_string(&k.public())?);
    Ok(())
}

pub fn device_show(home: &Home) -> Result<()> {
    println!("{}", serde_json::to_string(&home.keys()?.public())?);
    Ok(())
}

pub fn create(
    home: &Home,
    wallet: &Path,
    store: &str,
    include_secret: bool,
    witness: Option<&str>,
) -> Result<()> {
    let store = store::normalize_spec(store)?;
    let keys = home.keys()?;
    let witness = witness.map(witness::WitnessPin::fetch).transpose()?;
    let tmp = tempfile::tempdir()?;
    let cap = zcash::capture(wallet, tmp.path())?;
    let devices = vec![keys.public()];
    // The capsule id is only known after genesis is built, so seal in
    // memory and upload once there is somewhere to put the blobs.
    let sealed = std::cell::RefCell::new(Vec::new());
    let put = |name: &str, class: Class, pt: &[u8]| -> Result<SectionRef> {
        let ct = seal::seal(pt, &devices)?;
        let blob = Hash::of(b"ZcBlob_v1", &ct);
        sealed.borrow_mut().push(ct);
        Ok(SectionRef {
            name: name.into(),
            class,
            plain: Hash::of(b"ZcPlain_v1", pt),
            blob,
            len: pt.len() as u64,
        })
    };
    let mut sections = wallet_sections(&put, &cap, include_secret)?;
    sections.push(put(
        zcash::LABELS,
        Class::Metadata,
        &Labels::default().encode(),
    )?);
    let g = Body::genesis(
        "zcash/v1",
        &keys,
        devices.clone(),
        sections,
        Some(cap.anchor.clone()),
    )?
    .sign(&keys);
    if let Some(w) = &witness {
        w.cosign(&g)?;
        println!("  ✓ witness {} pinned and cosigned genesis", &w.key[..16]);
    }
    let real = Store::open(&store, g.body.capsule_id)?;
    for ct in sealed.take() {
        real.put_blob(&ct)?;
    }
    real.put_manifest(&g)?;
    Store::open(&home.replica(), g.body.capsule_id)?.pull_from(&real)?;
    home.save_membership(&Membership {
        capsule_id: g.body.capsule_id,
        genesis: g.id(),
        store,
        hwm: Some(HighWater { seq: 0, id: g.id() }),
        witness,
    })?;
    println!(
        "✓ capsule {} created (S0 {})",
        g.body.capsule_id.short(),
        g.id().short()
    );
    print_scan(&cap);
    for s in &g.body.sections {
        println!("  section {:<15} {:?} {} bytes", s.name, s.class, s.len);
    }
    if !include_secret {
        println!("  spend key NOT in capsule (view-only by default)");
    }
    Ok(())
}

pub fn pair(ctx: &Ctx) -> Result<()> {
    let (_, head) = ctx.head()?;
    let p = Pairing {
        capsule_id: ctx.mem.capsule_id,
        genesis: ctx.mem.genesis,
        head: HighWater {
            seq: head.body.seq,
            id: head.id(),
        },
        witness: ctx.mem.witness.clone(),
    };
    println!("{}", serde_json::to_string(&p)?);
    Ok(())
}

pub fn join(home: &Home, store: &str, pairing: &Path) -> Result<()> {
    let store = store::normalize_spec(store)?;
    let p: Pairing = serde_json::from_str(&fs::read_to_string(pairing)?)?;
    home.keys()?;
    home.save_membership(&Membership {
        capsule_id: p.capsule_id,
        genesis: p.genesis,
        store,
        hwm: Some(p.head),
        witness: p.witness,
    })?;
    println!(
        "✓ joined capsule {} (pinned genesis {}, freshness floor S{} {})",
        p.capsule_id.short(),
        p.genesis.short(),
        p.head.seq,
        p.head.id.short()
    );
    Ok(())
}

pub fn device_add(ctx: &Ctx, device: &Path) -> Result<()> {
    let (_, head) = ctx.head()?;
    let d: Device = serde_json::from_str(&fs::read_to_string(device)?)?;
    anyhow::ensure!(
        !head.body.devices.iter().any(|x| x.sign_pk == d.sign_pk),
        "device already authorized"
    );
    anyhow::ensure!(
        !head.body.devices.iter().any(|x| x.name == d.name),
        "a device named '{}' is already authorized; device names must be unique \
         because revocation is by name",
        d.name
    );
    let mut devices = head.body.devices.clone();
    devices.push(d.clone());
    let sections = ctx.reseal_all(&head.body.sections, &devices)?;
    let body = Body::child(
        &[&head],
        &ctx.keys,
        devices,
        sections,
        head.body.anchor.clone(),
        &format!("authorize device {}", d.name),
    )?;
    ctx.commit(body)?;
    Ok(())
}

pub fn device_revoke(ctx: &Ctx, name: &str) -> Result<()> {
    let (_, head) = ctx.head()?;
    let devices: Vec<Device> = head
        .body
        .devices
        .iter()
        .filter(|d| d.name != name)
        .cloned()
        .collect();
    anyhow::ensure!(
        devices.len() < head.body.devices.len(),
        "no device named {name}"
    );
    anyhow::ensure!(!devices.is_empty(), "cannot revoke the last device");
    let sections = ctx.reseal_all(&head.body.sections, &devices)?;
    let body = Body::child(
        &[&head],
        &ctx.keys,
        devices,
        sections,
        head.body.anchor.clone(),
        &format!("revoke device {name}"),
    )?;
    ctx.commit(body)?;
    Ok(())
}

pub fn sync(ctx: &Ctx, other: &str) -> Result<()> {
    let other = store::normalize_spec(other)?;
    // Syncing with a third store: bring our provider's state along.
    // Syncing with our own provider: let the counts below show it.
    if other != ctx.mem.store {
        ctx.reconcile()?;
    }
    let theirs = Store::open(&other, ctx.mem.capsule_id)?;
    let (m_in, b_in) = ctx.store.pull_from(&theirs)?;
    let (m_out, b_out) = theirs.pull_from(&ctx.store)?;
    println!(
        "✓ synced with {other}: ←{m_in} manifests/{b_in} blobs, →{m_out} manifests/{b_out} blobs"
    );
    let a = ctx.assess()?;
    println!("  verdict: {}", describe(&a.verdict));
    Ok(())
}
