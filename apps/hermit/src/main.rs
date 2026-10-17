mod chain;
mod home;
mod store;
mod zcash;
mod zewif_export;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hermit_kernel::assess::{
    assess, base_of, plan_merge, Assessment, HighWater, MergePlan, Resolution, Verdict,
};
use hermit_kernel::metadata::Labels;
use hermit_kernel::{seal, Anchor, Body, Class, Device, DeviceKeys, Hash, Manifest, SectionRef};
use home::{Home, Membership, Pairing};
use std::fs;
use std::path::PathBuf;
use store::Store;

/// Same code the kernel uses for `Verdict::Rollback`.
const EXIT_ROLLBACK: i32 = 20;
const EXIT_ANCHOR_MISMATCH: i32 = 23;

#[derive(Parser)]
#[command(
    name = "hermit",
    about = "Hermit: wallets are shells, your state moves on"
)]
struct Cli {
    /// This device's local state directory.
    #[arg(long, env = "HERMIT_HOME")]
    home: PathBuf,
    /// Work from this device's replica only and leave the provider alone;
    /// new transitions are published on the next sync.
    #[arg(long, global = true)]
    local: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Create a capsule from a wallet directory.
    Create {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        store: String,
        /// Also carry the (still age-encrypted) mnemonic as a Secret section.
        #[arg(long)]
        include_secret: bool,
    },
    /// Print the pairing payload a new device needs to join (genesis + current head).
    Pair,
    /// Join a capsule using a pairing payload from an existing device.
    Join {
        #[arg(long)]
        store: String,
        pairing: PathBuf,
    },
    /// Record the wallet's current state as a new transition.
    Snapshot {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        include_secret: bool,
        #[arg(long, default_value = "snapshot")]
        note: String,
        #[command(flatten)]
        net: Net,
    },
    /// Set (or with no value, delete) a label: tx notes, contacts, anything.
    Label { key: String, value: Option<String> },
    /// List labels.
    Labels,
    /// Verify lineage and chain anchor; report the verdict.
    Status {
        #[command(flatten)]
        net: Net,
    },
    /// Materialize the capsule into a fresh wallet directory.
    Restore {
        #[arg(long)]
        into: PathBuf,
        /// Restore spend authority too (requires the wallet's age identity to use).
        #[arg(long)]
        with_secret: bool,
        #[command(flatten)]
        net: Net,
    },
    /// Exchange manifests and blobs with another store (another provider,
    /// another device's replica). Both end up with the union.
    Sync { other: String },
    /// Reconcile a mergeable fork into a two-parent transition.
    Merge,
    /// Show the verified history.
    Log,
    /// Settle a conflict by choosing whose authority (device set) survives.
    /// Labels and progress are still reconciled as in a merge.
    Resolve {
        /// Prefix of the head whose device set to keep.
        #[arg(long)]
        keep: String,
    },
    /// Export the verified head as a view-only ZeWIF document.
    Zewif {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(clap::Args)]
struct Net {
    /// lightwalletd/Zaino endpoint, e.g. https://testnet.zec.rocks:443
    #[arg(long)]
    server: Option<String>,
    /// Skip chain verification (lineage is still verified).
    #[arg(long)]
    offline: bool,
}

#[derive(Subcommand)]
enum DeviceCmd {
    Init {
        #[arg(long)]
        name: String,
    },
    /// Print this device's public identity (share it to be added).
    Show,
    /// Authorize another device (authority transition; re-seals every section).
    Add { device: PathBuf },
    /// Revoke a device by name (authority transition).
    Revoke { name: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn die(code: i32, msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(code);
}

struct Ctx {
    home: Home,
    keys: DeviceKeys,
    mem: Membership,
    /// The provider. Untrusted, possibly stale or censoring. `None` when
    /// working locally.
    remote: Option<Store>,
    /// This device's replica. Everything is read from here after reconciling.
    store: Store,
}

impl Ctx {
    fn load(home: Home, local: bool) -> Result<Ctx> {
        let keys = home.keys()?;
        let mem = home.membership()?;
        let remote = if local {
            println!("  (local: working from this device's replica)");
            None
        } else {
            Some(Store::open(&mem.store, mem.capsule_id)?)
        };
        let store = Store::open(&home.replica(), mem.capsule_id)?;
        Ok(Ctx {
            home,
            keys,
            mem,
            remote,
            store,
        })
    }

    /// Pull what the provider has, republish what it lacks, and report
    /// anything it still withholds afterwards.
    fn reconcile(&self) -> Result<Vec<String>> {
        let Some(remote) = &self.remote else {
            return Ok(vec![]);
        };
        self.store.pull_from(remote)?;
        remote.pull_from(&self.store)?;
        let theirs = remote.manifest_ids()?;
        let mut missing: Vec<String> = self
            .store
            .manifest_ids()?
            .into_iter()
            .filter(|id| !theirs.contains(id))
            .collect();
        missing.sort();
        Ok(missing)
    }

    fn assess(&self) -> Result<Assessment> {
        let withheld = self.reconcile()?;
        let a = assess(self.store.list_manifests()?, self.mem.genesis, self.mem.hwm);
        for (id, why) in &a.rejected {
            println!("  ✗ rejected {}: {why}", id.short());
        }
        if !withheld.is_empty() {
            let ids: Vec<&str> = withheld.iter().map(|s| &s[..8]).collect();
            die(
                EXIT_ROLLBACK,
                format!(
                    "ROLLBACK DETECTED: provider {} withholds {} manifest(s) this device holds [{}]\n\
                     republish was accepted but not served; local state is intact",
                    self.mem.store,
                    withheld.len(),
                    ids.join(", ")
                ),
            );
        }
        Ok(a)
    }

    /// The single verified head, or exit with the verdict's code.
    fn head(&self) -> Result<(Assessment, Manifest)> {
        let a = self.assess()?;
        match a.verdict {
            Verdict::Ok { head } => {
                let m = a.valid[&head].clone();
                Ok((a, m))
            }
            ref v => die(v.code(), describe(v)),
        }
    }

    fn put_section(
        &self,
        name: &str,
        class: Class,
        plain: &[u8],
        devices: &[Device],
    ) -> Result<SectionRef> {
        let ct = seal::seal(plain, devices)?;
        let blob = self.store.put_blob(&ct)?;
        Ok(SectionRef {
            name: name.into(),
            class,
            plain: Hash::of(b"ZcPlain_v1", plain),
            blob,
            len: plain.len() as u64,
        })
    }

    fn read_section(&self, s: &SectionRef) -> Result<Vec<u8>> {
        let pt = seal::open(&self.store.get_blob(s.blob)?, &self.keys.identity())?;
        anyhow::ensure!(
            Hash::of(b"ZcPlain_v1", &pt) == s.plain,
            "section '{}' does not match its committed hash",
            s.name
        );
        Ok(pt)
    }

    fn reseal_all(&self, sections: &[SectionRef], devices: &[Device]) -> Result<Vec<SectionRef>> {
        sections
            .iter()
            .map(|s| self.put_section(&s.name, s.class, &self.read_section(s)?, devices))
            .collect()
    }

    /// A two-parent successor: sections reconciled per `plan`, every section
    /// re-sealed to `devices`, and the higher chain anchor of the two.
    fn merge_body(
        &self,
        a: &Assessment,
        first: Hash,
        second: Hash,
        plan: MergePlan,
        devices: Vec<Device>,
        note: &str,
    ) -> Result<Body> {
        let mut sections = Vec::new();
        for (name, res) in plan.sections {
            let s = match res {
                Resolution::Take(s) => {
                    let pt = self.read_section(&s)?;
                    self.put_section(&name, s.class, &pt, &devices)?
                }
                Resolution::MergeMetadata { a: x, b: y } => {
                    let merged = Labels::decode(&self.read_section(&x)?)?
                        .merge(&Labels::decode(&self.read_section(&y)?)?);
                    println!("  merged {name}: {} entries", merged.live().count());
                    self.put_section(&name, Class::Metadata, &merged.encode(), &devices)?
                }
            };
            sections.push(s);
        }
        let anchor = a.valid[&plan.anchor_from].body.anchor.clone();
        let parents = [&a.valid[&first], &a.valid[&second]];
        Body::child(&parents, &self.keys, devices, sections, anchor, note)
    }

    /// A transition's note, or a placeholder when this device was not one
    /// of its recipients (e.g. it was added later).
    fn note(&self, m: &Manifest) -> String {
        m.note(&self.keys.identity())
            .unwrap_or_else(|| "(sealed)".into())
    }

    fn commit(&self, body: Body) -> Result<Manifest> {
        let m = body.sign(&self.keys);
        self.store.put_manifest(&m)?;
        if let Some(remote) = &self.remote {
            remote.pull_from(&self.store)?;
        }
        self.home.set_hwm(HighWater {
            seq: m.body.seq,
            id: m.id(),
        })?;
        println!(
            "✓ S{} {} by {} — {}",
            m.body.seq,
            m.id().short(),
            self.keys.name,
            self.note(&m)
        );
        Ok(m)
    }
}

fn describe(v: &Verdict) -> String {
    match v {
        Verdict::Ok { head } => format!("OK head {}", head.short()),
        Verdict::Rollback { served, known } => format!(
            "ROLLBACK DETECTED: store serves S{} ({}) but this device already accepted S{} ({})",
            served.seq,
            served.id.short(),
            known.seq,
            known.id.short()
        ),
        Verdict::ForkMergeable { a, b, base } => format!(
            "FORK: heads {} and {} diverged from {} — mergeable, run `hermit merge`",
            a.short(),
            b.short(),
            base.short()
        ),
        Verdict::Conflict { a, b, reason } => format!(
            "CONFLICT: heads {} and {} — {reason}\nmanual resolution required; nothing was written",
            a.short(),
            b.short()
        ),
        Verdict::Diverged { known } => format!(
            "DIVERGED: store history does not extend S{} ({}) that this device accepted",
            known.seq,
            known.id.short()
        ),
        Verdict::Empty => "no valid state in store for this capsule".into(),
    }
}

/// Seals a plaintext section somewhere and returns its reference.
type PutSection<'a> = dyn Fn(&str, Class, &[u8]) -> Result<SectionRef> + 'a;

fn wallet_sections(
    ctx_put: &PutSection,
    cap: &zcash::Capture,
    include_secret: bool,
) -> Result<Vec<SectionRef>> {
    let mut out = vec![ctx_put(zcash::WALLET, Class::Progress, &cap.bundle)?];
    if include_secret {
        let m = cap
            .mnemonic
            .as_ref()
            .context("wallet has no mnemonic to include")?;
        out.push(ctx_put(zcash::SPENDKEY, Class::Secret, m.as_bytes())?);
    }
    Ok(out)
}

fn print_scan(cap: &zcash::Capture) {
    println!(
        "  anchor: {} height {} block {}",
        cap.anchor.network,
        cap.anchor.height,
        &chain::display_hash(&cap.anchor.block_hash)[..16]
    );
    println!(
        "  scan:   birthday {} → fully scanned {}",
        cap.scan.birthday, cap.scan.fully_scanned
    );
}

/// Check the anchor against the chain. Exits 23 on mismatch.
fn verify_anchor(anchor: Option<&Anchor>, net: &Net) -> Result<Option<(chain::Chain, u32)>> {
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    if net.offline {
        println!("  ! chain check skipped (--offline)");
        return Ok(None);
    }
    let server = net
        .server
        .clone()
        .unwrap_or_else(|| chain::default_server(&anchor.network).to_string());
    let mut c =
        chain::Chain::connect(&server).with_context(|| format!("connecting to {server}"))?;
    match c.check_anchor(anchor)? {
        None => println!(
            "  ✓ anchor {} @{} is on chain ({server})",
            &chain::display_hash(&anchor.block_hash)[..16],
            anchor.height
        ),
        Some(actual) => die(
            EXIT_ANCHOR_MISMATCH,
            format!(
                "ANCHOR MISMATCH: block {} at height {} is not on chain (chain has {})",
                chain::display_hash(&anchor.block_hash),
                anchor.height,
                chain::display_hash(&actual)
            ),
        ),
    }
    let tip = c.tip()?;
    Ok(Some((c, tip)))
}

fn run(cli: Cli) -> Result<()> {
    let home = Home::new(&cli.home)?;
    let local = cli.local;
    match cli.cmd {
        Cmd::Device(DeviceCmd::Init { name }) => {
            let k = DeviceKeys::generate(&name);
            home.save_keys(&k)?;
            println!("{}", serde_json::to_string(&k.public())?);
        }
        Cmd::Device(DeviceCmd::Show) => {
            println!("{}", serde_json::to_string(&home.keys()?.public())?);
        }
        Cmd::Create {
            wallet,
            store,
            include_secret,
        } => {
            let keys = home.keys()?;
            let tmp = tempfile::tempdir()?;
            let cap = zcash::capture(&wallet, tmp.path())?;
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
            let body = Body::genesis(
                "zcash/v1",
                &keys,
                devices.clone(),
                sections,
                Some(cap.anchor.clone()),
            )?;
            let g = body.sign(&keys);
            let real = Store::open(&store, g.body.capsule_id)?;
            for ct in sealed.take() {
                real.put_blob(&ct)?;
            }
            real.put_manifest(&g)?;
            let replica = Store::open(&home.replica(), g.body.capsule_id)?;
            replica.pull_from(&real)?;
            home.save_membership(&Membership {
                capsule_id: g.body.capsule_id,
                genesis: g.id(),
                store: store.clone(),
                hwm: Some(HighWater { seq: 0, id: g.id() }),
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
        }
        Cmd::Pair => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            let p = Pairing {
                capsule_id: ctx.mem.capsule_id,
                genesis: ctx.mem.genesis,
                head: HighWater {
                    seq: head.body.seq,
                    id: head.id(),
                },
            };
            println!("{}", serde_json::to_string(&p)?);
        }
        Cmd::Join { store, pairing } => {
            let p: Pairing = serde_json::from_str(&fs::read_to_string(pairing)?)?;
            home.keys()?;
            home.save_membership(&Membership {
                capsule_id: p.capsule_id,
                genesis: p.genesis,
                store,
                hwm: Some(p.head),
            })?;
            println!(
                "✓ joined capsule {} (pinned genesis {}, freshness floor S{} {})",
                p.capsule_id.short(),
                p.genesis.short(),
                p.head.seq,
                p.head.id.short()
            );
        }
        Cmd::Snapshot {
            wallet,
            include_secret,
            note,
            net,
        } => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            let tmp = tempfile::tempdir()?;
            let cap = zcash::capture(&wallet, tmp.path())?;
            // Never sign state built on a chain that doesn't exist.
            verify_anchor(Some(&cap.anchor), &net)?;
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
                &note,
            )?;
            ctx.commit(body)?;
            print_scan(&cap);
        }
        Cmd::Label { key, value } => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            let sref = head
                .body
                .section(zcash::LABELS)
                .context("capsule has no labels section")?;
            let mut labels = Labels::decode(&ctx.read_section(sref)?)?;
            labels.set(&key, value.clone(), ctx.keys.public().sign_pk);
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
            let note = match &value {
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
        }
        Cmd::Labels => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            let sref = head
                .body
                .section(zcash::LABELS)
                .context("capsule has no labels section")?;
            for (k, v) in Labels::decode(&ctx.read_section(sref)?)?.live() {
                println!("{k}\t{v}");
            }
        }
        Cmd::Device(DeviceCmd::Add { device }) => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            let d: Device = serde_json::from_str(&fs::read_to_string(device)?)?;
            anyhow::ensure!(
                !head.body.devices.iter().any(|x| x.sign_pk == d.sign_pk),
                "device already authorized"
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
        }
        Cmd::Device(DeviceCmd::Revoke { name }) => {
            let ctx = Ctx::load(home, local)?;
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
        }
        Cmd::Status { net } => {
            let ctx = Ctx::load(home, local)?;
            let a = ctx.assess()?;
            let Verdict::Ok { head } = a.verdict else {
                die(a.verdict.code(), describe(&a.verdict))
            };
            let m = &a.valid[&head];
            println!(
                "✓ lineage OK: S{} {} by {} ({} manifests verified)",
                m.body.seq,
                head.short(),
                m.author_name(),
                a.valid.len()
            );
            if let Some((_, tip)) = verify_anchor(m.body.anchor.as_ref(), &net)? {
                let h = m.body.anchor.as_ref().map(|x| x.height).unwrap_or(0);
                println!(
                    "  chain tip {tip}; capsule is {} blocks behind",
                    tip.saturating_sub(h)
                );
            }
            ctx.home.set_hwm(HighWater {
                seq: m.body.seq,
                id: head,
            })?;
        }
        Cmd::Restore {
            into,
            with_secret,
            net,
        } => {
            let ctx = Ctx::load(home, local)?;
            let (_, head) = ctx.head()?;
            println!(
                "✓ lineage OK: S{} {} by {}",
                head.body.seq,
                head.id().short(),
                head.author_name()
            );
            let chain = verify_anchor(head.body.anchor.as_ref(), &net)?;
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
            let scan = zcash::restore(&bundle, mnemonic.as_deref(), &into)?;
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
            ctx.home.set_hwm(HighWater {
                seq: head.body.seq,
                id: head.id(),
            })?;
        }
        Cmd::Sync { other } => {
            let ctx = Ctx::load(home, local)?;
            // Syncing with a third store: bring our provider's state along.
            // Syncing with our own provider: let the counts below show it.
            if other != ctx.mem.store {
                ctx.reconcile()?;
            }
            let theirs = Store::open(&other, ctx.mem.capsule_id)?;
            let (m_in, b_in) = ctx.store.pull_from(&theirs)?;
            let (m_out, b_out) = theirs.pull_from(&ctx.store)?;
            println!("✓ synced with {other}: ←{m_in} manifests/{b_in} blobs, →{m_out} manifests/{b_out} blobs");
            let a = ctx.assess()?;
            println!("  verdict: {}", describe(&a.verdict));
        }
        Cmd::Merge => {
            let ctx = Ctx::load(home, local)?;
            let a = ctx.assess()?;
            let Verdict::ForkMergeable { a: ha, b: hb, base } = a.verdict else {
                die(a.verdict.code(), describe(&a.verdict))
            };
            let plan = plan_merge(&a.valid, ha, hb, base);
            let devices = a.valid[&plan.devices_from].body.devices.clone();
            let note = format!("merge {} + {}", ha.short(), hb.short());
            let body = ctx.merge_body(&a, ha, hb, plan, devices, &note)?;
            println!("MERGED");
            ctx.commit(body)?;
        }
        Cmd::Resolve { keep } => {
            let ctx = Ctx::load(home, local)?;
            let a = ctx.assess()?;
            let Verdict::Conflict {
                a: ha,
                b: hb,
                ref reason,
            } = a.verdict
            else {
                die(a.verdict.code(), describe(&a.verdict))
            };
            let (kept, other) = match (ha.hex().starts_with(&keep), hb.hex().starts_with(&keep)) {
                (true, false) => (ha, hb),
                (false, true) => (hb, ha),
                _ => anyhow::bail!(
                    "--keep must be a prefix of exactly one head: {} or {}",
                    ha.short(),
                    hb.short()
                ),
            };
            let me = ctx.keys.public().sign_pk;
            for h in [kept, other] {
                anyhow::ensure!(
                    a.valid[&h].body.devices.iter().any(|d| d.sign_pk == me),
                    "this device is not authorized on branch {}; resolve from a device both branches trust",
                    h.short()
                );
            }
            let base = base_of(&a.valid, ha, hb).context("heads share no ancestor")?;
            let plan = plan_merge(&a.valid, ha, hb, base);
            let devices = a.valid[&kept].body.devices.clone();
            println!("  conflict was: {reason}");
            println!(
                "  keeping authority from {} ({}); discarding {} ({})",
                kept.short(),
                ctx.note(&a.valid[&kept]),
                other.short(),
                ctx.note(&a.valid[&other])
            );
            let note = format!("resolve: keep {} over {}", kept.short(), other.short());
            let body = ctx.merge_body(&a, kept, other, plan, devices, &note)?;
            println!("RESOLVED");
            ctx.commit(body)?;
        }
        Cmd::Zewif { out } => {
            let ctx = Ctx::load(home, local)?;
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
            let bytes = zewif_export::export(&db, anchor, &labels, &lineage)?;
            fs::write(&out, &bytes)?;
            println!(
                "✓ wrote {} ({} bytes) from S{} {}",
                out.display(),
                bytes.len(),
                head.body.seq,
                head.id().short()
            );
            // Read it back with the reference decoder before calling it done.
            println!("{}", zewif_export::describe(&fs::read(&out)?)?);
        }
        Cmd::Log => {
            let ctx = Ctx::load(home, local)?;
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
        }
    }
    Ok(())
}
