//! The per-invocation device context: keys, membership, the provider and
//! this device's replica, and the operations every command builds on.

use crate::cli::Net;
use crate::home::{Home, Membership};
use crate::store::{self, Store};
use crate::{chain, zcash};
use anyhow::{Context, Result};
use hermit_kernel::assess::{assess, Assessment, HighWater, MergePlan, Resolution, Verdict};
use hermit_kernel::metadata::Labels;
use hermit_kernel::{seal, Anchor, Body, Class, Device, DeviceKeys, Hash, Manifest, SectionRef};

/// Same code the kernel uses for `Verdict::Rollback`.
const EXIT_ROLLBACK: i32 = 20;
const EXIT_ANCHOR_MISMATCH: i32 = 23;

/// A deliberate refusal (rollback, fork, conflict, off-chain anchor) that
/// carries its own exit code, as opposed to an operational error (exit 1).
#[derive(Debug)]
pub struct Refusal {
    pub code: i32,
    pub msg: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Refusal {}

fn refuse(code: i32, msg: String) -> anyhow::Error {
    Refusal { code, msg }.into()
}

pub fn refuse_verdict(v: &Verdict) -> anyhow::Error {
    refuse(v.code(), describe(v))
}

pub struct Ctx {
    pub home: Home,
    pub keys: DeviceKeys,
    pub mem: Membership,
    /// The provider. Untrusted, possibly stale or censoring. `None` when
    /// working locally.
    remote: Option<Store>,
    /// This device's replica. Everything is read from here after reconciling.
    pub store: Store,
}

impl Ctx {
    pub fn load(home: Home, local: bool) -> Result<Ctx> {
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
    pub fn reconcile(&self) -> Result<Vec<String>> {
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

    pub fn assess(&self) -> Result<Assessment> {
        let withheld = self.reconcile()?;
        let a = assess(self.store.list_manifests()?, self.mem.genesis, self.mem.hwm);
        for (id, why) in &a.rejected {
            println!("  ✗ rejected {}: {why}", id.short());
        }
        if let (Some(w), Some(_)) = (&self.mem.witness, &self.remote) {
            match w.latest(self.mem.capsule_id) {
                Ok(Some(s)) if !a.valid.contains_key(&s.att.head) => {
                    return Err(refuse(
                        EXIT_ROLLBACK,
                        format!(
                            "ROLLBACK DETECTED: witness attests S{} {} but the provider does not serve it",
                            s.att.seq,
                            s.att.head.short()
                        ),
                    ))
                }
                Ok(_) => {}
                Err(e) => println!("  ! {e}; freshness not verified"),
            }
        }
        if !withheld.is_empty() {
            let ids: Vec<&str> = withheld.iter().map(|s| &s[..8]).collect();
            return Err(refuse(
                EXIT_ROLLBACK,
                format!(
                    "ROLLBACK DETECTED: provider {} withholds {} manifest(s) this device holds [{}]\n\
                     republish was accepted but not served; local state is intact",
                    self.mem.store,
                    withheld.len(),
                    ids.join(", ")
                ),
            ));
        }
        Ok(a)
    }

    /// The single verified head, or a refusal carrying the verdict's code.
    pub fn head(&self) -> Result<(Assessment, Manifest)> {
        let a = self.assess()?;
        match a.verdict {
            Verdict::Ok { head } => {
                let m = a.valid[&head].clone();
                Ok((a, m))
            }
            ref v => Err(refuse_verdict(v)),
        }
    }

    pub fn put_section(
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

    pub fn read_section(&self, s: &SectionRef) -> Result<Vec<u8>> {
        let pt = seal::open(
            &self.store.get_blob(s.blob, store::sealed_bound(s.len))?,
            &self.keys.identity(),
        )?;
        anyhow::ensure!(
            Hash::of(b"ZcPlain_v1", &pt) == s.plain,
            "section '{}' does not match its committed hash",
            s.name
        );
        Ok(pt)
    }

    pub fn reseal_all(
        &self,
        sections: &[SectionRef],
        devices: &[Device],
    ) -> Result<Vec<SectionRef>> {
        sections
            .iter()
            .map(|s| self.put_section(&s.name, s.class, &self.read_section(s)?, devices))
            .collect()
    }

    /// A two-parent successor: sections reconciled per `plan`, every section
    /// re-sealed to `devices`, and the higher chain anchor of the two.
    pub fn merge_body(
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
    pub fn note(&self, m: &Manifest) -> String {
        m.note(&self.keys.identity())
            .unwrap_or_else(|| "(sealed)".into())
    }

    pub fn commit(&self, body: Body) -> Result<Manifest> {
        let m = body.sign(&self.keys);
        // Never publish what every other device would reject.
        m.check_self()
            .map_err(|e| anyhow::anyhow!("refusing to publish an invalid transition: {e}"))?;
        // Cosign before anything is stored, so a refused transition leaves no
        // trace. Local work is cosigned later, by whatever builds on it.
        if let (Some(w), Some(_)) = (&self.mem.witness, &self.remote) {
            w.cosign(&m, self.store.list_manifests()?)?;
        }
        self.store.put_manifest(&m)?;
        if let Some(remote) = &self.remote {
            remote.pull_from(&self.store)?;
        }
        self.accept(&m)?;
        println!(
            "✓ S{} {} by {} — {}",
            m.body.seq,
            m.id().short(),
            self.keys.name,
            self.note(&m)
        );
        Ok(m)
    }

    /// Raise this device's high-water mark to `m`.
    pub fn accept(&self, m: &Manifest) -> Result<()> {
        self.home.set_hwm(HighWater {
            seq: m.body.seq,
            id: m.id(),
        })
    }
}

pub fn describe(v: &Verdict) -> String {
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
pub type PutSection<'a> = dyn Fn(&str, Class, &[u8]) -> Result<SectionRef> + 'a;

pub fn wallet_sections(
    put: &PutSection,
    cap: &zcash::Capture,
    include_secret: bool,
) -> Result<Vec<SectionRef>> {
    let mut out = vec![put(zcash::WALLET, Class::Progress, &cap.bundle)?];
    if include_secret {
        let m = cap
            .mnemonic
            .as_ref()
            .context("wallet has no mnemonic to include")?;
        out.push(put(zcash::SPENDKEY, Class::Secret, m.as_bytes())?);
    }
    Ok(out)
}

pub fn print_scan(cap: &zcash::Capture) {
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

/// Check the anchor against the chain; a mismatch is a refusal (exit 23).
/// Returns the connection and the chain tip when a check was made.
pub fn verify_anchor(anchor: Option<&Anchor>, net: &Net) -> Result<Option<(chain::Chain, u32)>> {
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    if net.offline {
        println!("  ! chain check skipped (--offline)");
        return Ok(None);
    }
    let server = match (&net.server, chain::default_server(&anchor.network)) {
        (Some(s), _) => s.clone(),
        (None, Some(s)) => s.to_string(),
        (None, None) => anyhow::bail!(
            "no public server for network '{}'; pass --server (or --offline)",
            anchor.network
        ),
    };
    let mut c =
        chain::Chain::connect(&server).with_context(|| format!("connecting to {server}"))?;
    if let Some(actual) = c.check_anchor(anchor)? {
        return Err(refuse(
            EXIT_ANCHOR_MISMATCH,
            format!(
                "ANCHOR MISMATCH: block {} at height {} is not on chain (chain has {})",
                chain::display_hash(&anchor.block_hash),
                anchor.height,
                chain::display_hash(&actual)
            ),
        ));
    }
    println!(
        "  ✓ anchor {} @{} is on chain ({server})",
        &chain::display_hash(&anchor.block_hash)[..16],
        anchor.height
    );
    let tip = c.tip()?;
    Ok(Some((c, tip)))
}
