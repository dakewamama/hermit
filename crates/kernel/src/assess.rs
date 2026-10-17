//! Lineage assessment. Given whatever manifests an (untrusted) store handed
//! us, the pinned genesis, and this device's high-water mark, decide what
//! the state actually is — or refuse.

use crate::hash::Hash;
use crate::manifest::{Class, Manifest, SectionRef};
use std::collections::{BTreeMap, BTreeSet};

/// What this device last accepted for the capsule. Persisted locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HighWater {
    pub seq: u64,
    pub id: Hash,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A single valid head that extends everything this device has seen.
    Ok { head: Hash },
    /// The store is serving state older than what this device already accepted.
    Rollback { served: HighWater, known: HighWater },
    /// Concurrent heads whose differences can be reconciled automatically.
    ForkMergeable { a: Hash, b: Hash, base: Hash },
    /// Concurrent heads that must not be merged without a human.
    Conflict { a: Hash, b: Hash, reason: String },
    /// The store's history does not contain anything this device recognizes.
    Diverged { known: HighWater },
    /// No valid manifests at all.
    Empty,
}

impl Verdict {
    pub fn code(&self) -> i32 {
        match self {
            Verdict::Ok { .. } => 0,
            Verdict::Rollback { .. } => 20,
            Verdict::ForkMergeable { .. } => 21,
            Verdict::Conflict { .. } => 22,
            Verdict::Diverged { .. } => 26,
            Verdict::Empty => 27,
        }
    }
}

pub struct Assessment {
    pub verdict: Verdict,
    /// Manifests the store offered that failed verification, with reasons.
    pub rejected: Vec<(Hash, String)>,
    pub valid: BTreeMap<Hash, Manifest>,
}

pub fn assess(offered: Vec<Manifest>, genesis: Hash, hwm: Option<HighWater>) -> Assessment {
    let mut rejected = Vec::new();
    let mut pending: Vec<Manifest> = Vec::new();
    for m in offered {
        match m.check_self() {
            Ok(()) => pending.push(m),
            Err(e) => rejected.push((m.id(), e)),
        }
    }
    pending.sort_by_key(|m| m.body.seq);

    // Accept in seq order; every parent must already be accepted.
    let mut valid: BTreeMap<Hash, Manifest> = BTreeMap::new();
    for m in pending {
        let id = m.id();
        match check_lineage(&m, &valid, genesis) {
            Ok(()) => {
                valid.insert(id, m);
            }
            Err(e) => rejected.push((id, e)),
        }
    }

    let verdict = decide(&valid, hwm);
    Assessment { verdict, rejected, valid }
}

fn check_lineage(m: &Manifest, valid: &BTreeMap<Hash, Manifest>, genesis: Hash) -> Result<(), String> {
    let b = &m.body;
    if b.parents.is_empty() {
        if m.id() != genesis {
            return Err("unknown genesis (not the capsule this device joined)".into());
        }
        if !b.devices.iter().any(|d| d.sign_pk == b.author) || b.seq != 0 {
            return Err("malformed genesis".into());
        }
        return Ok(());
    }
    let mut max_seq = 0;
    for p in &b.parents {
        let Some(parent) = valid.get(p) else {
            return Err(format!("parent {} missing or invalid", p.short()));
        };
        if parent.body.capsule_id != b.capsule_id {
            return Err("parent belongs to another capsule".into());
        }
        if !parent.body.devices.iter().any(|d| d.sign_pk == b.author) {
            return Err("UNKNOWN_DEVICE: author not authorized by parent".into());
        }
        max_seq = max_seq.max(parent.body.seq);
    }
    if b.seq != max_seq + 1 {
        return Err(format!("bad seq {} (expected {})", b.seq, max_seq + 1));
    }
    Ok(())
}

pub fn ancestors(valid: &BTreeMap<Hash, Manifest>, id: Hash) -> BTreeSet<Hash> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![id];
    while let Some(h) = stack.pop() {
        if seen.insert(h) {
            if let Some(m) = valid.get(&h) {
                stack.extend(m.body.parents.iter().copied());
            }
        }
    }
    seen
}

fn decide(valid: &BTreeMap<Hash, Manifest>, hwm: Option<HighWater>) -> Verdict {
    let referenced: BTreeSet<Hash> = valid
        .values()
        .flat_map(|m| m.body.parents.iter().copied())
        .collect();
    let mut tips: Vec<&Manifest> = valid
        .values()
        .filter(|m| !referenced.contains(&m.id()))
        .collect();
    if tips.is_empty() {
        return Verdict::Empty;
    }
    tips.sort_by_key(|m| (std::cmp::Reverse(m.body.seq), m.id()));

    if let Some(known) = hwm {
        let extends: Vec<&Manifest> = tips
            .iter()
            .copied()
            .filter(|t| ancestors(valid, t.id()).contains(&known.id))
            .collect();
        if extends.is_empty() {
            let best = tips[0];
            let served = HighWater { seq: best.body.seq, id: best.id() };
            return if served.seq <= known.seq {
                Verdict::Rollback { served, known }
            } else {
                Verdict::Diverged { known }
            };
        }
        tips = extends;
    }

    match tips.as_slice() {
        [one] => Verdict::Ok { head: one.id() },
        [a, b, ..] => classify_fork(valid, a, b),
        [] => unreachable!(),
    }
}

/// Latest common ancestor (highest seq) of two heads.
pub fn base_of(valid: &BTreeMap<Hash, Manifest>, a: Hash, b: Hash) -> Option<Hash> {
    let aa = ancestors(valid, a);
    let bb = ancestors(valid, b);
    aa.intersection(&bb)
        .filter_map(|h| valid.get(h))
        .max_by_key(|m| (m.body.seq, m.id()))
        .map(|m| m.id())
}

/// Names of sections whose plaintext differs from `base`.
pub fn changed(base: &Manifest, tip: &Manifest) -> BTreeMap<String, Class> {
    let mut out = BTreeMap::new();
    let names: BTreeSet<&String> = base
        .body
        .sections
        .iter()
        .chain(tip.body.sections.iter())
        .map(|s| &s.name)
        .collect();
    for n in names {
        let x = base.body.section(n);
        let y = tip.body.section(n);
        if x.map(|s| s.plain) != y.map(|s| s.plain) {
            let class = y.or(x).expect("present in one").class;
            out.insert(n.clone(), class);
        }
    }
    out
}

fn classify_fork(valid: &BTreeMap<Hash, Manifest>, a: &Manifest, b: &Manifest) -> Verdict {
    let (ai, bi) = (a.id(), b.id());
    let Some(base_id) = base_of(valid, ai, bi) else {
        return Verdict::Conflict { a: ai, b: bi, reason: "no common ancestor".into() };
    };
    let base = &valid[&base_id];

    let dev_a = a.body.devices != base.body.devices;
    let dev_b = b.body.devices != base.body.devices;
    if dev_a && dev_b && a.body.devices != b.body.devices {
        return Verdict::Conflict {
            a: ai,
            b: bi,
            reason: "AUTHORITY: device set changed concurrently on both branches".into(),
        };
    }

    let ca = changed(base, a);
    let cb = changed(base, b);
    for (name, class) in &ca {
        if *class == Class::Secret && cb.contains_key(name) {
            return Verdict::Conflict {
                a: ai,
                b: bi,
                reason: format!("SECRET: section '{name}' changed concurrently"),
            };
        }
    }
    Verdict::ForkMergeable { a: ai, b: bi, base: base_id }
}

/// How each section of a merge resolves. Metadata sections that changed on
/// both sides must be merged by the caller (which can decrypt them).
#[derive(Debug)]
pub enum Resolution {
    Take(SectionRef),
    MergeMetadata { a: SectionRef, b: SectionRef },
}

pub struct MergePlan {
    pub sections: Vec<(String, Resolution)>,
    /// Which branch supplies the anchor (the higher chain-verified one).
    pub anchor_from: Hash,
    pub devices_from: Hash,
}

pub fn plan_merge(valid: &BTreeMap<Hash, Manifest>, a: Hash, b: Hash, base: Hash) -> MergePlan {
    let (ma, mb, mbase) = (&valid[&a], &valid[&b], &valid[&base]);
    let ha = ma.body.anchor.as_ref().map(|x| x.height).unwrap_or(0);
    let hb = mb.body.anchor.as_ref().map(|x| x.height).unwrap_or(0);
    let (hi, lo) = if (hb, b) > (ha, a) { (mb, ma) } else { (ma, mb) };

    let ca = changed(mbase, ma);
    let cb = changed(mbase, mb);
    let names: BTreeSet<String> = [ma, mb]
        .iter()
        .flat_map(|m| m.body.sections.iter().map(|s| s.name.clone()))
        .collect();

    let mut sections = Vec::new();
    for n in names {
        let sa = ma.body.section(&n).cloned();
        let sb = mb.body.section(&n).cloned();
        let res = match (ca.contains_key(&n), cb.contains_key(&n)) {
            (true, false) => sa.map(Resolution::Take),
            (false, true) => sb.map(Resolution::Take),
            (false, false) => sa.or(sb).map(Resolution::Take),
            (true, true) => match (sa, sb) {
                (Some(x), Some(y)) if x.class == Class::Metadata => {
                    Some(Resolution::MergeMetadata { a: x, b: y })
                }
                // Derived / Progress: the branch with the higher anchor wins;
                // it is re-verified against the chain on restore.
                _ => hi.body.section(&n).or(lo.body.section(&n)).cloned().map(Resolution::Take),
            },
        };
        if let Some(r) = res {
            sections.push((n, r));
        }
    }

    let devices_from = if mb.body.devices != mbase.body.devices { b } else { a };
    MergePlan { sections, anchor_from: hi.id(), devices_from }
}
