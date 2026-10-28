//! Hermit's kernel in the browser.
//!
//! Three devices share one capsule through a relay that can be told to
//! misbehave, and an optional witness that cosigns every head it sees. Every
//! section is sealed with age to the authorized devices, every transition is
//! signed, and every verdict comes from `hermit_kernel::assess`, the same
//! code the command line runs. Only the Zcash wallet is left out: there is
//! no chain here, so capsules carry labels alone and no anchor.

use anyhow::{anyhow, bail, Result};
use hermit_kernel::assess::{assess, plan_merge, Assessment, HighWater, Resolution, Verdict};
use hermit_kernel::hash::Hash;
use hermit_kernel::manifest::{Body, Class, Evidence, Manifest, SectionRef};
use hermit_kernel::metadata::Labels;
use hermit_kernel::{seal, Device, DeviceKeys};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

const LABELS: &str = "labels";
const NAMES: [&str; 3] = ["laptop", "phone", "tablet"];

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Honest,
    /// Serves everything but the newest transition.
    Hide,
    /// Flips a byte in the newest transition.
    Corrupt,
    /// Appends a transition signed by a key of its own.
    Forge,
}

struct Node {
    keys: DeviceKeys,
    /// Every transition this device holds, published or not.
    replica: Vec<Manifest>,
    hwm: Option<HighWater>,
    offline: bool,
}

#[wasm_bindgen]
pub struct Lab {
    nodes: Vec<Node>,
    genesis: Hash,
    relay: Vec<Manifest>,
    /// Content-addressed ciphertext. A blob's address is its hash, so storage
    /// cannot swap one undetected; the attacks target manifests.
    blobs: BTreeMap<Hash, Vec<u8>>,
    mode: Mode,
    witness: Option<HighWater>,
    use_witness: bool,
    rogue: DeviceKeys,
}

fn hw(m: &Manifest) -> HighWater {
    HighWater {
        seq: m.body.seq,
        id: m.id(),
    }
}

fn newer(a: Option<HighWater>, b: Option<HighWater>) -> Option<HighWater> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.seq > x.seq { y } else { x }),
        (x, y) => x.or(y),
    }
}

fn union(into: &mut Vec<Manifest>, from: &[Manifest]) {
    for m in from {
        if !into.iter().any(|x| x.id() == m.id()) {
            into.push(m.clone());
        }
    }
}

fn describe(v: &Verdict) -> String {
    match v {
        Verdict::Ok { head } => format!("OK: head {}", head.short()),
        Verdict::Rollback { served, known } => format!(
            "ROLLBACK DETECTED: the relay serves S{} ({}) but S{} ({}) is known to exist",
            served.seq,
            served.id.short(),
            known.seq,
            known.id.short()
        ),
        Verdict::ForkMergeable { a, b, base } => format!(
            "FORK: heads {} and {} diverged from {}. Only labels changed, so it merges.",
            a.short(),
            b.short(),
            base.short()
        ),
        Verdict::Conflict { a, b, reason } => format!(
            "CONFLICT: heads {} and {}: {reason}. Nothing is merged automatically.",
            a.short(),
            b.short()
        ),
        Verdict::Diverged { known } => format!(
            "DIVERGED: the relay's history does not extend S{} ({})",
            known.seq,
            known.id.short()
        ),
        Verdict::Empty => "EMPTY: no valid state for this capsule".into(),
    }
}

fn verdict_kind(v: &Verdict) -> &'static str {
    match v {
        Verdict::Ok { .. } => "ok",
        Verdict::Rollback { .. } => "rollback",
        Verdict::ForkMergeable { .. } => "fork",
        Verdict::Conflict { .. } => "conflict",
        Verdict::Diverged { .. } => "diverged",
        Verdict::Empty => "empty",
    }
}

fn reply(r: Result<Value>) -> String {
    match r {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "ok": false, "kind": "error", "text": format!("{e:#}") }).to_string(),
    }
}

impl Lab {
    fn node(&self, name: &str) -> Result<usize> {
        NAMES
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| anyhow!("no device '{name}'"))
    }

    fn put(&mut self, plain: &[u8], class: Class, name: &str, to: &[Device]) -> Result<SectionRef> {
        let ct = seal::seal(plain, to)?;
        let blob = Hash::of(b"ZcBlob_v1", &ct);
        self.blobs.insert(blob, ct);
        Ok(SectionRef {
            name: name.into(),
            class,
            plain: Hash::of(b"ZcPlain_v1", plain),
            blob,
            len: seal::framed_len(plain.len()),
        })
    }

    fn read(&self, n: usize, s: &SectionRef) -> Result<Vec<u8>> {
        let ct = self
            .blobs
            .get(&s.blob)
            .ok_or_else(|| anyhow!("blob missing"))?;
        let pt = seal::open(ct, &self.nodes[n].keys.identity())?;
        if Hash::of(b"ZcPlain_v1", &pt) != s.plain {
            bail!("section '{}' does not match its committed hash", s.name);
        }
        Ok(pt)
    }

    fn labels_at(&self, n: usize, m: &Manifest) -> Result<Labels> {
        match m.body.section(LABELS) {
            Some(s) => Labels::decode(&self.read(n, s)?),
            None => Ok(Labels::default()),
        }
    }

    /// What the relay hands out right now, according to its mode.
    fn served(&self) -> Vec<Manifest> {
        let mut out = self.relay.clone();
        let top = out.iter().map(|m| m.body.seq).max().unwrap_or(0);
        match self.mode {
            Mode::Honest => {}
            Mode::Hide => {
                if top > 0 {
                    out.retain(|m| m.body.seq < top);
                }
            }
            Mode::Corrupt => {
                if let Some(m) = out.iter_mut().rfind(|m| m.body.seq == top) {
                    if let Some(byte) = m.body.note.last_mut() {
                        *byte ^= 1;
                    }
                }
            }
            Mode::Forge => {
                if let Some(tip) = self.relay.iter().rfind(|m| m.body.seq == top) {
                    let mut devices = tip.body.devices.clone();
                    devices.push(self.rogue.public());
                    if let Ok(b) = Body::child(
                        &[tip],
                        &self.rogue,
                        devices,
                        tip.body.sections.clone(),
                        None,
                        "relay: add my own key",
                    ) {
                        out.push(b.sign(&self.rogue));
                    }
                }
            }
        }
        out
    }

    /// Fetch from the relay (unless offline), assess, and accept an OK head.
    fn look(&mut self, n: usize) -> Assessment {
        let mut offered = self.nodes[n].replica.clone();
        if !self.nodes[n].offline {
            union(&mut offered, &self.served());
        }
        let floor = if self.use_witness && !self.nodes[n].offline {
            newer(self.nodes[n].hwm, self.witness)
        } else {
            self.nodes[n].hwm
        };
        let a = assess(offered, self.genesis, floor);
        let valid: Vec<Manifest> = a.valid.values().cloned().collect();
        union(&mut self.nodes[n].replica, &valid);
        if let Verdict::Ok { head } = a.verdict {
            self.nodes[n].hwm = Some(hw(&a.valid[&head]));
        }
        a
    }

    /// Publish what this device holds and the relay lacks.
    fn publish(&mut self, n: usize) {
        if self.nodes[n].offline {
            return;
        }
        let mine = self.nodes[n].replica.clone();
        union(&mut self.relay, &mine);
        let top = self.relay.iter().max_by_key(|m| m.body.seq).map(hw);
        self.witness = newer(self.witness, top);
    }

    fn commit(&mut self, n: usize, body: Body) -> Result<Manifest> {
        let m = body.sign(&self.nodes[n].keys);
        m.check_self().map_err(|e| anyhow!(e))?;
        self.nodes[n].replica.push(m.clone());
        self.nodes[n].hwm = Some(hw(&m));
        self.publish(n);
        Ok(m)
    }

    fn head(&mut self, n: usize) -> Result<(Assessment, Manifest)> {
        let a = self.look(n);
        match a.verdict {
            Verdict::Ok { head } => {
                let m = a.valid[&head].clone();
                Ok((a, m))
            }
            ref v => bail!("{}", describe(v)),
        }
    }

    fn reseal(
        &mut self,
        n: usize,
        sections: &[SectionRef],
        to: &[Device],
    ) -> Result<Vec<SectionRef>> {
        sections
            .iter()
            .map(|s| {
                let pt = self.read(n, s)?;
                self.put(&pt, s.class, &s.name, to)
            })
            .collect()
    }

    fn report(&self, n: usize, a: &Assessment) -> Value {
        let labels = match a.verdict {
            Verdict::Ok { head } => self
                .labels_at(n, &a.valid[&head])
                .map(|l| l.live().map(|(k, v)| json!([k, v])).collect::<Vec<_>>())
                .ok(),
            _ => None,
        };
        json!({
            "ok": matches!(a.verdict, Verdict::Ok { .. }),
            "kind": verdict_kind(&a.verdict),
            "code": a.verdict.code(),
            "text": describe(&a.verdict),
            "rejected": a.rejected.iter()
                .map(|(id, why)| format!("rejected {}: {why}", id.short()))
                .collect::<Vec<_>>(),
            "labels": labels,
        })
    }

    fn do_label(&mut self, n: usize, key: &str, value: &str) -> Result<Value> {
        let (_, head) = self.head(n)?;
        let mut labels = self.labels_at(n, &head)?;
        labels.set(
            key,
            Some(value.to_string()),
            self.nodes[n].keys.public().sign_pk,
        );
        let devices = head.body.devices.clone();
        let mut sections: Vec<SectionRef> = head
            .body
            .sections
            .iter()
            .filter(|s| s.name != LABELS)
            .cloned()
            .collect();
        sections.push(self.put(&labels.encode(), Class::Metadata, LABELS, &devices)?);
        let body = Body::child(
            &[&head],
            &self.nodes[n].keys,
            devices,
            sections,
            None,
            &format!("label {key} = {value}"),
        )?;
        let m = self.commit(n, body)?;
        Ok(json!({
            "ok": true, "kind": "write",
            "text": format!("S{} {} by {}: label {key} = {value}{}", m.body.seq, m.id().short(),
                NAMES[n], if self.nodes[n].offline { " (kept on this device)" } else { "" }),
        }))
    }

    fn do_devices(&mut self, n: usize, add: Option<&str>, revoke: Option<&str>) -> Result<Value> {
        let (_, head) = self.head(n)?;
        let mut devices = head.body.devices.clone();
        let note = if let Some(name) = add {
            if devices.iter().any(|d| d.name == name) {
                bail!("{name} is already authorized");
            }
            devices.push(self.nodes[self.node(name)?].keys.public());
            format!("authorize device {name}")
        } else {
            let name = revoke.unwrap_or_default();
            if name == NAMES[n] {
                bail!("a device cannot revoke itself here");
            }
            let before = devices.len();
            devices.retain(|d| d.name != name);
            if devices.len() == before {
                bail!("{name} is not authorized");
            }
            format!("revoke device {name}")
        };
        let sections = self.reseal(n, &head.body.sections, &devices)?;
        let body = Body::child(
            &[&head],
            &self.nodes[n].keys,
            devices,
            sections,
            None,
            &note,
        )?;
        let m = self.commit(n, body)?;
        Ok(json!({
            "ok": true, "kind": "write",
            "text": format!("S{} {} by {}: {note}, every section re-sealed{}", m.body.seq,
                m.id().short(), NAMES[n],
                if self.nodes[n].offline { " (kept on this device)" } else { "" }),
        }))
    }

    fn do_merge(&mut self, n: usize) -> Result<Value> {
        let a = self.look(n);
        let Verdict::ForkMergeable { a: x, b: y, base } = a.verdict else {
            bail!("nothing to merge: {}", describe(&a.verdict));
        };
        let plan = plan_merge(&a.valid, x, y, base);
        let devices = a.valid[&plan.devices_from].body.devices.clone();
        let mut sections = Vec::new();
        for (name, res) in plan.sections {
            let s = match res {
                Resolution::Take(s) => {
                    let pt = self.read(n, &s)?;
                    self.put(&pt, s.class, &name, &devices)?
                }
                Resolution::MergeMetadata { a: p, b: q } => {
                    let merged = Labels::decode(&self.read(n, &p)?)?
                        .merge(&Labels::decode(&self.read(n, &q)?)?);
                    self.put(&merged.encode(), Class::Metadata, &name, &devices)?
                }
            };
            sections.push(s);
        }
        let parents = [&a.valid[&x], &a.valid[&y]];
        let body = Body::child(
            &parents,
            &self.nodes[n].keys,
            devices,
            sections,
            None,
            "merge",
        )?;
        let m = self.commit(n, body)?;
        Ok(json!({
            "ok": true, "kind": "write",
            "text": format!("S{} {} by {}: merged {} and {}, labels from both sides kept",
                m.body.seq, m.id().short(), NAMES[n], x.short(), y.short()),
        }))
    }

    fn do_resolve(&mut self, n: usize) -> Result<Value> {
        let a = self.look(n);
        let Verdict::Conflict { a: x, b: y, .. } = a.verdict else {
            bail!("nothing to resolve: {}", describe(&a.verdict));
        };
        // Keep this device's own authority; reconcile labels as a merge does.
        let mine = |id: &Hash| a.valid[id].body.author == self.nodes[n].keys.public().sign_pk;
        let (keep, drop) = if mine(&x) { (x, y) } else { (y, x) };
        let devices = a.valid[&keep].body.devices.clone();
        let mut labels = Labels::default();
        for id in [keep, drop] {
            if let Ok(l) = self.labels_at(n, &a.valid[&id]) {
                labels = labels.merge(&l);
            }
        }
        let sections = vec![self.put(&labels.encode(), Class::Metadata, LABELS, &devices)?];
        let parents = [&a.valid[&keep], &a.valid[&drop]];
        let note = format!("resolve: keep {} over {}", keep.short(), drop.short());
        let body = Body::child(
            &parents,
            &self.nodes[n].keys,
            devices,
            sections,
            None,
            &note,
        )?;
        let m = self.commit(n, body)?;
        Ok(json!({
            "ok": true, "kind": "write",
            "text": format!("S{} {} by {}: {note}; authority from {}'s branch",
                m.body.seq, m.id().short(), NAMES[n], NAMES[n]),
        }))
    }
}

#[wasm_bindgen]
impl Lab {
    /// A fresh capsule created by the laptop, shared with the phone. The
    /// tablet exists but is not authorized yet.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Lab, JsError> {
        let keys: Vec<DeviceKeys> = NAMES.iter().map(|n| DeviceKeys::generate(n)).collect();
        let devices = vec![keys[0].public(), keys[1].public()];
        let mut lab = Lab {
            nodes: Vec::new(),
            genesis: Hash([0; 32]),
            relay: Vec::new(),
            blobs: BTreeMap::new(),
            mode: Mode::Honest,
            witness: None,
            use_witness: true,
            rogue: DeviceKeys::generate("relay"),
        };
        let labels = Labels::default();
        let section = lab
            .put(&labels.encode(), Class::Metadata, LABELS, &devices)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let g = Body::genesis("zcash/v1", &keys[0], devices, vec![section], None)
            .map_err(|e| JsError::new(&e.to_string()))?
            .sign(&keys[0]);
        lab.genesis = g.id();
        lab.nodes = keys
            .into_iter()
            .enumerate()
            .map(|(i, keys)| Node {
                keys,
                replica: if i < 2 { vec![g.clone()] } else { Vec::new() },
                hwm: (i < 2).then(|| hw(&g)),
                offline: false,
            })
            .collect();
        lab.relay.push(g.clone());
        lab.witness = Some(hw(&g));
        Ok(lab)
    }

    pub fn label(&mut self, device: &str, key: &str, value: &str) -> String {
        reply(self.node(device).and_then(|n| self.do_label(n, key, value)))
    }

    pub fn check(&mut self, device: &str) -> String {
        reply(self.node(device).map(|n| {
            let a = self.look(n);
            self.report(n, &a)
        }))
    }

    pub fn merge(&mut self, device: &str) -> String {
        reply(self.node(device).and_then(|n| self.do_merge(n)))
    }

    pub fn resolve(&mut self, device: &str) -> String {
        reply(self.node(device).and_then(|n| self.do_resolve(n)))
    }

    pub fn authorize(&mut self, device: &str, other: &str) -> String {
        reply(
            self.node(device)
                .and_then(|n| self.do_devices(n, Some(other), None)),
        )
    }

    pub fn revoke(&mut self, device: &str, other: &str) -> String {
        reply(
            self.node(device)
                .and_then(|n| self.do_devices(n, None, Some(other))),
        )
    }

    /// Going back online publishes what the device wrote meanwhile.
    pub fn set_offline(&mut self, device: &str, offline: bool) -> String {
        reply(self.node(device).map(|n| {
            self.nodes[n].offline = offline;
            self.publish(n);
            json!({ "ok": true, "kind": "info",
                "text": format!("{device} is {}", if offline { "offline" } else { "online" }) })
        }))
    }

    pub fn set_mode(&mut self, mode: &str) -> String {
        self.mode = match mode {
            "hide" => Mode::Hide,
            "corrupt" => Mode::Corrupt,
            "forge" => Mode::Forge,
            _ => Mode::Honest,
        };
        json!({ "ok": true }).to_string()
    }

    pub fn set_witness(&mut self, on: bool) {
        self.use_witness = on;
    }

    /// Everything the relay holds, as storage sees it.
    pub fn relay_view(&self) -> String {
        let mut ms = self.relay.clone();
        ms.sort_by_key(|m| m.body.seq);
        let rows: Vec<Value> = ms
            .iter()
            .map(|m| {
                let b = &m.body;
                json!({
                    "seq": b.seq,
                    "id": m.id().short(),
                    "parents": b.parents.iter().map(|p| p.short()).collect::<Vec<_>>(),
                    "author": hex::encode(&b.author[..4]),
                    "devices": b.devices.iter().map(|d| d.name.clone()).collect::<Vec<_>>(),
                    "sections": b.sections.iter()
                        .map(|s| format!("{} {:?} {} bytes", s.name, s.class, s.len))
                        .collect::<Vec<_>>(),
                    "note": format!("{} sealed bytes", b.note.len()),
                    "signed": m.evidence.iter().any(|e| matches!(e, Evidence::Signature { .. })),
                })
            })
            .collect();
        let sample = ms
            .last()
            .and_then(|m| m.body.sections.first())
            .and_then(|s| self.blobs.get(&s.blob))
            .map(|ct| {
                let head = &ct[..ct.len().min(160)];
                String::from_utf8_lossy(head)
                    .chars()
                    .map(|c| {
                        if c.is_ascii_graphic() || c == ' ' || c == '\n' {
                            c
                        } else {
                            '·'
                        }
                    })
                    .collect::<String>()
            });
        json!({
            "manifests": rows,
            "blobs": self.blobs.len(),
            "sample": sample,
            "witness": self.witness.map(|w| format!("S{} {}", w.seq, w.id.short())),
        })
        .to_string()
    }

    /// The device's own view: what it last accepted and the labels it can
    /// decrypt there. Nothing is fetched.
    pub fn device_view(&self, device: &str) -> String {
        reply(self.node(device).map(|n| {
            let node = &self.nodes[n];
            let accepted = node
                .hwm
                .and_then(|h| node.replica.iter().find(|m| m.id() == h.id));
            let labels = accepted.map(|m| match self.labels_at(n, m) {
                Ok(l) => json!(l.live().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()),
                Err(_) => json!(null),
            });
            json!({
                "ok": true,
                "offline": node.offline,
                "hwm": node.hwm.map(|h| format!("S{} {}", h.seq, h.id.short())),
                "labels": labels,
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(s: &str) -> String {
        serde_json::from_str::<Value>(s).unwrap()["kind"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_label_written_on_the_laptop_reaches_the_phone() {
        let mut lab = Lab::new().unwrap();
        assert_eq!(kind(&lab.label("laptop", "tx:rent", "October")), "write");
        let r: Value = serde_json::from_str(&lab.check("phone")).unwrap();
        assert_eq!(r["kind"], "ok");
        assert_eq!(r["labels"][0], json!(["tx:rent", "October"]));
    }

    #[test]
    fn every_relay_attack_is_caught() {
        for (mode, want) in [
            ("hide", "rollback"),
            ("corrupt", "rollback"),
            ("forge", "ok"),
        ] {
            let mut lab = Lab::new().unwrap();
            lab.label("laptop", "a", "1");
            lab.check("phone");
            lab.label("laptop", "b", "2");
            lab.set_mode(mode);
            let r: Value = serde_json::from_str(&lab.check("phone")).unwrap();
            assert_eq!(r["kind"], want, "{mode}: {r}");
            if mode != "hide" {
                assert!(!r["rejected"].as_array().unwrap().is_empty(), "{mode}");
            }
        }
    }

    #[test]
    fn hiding_from_a_device_without_the_witness_goes_unnoticed() {
        let mut lab = Lab::new().unwrap();
        lab.set_witness(false);
        lab.label("laptop", "a", "1");
        lab.set_mode("hide");
        assert_eq!(kind(&lab.check("phone")), "ok");
    }

    #[test]
    fn offline_label_edits_fork_and_merge() {
        let mut lab = Lab::new().unwrap();
        lab.set_offline("phone", true);
        lab.label("laptop", "contact:alice", "u1alice");
        lab.label("phone", "contact:bob", "u1bob");
        lab.set_offline("phone", false);
        assert_eq!(kind(&lab.check("phone")), "fork");
        assert_eq!(kind(&lab.merge("phone")), "write");
        let r: Value = serde_json::from_str(&lab.check("laptop")).unwrap();
        assert_eq!(r["labels"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn concurrent_authority_changes_conflict_until_resolved() {
        let mut lab = Lab::new().unwrap();
        lab.set_offline("phone", true);
        lab.authorize("laptop", "tablet");
        lab.revoke("phone", "laptop");
        lab.set_offline("phone", false);
        assert_eq!(kind(&lab.check("phone")), "conflict");
        assert_eq!(kind(&lab.merge("phone")), "error");
        assert_eq!(kind(&lab.resolve("phone")), "write");
        assert_eq!(kind(&lab.check("phone")), "ok");
        // The revoked laptop can no longer write anything the phone accepts.
        assert_eq!(kind(&lab.check("laptop")), "ok");
    }
}
