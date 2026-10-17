//! The attack matrix from the demo, at kernel level (no Zcash, no I/O).

use hermit_kernel::assess::{assess, plan_merge, HighWater, Resolution, Verdict};
use hermit_kernel::hash::Hash;
use hermit_kernel::manifest::{Anchor, Body, Class, Evidence, Manifest, SectionRef};
use hermit_kernel::{seal, DeviceKeys};

fn sec(name: &str, class: Class, content: &str) -> SectionRef {
    let plain = Hash::of(b"test", content.as_bytes());
    SectionRef {
        name: name.into(),
        class,
        plain,
        blob: plain,
        len: content.len() as u64,
    }
}

fn anchor(h: u32) -> Option<Anchor> {
    Some(Anchor {
        network: "test".into(),
        height: h,
        block_hash: Hash::of(b"blk", &h.to_le_bytes()),
    })
}

struct World {
    a: DeviceKeys,
    b: DeviceKeys,
    g: Manifest,
}

fn world() -> World {
    let a = DeviceKeys::generate("laptop");
    let b = DeviceKeys::generate("phone");
    let devices = vec![a.public(), b.public()];
    let g = Body::genesis(
        "zcash/v1",
        &a,
        devices,
        vec![
            sec("wallet", Class::Progress, "db@100"),
            sec("labels", Class::Metadata, "{}"),
        ],
        anchor(100),
    )
    .sign(&a);
    World { a, b, g }
}

fn step(parent: &Manifest, who: &DeviceKeys, wallet: &str, labels: &str, h: u32) -> Manifest {
    Body::child(
        &[parent],
        who,
        parent.body.devices.clone(),
        vec![
            sec("wallet", Class::Progress, wallet),
            sec("labels", Class::Metadata, labels),
        ],
        anchor(h),
        "step",
    )
    .sign(who)
}

fn hw(m: &Manifest) -> HighWater {
    HighWater {
        seq: m.body.seq,
        id: m.id(),
    }
}

#[test]
fn linear_history_is_ok() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let s2 = step(&s1, &w.b, "db@120", "{}", 120);
    let r = assess(vec![w.g.clone(), s1, s2.clone()], w.g.id(), Some(hw(&w.g)));
    assert_eq!(r.verdict, Verdict::Ok { head: s2.id() });
    assert!(r.rejected.is_empty());
}

#[test]
fn stale_store_is_rollback() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let s2 = step(&s1, &w.a, "db@120", "{}", 120);
    // Device has accepted s2; store hides it and serves only up to s1.
    let r = assess(vec![w.g.clone(), s1.clone()], w.g.id(), Some(hw(&s2)));
    assert_eq!(
        r.verdict,
        Verdict::Rollback {
            served: hw(&s1),
            known: hw(&s2)
        }
    );
    assert_eq!(r.verdict.code(), 20);
}

#[test]
fn metadata_and_progress_fork_is_mergeable() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let xa = step(&s1, &w.a, "db@130", "{rent}", 130);
    let xb = step(&s1, &w.b, "db@125", "{bob}", 125);
    let r = assess(
        vec![w.g.clone(), s1.clone(), xa.clone(), xb.clone()],
        w.g.id(),
        Some(hw(&s1)),
    );
    let Verdict::ForkMergeable { a, b, base } = r.verdict else {
        panic!("{:?}", r.verdict)
    };
    assert_eq!(base, s1.id());
    let plan = plan_merge(&r.valid, a, b, base);
    assert_eq!(plan.anchor_from, xa.id(), "higher anchor wins");
    let wallet = plan.sections.iter().find(|(n, _)| n == "wallet").unwrap();
    assert!(matches!(&wallet.1, Resolution::Take(s) if s.plain == Hash::of(b"test", b"db@130")));
    let labels = plan.sections.iter().find(|(n, _)| n == "labels").unwrap();
    assert!(matches!(labels.1, Resolution::MergeMetadata { .. }));
}

#[test]
fn own_branch_accepted_does_not_hide_the_other_branch() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let xa = step(&s1, &w.a, "db@130", "{rent}", 130);
    let xb = step(&s1, &w.b, "db@125", "{bob}", 125);
    // Device A already accepted its own xa, then syncs and sees xb.
    let r = assess(
        vec![w.g.clone(), s1, xa.clone(), xb],
        w.g.id(),
        Some(hw(&xa)),
    );
    assert!(
        matches!(r.verdict, Verdict::ForkMergeable { .. }),
        "{:?}",
        r.verdict
    );
}

#[test]
fn concurrent_authority_change_is_conflict() {
    let w = world();
    let c = DeviceKeys::generate("tablet");
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    // A adds a tablet; B concurrently removes A.
    let mut add = s1.body.devices.clone();
    add.push(c.public());
    let xa = Body::child(
        &[&s1],
        &w.a,
        add,
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "add tablet",
    )
    .sign(&w.a);
    let xb = Body::child(
        &[&s1],
        &w.b,
        vec![w.b.public()],
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "revoke laptop",
    )
    .sign(&w.b);
    let r = assess(vec![w.g.clone(), s1, xa, xb], w.g.id(), None);
    assert!(
        matches!(r.verdict, Verdict::Conflict { ref reason, .. } if reason.starts_with("AUTHORITY")),
        "{:?}",
        r.verdict
    );
    assert_eq!(r.verdict.code(), 22);
}

#[test]
fn unknown_device_and_tampering_are_rejected() {
    let w = world();
    let mallory = DeviceKeys::generate("mallory");
    let evil = step(&w.g, &mallory, "db@999", "{}", 999);
    let mut tampered = step(&w.g, &w.a, "db@110", "{}", 110);
    tampered.body.note = "edited after signing".into();
    let mut forged_root = step(&w.g, &w.a, "db@111", "{}", 111);
    forged_root.body.sections[0].plain = Hash::of(b"x", b"y");
    let r = assess(
        vec![w.g.clone(), evil, tampered, forged_root],
        w.g.id(),
        None,
    );
    assert_eq!(r.verdict, Verdict::Ok { head: w.g.id() });
    assert_eq!(r.rejected.len(), 3);
    assert!(r
        .rejected
        .iter()
        .any(|(_, e)| e.starts_with("UNKNOWN_DEVICE")));
}

#[test]
fn foreign_genesis_is_rejected() {
    let w = world();
    let other = world();
    let r = assess(vec![other.g.clone()], w.g.id(), None);
    assert_eq!(r.verdict, Verdict::Empty);
}

#[test]
fn revoked_device_cannot_author() {
    let w = world();
    let s1 = Body::child(
        &[&w.g],
        &w.a,
        vec![w.a.public()],
        w.g.body.sections.clone(),
        w.g.body.anchor.clone(),
        "revoke phone",
    )
    .sign(&w.a);
    let s2 = step(&s1, &w.b, "db@200", "{}", 200);
    let r = assess(vec![w.g.clone(), s1.clone(), s2], w.g.id(), None);
    assert_eq!(r.verdict, Verdict::Ok { head: s1.id() });
    assert_eq!(r.rejected.len(), 1);
}

#[test]
fn seal_roundtrip_and_non_recipient() {
    let w = world();
    let outsider = DeviceKeys::generate("outsider");
    let ct = seal::seal(b"secret wallet bytes", &w.g.body.devices).unwrap();
    assert_eq!(
        seal::open(&ct, &w.b.identity()).unwrap(),
        b"secret wallet bytes"
    );
    assert!(seal::open(&ct, &outsider.identity()).is_err());
    assert!(!ct.windows(6).any(|x| x == b"secret"));
}

#[test]
fn signature_evidence_is_required() {
    let w = world();
    let mut s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    s1.evidence = vec![Evidence::Signature { sig: [0; 64] }];
    let r = assess(vec![w.g.clone(), s1], w.g.id(), None);
    assert_eq!(r.rejected.len(), 1);
}

#[test]
fn conflict_is_settled_only_by_a_device_both_branches_trust() {
    let w = world();
    let c = DeviceKeys::generate("tablet");
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let mut add = s1.body.devices.clone();
    add.push(c.public());
    let xa = Body::child(
        &[&s1],
        &w.a,
        add,
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "add tablet",
    )
    .sign(&w.a);
    let xb = Body::child(
        &[&s1],
        &w.b,
        vec![w.b.public()],
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "revoke laptop",
    )
    .sign(&w.b);

    // Laptop was revoked on xb, so its resolution has no standing there.
    let by_laptop = Body::child(
        &[&xa, &xb],
        &w.a,
        xa.body.devices.clone(),
        xa.body.sections.clone(),
        xa.body.anchor.clone(),
        "resolve",
    )
    .sign(&w.a);
    let r = assess(
        vec![w.g.clone(), s1.clone(), xa.clone(), xb.clone(), by_laptop],
        w.g.id(),
        None,
    );
    assert!(
        matches!(r.verdict, Verdict::Conflict { .. }),
        "{:?}",
        r.verdict
    );

    // Phone is trusted on both branches; keeping xb's authority settles it.
    let by_phone = Body::child(
        &[&xb, &xa],
        &w.b,
        xb.body.devices.clone(),
        xb.body.sections.clone(),
        xb.body.anchor.clone(),
        "resolve",
    )
    .sign(&w.b);
    let r = assess(
        vec![w.g.clone(), s1, xa, xb, by_phone.clone()],
        w.g.id(),
        None,
    );
    assert_eq!(
        r.verdict,
        Verdict::Ok {
            head: by_phone.id()
        }
    );
}
