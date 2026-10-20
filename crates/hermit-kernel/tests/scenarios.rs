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
    .unwrap()
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
    .unwrap()
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
    .unwrap()
    .sign(&w.a);
    let xb = Body::child(
        &[&s1],
        &w.b,
        vec![w.b.public()],
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "revoke laptop",
    )
    .unwrap()
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
    tampered.body.note = b"edited after signing".to_vec();
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
    .unwrap()
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
    .unwrap()
    .sign(&w.a);
    let xb = Body::child(
        &[&s1],
        &w.b,
        vec![w.b.public()],
        s1.body.sections.clone(),
        s1.body.anchor.clone(),
        "revoke laptop",
    )
    .unwrap()
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
    .unwrap()
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
    .unwrap()
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

#[test]
fn notes_are_sealed_from_storage() {
    let w = world();
    let outsider = DeviceKeys::generate("relay");
    let m = Body::child(
        &[&w.g],
        &w.a,
        w.g.body.devices.clone(),
        w.g.body.sections.clone(),
        w.g.body.anchor.clone(),
        "label contact:alice = u1alice",
    )
    .unwrap()
    .sign(&w.a);
    let stored = stored_bytes(&m);
    assert!(!stored.windows(7).any(|x| x == b"u1alice"));
    assert_eq!(
        m.note(&w.b.identity()).as_deref(),
        Some("label contact:alice = u1alice")
    );
    assert_eq!(m.note(&outsider.identity()), None);
}

fn stored_bytes(m: &Manifest) -> Vec<u8> {
    hermit_kernel::hash::cbor(m)
}

#[test]
fn device_sets_must_be_unambiguous() {
    let w = world();
    let other_phone = DeviceKeys::generate("phone");
    let mut twice_named = w.g.body.devices.clone();
    twice_named.push(other_phone.public());
    let mut twice_keyed = w.g.body.devices.clone();
    let mut renamed = w.a.public();
    renamed.name = "laptop-2".into();
    twice_keyed.push(renamed);
    let mut unnamed = w.g.body.devices.clone();
    unnamed[1].name = " ".into();

    for (devices, why) in [
        (twice_named, "used twice"),
        (twice_keyed, "used twice"),
        (unnamed, "empty name"),
        (vec![], "empty"),
    ] {
        let m = Body::child(
            &[&w.g],
            &w.a,
            devices.clone(),
            w.g.body.sections.clone(),
            w.g.body.anchor.clone(),
            "authority change",
        );
        // An empty set cannot even be sealed to; anything else must be
        // rejected by the kernel, not just by a well-behaved client.
        let Ok(body) = m else {
            assert!(devices.is_empty());
            continue;
        };
        let err = body.sign(&w.a).check_self().unwrap_err();
        assert!(err.contains(why), "{err}");
    }
}

#[test]
fn junk_evidence_is_rejected_before_verification() {
    let w = world();
    let mut m = step(&w.g, &w.a, "db@110", "{}", 110);
    let real = m.evidence[0].clone();
    m.evidence = std::iter::repeat_n(Evidence::Signature { sig: [0; 64] }, 10_000)
        .chain([real])
        .collect();
    let err = m.check_self().unwrap_err();
    assert!(err.contains("too much evidence"), "{err}");
}

fn child_with(
    parent: &Manifest,
    who: &DeviceKeys,
    devices: Vec<hermit_kernel::Device>,
    sections: Vec<SectionRef>,
    note: &str,
) -> Manifest {
    Body::child(
        &[parent],
        who,
        devices,
        sections,
        parent.body.anchor.clone(),
        note,
    )
    .unwrap()
    .sign(who)
}

#[test]
fn concurrent_secret_edits_conflict_whichever_branch_sorts_first() {
    // Run many times: ids are random, so the branch order varies.
    for _ in 0..24 {
        let w = world();
        let base = child_with(
            &w.g,
            &w.a,
            w.g.body.devices.clone(),
            vec![
                sec("labels", Class::Metadata, "{}"),
                sec("spend", Class::Secret, "k0"),
            ],
            "add spend key",
        );
        // One branch rewrites the secret *and* reclassifies it as metadata.
        let xa = child_with(
            &base,
            &w.a,
            base.body.devices.clone(),
            vec![
                sec("labels", Class::Metadata, "{}"),
                sec("spend", Class::Metadata, "k1"),
            ],
            "a",
        );
        let xb = child_with(
            &base,
            &w.b,
            base.body.devices.clone(),
            vec![
                sec("labels", Class::Metadata, "{}"),
                sec("spend", Class::Secret, "k2"),
            ],
            "b",
        );
        let r = assess(vec![w.g.clone(), base, xa, xb], w.g.id(), None);
        assert!(
            matches!(r.verdict, Verdict::Conflict { .. }),
            "{:?}",
            r.verdict
        );
    }
}

#[test]
fn a_revoked_device_cannot_slip_writes_in_through_a_concurrent_branch() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    // Laptop revokes the phone...
    let revoke = child_with(
        &s1,
        &w.a,
        vec![w.a.public()],
        s1.body.sections.clone(),
        "revoke phone",
    );
    // ...while the phone, concurrently, keeps writing.
    let sneak = step(&s1, &w.b, "db@110", "{evil}", 110);
    let r = assess(vec![w.g.clone(), s1, revoke, sneak], w.g.id(), None);
    assert!(
        matches!(r.verdict, Verdict::Conflict { ref reason, .. } if reason.contains("AUTHORITY")),
        "{:?}",
        r.verdict
    );
}

#[test]
fn a_device_added_on_one_branch_may_write_there() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let tablet = DeviceKeys::generate("tablet");
    let mut devices = s1.body.devices.clone();
    devices.push(tablet.public());
    let add = child_with(&s1, &w.a, devices, s1.body.sections.clone(), "add tablet");
    let by_tablet = step(&add, &tablet, "db@111", "{tablet}", 111);
    let by_phone = step(&s1, &w.b, "db@112", "{phone}", 112);
    let r = assess(
        vec![w.g.clone(), s1, add, by_tablet, by_phone],
        w.g.id(),
        None,
    );
    assert!(
        matches!(r.verdict, Verdict::ForkMergeable { .. }),
        "{:?}",
        r.verdict
    );
}

#[test]
fn with_three_heads_this_devices_branch_is_never_left_out() {
    let w = world();
    let mine = step(&w.g, &w.a, "db@101", "{mine}", 101);
    let x1 = step(&w.g, &w.b, "db@102", "{x1}", 102);
    let x2 = step(&x1, &w.b, "db@103", "{x2}", 103);
    let y1 = step(&w.g, &w.b, "db@104", "{y1}", 104);
    let y2 = step(&y1, &w.b, "db@105", "{y2}", 105);
    let r = assess(
        vec![w.g.clone(), mine.clone(), x1, x2, y1, y2],
        w.g.id(),
        Some(hw(&mine)),
    );
    match r.verdict {
        Verdict::ForkMergeable { a, b, .. } => {
            assert!(a == mine.id() || b == mine.id(), "own branch left out")
        }
        Verdict::Conflict { .. } => {}
        v => panic!("{v:?}"),
    }
}

#[test]
fn reordering_the_same_devices_is_not_an_authority_change() {
    let w = world();
    let s1 = step(&w.g, &w.a, "db@110", "{}", 110);
    let mut reversed = s1.body.devices.clone();
    reversed.reverse();
    let xa = child_with(&s1, &w.a, reversed, s1.body.sections.clone(), "reorder");
    let xb = step(&s1, &w.b, "db@111", "{bob}", 111);
    let r = assess(vec![w.g.clone(), s1, xa, xb], w.g.id(), None);
    assert!(
        matches!(r.verdict, Verdict::ForkMergeable { .. }),
        "{:?}",
        r.verdict
    );
}

#[test]
fn device_sets_must_name_real_age_recipients() {
    let w = world();
    // Built by hand: Body::child would refuse to seal to it in the first place.
    let mut body = Body::child(
        &[&w.g],
        &w.a,
        w.g.body.devices.clone(),
        w.g.body.sections.clone(),
        None,
        "x",
    )
    .unwrap();
    body.devices[1].recipient = "not-an-age-recipient".into();
    let err = body.sign(&w.a).check_self().unwrap_err();
    assert!(err.contains("recipient"), "{err}");
}
