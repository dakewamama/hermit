//! Turning concurrent histories back into one: automatic merges, and
//! human-chosen resolutions of authority conflicts.

use crate::ctx::{refuse_verdict, Ctx};
use anyhow::{Context, Result};
use hermit_kernel::assess::{base_of, plan_merge, Verdict};

pub fn merge(ctx: &Ctx) -> Result<()> {
    let a = ctx.assess()?;
    let Verdict::ForkMergeable { a: ha, b: hb, base } = a.verdict else {
        return Err(refuse_verdict(&a.verdict));
    };
    let plan = plan_merge(&a.valid, ha, hb, base);
    let devices = a.valid[&plan.devices_from].body.devices.clone();
    let note = format!("merge {} + {}", ha.short(), hb.short());
    let body = ctx.merge_body(&a, ha, hb, plan, devices, &note)?;
    println!("MERGED");
    ctx.commit(body)?;
    Ok(())
}

pub fn resolve(ctx: &Ctx, keep: &str) -> Result<()> {
    let a = ctx.assess()?;
    let Verdict::Conflict {
        a: ha,
        b: hb,
        ref reason,
    } = a.verdict
    else {
        return Err(refuse_verdict(&a.verdict));
    };
    let (kept, other) = match (ha.hex().starts_with(keep), hb.hex().starts_with(keep)) {
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
    Ok(())
}
