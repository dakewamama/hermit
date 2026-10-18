//! Turning concurrent histories back into one: automatic merges, and
//! human-chosen resolutions of authority conflicts.

use crate::ctx::{refuse_verdict, Ctx};
use anyhow::{Context, Result};
use hermit_kernel::assess::{base_of, plan_merge, Verdict};

pub fn merge(ctx: &Ctx) -> Result<()> {
    let a = ctx.assess()?;
    let (ha, hb, base) = match a.verdict {
        Verdict::ForkMergeable { a, b, base } => (a, b, base),
        Verdict::Ok { head } => {
            println!("nothing to merge: single head {}", head.short());
            return Ok(());
        }
        ref v => return Err(refuse_verdict(v)),
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
    let (ha, hb, reason) = match &a.verdict {
        Verdict::Conflict { a, b, reason } => (*a, *b, reason.clone()),
        Verdict::Ok { head } => {
            println!("nothing to resolve: single head {}", head.short());
            return Ok(());
        }
        v => return Err(refuse_verdict(v)),
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
