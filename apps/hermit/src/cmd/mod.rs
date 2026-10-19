//! One function per command; `run` only dispatches.

mod capsule;
mod export;
mod reconcile;
mod state;

use crate::cli::{Cli, Cmd, DeviceCmd};
use crate::ctx::Ctx;
use crate::home::Home;
use anyhow::Result;

pub fn run(cli: Cli) -> Result<()> {
    crate::net::init(cli.proxy.as_deref())?;
    let home = Home::new(&cli.home)?;
    // Commands that work on an existing capsule get a context.
    let ctx = |home| Ctx::load(home, cli.local);
    match cli.cmd {
        Cmd::Device(DeviceCmd::Init { name }) => capsule::device_init(&home, &name),
        Cmd::Device(DeviceCmd::Show) => capsule::device_show(&home),
        Cmd::Device(DeviceCmd::Add { device }) => capsule::device_add(&ctx(home)?, &device),
        Cmd::Device(DeviceCmd::Revoke { name }) => capsule::device_revoke(&ctx(home)?, &name),
        Cmd::Create {
            wallet,
            store,
            include_secret,
            witness,
        } => capsule::create(&home, &wallet, &store, include_secret, witness.as_deref()),
        Cmd::Pair { qr } => capsule::pair(&ctx(home)?, qr),
        Cmd::Join { pairing, store } => capsule::join(&home, &pairing, store.as_deref()),
        Cmd::Sync { other } => capsule::sync(&ctx(home)?, &other),
        Cmd::Snapshot {
            wallet,
            include_secret,
            note,
            net,
        } => state::snapshot(&ctx(home)?, &wallet, include_secret, &note, &net),
        Cmd::Label { key, value } => state::label(&ctx(home)?, &key, value.as_deref()),
        Cmd::Labels => state::labels(&ctx(home)?),
        Cmd::Status { net } => state::status(&ctx(home)?, &net),
        Cmd::Restore {
            into,
            with_secret,
            net,
        } => state::restore(&ctx(home)?, &into, with_secret, &net),
        Cmd::Log => state::log(&ctx(home)?),
        Cmd::Merge => reconcile::merge(&ctx(home)?),
        Cmd::Resolve { keep } => reconcile::resolve(&ctx(home)?, &keep),
        Cmd::Zewif { out } => export::zewif(&ctx(home)?, &out),
        Cmd::Adopt { zewif, into } => export::adopt(&zewif, &into),
    }
}
