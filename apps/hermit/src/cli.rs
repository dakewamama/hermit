//! Command-line interface definitions.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hermit",
    about = "Hermit: wallets are shells, your state moves on"
)]
pub struct Cli {
    /// This device's local state directory.
    #[arg(long, env = "HERMIT_HOME")]
    pub home: PathBuf,
    /// Work from this device's replica only and leave the provider alone;
    /// new transitions are published on the next sync.
    #[arg(long, global = true)]
    pub local: bool,
    /// Send all relay and witness traffic through this SOCKS5 proxy, e.g.
    /// socks5://127.0.0.1:9050 for Tor. Fails closed: no direct fallback.
    #[arg(long, global = true, env = "HERMIT_PROXY")]
    pub proxy: Option<String>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
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
        /// Freshness witness to pin for this capsule.
        #[arg(long)]
        witness: Option<String>,
    },
    /// Hand this capsule to a new device: prints a hermit: URI (or a QR)
    /// and the verification code both devices must show.
    Pair {
        /// Draw the URI as a QR code in the terminal.
        #[arg(long)]
        qr: bool,
    },
    /// Join a capsule from a pairing URI (or a file holding one).
    Join {
        pairing: String,
        /// Provider to join through, if not the one in the pairing.
        #[arg(long)]
        store: Option<String>,
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
    /// Turn a ZeWIF document into a fresh, view-only wallet another program
    /// can open (zcash_client_sqlite's own importer does the import).
    Adopt {
        zewif: PathBuf,
        #[arg(long)]
        into: PathBuf,
    },
}

#[derive(clap::Args)]
pub struct Net {
    /// lightwalletd/Zaino endpoint, e.g. https://testnet.zec.rocks:443
    #[arg(long)]
    pub server: Option<String>,
    /// Skip chain verification (lineage is still verified).
    #[arg(long)]
    pub offline: bool,
}

#[derive(Subcommand)]
pub enum DeviceCmd {
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
