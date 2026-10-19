//! Per-device local state: device keys, the pinned capsule, and the
//! high-water mark used for rollback detection.

use crate::witness::WitnessPin;
use anyhow::{Context, Result};
use hermit_kernel::assess::HighWater;
use hermit_kernel::{DeviceKeys, Hash};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Home {
    dir: PathBuf,
}

/// What a device knows about the capsule it belongs to. `genesis` and the
/// initial `hwm` arrive out of band when pairing (think QR code), so a fresh
/// device cannot be rolled back by the store at join time.
#[derive(Serialize, Deserialize, Clone)]
pub struct Membership {
    pub capsule_id: Hash,
    pub genesis: Hash,
    pub store: String,
    pub hwm: Option<HighWater>,
    #[serde(default)]
    pub witness: Option<WitnessPin>,
}

/// The out-of-band pairing payload.
#[derive(Serialize, Deserialize)]
pub struct Pairing {
    pub capsule_id: Hash,
    pub genesis: Hash,
    pub head: HighWater,
    #[serde(default)]
    pub witness: Option<WitnessPin>,
    /// The provider to join through, so the new device needs nothing else.
    #[serde(default)]
    pub store: Option<String>,
}

impl Home {
    pub fn new(dir: &Path) -> Result<Home> {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating device home {}", dir.display()))?;
        Ok(Home {
            dir: dir.to_owned(),
        })
    }

    /// This device's own copy of every manifest and blob it has seen or
    /// written. Providers can withhold; they cannot make us forget.
    pub fn replica(&self) -> String {
        self.dir.join("replica").to_string_lossy().into_owned()
    }

    pub fn keys(&self) -> Result<DeviceKeys> {
        let s = fs::read_to_string(self.dir.join("device.json"))
            .context("no device here; run `hermit device init` first")?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn save_keys(&self, k: &DeviceKeys) -> Result<()> {
        let p = self.dir.join("device.json");
        anyhow::ensure!(!p.exists(), "device already initialized at {}", p.display());
        fs::write(p, serde_json::to_string_pretty(k)?)?;
        Ok(())
    }

    pub fn membership(&self) -> Result<Membership> {
        let s = fs::read_to_string(self.dir.join("capsule.json"))
            .context("device has no capsule; run `hermit create` or `hermit join`")?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn save_membership(&self, m: &Membership) -> Result<()> {
        fs::write(
            self.dir.join("capsule.json"),
            serde_json::to_string_pretty(m)?,
        )?;
        Ok(())
    }

    pub fn set_hwm(&self, hwm: HighWater) -> Result<()> {
        let mut m = self.membership()?;
        m.hwm = Some(hwm);
        self.save_membership(&m)
    }
}
