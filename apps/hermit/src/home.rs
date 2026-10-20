//! Per-device local state: device keys, the pinned capsule, and the
//! high-water mark used for rollback detection.

use crate::witness::WitnessPin;
use anyhow::{Context, Result};
use hermit_kernel::assess::HighWater;
use hermit_kernel::{DeviceKeys, Hash};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Create `path` readable by this user only, refusing to replace anything
/// already there.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replace `path` all at once: a crash leaves the old file or the new one,
/// never half of either.
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

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
        write_private(&p, serde_json::to_string_pretty(k)?.as_bytes())
    }

    pub fn membership(&self) -> Result<Membership> {
        let s = fs::read_to_string(self.dir.join("capsule.json"))
            .context("device has no capsule; run `hermit create` or `hermit join`")?;
        Ok(serde_json::from_str(&s)?)
    }

    /// Belong to a capsule for the first time. A device holds one capsule;
    /// joining another would silently drop this one's rollback floor.
    pub fn new_membership(&self, m: &Membership) -> Result<()> {
        let p = self.dir.join("capsule.json");
        if let Ok(old) = self.membership() {
            anyhow::bail!(
                "this device already belongs to capsule {}; use another --home",
                old.capsule_id.short()
            );
        }
        write_private(&p, serde_json::to_string_pretty(m)?.as_bytes())
    }

    pub fn save_membership(&self, m: &Membership) -> Result<()> {
        replace_private(
            &self.dir.join("capsule.json"),
            serde_json::to_string_pretty(m)?.as_bytes(),
        )
    }

    pub fn set_hwm(&self, hwm: HighWater) -> Result<()> {
        let mut m = self.membership()?;
        m.hwm = Some(hwm);
        self.save_membership(&m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(byte: u8) -> Membership {
        Membership {
            capsule_id: Hash([byte; 32]),
            genesis: Hash([byte; 32]),
            store: "dir:///tmp/x".into(),
            hwm: None,
            witness: None,
        }
    }

    #[test]
    fn device_keys_are_private_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path()).unwrap();
        home.save_keys(&DeviceKeys::generate("laptop")).unwrap();
        let mode = fs::metadata(dir.path().join("device.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(home.save_keys(&DeviceKeys::generate("other")).is_err());
        assert_eq!(home.keys().unwrap().name, "laptop");
    }

    #[test]
    fn a_device_cannot_silently_switch_capsules() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path()).unwrap();
        home.new_membership(&membership(1)).unwrap();
        let err = home.new_membership(&membership(2)).unwrap_err().to_string();
        assert!(err.contains("already belongs"), "{err}");
        assert_eq!(home.membership().unwrap().capsule_id, Hash([1; 32]));
        // Updating the one it has still works, and stays private.
        home.set_hwm(HighWater {
            seq: 3,
            id: Hash([9; 32]),
        })
        .unwrap();
        assert_eq!(home.membership().unwrap().hwm.unwrap().seq, 3);
        let mode = fs::metadata(dir.path().join("capsule.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
