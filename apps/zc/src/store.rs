//! Dumb, untrusted storage. It holds content-addressed ciphertext blobs and
//! signed manifests, and is never asked what is "latest": clients list
//! everything and decide for themselves.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use zc_kernel::hash::{cbor, from_cbor, Hash};
use zc_kernel::Manifest;

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(spec: &str, capsule: Hash) -> Result<Store> {
        let base = spec.strip_prefix("dir://").unwrap_or(spec);
        let root = PathBuf::from(base).join(capsule.hex());
        fs::create_dir_all(root.join("m"))?;
        fs::create_dir_all(root.join("b"))?;
        Ok(Store { root })
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<Hash> {
        let h = Hash::of(b"ZcBlob_v1", bytes);
        let p = self.root.join("b").join(h.hex());
        if !p.exists() {
            fs::write(&p, bytes)?;
        }
        Ok(h)
    }

    pub fn get_blob(&self, h: Hash) -> Result<Vec<u8>> {
        let bytes = fs::read(self.root.join("b").join(h.hex()))
            .with_context(|| format!("store is missing blob {}", h.short()))?;
        anyhow::ensure!(
            Hash::of(b"ZcBlob_v1", &bytes) == h,
            "store returned corrupted blob {}",
            h.short()
        );
        Ok(bytes)
    }

    pub fn put_manifest(&self, m: &Manifest) -> Result<()> {
        fs::write(self.root.join("m").join(m.id().hex()), cbor(m))?;
        Ok(())
    }

    /// Copy every manifest and blob `other` has that we lack. Stores are
    /// grow-only sets, so union is always safe; deciding what it means is the
    /// kernel's job. Returns (manifests, blobs) copied.
    pub fn pull_from(&self, other: &Store) -> Result<(usize, usize)> {
        let mut counts = (0, 0);
        for (dir, n) in [("m", &mut counts.0), ("b", &mut counts.1)] {
            for e in fs::read_dir(other.root.join(dir))? {
                let e = e?;
                let dst = self.root.join(dir).join(e.file_name());
                if !dst.exists() {
                    fs::copy(e.path(), dst)?;
                    *n += 1;
                }
            }
        }
        Ok(counts)
    }

    /// Everything the store claims to have. Garbage is skipped here and
    /// forgeries are rejected later by the kernel.
    pub fn list_manifests(&self) -> Result<Vec<Manifest>> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.root.join("m"))? {
            let bytes = fs::read(e?.path())?;
            if let Ok(m) = from_cbor::<Manifest>(&bytes) {
                out.push(m);
            }
        }
        Ok(out)
    }
}
