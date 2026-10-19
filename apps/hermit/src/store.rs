//! Dumb, untrusted storage. It holds content-addressed ciphertext blobs and
//! signed manifests, and is never asked what is "latest": clients list
//! everything and decide for themselves.
//!
//! Backends: `dir://path` (or a bare path) and `http://host:port` (a
//! hermit-relay). Both expose the same two grow-only sets per capsule.

use anyhow::{bail, Context, Result};
use hermit_kernel::hash::{cbor, from_cbor, Hash};
use hermit_kernel::Manifest;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

enum Backend {
    Dir(PathBuf),
    Http(String),
}

pub struct Store {
    backend: Backend,
}

const MANIFESTS: &str = "m";
const BLOBS: &str = "b";

/// Manifests are a few KB; anything near this is hostile.
const MAX_MANIFEST: u64 = 1 << 20;
/// Same ceiling the relay enforces on uploads.
const MAX_BLOB: u64 = 256 << 20;

/// Upper bound on an age ciphertext of `plain_len` bytes: 16 bytes of tag
/// per 64 KiB chunk plus a header that grows with the recipient count.
pub fn sealed_bound(plain_len: u64) -> u64 {
    plain_len + (plain_len / 65536 + 1) * 16 + (1 << 20)
}

/// The form of a store spec worth persisting: directory stores become
/// absolute, so the device works from any working directory.
pub fn normalize_spec(spec: &str) -> Result<String> {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        return Ok(spec.trim_end_matches('/').to_string());
    }
    let path = PathBuf::from(spec.strip_prefix("dir://").unwrap_or(spec));
    fs::create_dir_all(&path)?;
    Ok(format!("dir://{}", fs::canonicalize(&path)?.display()))
}

impl Store {
    pub fn open(spec: &str, capsule: Hash) -> Result<Store> {
        let backend = if spec.starts_with("http://") || spec.starts_with("https://") {
            Backend::Http(format!(
                "{}/c/{}",
                spec.trim_end_matches('/'),
                capsule.hex()
            ))
        } else {
            let root =
                PathBuf::from(spec.strip_prefix("dir://").unwrap_or(spec)).join(capsule.hex());
            fs::create_dir_all(root.join(MANIFESTS))?;
            fs::create_dir_all(root.join(BLOBS))?;
            Backend::Dir(root)
        };
        Ok(Store { backend })
    }

    fn list(&self, kind: &str) -> Result<Vec<String>> {
        match &self.backend {
            Backend::Dir(root) => fs::read_dir(root.join(kind))?
                .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
                .collect(),
            Backend::Http(base) => {
                let body = crate::net::agent()
                    .get(&format!("{base}/{kind}"))
                    .call()
                    .with_context(|| format!("listing {base}/{kind}"))?
                    .into_string()?;
                Ok(body
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect())
            }
        }
    }

    /// Read at most `max` bytes; a provider serving more is refused rather
    /// than allowed to exhaust our memory.
    fn get(&self, kind: &str, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let reader: Box<dyn Read> = match &self.backend {
            Backend::Dir(root) => match fs::File::open(root.join(kind).join(name)) {
                Ok(f) => Box::new(f),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            },
            Backend::Http(base) => match crate::net::agent()
                .get(&format!("{base}/{kind}/{name}"))
                .call()
            {
                Ok(resp) => resp.into_reader(),
                Err(ureq::Error::Status(404, _)) => return Ok(None),
                Err(e) => return Err(e.into()),
            },
        };
        let mut out = Vec::new();
        reader.take(max + 1).read_to_end(&mut out)?;
        if out.len() as u64 > max {
            bail!(
                "provider served more than {max} bytes for {kind}/{}",
                &name[..8.min(name.len())]
            );
        }
        Ok(Some(out))
    }

    fn put(&self, kind: &str, name: &str, bytes: &[u8]) -> Result<()> {
        match &self.backend {
            Backend::Dir(root) => {
                let p = root.join(kind).join(name);
                if !p.exists() {
                    fs::write(p, bytes)?;
                }
            }
            Backend::Http(base) => {
                let url = format!("{base}/{kind}/{name}");
                if let Err(e) = crate::net::agent().put(&url).send_bytes(bytes) {
                    bail!("uploading {url}: {e}");
                }
            }
        }
        Ok(())
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<Hash> {
        let h = Hash::of(b"ZcBlob_v1", bytes);
        self.put(BLOBS, &h.hex(), bytes)?;
        Ok(h)
    }

    /// `max` is what the caller expects the ciphertext to be at most; see
    /// [`sealed_bound`].
    pub fn get_blob(&self, h: Hash, max: u64) -> Result<Vec<u8>> {
        let bytes = self.get(BLOBS, &h.hex(), max)?.with_context(|| {
            format!(
                "no verified copy of blob {} (provider lacks it or served corrupted content)",
                h.short()
            )
        })?;
        anyhow::ensure!(
            Hash::of(b"ZcBlob_v1", &bytes) == h,
            "store returned corrupted blob {}",
            h.short()
        );
        Ok(bytes)
    }

    pub fn put_manifest(&self, m: &Manifest) -> Result<()> {
        self.put(MANIFESTS, &m.id().hex(), &cbor(m))
    }

    pub fn manifest_ids(&self) -> Result<std::collections::HashSet<String>> {
        Ok(self.list(MANIFESTS)?.into_iter().collect())
    }

    /// Everything the store claims to have. Garbage is skipped here and
    /// forgeries are rejected later by the kernel.
    pub fn list_manifests(&self) -> Result<Vec<Manifest>> {
        let mut out = Vec::new();
        for name in self.list(MANIFESTS)? {
            if let Some(bytes) = self.get(MANIFESTS, &name, MAX_MANIFEST)? {
                if let Ok(m) = from_cbor::<Manifest>(&bytes) {
                    out.push(m);
                }
            }
        }
        Ok(out)
    }

    /// Copy every manifest and blob `other` has that we lack. Stores are
    /// grow-only sets, so union is always safe; deciding what it means is the
    /// kernel's job. Returns (manifests, blobs) copied.
    pub fn pull_from(&self, other: &Store) -> Result<(usize, usize)> {
        let mut counts = (0, 0);
        for (kind, n) in [(MANIFESTS, &mut counts.0), (BLOBS, &mut counts.1)] {
            let have: std::collections::HashSet<String> = self.list(kind)?.into_iter().collect();
            for name in other.list(kind)? {
                if have.contains(&name) {
                    continue;
                }
                let max = if kind == BLOBS {
                    MAX_BLOB
                } else {
                    MAX_MANIFEST
                };
                let Some(bytes) = other.get(kind, &name, max)? else {
                    continue;
                };
                // Never let a bad copy occupy the true name in our replica.
                let addressed = match kind {
                    BLOBS => Ok(Hash::of(b"ZcBlob_v1", &bytes).hex()),
                    _ => from_cbor::<Manifest>(&bytes)
                        .map(|m| m.id().hex())
                        .map_err(|_| "not a manifest this version can read"),
                };
                let problem = match addressed {
                    Ok(a) if a == name => None,
                    Ok(_) => Some("content does not match its address"),
                    Err(e) => Some(e),
                };
                if let Some(why) = problem {
                    eprintln!("  ✗ skipped {kind}/{}: {why}", &name[..8.min(name.len())]);
                    continue;
                }
                self.put(kind, &name, &bytes)?;
                *n += 1;
            }
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_content_is_refused_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let cap = Hash([7; 32]);
        let store = Store::open(dir.path().to_str().unwrap(), cap).unwrap();
        let root = dir.path().join(cap.hex());

        let blob = vec![0u8; 4096];
        let h = store.put_blob(&blob).unwrap();
        assert!(store.get_blob(h, 4096).is_ok());
        let err = store.get_blob(h, 4095).unwrap_err().to_string();
        assert!(err.contains("more than 4095 bytes"), "{err}");

        // A "manifest" bigger than any real one stops the listing.
        fs::write(
            root.join(MANIFESTS).join("f".repeat(64)),
            vec![0u8; MAX_MANIFEST as usize + 1],
        )
        .unwrap();
        assert!(store.list_manifests().is_err());
    }
}
