use crate::device::{verify_sig, Device, DeviceKeys};
use crate::hash::{bytes_vec, cbor, hex_bytes, Hash};
use crate::seal;
use serde::{Deserialize, Serialize};

/// How a section may evolve. This is the core of the continuity semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Class {
    /// Re-derivable from the chain; verify against it, never trust it blindly.
    Derived,
    /// Scan progress; concurrent versions resolve to the one with the higher
    /// chain-verified anchor.
    Progress,
    /// User metadata (labels, notes); concurrent edits merge per key (LWW).
    Metadata,
    /// Spend authority; never in the default capsule, never merged.
    Secret,
}

/// The chain point the capsule's derived/progress state was built on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub network: String,
    pub height: u32,
    /// Block hash in display (RPC) byte order.
    pub block_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionRef {
    pub name: String,
    pub class: Class,
    /// Hash of the plaintext; feeds the state root.
    pub plain: Hash,
    /// Content address of the ciphertext blob in storage.
    pub blob: Hash,
    pub len: u64,
}

/// The signed part of a manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub version: u16,
    pub capsule_id: Hash,
    /// 0 for genesis, otherwise max(parent.seq) + 1.
    pub seq: u64,
    pub parents: Vec<Hash>,
    pub domain: String,
    pub anchor: Option<Anchor>,
    /// Sorted by name.
    pub sections: Vec<SectionRef>,
    pub state_root: Hash,
    /// Authority state: devices allowed to author the *next* transition and
    /// to decrypt sections. Changing it is an authority transition.
    pub devices: Vec<Device>,
    #[serde(with = "hex_bytes")]
    pub author: [u8; 32],
    /// Human description of the transition, sealed to `devices` like every
    /// section: storage must not learn labels or device actions from it.
    #[serde(with = "bytes_vec")]
    pub note: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    Signature {
        #[serde(with = "hex_bytes")]
        sig: [u8; 64],
    },
    /// A freshness witness attesting it has seen this manifest at this seq.
    WitnessCosig {
        #[serde(with = "hex_bytes")]
        witness: [u8; 32],
        #[serde(with = "hex_bytes")]
        sig: [u8; 64],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub body: Body,
    pub evidence: Vec<Evidence>,
}

pub const VERSION: u16 = 1;

pub fn state_root(sections: &[SectionRef]) -> Hash {
    let leaves: Vec<(&str, Class, Hash)> = sections
        .iter()
        .map(|s| (s.name.as_str(), s.class, s.plain))
        .collect();
    Hash::of(b"ZcState_root_v1", &cbor(&leaves))
}

pub fn devices_hash(devices: &[Device]) -> Hash {
    Hash::of(b"ZcDevices_v1", &cbor(&devices))
}

impl Body {
    pub fn genesis(
        domain: &str,
        author: &DeviceKeys,
        devices: Vec<Device>,
        mut sections: Vec<SectionRef>,
        anchor: Option<Anchor>,
    ) -> anyhow::Result<Body> {
        sections.sort_by(|a, b| a.name.cmp(&b.name));
        let note = seal::seal(b"genesis", &devices)?;
        let capsule_id = Hash::of(b"ZcCapsule_id_v1", &rand::random::<[u8; 32]>());
        Ok(Body {
            version: VERSION,
            capsule_id,
            seq: 0,
            parents: vec![],
            domain: domain.to_string(),
            anchor,
            state_root: state_root(&sections),
            sections,
            devices,
            author: author.public().sign_pk,
            note,
        })
    }

    /// A successor of `parents` (one parent normally, two for a merge).
    pub fn child(
        parents: &[&Manifest],
        author: &DeviceKeys,
        devices: Vec<Device>,
        mut sections: Vec<SectionRef>,
        anchor: Option<Anchor>,
        note: &str,
    ) -> anyhow::Result<Body> {
        sections.sort_by(|a, b| a.name.cmp(&b.name));
        let note = seal::seal(note.as_bytes(), &devices)?;
        let first = &parents[0].body;
        Ok(Body {
            version: VERSION,
            capsule_id: first.capsule_id,
            seq: parents.iter().map(|p| p.body.seq).max().unwrap_or(0) + 1,
            parents: parents.iter().map(|p| p.id()).collect(),
            domain: first.domain.clone(),
            anchor,
            state_root: state_root(&sections),
            sections,
            devices,
            author: author.public().sign_pk,
            note,
        })
    }

    pub fn id(&self) -> Hash {
        Hash::of(b"ZcManifest_v1", &cbor(self))
    }

    pub fn section(&self, name: &str) -> Option<&SectionRef> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn sign(self, keys: &DeviceKeys) -> Manifest {
        let sig = keys.sign(&self.id().0);
        Manifest {
            body: self,
            evidence: vec![Evidence::Signature { sig }],
        }
    }
}

impl Manifest {
    pub fn id(&self) -> Hash {
        self.body.id()
    }

    /// Internal consistency: the author's signature, the state root, and section ordering.
    /// Whether the author was *authorized* is a lineage question, checked in `assess`.
    pub fn check_self(&self) -> Result<(), String> {
        let b = &self.body;
        if b.version != VERSION {
            return Err(format!("unsupported version {}", b.version));
        }
        if state_root(&b.sections) != b.state_root {
            return Err("state root does not match sections".into());
        }
        if !b.sections.windows(2).all(|w| w[0].name < w[1].name) {
            return Err("sections not strictly sorted".into());
        }
        let id = self.id();
        let signed = self
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Signature { sig } if verify_sig(&b.author, &id.0, sig)));
        if !signed {
            return Err("missing or invalid author signature".into());
        }
        Ok(())
    }

    /// The transition's note, if `identity` is one of its recipients.
    pub fn note(&self, identity: &age::x25519::Identity) -> Option<String> {
        let pt = seal::open(&self.body.note, identity).ok()?;
        String::from_utf8(pt).ok()
    }

    pub fn author_name(&self) -> String {
        self.body
            .devices
            .iter()
            .find(|d| d.sign_pk == self.body.author)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| hex::encode(&self.body.author[..4]))
    }
}
