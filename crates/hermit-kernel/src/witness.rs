//! Freshness attestations. A witness signs "the newest head I have seen for
//! this capsule is (seq, head)" and never signs an older or conflicting one,
//! so a device that has been offline can tell when storage withholds state.
//! A witness is trusted for freshness only: it never sees content and its
//! signature grants no authority over the capsule.

use crate::device::verify_sig;
use crate::hash::{cbor, hex_bytes, Hash};
use crate::Manifest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub capsule_id: Hash,
    pub seq: u64,
    pub head: Hash,
}

impl Attestation {
    pub fn of(m: &Manifest) -> Attestation {
        Attestation {
            capsule_id: m.body.capsule_id,
            seq: m.body.seq,
            head: m.id(),
        }
    }

    fn message(&self) -> Vec<u8> {
        cbor(&("hermit-witness-v1", self))
    }
}

/// What a client sends to have `tip` attested: the tip and the manifests it
/// descends from, so the witness can verify lineage from the capsule's
/// genesis instead of trusting a signed sequence number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CosignRequest {
    pub tip: Manifest,
    pub ancestry: Vec<Manifest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub att: Attestation,
    #[serde(with = "hex_bytes")]
    pub sig: [u8; 64],
}

impl Signed {
    pub fn sign(att: Attestation, key: &ed25519_dalek::SigningKey) -> Signed {
        use ed25519_dalek::Signer;
        Signed {
            att,
            sig: key.sign(&att.message()).to_bytes(),
        }
    }

    pub fn verify(&self, witness: &[u8; 32]) -> bool {
        verify_sig(witness, &self.att.message(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_binds_every_field() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = key.verifying_key().to_bytes();
        let att = Attestation {
            capsule_id: Hash([1; 32]),
            seq: 5,
            head: Hash([2; 32]),
        };
        let s = Signed::sign(att, &key);
        assert!(s.verify(&pk));
        for tampered in [
            Attestation { seq: 4, ..att },
            Attestation {
                head: Hash([3; 32]),
                ..att
            },
            Attestation {
                capsule_id: Hash([9; 32]),
                ..att
            },
        ] {
            assert!(!Signed {
                att: tampered,
                sig: s.sig
            }
            .verify(&pk));
        }
        let other = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(!s.verify(&other.verifying_key().to_bytes()));
    }
}
