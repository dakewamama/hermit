//! Client side of the freshness witness. Every response must be signed by
//! the key pinned when the capsule was created or paired; an unsigned or
//! mis-signed answer is treated as no answer at all.

use anyhow::{anyhow, bail, Context, Result};
use hermit_kernel::hash::cbor;
use hermit_kernel::witness::{Attestation, CosignRequest, Signed};
use hermit_kernel::{Hash, Manifest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessPin {
    pub url: String,
    /// Hex Ed25519 public key.
    pub key: String,
}

impl WitnessPin {
    /// Trust-on-first-use, at capsule creation only; joiners get the pin
    /// from the pairing payload, never from the witness itself.
    pub fn fetch(url: &str) -> Result<WitnessPin> {
        let url = url.trim_end_matches('/').to_string();
        let key = ureq::get(&format!("{url}/key"))
            .call()
            .with_context(|| format!("contacting witness {url}"))?
            .into_string()?;
        let key = key.trim().to_string();
        anyhow::ensure!(
            hex::decode(&key).map(|b| b.len() == 32).unwrap_or(false),
            "witness returned a malformed key"
        );
        Ok(WitnessPin { url, key })
    }

    fn pk(&self) -> [u8; 32] {
        hex::decode(&self.key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .expect("pinned witness key is 32 hex bytes")
    }

    fn checked(&self, body: &str, capsule: Hash) -> Result<Signed> {
        let s: Signed = serde_json::from_str(body).context("witness sent garbage")?;
        anyhow::ensure!(
            s.verify(&self.pk()),
            "witness answer is not signed by the pinned key"
        );
        anyhow::ensure!(
            s.att.capsule_id == capsule,
            "witness answered about another capsule"
        );
        Ok(s)
    }

    /// Ask the witness to attest `m` as the newest head. `ancestry` must let
    /// the witness trace `m` back to the capsule's genesis; it ignores
    /// anything that doesn't.
    pub fn cosign(&self, m: &Manifest, ancestry: Vec<Manifest>) -> Result<Signed> {
        let cap = m.body.capsule_id;
        let req = CosignRequest {
            tip: m.clone(),
            ancestry,
        };
        match ureq::post(&format!("{}/cosign", self.url)).send_bytes(&cbor(&req)) {
            Ok(resp) => {
                let s = self.checked(&resp.into_string()?, cap)?;
                anyhow::ensure!(
                    s.att == Attestation::of(m),
                    "witness attested something other than what was asked"
                );
                Ok(s)
            }
            Err(ureq::Error::Status(409, resp)) => {
                let newer = self.checked(&resp.into_string()?, cap)?;
                bail!(
                    "witness already attests S{} {}; sync and build on it first",
                    newer.att.seq,
                    newer.att.head.short()
                )
            }
            Err(ureq::Error::Status(code, resp)) => {
                bail!(
                    "witness refused ({code}): {}",
                    resp.into_string().unwrap_or_default()
                )
            }
            Err(e) => Err(anyhow!("witness unreachable: {e}")),
        }
    }

    /// The newest head the witness has attested for `capsule`, if any.
    pub fn latest(&self, capsule: Hash) -> Result<Option<Signed>> {
        match ureq::get(&format!("{}/latest/{}", self.url, capsule.hex())).call() {
            Ok(resp) => Ok(Some(self.checked(&resp.into_string()?, capsule)?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(anyhow!("witness unreachable: {e}")),
        }
    }
}
