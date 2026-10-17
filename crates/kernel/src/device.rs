use crate::hash::hex_bytes;
use age::secrecy::ExposeSecret;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// The public half of a device: who may sign transitions, and who may read sections.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    #[serde(with = "hex_bytes")]
    pub sign_pk: [u8; 32],
    /// age X25519 recipient (`age1...`).
    pub recipient: String,
}

/// Private device material. Never leaves the device.
#[derive(Serialize, Deserialize)]
pub struct DeviceKeys {
    pub name: String,
    sign_sk: String,
    age_identity: String,
}

impl DeviceKeys {
    pub fn generate(name: &str) -> DeviceKeys {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = age::x25519::Identity::generate();
        DeviceKeys {
            name: name.to_string(),
            sign_sk: hex::encode(sk.to_bytes()),
            age_identity: id.to_string().expose_secret().to_string(),
        }
    }

    fn signing_key(&self) -> SigningKey {
        let b: [u8; 32] = hex::decode(&self.sign_sk)
            .expect("device key file is hex")
            .try_into()
            .expect("32-byte key");
        SigningKey::from_bytes(&b)
    }

    pub fn identity(&self) -> age::x25519::Identity {
        age::x25519::Identity::from_str(&self.age_identity).expect("valid age identity")
    }

    pub fn public(&self) -> Device {
        Device {
            name: self.name.clone(),
            sign_pk: self.signing_key().verifying_key().to_bytes(),
            recipient: self.identity().to_public().to_string(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key().sign(msg).to_bytes()
    }
}

pub fn verify_sig(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}
