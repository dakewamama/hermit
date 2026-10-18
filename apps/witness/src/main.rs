//! hermit-witness: signs the newest head it has seen per capsule.
//!
//!   GET  /key               this witness's public key (hex)
//!   GET  /latest/{capsule}  newest attestation, or 404
//!   POST /cosign            body: a CBOR manifest; returns an attestation,
//!                           or 409 with the newer one this witness holds
//!
//! It cosigns only manifests signed by a device that the previously cosigned
//! state authorized (genesis on first contact), so nobody without a device
//! key can push a fake "newer" head and freeze the capsule.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ed25519_dalek::SigningKey;
use hermit_kernel::hash::from_cbor;
use hermit_kernel::witness::{Attestation, Signed};
use hermit_kernel::{Device, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8788")]
    listen: String,
    #[arg(long, default_value = "witness-data")]
    data: PathBuf,
}

/// What the witness remembers per capsule: the newest attestation and who
/// may author the next one.
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    latest: Attestation,
    devices: Vec<Device>,
}

#[derive(Clone)]
struct Witness {
    key: Arc<SigningKey>,
    state: Arc<Mutex<BTreeMap<String, Entry>>>,
    path: PathBuf,
}

enum Decision {
    Accept,
    Stale(Attestation),
    Reject(&'static str),
}

/// The witness's whole policy, kept pure so it can be tested directly.
fn decide(prev: Option<&Entry>, m: &Manifest) -> Decision {
    if m.check_self().is_err() {
        return Decision::Reject("manifest signature or structure is invalid");
    }
    let Some(prev) = prev else {
        return if m.body.seq == 0 && m.body.parents.is_empty() {
            Decision::Accept
        } else {
            Decision::Reject("first contact for a capsule must be its genesis")
        };
    };
    if !prev.devices.iter().any(|d| d.sign_pk == m.body.author) {
        return Decision::Reject("author is not authorized by the last witnessed state");
    }
    let att = Attestation::of(m);
    if att.seq > prev.latest.seq || att == prev.latest {
        Decision::Accept
    } else {
        Decision::Stale(prev.latest)
    }
}

impl Witness {
    fn persist(&self, state: &BTreeMap<String, Entry>) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

async fn public_key(State(w): State<Witness>) -> String {
    hex::encode(w.key.verifying_key().to_bytes())
}

async fn latest(State(w): State<Witness>, Path(cap): Path<String>) -> Response {
    let state = w.state.lock().unwrap();
    match state.get(&cap) {
        Some(e) => Json(Signed::sign(e.latest, &w.key)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn cosign(State(w): State<Witness>, body: Bytes) -> Response {
    let Ok(m) = from_cbor::<Manifest>(&body) else {
        return (StatusCode::BAD_REQUEST, "not a manifest").into_response();
    };
    let cap = m.body.capsule_id.hex();
    let mut state = w.state.lock().unwrap();
    match decide(state.get(&cap), &m) {
        Decision::Accept => {
            let entry = Entry {
                latest: Attestation::of(&m),
                devices: m.body.devices.clone(),
            };
            state.insert(cap, entry.clone());
            if let Err(e) = w.persist(&state) {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            println!(
                "cosigned {} S{} {}",
                m.body.capsule_id.short(),
                entry.latest.seq,
                entry.latest.head.short()
            );
            Json(Signed::sign(entry.latest, &w.key)).into_response()
        }
        Decision::Stale(newer) => {
            (StatusCode::CONFLICT, Json(Signed::sign(newer, &w.key))).into_response()
        }
        Decision::Reject(why) => (StatusCode::FORBIDDEN, why).into_response(),
    }
}

fn load_or_create_key(path: &std::path::Path) -> anyhow::Result<SigningKey> {
    if let Ok(s) = std::fs::read_to_string(path) {
        let b: [u8; 32] = hex::decode(s.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("witness key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&b));
    }
    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    std::fs::write(path, hex::encode(k.to_bytes()))?;
    Ok(k)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.data)?;
    let key = load_or_create_key(&args.data.join("witness.key"))?;
    let path = args.data.join("state.json");
    let state: BTreeMap<String, Entry> = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => BTreeMap::new(),
    };
    let w = Witness {
        key: Arc::new(key),
        state: Arc::new(Mutex::new(state)),
        path,
    };
    println!(
        "hermit-witness {} listening on http://{}",
        hex::encode(w.key.verifying_key().to_bytes()),
        args.listen
    );
    let app = Router::new()
        .route("/key", get(public_key))
        .route("/latest/{cap}", get(latest))
        .route("/cosign", post(cosign))
        .with_state(w);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermit_kernel::{Body, DeviceKeys};

    fn genesis(k: &DeviceKeys) -> Manifest {
        Body::genesis("zcash/v1", k, vec![k.public()], vec![], None)
            .unwrap()
            .sign(k)
    }

    fn next(parent: &Manifest, k: &DeviceKeys, note: &str) -> Manifest {
        Body::child(
            &[parent],
            k,
            parent.body.devices.clone(),
            vec![],
            None,
            note,
        )
        .unwrap()
        .sign(k)
    }

    fn entry(m: &Manifest) -> Entry {
        Entry {
            latest: Attestation::of(m),
            devices: m.body.devices.clone(),
        }
    }

    #[test]
    fn policy() {
        let a = DeviceKeys::generate("laptop");
        let mallory = DeviceKeys::generate("mallory");
        let g = genesis(&a);
        let s1 = next(&g, &a, "one");
        let s1b = next(&g, &a, "fork");

        assert!(matches!(decide(None, &g), Decision::Accept));
        assert!(
            matches!(decide(None, &s1), Decision::Reject(_)),
            "first contact must be genesis"
        );

        let e = entry(&s1);
        assert!(
            matches!(decide(Some(&e), &s1), Decision::Accept),
            "re-sign same head"
        );
        assert!(matches!(
            decide(Some(&e), &next(&s1, &a, "two")),
            Decision::Accept
        ));
        assert!(
            matches!(decide(Some(&e), &g), Decision::Stale(l) if l == e.latest),
            "never go back"
        );
        assert!(
            matches!(decide(Some(&e), &s1b), Decision::Stale(_)),
            "never two heads at one seq"
        );

        // Someone without a device key cannot push the capsule forward.
        let forged = Body::child(&[&s1], &mallory, s1.body.devices.clone(), vec![], None, "x")
            .unwrap()
            .sign(&mallory);
        assert!(matches!(decide(Some(&e), &forged), Decision::Reject(_)));
        let mut tampered = next(&s1, &a, "two");
        tampered.body.seq = 99;
        assert!(matches!(decide(Some(&e), &tampered), Decision::Reject(_)));
    }

    #[test]
    fn genesis_id_is_not_reused_across_capsules() {
        let a = DeviceKeys::generate("laptop");
        assert_ne!(genesis(&a).body.capsule_id, genesis(&a).body.capsule_id);
    }
}
