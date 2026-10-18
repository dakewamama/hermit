//! hermit-witness: signs the newest head it has seen per capsule.
//!
//!   GET  /key               this witness's public key (hex)
//!   GET  /latest/{capsule}  newest attestation, or 404
//!   POST /cosign            body: a CBOR CosignRequest (tip + ancestry);
//!                           returns an attestation, or 409 with the newer
//!                           one this witness holds
//!
//! First contact for a capsule must be its genesis, which the witness then
//! pins. After that it runs the kernel's own lineage verification over the
//! submitted ancestry and only attests a tip that is valid from that genesis
//! and descends from what it last attested. A signature alone is never
//! enough: a stolen device key cannot make it attest a sequence jump.

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
use hermit_kernel::assess::{ancestors, assess};
use hermit_kernel::hash::from_cbor;
use hermit_kernel::witness::{Attestation, CosignRequest, Signed};
use hermit_kernel::Hash;
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

/// What the witness remembers per capsule: its genesis and the newest
/// attestation.
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    genesis: Hash,
    latest: Attestation,
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
fn decide(prev: Option<&Entry>, req: &CosignRequest) -> Decision {
    let tip = &req.tip;
    if tip.check_self().is_err() {
        return Decision::Reject("manifest signature or structure is invalid");
    }
    let Some(prev) = prev else {
        let b = &tip.body;
        return if b.seq == 0
            && b.parents.is_empty()
            && b.devices.iter().any(|d| d.sign_pk == b.author)
        {
            Decision::Accept
        } else {
            Decision::Reject("first contact for a capsule must be its genesis")
        };
    };
    let mut offered = req.ancestry.clone();
    offered.push(tip.clone());
    let a = assess(offered, prev.genesis, None);
    let id = tip.id();
    if !a.valid.contains_key(&id) {
        return Decision::Reject("tip is not valid lineage from this capsule's genesis");
    }
    if Attestation::of(tip) == prev.latest || ancestors(&a.valid, id).contains(&prev.latest.head) {
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
    let Ok(req) = from_cbor::<CosignRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "not a cosign request").into_response();
    };
    let m = &req.tip;
    let cap = m.body.capsule_id.hex();
    let mut state = w.state.lock().unwrap();
    let prev = state.get(&cap).cloned();
    match decide(prev.as_ref(), &req) {
        Decision::Accept => {
            let entry = Entry {
                genesis: prev.map(|e| e.genesis).unwrap_or_else(|| m.id()),
                latest: Attestation::of(m),
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
    use hermit_kernel::{Body, DeviceKeys, Manifest};

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

    fn entry(genesis: &Manifest, latest: &Manifest) -> Entry {
        Entry {
            genesis: genesis.id(),
            latest: Attestation::of(latest),
        }
    }

    fn req(tip: &Manifest, ancestry: &[&Manifest]) -> CosignRequest {
        CosignRequest {
            tip: tip.clone(),
            ancestry: ancestry.iter().map(|m| (*m).clone()).collect(),
        }
    }

    #[test]
    fn policy() {
        let a = DeviceKeys::generate("laptop");
        let mallory = DeviceKeys::generate("mallory");
        let g = genesis(&a);
        let s1 = next(&g, &a, "one");
        let s1b = next(&g, &a, "fork");
        let s2 = next(&s1, &a, "two");

        assert!(matches!(decide(None, &req(&g, &[])), Decision::Accept));
        assert!(
            matches!(decide(None, &req(&s1, &[&g])), Decision::Reject(_)),
            "first contact must be genesis"
        );

        let e = entry(&g, &s1);
        assert!(
            matches!(decide(Some(&e), &req(&s1, &[&g])), Decision::Accept),
            "re-sign same head"
        );
        assert!(matches!(
            decide(Some(&e), &req(&s2, &[&g, &s1])),
            Decision::Accept
        ));
        assert!(
            matches!(decide(Some(&e), &req(&g, &[])), Decision::Stale(l) if l == e.latest),
            "never go back"
        );
        assert!(
            matches!(decide(Some(&e), &req(&s1b, &[&g])), Decision::Stale(_)),
            "never two heads at one seq"
        );
        assert!(
            matches!(decide(Some(&e), &req(&s2, &[&s1])), Decision::Reject(_)),
            "ancestry must reach the pinned genesis"
        );

        // Someone without a device key cannot push the capsule forward.
        let forged = Body::child(&[&s1], &mallory, s1.body.devices.clone(), vec![], None, "x")
            .unwrap()
            .sign(&mallory);
        assert!(matches!(
            decide(Some(&e), &req(&forged, &[&g, &s1])),
            Decision::Reject(_)
        ));
        let mut tampered = s2.clone();
        tampered.body.seq = 99;
        assert!(matches!(
            decide(Some(&e), &req(&tampered, &[&g, &s1])),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn a_merge_of_offline_branches_is_attested() {
        let a = DeviceKeys::generate("laptop");
        let g = genesis(&a);
        let s1 = next(&g, &a, "online");
        // Two branches written offline, never seen by the witness.
        let xa = next(&s1, &a, "offline a");
        let xb = next(&s1, &a, "offline b");
        let m = Body::child(
            &[&xa, &xb],
            &a,
            s1.body.devices.clone(),
            vec![],
            None,
            "merge",
        )
        .unwrap()
        .sign(&a);
        let e = entry(&g, &s1);
        assert!(matches!(
            decide(Some(&e), &req(&m, &[&g, &s1, &xa, &xb])),
            Decision::Accept
        ));
    }

    #[test]
    fn an_authorized_device_cannot_jump_the_sequence() {
        let a = DeviceKeys::generate("laptop");
        let g = genesis(&a);
        let s1 = next(&g, &a, "one");
        // Validly signed by an authorized device, but not valid lineage.
        let mut body =
            Body::child(&[&s1], &a, s1.body.devices.clone(), vec![], None, "jump").unwrap();
        body.seq = 1_000_000_000;
        let jump = body.sign(&a);
        assert!(
            jump.check_self().is_ok(),
            "signature and structure are fine"
        );
        assert!(
            matches!(
                decide(Some(&entry(&g, &s1)), &req(&jump, &[&g, &s1])),
                Decision::Reject(_)
            ),
            "a seq jump would freeze every honest writer and alarm every reader"
        );
    }

    #[test]
    fn genesis_id_is_not_reused_across_capsules() {
        let a = DeviceKeys::generate("laptop");
        assert_ne!(genesis(&a).body.capsule_id, genesis(&a).body.capsule_id);
    }
}
