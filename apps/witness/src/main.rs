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
    extract::DefaultBodyLimit,
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
use std::io::Write;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Cosign requests carry the capsule's history; this bounds how long a
/// history one request may carry.
const MAX_REQUEST: usize = 32 << 20;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8788")]
    listen: String,
    #[arg(long, default_value = "witness-data")]
    data: PathBuf,
    /// Most capsules this witness will track; new ones are refused beyond it.
    #[arg(long, default_value_t = 100_000)]
    max_capsules: usize,
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
    /// One file per capsule: `<dir>/<capsule>.json`.
    dir: PathBuf,
    max_capsules: usize,
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
    /// Memory is only ever updated after its file is durably written, so a
    /// failed write can never leave the witness forgetting what it signed.
    /// Nothing under the lock can panic, so poisoning is recovered safely.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn persist(&self, cap: &str, entry: &Entry) -> anyhow::Result<()> {
        write_atomic(
            &self.dir.join(format!("{cap}.json")),
            &serde_json::to_vec(entry)?,
        )
    }
}

/// Write, fsync, rename, fsync the directory: after a crash the file holds
/// either the old content or the new, never a truncated mix.
fn write_atomic(path: &FsPath, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(path.parent().expect("file in a directory"))?.sync_all()?;
    Ok(())
}

async fn public_key(State(w): State<Witness>) -> String {
    hex::encode(w.key.verifying_key().to_bytes())
}

async fn latest(State(w): State<Witness>, Path(cap): Path<String>) -> Response {
    let latest = w.lock().get(&cap).map(|e| e.latest);
    match latest {
        Some(att) => Json(Signed::sign(att, &w.key)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn cosign(State(w): State<Witness>, body: Bytes) -> Response {
    let Ok(req) = from_cbor::<CosignRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "not a cosign request").into_response();
    };
    let cap = req.tip.body.capsule_id.hex();
    let prev = w.lock().get(&cap).cloned();
    // Lineage verification is the expensive part: run it off the async
    // workers and without holding the lock.
    let (decision, req) = {
        let prev = prev.clone();
        match tokio::task::spawn_blocking(move || (decide(prev.as_ref(), &req), req)).await {
            Ok(r) => r,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
    let m = &req.tip;
    match decision {
        Decision::Accept => {
            let entry = Entry {
                genesis: prev.as_ref().map(|e| e.genesis).unwrap_or_else(|| m.id()),
                latest: Attestation::of(m),
            };
            let mut state = w.lock();
            let now = state.get(&cap).cloned();
            // Someone may have advanced the capsule while we verified.
            if now.as_ref().map(|e| e.latest) != prev.as_ref().map(|e| e.latest) {
                let newer = now.expect("only ever added").latest;
                return (StatusCode::CONFLICT, Json(Signed::sign(newer, &w.key))).into_response();
            }
            if now.is_none() && state.len() >= w.max_capsules {
                return (StatusCode::INSUFFICIENT_STORAGE, "witness is at capacity")
                    .into_response();
            }
            if now.as_ref().map(|e| e.latest) != Some(entry.latest) {
                if let Err(e) = w.persist(&cap, &entry) {
                    eprintln!("persisting {cap}: {e}");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                state.insert(cap, entry.clone());
                println!(
                    "cosigned {} S{} {}",
                    m.body.capsule_id.short(),
                    entry.latest.seq,
                    entry.latest.head.short()
                );
            }
            drop(state);
            Json(Signed::sign(entry.latest, &w.key)).into_response()
        }
        Decision::Stale(newer) => {
            (StatusCode::CONFLICT, Json(Signed::sign(newer, &w.key))).into_response()
        }
        Decision::Reject(why) => (StatusCode::FORBIDDEN, why).into_response(),
    }
}

/// The witness's identity. It is created once, readable only by its owner,
/// and never silently replaced: clients have pinned it.
fn load_or_create_key(path: &FsPath) -> anyhow::Result<SigningKey> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let b: [u8; 32] = hex::decode(s.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("witness key must be 32 bytes"))?;
            Ok(SigningKey::from_bytes(&b))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = SigningKey::generate(&mut rand::rngs::OsRng);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(path)?;
            f.write_all(hex::encode(k.to_bytes()).as_bytes())?;
            f.sync_all()?;
            Ok(k)
        }
        Err(e) => Err(anyhow::anyhow!(
            "reading witness key {}: {e}",
            path.display()
        )),
    }
}

/// Load every capsule file; anything unreadable stops startup rather than
/// being treated as "never seen", which could let the witness go backwards.
fn load_state(dir: &FsPath) -> anyhow::Result<BTreeMap<String, Entry>> {
    let mut state = BTreeMap::new();
    for e in std::fs::read_dir(dir)? {
        let path = e?.path();
        if path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let cap = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("odd file name {}", path.display()))?
            .to_string();
        let entry: Entry = serde_json::from_slice(&std::fs::read(&path)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        state.insert(cap, entry);
    }
    Ok(state)
}

/// One-time move from the single state.json of earlier versions.
fn migrate(data: &FsPath, dir: &FsPath) -> anyhow::Result<()> {
    let old = data.join("state.json");
    if !old.exists() {
        return Ok(());
    }
    let state: BTreeMap<String, Entry> = serde_json::from_slice(&std::fs::read(&old)?)?;
    for (cap, entry) in &state {
        write_atomic(
            &dir.join(format!("{cap}.json")),
            &serde_json::to_vec(entry)?,
        )?;
    }
    std::fs::rename(&old, data.join("state.json.migrated"))?;
    println!("migrated {} capsules from state.json", state.len());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let dir = args.data.join("capsules");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.data, std::fs::Permissions::from_mode(0o700))?;
    }
    let key = load_or_create_key(&args.data.join("witness.key"))?;
    migrate(&args.data, &dir)?;
    let state = load_state(&dir)?;
    let w = Witness {
        key: Arc::new(key),
        state: Arc::new(Mutex::new(state)),
        dir,
        max_capsules: args.max_capsules,
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
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
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
    fn key_is_private_created_once_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness.key");
        let k1 = load_or_create_key(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let k2 = load_or_create_key(&path).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        std::fs::write(&path, [0xffu8, 0xfe]).unwrap();
        assert!(
            load_or_create_key(&path).is_err(),
            "a broken key file must stop startup"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [0xffu8, 0xfe],
            "and stay untouched"
        );
    }

    #[test]
    fn state_round_trips_and_a_corrupt_file_stops_startup() {
        let dir = tempfile::tempdir().unwrap();
        let a = DeviceKeys::generate("laptop");
        let g = genesis(&a);
        let e = entry(&g, &g);
        let cap = g.body.capsule_id.hex();
        write_atomic(
            &dir.path().join(format!("{cap}.json")),
            &serde_json::to_vec(&e).unwrap(),
        )
        .unwrap();
        let state = load_state(dir.path()).unwrap();
        assert_eq!(state[&cap].latest, e.latest);
        std::fs::write(dir.path().join("broken.json"), b"{").unwrap();
        assert!(load_state(dir.path()).is_err());
    }

    #[test]
    fn old_single_file_state_is_migrated_once() {
        let data = tempfile::tempdir().unwrap();
        let caps = data.path().join("capsules");
        std::fs::create_dir_all(&caps).unwrap();
        let a = DeviceKeys::generate("laptop");
        let g = genesis(&a);
        let cap = g.body.capsule_id.hex();
        let old = BTreeMap::from([(cap.clone(), entry(&g, &g))]);
        std::fs::write(
            data.path().join("state.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        migrate(data.path(), &caps).unwrap();
        assert_eq!(load_state(&caps).unwrap()[&cap].genesis, g.id());
        assert!(!data.path().join("state.json").exists());
        assert!(data.path().join("state.json.migrated").exists());
        migrate(data.path(), &caps).unwrap(); // second run is a no-op
    }

    #[test]
    fn genesis_id_is_not_reused_across_capsules() {
        let a = DeviceKeys::generate("laptop");
        assert_ne!(genesis(&a).body.capsule_id, genesis(&a).body.capsule_id);
    }
}
