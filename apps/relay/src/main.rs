//! A deliberately dumb relay: it stores content-addressed blobs and
//! manifests and lists what it has. Clients trust none of it. It does check
//! one thing on upload, that content matches the name it is stored under, so
//! nobody can overwrite or destroy what others put there. Started with an
//! admin token it can be switched at runtime into hostile modes, for
//! demonstrations:
//!
//!   honest   serve everything (default)
//!   freeze   keep serving the manifest set as of the switch; accept and
//!            silently drop new writes (a stale or censoring provider)
//!   corrupt  flip a byte in every blob served
//!
//!   curl -X POST localhost:8787/admin/mode -H "Authorization: Bearer $TOKEN" -d freeze

use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use clap::Parser;
use futures_util::StreamExt;
use hermit_kernel::hash::from_cbor;
use hermit_kernel::{Hash, Manifest};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;

const MAX_BLOB: u64 = 256 * 1024 * 1024;
/// Manifests are a few KB; the client refuses anything above 1 MiB too.
const MAX_MANIFEST: u64 = 1 << 20;
/// Distinguishes concurrent uploads' temporary files.
static UPLOADS: AtomicU64 = AtomicU64::new(0);

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, default_value = "relay-data")]
    data: PathBuf,
    /// Enables /admin/mode, which makes the relay misbehave on request, for
    /// callers presenting this bearer token. Without it the route does not
    /// exist. For demonstrations only.
    #[arg(long, env = "HERMIT_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum Mode {
    Honest,
    /// Manifest ids (across all capsules) visible at the moment of freezing.
    Freeze(HashSet<String>),
    Corrupt,
}

#[derive(Clone)]
struct Relay {
    data: PathBuf,
    mode: Arc<Mutex<Mode>>,
    admin_token: Option<Arc<str>>,
}

/// Constant-time check of an `Authorization: Bearer <token>` header. Both
/// sides are hashed first, so not even the token's length leaks.
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(given) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let a = Hash::of(b"ZcRelayAdmin_v1", given.as_bytes());
    let b = Hash::of(b"ZcRelayAdmin_v1", token.as_bytes());
    a.0.iter()
        .zip(b.0.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn valid_name(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Relay {
    fn path(&self, cap: &str, kind: &str, name: Option<&str>) -> Result<PathBuf, StatusCode> {
        // Every path component is checked here, the single place paths are
        // built, so no handler can reach outside <data>/<cap>/{m,b}.
        if !valid_name(cap) || !matches!(kind, "m" | "b") || name.is_some_and(|n| !valid_name(n)) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut p = self.data.join(cap).join(kind);
        if let Some(n) = name {
            p.push(n);
        }
        Ok(p)
    }

    fn mode(&self) -> Mode {
        self.mode.lock().unwrap().clone()
    }

    async fn all_manifests(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        let Ok(mut caps) = tokio::fs::read_dir(&self.data).await else {
            return out;
        };
        while let Ok(Some(cap)) = caps.next_entry().await {
            if let Ok(mut ms) = tokio::fs::read_dir(cap.path().join("m")).await {
                while let Ok(Some(m)) = ms.next_entry().await {
                    out.insert(m.file_name().to_string_lossy().into_owned());
                }
            }
        }
        out
    }
}

async fn list(
    State(r): State<Relay>,
    Path((cap, kind)): Path<(String, String)>,
) -> Result<String, StatusCode> {
    let dir = r.path(&cap, &kind, None)?;
    let mut names = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    if let (Mode::Freeze(visible), "m") = (r.mode(), kind.as_str()) {
        names.retain(|n| visible.contains(n));
    }
    names.sort();
    Ok(names.join("\n"))
}

async fn fetch(
    State(r): State<Relay>,
    Path((cap, kind, name)): Path<(String, String, String)>,
) -> Result<Body, StatusCode> {
    if let (Mode::Freeze(visible), "m") = (r.mode(), kind.as_str()) {
        if !visible.contains(&name) {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    let p = r.path(&cap, &kind, Some(&name))?;
    if r.mode() == Mode::Corrupt && kind == "b" {
        // Demonstration mode only: load the blob to damage one byte of it.
        let mut bytes = tokio::fs::read(&p)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        if !bytes.is_empty() {
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0x01;
        }
        return Ok(Body::from(bytes));
    }
    // Streamed from disk: serving a large blob does not hold it in memory.
    let file = tokio::fs::File::open(&p)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Body::from_stream(tokio_util::io::ReaderStream::new(file)))
}

/// Stream an upload into `tmp`, enforcing `max` as it arrives and hashing it
/// on the way.
async fn receive(body: Body, tmp: &std::path::Path, max: u64) -> Result<Hash, StatusCode> {
    let mut file = tokio::fs::File::create(tmp)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut hasher = Hash::hasher(b"ZcBlob_v1");
    let mut len = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        len += chunk.len() as u64;
        if len > max {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    file.sync_all()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(hasher.finish())
}

async fn store(
    State(r): State<Relay>,
    Path((cap, kind, name)): Path<(String, String, String)>,
    body: Body,
) -> Result<StatusCode, StatusCode> {
    let p = r.path(&cap, &kind, Some(&name))?;
    if matches!(r.mode(), Mode::Freeze(_)) {
        // Pretend to accept; a censoring provider looks healthy to the writer.
        return Ok(StatusCode::CREATED);
    }
    if tokio::fs::try_exists(&p).await.unwrap_or(false) {
        // Content-addressed: what is stored there is already exactly this.
        return Ok(StatusCode::OK);
    }
    let dir = p.parent().expect("path() always has a parent");
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tmp = dir.join(format!(
        ".{name}.{}.{}.part",
        std::process::id(),
        UPLOADS.fetch_add(1, Ordering::Relaxed)
    ));
    let max = if kind == "b" { MAX_BLOB } else { MAX_MANIFEST };
    let result = async {
        let hash = receive(body, &tmp, max).await?;
        // Only content that matches its name is kept, so an upload can
        // never replace or destroy anything stored before.
        let addressed = if kind == "b" {
            hash
        } else {
            let bytes = tokio::fs::read(&tmp)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            from_cbor::<Manifest>(&bytes)
                .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?
                .id()
        };
        if addressed.hex() != name {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        // Atomic: readers see the whole file or none of it.
        tokio::fs::rename(&tmp, &p)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result.map(|_| StatusCode::CREATED)
}

async fn set_mode(
    State(r): State<Relay>,
    headers: HeaderMap,
    body: String,
) -> Result<String, StatusCode> {
    match &r.admin_token {
        Some(t) if authorized(&headers, t) => {}
        _ => return Err(StatusCode::UNAUTHORIZED),
    }
    let mode = match body.trim() {
        "honest" => Mode::Honest,
        "freeze" => Mode::Freeze(r.all_manifests().await),
        "corrupt" => Mode::Corrupt,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let label = body.trim().to_string();
    *r.mode.lock().unwrap() = mode;
    println!("relay mode: {label}");
    Ok(label)
}

/// The data directory is the relay's alone.
fn restrict(dir: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tokio::fs::create_dir_all(&args.data).await?;
    restrict(&args.data)?;
    let relay = Relay {
        data: args.data,
        mode: Arc::new(Mutex::new(Mode::Honest)),
        admin_token: args.admin_token.filter(|t| !t.is_empty()).map(Arc::from),
    };
    let mut app = Router::new()
        .route("/c/{cap}/{kind}", get(list))
        .route("/c/{cap}/{kind}/{name}", get(fetch).put(store));
    if relay.admin_token.is_some() {
        println!("/admin/mode enabled (token required)");
        app = app.route("/admin/mode", post(set_mode));
    }
    let app = app
        // A wallet section is a whole data.sqlite: tens of MB is normal.
        .layer(DefaultBodyLimit::max(MAX_BLOB as usize))
        .with_state(relay);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    println!("hermit-relay listening on http://{}", args.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> Relay {
        Relay {
            data: PathBuf::from("/srv/relay"),
            mode: Arc::new(Mutex::new(Mode::Honest)),
            admin_token: None,
        }
    }

    #[test]
    fn admin_needs_the_exact_bearer_token() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert!(authorized(&with("Bearer s3cret"), "s3cret"));
        for bad in [
            "Bearer s3cre",
            "Bearer s3cret!",
            "bearer s3cret",
            "s3cret",
            "Basic s3cret",
        ] {
            assert!(!authorized(&with(bad), "s3cret"), "{bad}");
        }
        assert!(!authorized(&HeaderMap::new(), "s3cret"));
    }

    #[test]
    fn paths_cannot_leave_the_capsule() {
        let r = relay();
        let cap = "c".repeat(64);
        let name = "a".repeat(64);
        for kind in ["..", ".", "", "m/..", "x"] {
            assert!(r.path(&cap, kind, None).is_err(), "kind {kind:?}");
            assert!(r.path(&cap, kind, Some(&name)).is_err(), "kind {kind:?}");
        }
        for bad in ["..", "../etc", &"a".repeat(63), &"g".repeat(64)] {
            assert!(r.path(bad, "m", None).is_err(), "cap {bad:?}");
            assert!(r.path(&cap, "b", Some(bad)).is_err(), "name {bad:?}");
        }
        assert_eq!(
            r.path(&cap, "b", Some(&name)).unwrap(),
            PathBuf::from("/srv/relay").join(&cap).join("b").join(&name)
        );
    }
}
