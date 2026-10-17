//! A deliberately dumb relay: it stores whatever it is given and lists
//! whatever it has. Clients trust none of it. Started with --demo-admin it
//! can be switched at runtime into hostile modes:
//!
//!   honest   serve everything (default)
//!   freeze   keep serving the manifest set as of the switch; accept and
//!            silently drop new writes (a stale or censoring provider)
//!   corrupt  flip a byte in every blob served
//!
//!   curl -X POST localhost:8787/admin/mode -d freeze

use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const MAX_BLOB: usize = 256 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, default_value = "relay-data")]
    data: PathBuf,
    /// Expose the unauthenticated /admin/mode endpoint that makes the relay
    /// misbehave on request. For demonstrations only.
    #[arg(long)]
    demo_admin: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Mode {
    Honest,
    /// Manifest ids visible at the moment of freezing, per capsule dir.
    Freeze(HashSet<String>),
    Corrupt,
}

#[derive(Clone)]
struct Relay {
    data: PathBuf,
    mode: Arc<Mutex<Mode>>,
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
) -> Result<Vec<u8>, StatusCode> {
    if let (Mode::Freeze(visible), "m") = (r.mode(), kind.as_str()) {
        if !visible.contains(&name) {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    let mut bytes = tokio::fs::read(r.path(&cap, &kind, Some(&name))?)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if r.mode() == Mode::Corrupt && kind == "b" && !bytes.is_empty() {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
    }
    Ok(bytes)
}

async fn store(
    State(r): State<Relay>,
    Path((cap, kind, name)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let p = r.path(&cap, &kind, Some(&name))?;
    if matches!(r.mode(), Mode::Freeze(_)) {
        // Pretend to accept; a censoring provider looks healthy to the writer.
        return Ok(StatusCode::CREATED);
    }
    tokio::fs::create_dir_all(p.parent().unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tokio::fs::write(&p, &body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::CREATED)
}

async fn set_mode(State(r): State<Relay>, body: String) -> Result<String, StatusCode> {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tokio::fs::create_dir_all(&args.data).await?;
    let relay = Relay {
        data: args.data,
        mode: Arc::new(Mutex::new(Mode::Honest)),
    };
    let mut app = Router::new()
        .route("/c/{cap}/{kind}", get(list))
        .route("/c/{cap}/{kind}/{name}", get(fetch).put(store));
    if args.demo_admin {
        println!("WARNING: /admin/mode is enabled; anyone who can reach this relay can make it misbehave");
        app = app.route("/admin/mode", post(set_mode));
    }
    let app = app
        // A wallet section is a whole data.sqlite: tens of MB is normal.
        .layer(DefaultBodyLimit::max(MAX_BLOB))
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
        }
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
