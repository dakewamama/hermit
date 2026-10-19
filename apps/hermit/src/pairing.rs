//! The pairing handoff: one QR (or URI) from an existing device carries
//! everything a new device needs to join, and both devices show the same
//! short verification code so a swapped or altered payload is noticed.

use crate::home::Pairing;
use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hermit_kernel::hash::{cbor, from_cbor};
use hermit_kernel::Hash;

const SCHEME: &str = "hermit:";

/// A compact, QR-friendly encoding of the payload.
pub fn to_uri(p: &Pairing) -> String {
    format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(cbor(p)))
}

/// Accepts a `hermit:` URI, or a path to a file holding one (or the JSON
/// payload written by earlier versions).
pub fn read(arg: &str) -> Result<Pairing> {
    let text = match arg.strip_prefix(SCHEME) {
        Some(_) => arg.to_string(),
        None => std::fs::read_to_string(arg)
            .with_context(|| format!("{arg} is neither a hermit: URI nor a readable file"))?,
    };
    let text = text.trim();
    match text.strip_prefix(SCHEME) {
        Some(b64) => {
            let bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .context("pairing URI is not valid base64url")?;
            from_cbor(&bytes).context("pairing URI does not hold a pairing payload")
        }
        None => serde_json::from_str(text).context("not a pairing payload"),
    }
}

/// Nine digits derived from the whole payload. Two devices showing the same
/// code hold the same capsule, genesis, freshness floor, witness and
/// provider; an attacker who alters any of them changes the code.
pub fn code(p: &Pairing) -> String {
    let h = Hash::of(b"ZcPairCode_v1", &cbor(p));
    let n = u32::from_le_bytes(h.0[..4].try_into().expect("4 bytes")) % 1_000_000_000;
    let d = format!("{n:09}");
    format!("{}-{}-{}", &d[0..3], &d[3..6], &d[6..9])
}

/// The URI as a QR code drawn with half-block characters, two rows per line.
pub fn qr(uri: &str) -> Result<String> {
    let code = qrcode::QrCode::new(uri.as_bytes())?;
    let width = code.width();
    let dark = |x: usize, y: usize| x < width && y < width && code[(x, y)] == qrcode::Color::Dark;
    // A quiet zone of two modules on every side keeps scanners happy.
    let quiet = 2;
    let span = width + 2 * quiet;
    let mut out = String::new();
    for row in (0..span).step_by(2) {
        for col in 0..span {
            let at = |r: usize| r >= quiet && col >= quiet && dark(col - quiet, r - quiet);
            out.push(match (at(row), at(row + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermit_kernel::assess::HighWater;

    fn pairing() -> Pairing {
        Pairing {
            capsule_id: Hash([1; 32]),
            genesis: Hash([2; 32]),
            head: HighWater {
                seq: 4,
                id: Hash([3; 32]),
            },
            witness: None,
            store: Some("https://relay.example".into()),
        }
    }

    #[test]
    fn uri_round_trips_and_stays_scannable() {
        let p = pairing();
        let uri = to_uri(&p);
        assert!(uri.starts_with("hermit:"));
        let back = read(&uri).unwrap();
        assert_eq!(code(&back), code(&p));
        assert!(qr(&uri).unwrap().lines().count() > 10);
    }

    #[test]
    fn any_change_changes_the_code() {
        let p = pairing();
        let mut other_store = pairing();
        other_store.store = Some("https://evil.example".into());
        let mut older = pairing();
        older.head.seq = 3;
        for q in [other_store, older] {
            assert_ne!(code(&p), code(&q));
        }
        assert_eq!(code(&p).len(), 11);
    }

    #[test]
    fn rejects_garbage() {
        assert!(read("hermit:!!!").is_err());
        assert!(read("hermit:AAAA").is_err());
    }
}
