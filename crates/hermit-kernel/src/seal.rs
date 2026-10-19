//! Section encryption: each section is an age file addressed to every
//! authorized device. Storage only ever sees ciphertext.
//!
//! Before encryption the plaintext is framed (an 8-byte length, the data,
//! then zeros) and padded with Padmé (Nikitin et al., PURBs, 2019): sizes
//! round up to a bucket that leaks O(log log n) bits of the length, at most
//! ~12% overhead. Without this, a provider watching blob sizes learns how
//! large a wallet is and every time it grows.

use crate::device::Device;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::str::FromStr;

/// Padmé: round `len` up so that only its top O(log log len) bits survive.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - u64::from(len.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// The size of the padded frame a plaintext of `plain_len` bytes is sealed
/// as. This, not the true length, is what manifests may record.
pub fn framed_len(plain_len: usize) -> u64 {
    padme(plain_len as u64 + 8)
}

pub fn seal(plaintext: &[u8], devices: &[Device]) -> Result<Vec<u8>> {
    let recipients = devices
        .iter()
        .map(|d| {
            age::x25519::Recipient::from_str(&d.recipient)
                .map_err(|e| anyhow!("bad recipient for {}: {e}", d.name))
        })
        .collect::<Result<Vec<_>>>()?;
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let mut out = Vec::new();
    let mut w = encryptor.wrap_output(&mut out)?;
    let framed = framed_len(plaintext.len());
    w.write_all(&(plaintext.len() as u64).to_le_bytes())?;
    w.write_all(plaintext)?;
    std::io::copy(
        &mut std::io::repeat(0).take(framed - 8 - plaintext.len() as u64),
        &mut w,
    )?;
    w.finish()?;
    Ok(out)
}

pub fn open(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut r = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow!("cannot decrypt section (this device is not a recipient?): {e}"))?;
    let mut frame = Vec::new();
    r.read_to_end(&mut frame)?;
    let (len, rest) = frame
        .split_first_chunk::<8>()
        .ok_or_else(|| anyhow!("sealed frame is too short"))?;
    let len = usize::try_from(u64::from_le_bytes(*len))?;
    anyhow::ensure!(
        len <= rest.len() && rest[len..].iter().all(|&b| b == 0),
        "sealed frame is malformed"
    );
    Ok(rest[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_matches_the_paper_and_bounds_overhead() {
        // Values from the PURBs paper's definition.
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(1000), 1024);
        assert_eq!(padme(1025), 1088);
        for len in (2..2_000_000u64).step_by(997) {
            let p = padme(len);
            assert!(p >= len);
            assert!((p - len) * 100 <= len * 12 + 100, "{len} -> {p}");
        }
    }

    #[test]
    fn nearby_sizes_share_a_bucket() {
        assert_eq!(framed_len(8_220_000), framed_len(8_230_000));
    }

    #[test]
    fn frames_round_trip_and_hide_the_exact_length() {
        let d = crate::DeviceKeys::generate("d");
        for n in [0usize, 1, 7, 8, 100, 65_536, 70_001] {
            let pt: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let ct = seal(&pt, &[d.public()]).unwrap();
            assert_eq!(open(&ct, &d.identity()).unwrap(), pt);
        }
        // 1000 and 1010 bytes land in the same 1024-byte frame. age adds a
        // random-length grease stanza to every header, so whole ciphertexts
        // differ only by that noise, never by the data's length.
        assert_eq!(framed_len(1000), 1024);
        assert_eq!(framed_len(1010), 1024);
        let sizes: Vec<usize> = (0..20)
            .flat_map(|_| [1000usize, 1010])
            .map(|n| seal(&vec![1u8; n], &[d.public()]).unwrap().len())
            .collect();
        let (min, max) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
        assert!(max - min < 300, "spread {min}..{max} exceeds header noise");
    }
}
