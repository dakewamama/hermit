//! Section encryption: each section is an age file addressed to every
//! authorized device. Storage only ever sees ciphertext.

use crate::device::Device;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::str::FromStr;

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
    w.write_all(plaintext)?;
    w.finish()?;
    Ok(out)
}

pub fn open(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut r = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow!("cannot decrypt section (this device is not a recipient?): {e}"))?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}
