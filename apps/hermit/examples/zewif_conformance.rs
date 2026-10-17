//! Validate a ZeWIF document against the normative CDDL schema.
//!
//!   cargo run -p hermit --example zewif_conformance -- export.zewif

use std::process::ExitCode;

const SCHEMA: &str = include_str!("../schema/zewif.cddl");

/// Skip the container framing (self-described CBOR tag, ZeWIF tag, the
/// two-element array header and the version) to reach the `zewif` map.
fn payload(document: &[u8]) -> Result<&[u8], minicbor::decode::Error> {
    let mut d = minicbor::Decoder::new(document);
    d.decode::<minicbor::data::Tag>()?;
    d.decode::<minicbor::data::Tag>()?;
    d.array()?;
    d.u32()?;
    Ok(&document[d.position()..])
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: zewif_conformance <file.zewif>");
        return ExitCode::from(2);
    };
    let document = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let result = payload(&document)
        .map_err(|e| e.to_string())
        .and_then(|p| cddl_cat::validate_cbor_bytes("zewif", SCHEMA, p).map_err(|e| e.to_string()));
    match result {
        Ok(()) => {
            println!("✓ {path} conforms to zewif.cddl");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("✗ {path} does not conform to zewif.cddl:\n{e}");
            ExitCode::FAILURE
        }
    }
}
