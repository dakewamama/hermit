use serde::{Deserialize, Serialize};
use std::fmt;

/// BLAKE2b-256, personalized per use, following the Zcash convention.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Hash {
    /// `domain` must be at most 16 bytes (BLAKE2b personalization limit).
    pub fn of(domain: &[u8], data: &[u8]) -> Hash {
        let out = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(domain)
            .hash(data);
        let mut h = [0u8; 32];
        h.copy_from_slice(out.as_bytes());
        Hash(h)
    }

    /// The same hash as [`Hash::of`], fed incrementally (e.g. while
    /// streaming an upload to disk).
    pub fn hasher(domain: &[u8]) -> Hasher {
        Hasher(
            blake2b_simd::Params::new()
                .hash_length(32)
                .personal(domain)
                .to_state(),
        )
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }

    pub fn parse(s: &str) -> anyhow::Result<Hash> {
        let v = hex::decode(s)?;
        let arr: [u8; 32] = v
            .try_into()
            .map_err(|_| anyhow::anyhow!("hash must be 32 bytes"))?;
        Ok(Hash(arr))
    }
}

pub struct Hasher(blake2b_simd::State);

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(&self) -> Hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.finalize().as_bytes());
        Hash(h)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

/// Serialize byte arrays as raw CBOR byte strings rather than integer arrays.
pub(crate) mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    /// Hex in human-readable formats (JSON: pairing payloads, device
    /// homes, witness answers), raw bytes in CBOR.
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let v: serde_bytes_compat::Bytes = Deserialize::deserialize(d)?;
        v.0.try_into().map_err(|_| D::Error::custom("wrong length"))
    }

    mod serde_bytes_compat {
        use serde::de::{Deserializer, SeqAccess, Visitor};
        use std::fmt;

        pub struct Bytes(pub Vec<u8>);

        impl<'de> serde::Deserialize<'de> for Bytes {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = Bytes;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("bytes")
                    }
                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                        Ok(Bytes(v.to_vec()))
                    }
                    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E> {
                        Ok(Bytes(v))
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Bytes, E> {
                        hex::decode(v).map(Bytes).map_err(E::custom)
                    }
                    // Integer arrays: what JSON files written before hex
                    // encoding contain.
                    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Bytes, A::Error> {
                        let mut out = Vec::new();
                        while let Some(b) = a.next_element()? {
                            out.push(b);
                        }
                        Ok(Bytes(out))
                    }
                }
                if d.is_human_readable() {
                    d.deserialize_any(V)
                } else {
                    d.deserialize_bytes(V)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_hash_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let mut h = Hash::hasher(b"ZcBlob_v1");
        for chunk in data.chunks(777) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), Hash::of(b"ZcBlob_v1", &data));
    }

    #[test]
    fn hashes_are_hex_in_json_and_bytes_in_cbor() {
        let h = Hash([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<Hash>(&json).unwrap(), h);
        // Device homes written before hex encoding still load.
        let legacy = serde_json::to_string(&[0xabu8; 32]).unwrap();
        assert_eq!(serde_json::from_str::<Hash>(&legacy).unwrap(), h);
        // CBOR: a single 32-byte string (major type 2), not an array.
        let c = cbor(&h);
        assert_eq!((c[0], c.len()), (0x58, 34));
        assert_eq!(from_cbor::<Hash>(&c).unwrap(), h);
    }
}

/// Serialize a byte vector as one CBOR byte string.
pub(crate) mod bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v: ciborium::Value = Deserialize::deserialize(d)?;
        v.into_bytes()
            .map_err(|_| serde::de::Error::custom("expected bytes"))
    }
}

/// Deterministic CBOR: struct fields serialize in declaration order and the
/// kernel only uses Vec/BTreeMap, so equal values always give equal bytes.
pub fn cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

pub fn from_cbor<T: serde::de::DeserializeOwned>(b: &[u8]) -> anyhow::Result<T> {
    Ok(ciborium::from_reader(b)?)
}
