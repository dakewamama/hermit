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

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
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
                    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Bytes, A::Error> {
                        let mut out = Vec::new();
                        while let Some(b) = a.next_element()? {
                            out.push(b);
                        }
                        Ok(Bytes(out))
                    }
                }
                d.deserialize_bytes(V)
            }
        }
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
