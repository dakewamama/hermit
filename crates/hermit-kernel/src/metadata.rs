//! Metadata class: a last-writer-wins map. Two devices editing different
//! keys (or the same key) always converge without asking the user.

use crate::hash::{cbor, from_cbor, hex_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `None` is a tombstone.
    pub value: Option<String>,
    pub lamport: u64,
    #[serde(with = "hex_bytes")]
    pub device: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Labels(pub BTreeMap<String, Entry>);

impl Labels {
    pub fn decode(b: &[u8]) -> anyhow::Result<Labels> {
        from_cbor(b)
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor(self)
    }

    pub fn clock(&self) -> u64 {
        self.0.values().map(|e| e.lamport).max().unwrap_or(0)
    }

    pub fn set(&mut self, key: &str, value: Option<String>, device: [u8; 32]) {
        let lamport = self.clock() + 1;
        self.0.insert(
            key.to_string(),
            Entry {
                value,
                lamport,
                device,
            },
        );
    }

    pub fn merge(&self, other: &Labels) -> Labels {
        let mut out = self.0.clone();
        for (k, theirs) in &other.0 {
            match out.get(k) {
                Some(ours) if (ours.lamport, ours.device) >= (theirs.lamport, theirs.device) => {}
                _ => {
                    out.insert(k.clone(), theirs.clone());
                }
            }
        }
        Labels(out)
    }

    pub fn live(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0
            .iter()
            .filter_map(|(k, e)| e.value.as_ref().map(|v| (k, v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_is_commutative_and_keeps_both_sides() {
        let mut base = Labels::default();
        base.set("tx:aa", Some("rent".into()), [1; 32]);
        let mut a = base.clone();
        a.set("tx:aa", Some("rent (Oct)".into()), [1; 32]);
        let mut b = base.clone();
        b.set("contact:bob", Some("u1bob".into()), [2; 32]);
        assert_eq!(a.merge(&b), b.merge(&a));
        let m = a.merge(&b);
        assert_eq!(m.0["tx:aa"].value.as_deref(), Some("rent (Oct)"));
        assert_eq!(m.0["contact:bob"].value.as_deref(), Some("u1bob"));
    }
}
