//! Continuity kernel.
//!
//! A capsule is a DAG of signed manifests. Each manifest commits to a set of
//! encrypted sections, each tagged with a [`Class`] that decides how
//! concurrent changes to it may be reconciled. Storage is never trusted:
//! everything a client acts on is re-derived from signatures and lineage.

pub mod assess;
pub mod device;
pub mod hash;
pub mod manifest;
pub mod metadata;
pub mod seal;
pub mod witness;

pub use assess::{assess, Verdict};
pub use device::{Device, DeviceKeys};
pub use hash::Hash;
pub use manifest::{Anchor, Body, Class, Manifest, SectionRef};
