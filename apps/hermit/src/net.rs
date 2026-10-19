//! Outbound HTTP for providers and witnesses, optionally through a SOCKS5
//! proxy (Tor, a Nym client, ...). Encryption hides what a capsule holds; it
//! does not hide who syncs which capsule, from where, and when. With a proxy
//! set, every relay and witness request goes through it or fails: there is
//! no silent fallback to a direct connection.

use anyhow::{bail, Result};
use std::sync::OnceLock;

static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
static PROXIED: OnceLock<bool> = OnceLock::new();

/// Configure outbound HTTP once, at startup.
pub fn init(proxy: Option<&str>) -> Result<()> {
    let mut builder = ureq::AgentBuilder::new();
    if let Some(p) = proxy {
        // SOCKS5 hands hostnames to the proxy, so DNS (and .onion names)
        // resolve on the far side. SOCKS4 and HTTP proxies would resolve or
        // expose names locally.
        if !p.starts_with("socks5://") {
            bail!("--proxy must be a socks5:// URL (e.g. socks5://127.0.0.1:9050 for Tor)");
        }
        builder = builder.proxy(ureq::Proxy::new(p)?);
    }
    AGENT
        .set(builder.build())
        .map_err(|_| anyhow::anyhow!("network already initialized"))?;
    PROXIED
        .set(proxy.is_some())
        .map_err(|_| anyhow::anyhow!("network already initialized"))?;
    Ok(())
}

pub fn agent() -> &'static ureq::Agent {
    AGENT.get_or_init(ureq::Agent::new)
}

/// Whether outbound traffic must go through a proxy.
pub fn proxied() -> bool {
    *PROXIED.get().unwrap_or(&false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_socks5_is_accepted() {
        for bad in [
            "socks4://127.0.0.1:9050",
            "http://127.0.0.1:8080",
            "127.0.0.1:9050",
        ] {
            assert!(init(Some(bad)).is_err(), "{bad}");
        }
    }
}
