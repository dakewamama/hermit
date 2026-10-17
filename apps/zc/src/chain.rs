//! Chain checks against a lightwalletd-compatible server (lightwalletd or
//! Zaino). The capsule is never trusted about the chain: its anchor must be a
//! real block, and the rescan delta is measured against the live tip.

use anyhow::{anyhow, Result};
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec,
};
use zc_kernel::{Anchor, Hash};

pub fn default_server(network: &str) -> &'static str {
    match network {
        "main" => "https://zec.rocks:443",
        _ => "https://testnet.zec.rocks:443",
    }
}

pub struct Chain {
    client: CompactTxStreamerClient<Channel>,
    rt: tokio::runtime::Runtime,
}

impl Chain {
    pub fn connect(server: &str) -> Result<Chain> {
        let rt = tokio::runtime::Runtime::new()?;
        let client = rt.block_on(async {
            let mut ch = Channel::from_shared(server.to_string())?;
            if server.starts_with("https://") {
                let host = server
                    .trim_start_matches("https://")
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                ch = ch.tls_config(
                    ClientTlsConfig::new()
                        .domain_name(host)
                        .assume_http2(true)
                        .with_webpki_roots(),
                )?;
            }
            anyhow::Ok(CompactTxStreamerClient::new(ch.connect().await?))
        })?;
        Ok(Chain { client, rt })
    }

    pub fn tip(&mut self) -> Result<u32> {
        let r = self
            .rt
            .block_on(self.client.get_latest_block(ChainSpec {}))?
            .into_inner();
        Ok(r.height as u32)
    }

    pub fn block_hash(&mut self, height: u32) -> Result<Hash> {
        let r = self
            .rt
            .block_on(self.client.get_block(BlockId { height: height as u64, hash: vec![] }))?
            .into_inner();
        Ok(Hash(r.hash.try_into().map_err(|_| anyhow!("server returned a malformed block hash"))?))
    }

    /// `Ok(None)` if the anchor is on the chain, `Ok(Some(actual))` if not.
    pub fn check_anchor(&mut self, anchor: &Anchor) -> Result<Option<Hash>> {
        let actual = self.block_hash(anchor.height)?;
        Ok((actual != anchor.block_hash).then_some(actual))
    }
}

/// Block hashes are stored in internal byte order; humans read them reversed.
pub fn display_hash(h: &Hash) -> String {
    let mut b = h.0;
    b.reverse();
    hex::encode(b)
}
