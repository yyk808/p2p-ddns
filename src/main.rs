use core::fmt;
use std::{
    collections::{BTreeMap, HashMap}, iter::Map, net::SocketAddr, str::FromStr, sync::Arc
};

use anyhow::Result;
use bytes::Bytes;
use ed25519::Signature;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use iroh::{
    discovery::pkarr::dht::DhtDiscovery, node_info::UserData, protocol::Router, Endpoint, NodeAddr, NodeId, PublicKey, SecretKey
};
use iroh_gossip::{
    ALPN,
    net::Gossip,
    proto::{Config, TopicId},
};
use network::Context;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use clap::Parser;
use storage::init_storage;
use utils::Args;

mod host;
mod storage;
mod network;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    Args::validate(&args)?;

    let storage = init_storage(&args).await?;
    let (ctx, receiver) = network::init_network(
        &args,
        storage,
    ).await?;

    ctx.run(receiver).await
}
