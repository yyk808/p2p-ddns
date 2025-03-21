use anyhow::Result;
use clap::Parser;
use storage::init_storage;
use utils::Args;

mod host;
mod network;
mod storage;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    Args::validate(&args)?;

    let storage = init_storage(&args).await?;
    let (ctx, receiver) = network::init_network(&args, storage).await?;

    ctx.run(receiver).await
}
