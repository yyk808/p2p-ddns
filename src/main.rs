use anyhow::Result;
use clap::Parser;
use network::init_network;
use storage::init_storage;
use utils::CliArgs;

mod host;
mod network;
mod storage;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();
    CliArgs::validate(&args)?;

    let storage = init_storage(&args).await?;
    let (ctx, receiver) = init_network(args, storage).await?;

    ctx.run(receiver).await;
    Ok(())
}
