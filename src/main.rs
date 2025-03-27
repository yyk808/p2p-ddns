use anyhow::Result;
use clap::Parser;
use network::init_network;
use storage::init_storage;
use utils::{CliArgs, environment_detection};

mod host;
mod network;
mod protocol;
mod storage;
mod utils;

#[compio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();
    CliArgs::validate(&args)?;
    CliArgs::apply(&args);
    environment_detection(&args);

    let storage = init_storage(&args).await?;

    match init_network(args, storage).await {
        Ok((ctx, gos_recv, sp_recv, rnum)) => {
            log::info!("Ticket: {}", ctx.ticket);
            ctx.run(gos_recv, sp_recv, rnum).await;
        }
        Err(e) => {
            log::error!("Failed to initialize network: {}", e);
        }
    }
    Ok(())
}
