use anyhow::Result;
use clap::Parser;
use network::init_network;
use storage::init_storage;
use utils::{environment_detection, CliArgs};

mod host;
mod network;
mod storage;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();
    CliArgs::validate(&args)?;
    CliArgs::apply(&args);
    environment_detection(&args);

    let storage = init_storage(&args).await?;
    match init_network(args, storage).await {
        Ok((ctx, receiver)) => {
            println!("Ticket: {}", ctx.ticket);
            ctx.run(receiver).await;
        },
        Err(e) => {
            log::error!("Failed to initialize network: {}", e);
        }
    }
    Ok(())
}
