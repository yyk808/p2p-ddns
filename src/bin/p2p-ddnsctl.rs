use anyhow::Result;
use clap::Parser;

use p2p_ddns::app::{self, ClientArgs};

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();
    app::run_client(args).await
}
