use core::fmt;
use std::str::FromStr;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use clap::Parser;
use iroh::NodeAddr;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub topic: TopicId,
    pub rnum: Vec<u8>,
    pub addr: NodeAddr,
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = postcard::to_stdvec(self).unwrap();
        let text = STANDARD_NO_PAD.encode(text);
        write!(f, "{}", text)
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = STANDARD_NO_PAD.decode(s)?;
        postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub daemon: bool,

    #[arg(long)]
    pub primary: bool,

    #[arg(short, long, default_value_t = true)]
    pub client: bool,

    #[arg(short, long, value_name = "NICKNAME")]
    pub alias: Option<String>,

    #[arg(short, long, value_name = "TICKET")]
    pub ticket: Option<String>,

    #[arg(short = 'D', value_name = "FILENAME", value_hint = clap::ValueHint::FilePath)]
    pub database: Option<std::path::PathBuf>,
}

impl Args {
    pub fn validate(args: &Self) -> Result<()> {
        Ok(())
    }
}
