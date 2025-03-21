use core::fmt;
use std::str::FromStr;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use clap::{Args, Parser};
use iroh::{NodeAddr, node_info::UserData};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

#[derive(Debug, Default, Clone, Parser)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// Running mode, client or daemon
    #[command(flatten)]
    pub running_mode: RunningMode,

    /// To be the first node in this p2p network
    #[arg(long, group = "daemon")]
    pub primary: bool,

    /// Name of this node, used in dns resolving
    #[arg(short, long, value_name = "NICKNAME", requires = "daemon")]
    pub alias: Option<String>,

    /// Use ticket string to join a existing network
    #[arg(short, long, value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Manually specify the path of the database file
    #[arg(short = 'D', value_name = "FILENAME", value_hint = clap::ValueHint::FilePath)]
    pub database: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Default, Args)]
#[group(required = true, multiple = false)]
pub struct RunningMode {
    #[arg(short, long, group = "client")]
    pub client: bool,

    #[arg(short, long, group = "daemon")]
    pub daemon: bool,
}

impl CliArgs {
    pub fn validate(args: &Self) -> Result<()> {
        if args
            .alias
            .as_deref()
            .is_some_and(|s| s.len() >= UserData::MAX_LENGTH)
        {
            anyhow::bail!("alias length should be less than {}", UserData::MAX_LENGTH);
        }
        Ok(())
    }
}

pub(crate) fn default_storage_path(args: &CliArgs) -> PathBuf {
    // depending on platform and running_mode, return the default path
    if let Some(path) = &args.database {
        return path.clone();
    }

    let mut path = if args.running_mode.daemon {
        // Daemon mode uses system paths
        if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\ProgramData\p2p-ddns")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/p2p-ddns")
        } else {
            // Linux and others
            PathBuf::from("/etc/p2p-ddns")
        }
    } else {
        // Client mode uses user home directory
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

        if cfg!(target_os = "windows") {
            home.join("AppData").join("Local").join("p2p-ddns")
        } else if cfg!(target_os = "macos") {
            home.join("Library")
                .join("Application Support")
                .join("p2p-ddns")
        } else {
            // Linux and others
            home.join(".config").join("p2p-ddns")
        }
    };

    path.push("nodes.db");
    path
}
