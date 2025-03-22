use core::fmt;
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
    sync::Arc, time::Duration,
};

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use clap::{Args, Parser, builder::TypedValueParser};
use iroh::{NodeAddr, node_info::UserData};
use iroh_gossip::proto::TopicId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tabled::{settings::{object::Columns, Style}, Tabled};
use std::path::PathBuf;

use crate::network::Context;

#[derive(Debug, Clone)]
pub struct Ticket {
    inner: Arc<RwLock<TicketInner>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TicketInner {
    pub topic: TopicId,
    pub rnum: Vec<u8>,
    pub addr: NodeAddr,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

#[derive(Debug, Default, Clone, Parser)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// Running mode, daemon or client(default)
    #[arg(short, long, default_value_t = false, group = "backend")]
    pub daemon: bool,

    /// To be the first node in this p2p network
    #[arg(long, requires = "backend")]
    pub primary: bool,

    /// Name of this node, used in dns resolving
    #[arg(short, long, value_name = "NICKNAME", requires = "backend")]
    pub alias: Option<String>,

    /// Use ticket string to join a existing network
    #[arg(short, long, value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Manually specify the path of the database file
    #[arg(short, long , value_name = "CONFIG_PATH", value_hint = clap::ValueHint::DirPath)]
    pub config: Option<std::path::PathBuf>,

    /// Log level, default is info
    #[arg(
        long,
        short = 'L',
        default_value_t = LogLevel::Info,
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"])
            .map(|s| s.parse::<LogLevel>().unwrap()),
    )]
    log: LogLevel,

    /// For debug convinience
    #[cfg(debug_assertions)]
    #[arg(long)]
    pub debug: bool,
}

impl Ticket {
    pub fn new(topic: Option<TopicId>, addr: NodeAddr) -> Self {
        let rnum = rand::random::<[u8; 32]>().to_vec();
        let topic = topic.unwrap_or_else(|| TopicId::from_bytes(rand::random()));
        Self {
            inner: Arc::new(RwLock::new(TicketInner { topic, rnum, addr })),
        }
    }

    pub fn topic(&self) -> TopicId {
        self.inner.read().topic
    }

    pub fn validate(&self, topic: TopicId, rnum: impl AsRef<[u8]>) -> bool {
        self.inner.read().topic == topic && self.inner.read().rnum == rnum.as_ref()
    }

    pub fn load_addr(&self) -> NodeAddr {
        self.inner.read().addr.clone()
    }

    pub fn flatten(&self) -> (TopicId, Vec<u8>, NodeAddr) {
        let inner = self.inner.read();
        (inner.topic, inner.rnum.clone(), inner.addr.clone())
    }

    pub fn refresh(&self, ctx: Context) {
        let mut inner = self.inner.write();
        inner.rnum = rand::random::<[u8; 32]>().to_vec();
        inner.addr = ctx.me.addr.clone();
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(debug_assertions)]
        log::debug!("Displaying Ticket: {:?}", self.inner);

        let inner = self.inner.read();
        let text = postcard::to_stdvec(&*inner).unwrap();
        let text = STANDARD_NO_PAD.encode(text);
        write!(f, "{}", text)
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = STANDARD_NO_PAD.decode(s)?;
        let inner: Result<TicketInner> =
            postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!(e));

        #[cfg(debug_assertions)]
        log::debug!("Loaded Ticket from str: {:?}", inner);

        inner.map(|inner| Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

impl From<LogLevel> for log::LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Off => log::LevelFilter::Off,
        }
    }
}

impl FromStr for LogLevel {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let level = match s {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "off" => LogLevel::Off,
            _ => anyhow::bail!("Invalid log level: {}", s),
        };
        Ok(level.into())
    }
}

impl ToString for LogLevel {
    fn to_string(&self) -> String {
        match self {
            Self::Trace => "trace".to_string(),
            Self::Debug => "debug".to_string(),
            Self::Info => "info".to_string(),
            Self::Warn => "warn".to_string(),
            Self::Error => "error".to_string(),
            Self::Off => "off".to_string(),
        }
    }
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

    pub fn apply(&self) {
        env_logger::Builder::new()
            .filter(Some("p2p_ddns2"), self.log.into())
            .init();
    }
}

pub(crate) fn environment_detection(args: &CliArgs) {
    // check if the user has permission to write to the default storage path
    let mut path = default_config_path(args);
    let error;
    if !path.exists() {
        error = std::fs::create_dir_all(&path).is_err();
    } else {
        path.push(".test");
        error = std::fs::File::create(&path).is_err();
    }

    if error {
        eprintln!("Cannot write to the default storage path: {:?}", path);
        eprintln!("Please run the program with sudo or specify a different path");
        std::process::exit(1);
    }
}

pub(crate) fn default_config_path(args: &CliArgs) -> PathBuf {
    // depending on platform and running_mode, return the default path
    if let Some(path) = &args.config {
        return path.clone();
    }

    let privileged_path = if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\ProgramData\p2p-ddns")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/p2p-ddns")
    } else {
        // Linux and others
        PathBuf::from("/etc/p2p-ddns")
    };
    let normal_path = {
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

    // Check if the user has permission to write to the default storage path
    if args.daemon {
        let test_file = privileged_path.join("test");
        if test_file.exists() {
            match std::fs::remove_dir(&test_file) {
                Ok(_) => privileged_path,
                Err(_) => normal_path,
            }
        } else {
            match std::fs::create_dir_all(&test_file) {
                Ok(_) => {
                    std::fs::remove_dir(&test_file).ok();
                    privileged_path
                }
                Err(_) => normal_path,
            }
        }
    } else {
        normal_path
    }
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    format!("{}Hour {}Min {}Sec ago", hours, minutes, seconds)
}

pub fn output(ctx: Context) {
    let data = ctx.nodes.iter().map(|r| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let node = r.value();
        // find out the first addr start with 10.xxx or 192.168.xxx
        let addr = node.addr.direct_addresses.iter().find(|addr| {
            addr.is_ipv4() && !addr.ip().is_loopback() && !addr.ip().is_multicast()
        }).map(|addr| addr.to_string()).unwrap_or_else(|| "Unknown".to_string());
        let alias = node.alias.clone();
        let last_seen = format_duration(now - node.last_heartbeat);
        (addr, alias, last_seen)
    }).collect::<Vec<_>>();

    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["Address", "Name", "Last Seen"]);
    for (addr, alias, last_seen) in data {
        builder.push_record([addr, alias, last_seen]);
    }
    let table = builder.build();
    println!("{}", table);
}
