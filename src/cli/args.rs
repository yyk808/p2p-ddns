use core::fmt;
use std::{fmt::Display, str::FromStr};

use anyhow::Result;
use clap::{Parser, builder::TypedValueParser};
use iroh::discovery::UserData;

use crate::util;

#[derive(Debug, Clone, Copy, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

#[derive(Debug, Default, Clone, Parser)]
#[command(version, about, long_about = None)]
pub struct DaemonArgs {
    /// Internal flag used by the daemon entrypoint.
    /// In the unified binary, `--daemon` sets this automatically.
    #[arg(skip)]
    pub daemon: bool,

    /// To be the first node in this p2p network
    #[arg(long)]
    pub primary: bool,

    /// Name of this node, used in dns resolving
    #[arg(short = 'D', long, value_name = "NICKNAME")]
    pub domain: Option<String>,

    /// Use ticket string to join a existing network
    #[arg(short, long, value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Manually specify the path of the database directory
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
    pub log: LogLevel,

    #[arg(long, short = 'B', value_name = "BIND_ADDR")]
    pub bind: Option<String>,

    /// Disable local-network discovery (mDNS)
    #[arg(long, default_value_t = false)]
    pub no_mdns: bool,

    /// Enable DHT-based discovery (PKARR on Mainline DHT); helps in cross-subnet scenarios without DNS.
    #[arg(long, default_value_t = false)]
    pub dht: bool,

    /// Enable admin HTTP server (e.g. 127.0.0.1:8080)
    #[arg(long, value_name = "ADMIN_HTTP")]
    pub admin_http: Option<String>,

    /// For debug convinience
    #[cfg(debug_assertions)]
    #[arg(long)]
    pub debug: bool,
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
        Ok(level)
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Off => "off",
        };
        write!(f, "{}", text)
    }
}

impl DaemonArgs {
    pub fn validate(args: &Self) -> Result<()> {
        if args
            .domain
            .as_deref()
            .is_some_and(|s| s.len() >= UserData::MAX_LENGTH)
        {
            anyhow::bail!("alias length should be less than {}", UserData::MAX_LENGTH);
        }

        if let Some(bind) = args.bind.as_deref() {
            let _ = util::parse_bind_addr(bind)?;
        }

        if let Some(bind) = args.admin_http.as_deref() {
            let _ = util::parse_bind_addr(bind)?;
        }

        Ok(())
    }

    pub fn apply(&self) {
        // Logger initialization moved to main() to avoid double initialization.
    }
}
