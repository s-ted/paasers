//! Command line interface.
mod tools;

use crate::config;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;

const DEFAULT_CONFIG: &str = "/etc/paasers/gateway.kdl";

#[derive(Parser, Debug)]
#[command(name = "paasers", version, about = "PaaS edge gateway & ingress proxy")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the gateway.
    Run {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Validate a configuration file.
    Check {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Read a password on stdin and print its argon2id hash.
    HashPassword,
    /// Read an API key on stdin and print its sha256 hex digest.
    HashApiKey,
    /// Generate a TOTP secret.
    GenTotp {
        #[arg(long, default_value = "paasers")]
        issuer: String,
        #[arg(long, default_value = "gateway")]
        account: String,
    },
    /// Print the version.
    Version,
}

fn init_logs(cfg: &config::GatewayCfg) {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{Layer, fmt};
    // `Targets` understands `info,hyper=warn` directives without pulling a regex engine.
    let parse = |s: &str| s.parse::<Targets>().ok();
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| parse(&s))
        .or_else(|| parse(&cfg.log.level))
        .unwrap_or_else(|| Targets::new().with_default(LevelFilter::INFO));
    let layer = if cfg.log.json {
        fmt::layer().json().with_filter(filter).boxed()
    } else {
        fmt::layer().with_filter(filter).boxed()
    };
    let _ = tracing_subscriber::registry().with(layer).try_init();
}

/// Loads the configuration. A missing *default* file means the built-in defaults (serve the current directory).
fn load_config(path: &std::path::Path) -> Result<config::Config, config::ConfigError> {
    if path == std::path::Path::new(DEFAULT_CONFIG) && !path.exists() {
        return config::parse_str("", &|k| std::env::var(k).ok());
    }
    config::load(path)
}

fn run(path: PathBuf) -> ExitCode {
    let cfg = match load_config(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };
    init_logs(&cfg.gateway);
    config::warnings(&cfg).iter().for_each(|w| tracing::warn!("{w}"));
    let threads = cfg
        .gateway
        .worker_threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from).min(4));
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let (tx, _rx) = tokio::sync::oneshot::channel();
    match rt.block_on(crate::server::run_with(
        cfg,
        Some(path),
        tx,
        CancellationToken::new(),
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "gateway failed");
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn check(path: PathBuf) -> ExitCode {
    match load_config(&path) {
        Ok(c) => {
            config::warnings(&c)
                .iter()
                .for_each(|w| eprintln!("warning: {w}"));
            println!("OK: {} routes", c.routes.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}:{e}", path.display());
            ExitCode::from(2)
        }
    }
}

pub fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run { config } => run(config),
        Command::Check { config } => check(config),
        Command::HashPassword => tools::hash_password(),
        Command::HashApiKey => tools::hash_api_key(),
        Command::GenTotp { issuer, account } => tools::gen_totp(&issuer, &account),
        Command::Version => {
            println!("paasers {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
