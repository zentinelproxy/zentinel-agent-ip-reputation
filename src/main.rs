//! IP Reputation Agent CLI.

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zentinel_agent_ip_reputation::{Config, IpReputationAgent};
use zentinel_agent_sdk::v2::{AgentRunnerV2, TransportConfig};

#[derive(Parser, Debug)]
#[command(name = "zentinel-ip-reputation-agent")]
#[command(
    about = "IP Reputation agent for Zentinel - check client IPs against threat intelligence and blocklists"
)]
#[command(version)]
struct Args {
    /// Path to configuration file. Without it, `ip-reputation.yaml` in the
    /// working directory is read if it exists, otherwise the agent starts
    /// with the defaults (no providers: every request is allowed).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Unix socket path
    #[arg(short, long, default_value = "/tmp/zentinel-ip-reputation.sock")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    #[arg(long, value_name = "ADDR")]
    grpc_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'L', long, default_value = "info")]
    log_level: String,

    /// Print example configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,
}

/// Config file read when `--config` is not given, if it exists.
const DEFAULT_CONFIG: &str = "ip-reputation.yaml";

/// An explicit `--config` must exist; the implicit default file is optional.
fn load_config(path: Option<&Path>) -> Result<Config> {
    match path {
        Some(path) => {
            info!(config = %path.display(), "Loading configuration");
            Config::load(path).with_context(|| format!("failed to load config {}", path.display()))
        }
        None if Path::new(DEFAULT_CONFIG).exists() => {
            info!(config = DEFAULT_CONFIG, "Loading configuration");
            Config::load(Path::new(DEFAULT_CONFIG))
                .with_context(|| format!("failed to load config {DEFAULT_CONFIG}"))
        }
        None => {
            info!("No configuration file, using defaults (no providers enabled)");
            let config = Config::default();
            config.validate()?;
            Ok(config)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-config
    if args.print_config {
        println!("{}", Config::example());
        return Ok(());
    }

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configuration
    let config = load_config(args.config.as_deref())?;

    // Handle --validate
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = IpReputationAgent::new(config).await?;

    // Configure transport based on CLI options
    let transport = match args.grpc_address {
        Some(grpc_addr) => {
            info!(
                grpc_address = %grpc_addr,
                socket = %args.socket.display(),
                "Starting IP Reputation agent with gRPC and UDS (v2 protocol)"
            );
            TransportConfig::Both {
                grpc_address: grpc_addr,
                uds_path: args.socket,
            }
        }
        None => {
            info!(socket = %args.socket.display(), "Starting IP Reputation agent with UDS (v2 protocol)");
            TransportConfig::Uds { path: args.socket }
        }
    };

    // Run agent with v2 runner
    let mut runner = AgentRunnerV2::new(agent).with_name("ip-reputation");

    runner = match transport {
        TransportConfig::Grpc { address } => runner.with_grpc(address),
        TransportConfig::Uds { path } => runner.with_uds(path),
        TransportConfig::Both {
            grpc_address,
            uds_path,
        } => runner.with_both(grpc_address, uds_path),
    };

    runner.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The release pipeline and `zentinel bundle install` expect exactly
    /// `<binary> <version>`.
    #[test]
    fn version_is_binary_name_and_package_version() {
        assert_eq!(
            Args::command().render_version(),
            format!("{} {}\n", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn starts_without_a_config_file() {
        let config = load_config(None).unwrap();
        assert!(config.blocklists.is_empty());
        assert!(config.abuseipdb.is_none());
    }

    #[test]
    fn explicit_missing_config_is_an_error() {
        assert!(load_config(Some(Path::new("/nonexistent/ip-reputation.yaml"))).is_err());
    }
}
