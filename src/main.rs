//! IP Reputation Agent CLI.

use anyhow::Result;
use clap::Parser;
use zentinel_agent_ip_reputation::{Config, IpReputationAgent};
use zentinel_agent_sdk::v2::{AgentRunnerV2, TransportConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "zentinel-agent-ip-reputation")]
#[command(about = "IP Reputation agent for Zentinel - check client IPs against threat intelligence and blocklists")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "ip-reputation.yaml")]
    config: PathBuf,

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-config
    if args.print_config {
        println!("{}", Config::example());
        return Ok(());
    }

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configuration
    info!(config = %args.config.display(), "Loading configuration");
    let config = Config::load(&args.config)?;

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
        TransportConfig::Both { grpc_address, uds_path } => runner.with_both(grpc_address, uds_path),
    };

    runner.run().await?;

    Ok(())
}
