//! IP Reputation Agent CLI.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_ip_reputation::{Config, IpReputationAgent};
use sentinel_agent_sdk::AgentRunner;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-ip-reputation")]
#[command(about = "IP Reputation agent for Sentinel - check client IPs against threat intelligence and blocklists")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "ip-reputation.yaml")]
    config: PathBuf,

    /// Unix socket path
    #[arg(short, long, default_value = "/tmp/sentinel-ip-reputation.sock")]
    socket: PathBuf,

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

    // Run agent
    info!(socket = %args.socket.display(), "Starting IP Reputation agent");
    AgentRunner::new(agent)
        .with_name("ip-reputation")
        .with_socket(&args.socket)
        .run()
        .await?;

    Ok(())
}
