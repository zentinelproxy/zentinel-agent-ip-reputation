//! IP Reputation Agent for Zentinel.
//!
//! Checks client IPs against threat intelligence feeds and blocklists to
//! identify and block malicious traffic.
//!
//! # Features
//!
//! - **AbuseIPDB Integration** - Query AbuseIPDB API for IP reputation scores
//! - **Custom Blocklists** - Load blocklists from CSV, JSON, or plain text files
//! - **Tor Exit Node Detection** - Check against Tor exit node list
//! - **Reputation Thresholds** - Block/allow based on configurable score thresholds
//! - **Caching** - Cache lookups with configurable TTL
//! - **Fail-Open/Closed** - Configurable behavior when lookup fails
//!
//! # Example Configuration
//!
//! ```yaml
//! settings:
//!   enabled: true
//!   fail_action: allow
//!
//! thresholds:
//!   block_score: 80
//!   flag_score: 50
//!
//! abuseipdb:
//!   enabled: true
//!   api_key: "${ABUSEIPDB_API_KEY}"
//!   cache_ttl_seconds: 3600
//!
//! allowlist:
//!   - "127.0.0.1"
//!   - "10.0.0.0/8"
//! ```

pub mod agent;
pub mod cache;
pub mod config;
pub mod providers;

pub use agent::IpReputationAgent;
pub use config::Config;
