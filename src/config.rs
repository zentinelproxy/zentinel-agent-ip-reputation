//! Configuration types for IP Reputation agent.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Root configuration for IP Reputation agent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Global settings.
    #[serde(default)]
    pub settings: Settings,

    /// IP extraction configuration.
    #[serde(default)]
    pub ip_extraction: IpExtractionConfig,

    /// Reputation thresholds.
    #[serde(default)]
    pub thresholds: Thresholds,

    /// AbuseIPDB provider configuration.
    #[serde(default)]
    pub abuseipdb: Option<AbuseIPDBConfig>,

    /// File-based blocklists.
    #[serde(default)]
    pub blocklists: Vec<BlocklistConfig>,

    /// Tor exit node detection.
    #[serde(default)]
    pub tor: Option<TorConfig>,

    /// IP allowlist (always allowed, skips all checks).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Global settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    /// Master enable/disable switch.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Action when provider lookup fails.
    #[serde(default)]
    pub fail_action: FailAction,

    /// Log blocked requests.
    #[serde(default = "default_true")]
    pub log_blocked: bool,

    /// Log allowed requests.
    #[serde(default)]
    pub log_allowed: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_action: FailAction::default(),
            log_blocked: true,
            log_allowed: false,
        }
    }
}

/// Action to take when provider lookup fails.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FailAction {
    /// Allow request when lookup fails (fail-open).
    #[default]
    Allow,
    /// Block request when lookup fails (fail-closed).
    Block,
}

/// IP extraction configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpExtractionConfig {
    /// Headers to check for client IP, in order of preference.
    #[serde(default = "default_ip_headers")]
    pub headers: Vec<String>,

    /// Use first IP from X-Forwarded-For (true) or last IP (false).
    #[serde(default = "default_true")]
    pub use_first_ip: bool,
}

impl Default for IpExtractionConfig {
    fn default() -> Self {
        Self {
            headers: default_ip_headers(),
            use_first_ip: true,
        }
    }
}

fn default_ip_headers() -> Vec<String> {
    vec![
        "x-forwarded-for".to_string(),
        "x-real-ip".to_string(),
        "cf-connecting-ip".to_string(),
    ]
}

/// Reputation score thresholds.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Thresholds {
    /// Block if score is >= this value.
    #[serde(default = "default_block_score")]
    pub block_score: u8,

    /// Flag (add warning header) if score >= this value.
    #[serde(default = "default_flag_score")]
    pub flag_score: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            block_score: default_block_score(),
            flag_score: default_flag_score(),
        }
    }
}

fn default_block_score() -> u8 {
    80
}

fn default_flag_score() -> u8 {
    50
}

/// AbuseIPDB provider configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AbuseIPDBConfig {
    /// Enable AbuseIPDB lookups.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API key (supports ${ENV_VAR} syntax).
    pub api_key: String,

    /// Only consider reports from the last N days.
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,

    /// Cache TTL in seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// API request timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_max_age_days() -> u32 {
    90
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_timeout() -> u64 {
    5000
}

/// File-based blocklist configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlocklistConfig {
    /// Name for logging/metrics.
    pub name: String,

    /// Enable this blocklist.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to blocklist file.
    pub path: PathBuf,

    /// File format.
    #[serde(default)]
    pub format: BlocklistFormat,

    /// Action to take for matched IPs.
    #[serde(default)]
    pub action: BlocklistAction,

    /// How often to refresh the blocklist from disk (seconds).
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_seconds: u64,
}

fn default_refresh_interval() -> u64 {
    300
}

/// Blocklist file format.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// Plain text, one IP/CIDR per line.
    #[default]
    Plain,
    /// CSV with IP column.
    Csv,
    /// JSON array of IPs.
    Json,
}

/// Action for blocklist matches.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistAction {
    /// Block the request.
    #[default]
    Block,
    /// Flag the request but allow.
    Flag,
}

/// Tor exit node detection configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TorConfig {
    /// Enable Tor exit node detection.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Action to take for Tor exit nodes.
    #[serde(default = "default_tor_action")]
    pub action: BlocklistAction,

    /// URL to fetch Tor exit node list.
    #[serde(default = "default_tor_url")]
    pub exit_node_list_url: String,

    /// How often to refresh the Tor list (seconds).
    #[serde(default = "default_tor_refresh")]
    pub refresh_interval_seconds: u64,
}

fn default_tor_action() -> BlocklistAction {
    BlocklistAction::Flag
}

fn default_tor_url() -> String {
    "https://check.torproject.org/torbulkexitlist".to_string()
}

fn default_tor_refresh() -> u64 {
    3600
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let expanded = expand_env_vars(&content);
        let config: Config = serde_yaml::from_str(&expanded)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate thresholds
        if self.thresholds.flag_score > self.thresholds.block_score {
            anyhow::bail!(
                "flag_score ({}) must be <= block_score ({})",
                self.thresholds.flag_score,
                self.thresholds.block_score
            );
        }

        // Validate AbuseIPDB config
        if let Some(ref abuseipdb) = self.abuseipdb {
            if abuseipdb.enabled && abuseipdb.api_key.is_empty() {
                anyhow::bail!("AbuseIPDB is enabled but api_key is empty");
            }
        }

        // Validate blocklist paths
        for blocklist in &self.blocklists {
            if blocklist.enabled && !blocklist.path.exists() {
                anyhow::bail!(
                    "Blocklist '{}' path does not exist: {}",
                    blocklist.name,
                    blocklist.path.display()
                );
            }
        }

        // Validate allowlist entries can be parsed
        for entry in &self.allowlist {
            if entry.parse::<IpAddr>().is_err() && entry.parse::<IpNet>().is_err() {
                anyhow::bail!("Invalid allowlist entry: {}", entry);
            }
        }

        Ok(())
    }

    /// Parse allowlist entries into IpAddr or IpNet.
    pub fn parse_allowlist(&self) -> Vec<AllowlistEntry> {
        self.allowlist
            .iter()
            .filter_map(|s| {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    Some(AllowlistEntry::Single(ip))
                } else if let Ok(net) = s.parse::<IpNet>() {
                    Some(AllowlistEntry::Network(net))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Generate example configuration YAML.
    pub fn example() -> String {
        r#"# IP Reputation Agent Configuration

settings:
  enabled: true
  fail_action: allow           # allow or block when lookup fails
  log_blocked: true
  log_allowed: false

# IP extraction from request headers
ip_extraction:
  headers:
    - "x-forwarded-for"
    - "x-real-ip"
    - "cf-connecting-ip"
  use_first_ip: true           # Use first IP from X-Forwarded-For

# Reputation score thresholds (0-100, higher = worse)
thresholds:
  block_score: 80              # Block if score >= 80
  flag_score: 50               # Flag (add header) if score >= 50

# AbuseIPDB provider (optional)
abuseipdb:
  enabled: true
  api_key: "${ABUSEIPDB_API_KEY}"  # Use environment variable
  max_age_days: 90             # Only consider reports from last 90 days
  cache_ttl_seconds: 3600      # Cache results for 1 hour
  timeout_ms: 5000             # API timeout

# File-based blocklists (optional)
blocklists:
  - name: "internal-blocklist"
    enabled: true
    path: "/etc/zentinel/blocklist.txt"
    format: plain              # plain, csv, or json
    action: block              # block or flag
    refresh_interval_seconds: 300

# Tor exit node detection (optional)
tor:
  enabled: true
  action: flag                 # block or flag
  exit_node_list_url: "https://check.torproject.org/torbulkexitlist"
  refresh_interval_seconds: 3600

# IP allowlist - always allowed, skips all checks
# Supports single IPs and CIDR notation
allowlist:
  - "127.0.0.1"
  - "10.0.0.0/8"
  - "192.168.0.0/16"
  - "172.16.0.0/12"
"#
        .to_string()
    }
}

/// Parsed allowlist entry.
#[derive(Debug, Clone)]
pub enum AllowlistEntry {
    Single(IpAddr),
    Network(IpNet),
}

impl AllowlistEntry {
    /// Check if an IP address matches this allowlist entry.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            AllowlistEntry::Single(allowed) => allowed == ip,
            AllowlistEntry::Network(net) => net.contains(ip),
        }
    }
}

/// Expand environment variables in the format ${VAR_NAME}.
fn expand_env_vars(content: &str) -> String {
    let mut result = content.to_string();
    let re = regex::Regex::new(r"\$\{([^}]+)\}").unwrap();

    for cap in re.captures_iter(content) {
        let var_name = &cap[1];
        let var_value = std::env::var(var_name).unwrap_or_default();
        result = result.replace(&cap[0], &var_value);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert!(settings.enabled);
        assert_eq!(settings.fail_action, FailAction::Allow);
        assert!(settings.log_blocked);
        assert!(!settings.log_allowed);
    }

    #[test]
    fn test_default_thresholds() {
        let thresholds = Thresholds::default();
        assert_eq!(thresholds.block_score, 80);
        assert_eq!(thresholds.flag_score, 50);
    }

    #[test]
    fn test_default_ip_extraction() {
        let config = IpExtractionConfig::default();
        assert_eq!(config.headers.len(), 3);
        assert_eq!(config.headers[0], "x-forwarded-for");
        assert!(config.use_first_ip);
    }

    #[test]
    fn test_expand_env_vars() {
        std::env::set_var("TEST_API_KEY", "secret123");
        let input = "api_key: \"${TEST_API_KEY}\"";
        let result = expand_env_vars(input);
        assert_eq!(result, "api_key: \"secret123\"");
        std::env::remove_var("TEST_API_KEY");
    }

    #[test]
    fn test_expand_env_vars_missing() {
        let input = "api_key: \"${NONEXISTENT_VAR}\"";
        let result = expand_env_vars(input);
        assert_eq!(result, "api_key: \"\"");
    }

    #[test]
    fn test_allowlist_entry_single() {
        let entry = AllowlistEntry::Single("192.168.1.1".parse().unwrap());
        assert!(entry.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!entry.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_allowlist_entry_network() {
        let entry = AllowlistEntry::Network("10.0.0.0/8".parse().unwrap());
        assert!(entry.contains(&"10.0.0.1".parse().unwrap()));
        assert!(entry.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!entry.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_config_yaml() {
        let yaml = r#"
settings:
  enabled: true
  fail_action: block

thresholds:
  block_score: 90
  flag_score: 60

allowlist:
  - "127.0.0.1"
  - "10.0.0.0/8"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.settings.enabled);
        assert_eq!(config.settings.fail_action, FailAction::Block);
        assert_eq!(config.thresholds.block_score, 90);
        assert_eq!(config.thresholds.flag_score, 60);
        assert_eq!(config.allowlist.len(), 2);
    }

    #[test]
    fn test_validate_thresholds() {
        let config = Config {
            settings: Settings::default(),
            ip_extraction: IpExtractionConfig::default(),
            thresholds: Thresholds {
                block_score: 50,
                flag_score: 80, // Invalid: flag > block
            },
            abuseipdb: None,
            blocklists: vec![],
            tor: None,
            allowlist: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_allowlist_invalid() {
        let config = Config {
            settings: Settings::default(),
            ip_extraction: IpExtractionConfig::default(),
            thresholds: Thresholds::default(),
            abuseipdb: None,
            blocklists: vec![],
            tor: None,
            allowlist: vec!["not-an-ip".to_string()],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_allowlist() {
        let config = Config {
            settings: Settings::default(),
            ip_extraction: IpExtractionConfig::default(),
            thresholds: Thresholds::default(),
            abuseipdb: None,
            blocklists: vec![],
            tor: None,
            allowlist: vec![
                "127.0.0.1".to_string(),
                "10.0.0.0/8".to_string(),
                "::1".to_string(),
            ],
        };

        let entries = config.parse_allowlist();
        assert_eq!(entries.len(), 3);
    }
}
