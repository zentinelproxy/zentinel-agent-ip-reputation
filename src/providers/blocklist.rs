//! File-based blocklist provider.

use super::{Action, ProviderError, ReputationProvider, ReputationResult};
use crate::config::{BlocklistAction, BlocklistConfig, BlocklistFormat};
use async_trait::async_trait;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Entry in the blocklist - either a single IP or a CIDR range.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum BlocklistEntry {
    Single(IpAddr),
    Network(IpNet),
}

impl BlocklistEntry {
    /// Check if an IP address matches this entry.
    fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            BlocklistEntry::Single(addr) => addr == ip,
            BlocklistEntry::Network(net) => net.contains(ip),
        }
    }
}

/// File-based blocklist provider.
pub struct BlocklistProvider {
    config: BlocklistConfig,
    entries: RwLock<HashSet<BlocklistEntry>>,
    last_refresh: RwLock<Option<Instant>>,
}

impl BlocklistProvider {
    /// Create a new blocklist provider.
    pub fn new(config: BlocklistConfig) -> Result<Self, ProviderError> {
        let provider = Self {
            config,
            entries: RwLock::new(HashSet::new()),
            last_refresh: RwLock::new(None),
        };

        // Load initial blocklist
        provider.refresh()?;

        Ok(provider)
    }

    /// Refresh the blocklist from disk if needed.
    pub fn refresh_if_needed(&self) -> Result<(), ProviderError> {
        let should_refresh = {
            let last = self.last_refresh.read().ok();
            match last.as_ref().and_then(|l| l.as_ref()) {
                Some(instant) => {
                    instant.elapsed() > Duration::from_secs(self.config.refresh_interval_seconds)
                }
                None => true,
            }
        };

        if should_refresh {
            self.refresh()?;
        }

        Ok(())
    }

    /// Force refresh the blocklist from disk.
    pub fn refresh(&self) -> Result<(), ProviderError> {
        let entries = load_blocklist(&self.config.path, self.config.format)?;

        let count = entries.len();
        if let Ok(mut e) = self.entries.write() {
            *e = entries;
        }

        if let Ok(mut last) = self.last_refresh.write() {
            *last = Some(Instant::now());
        }

        info!(
            blocklist = %self.config.name,
            entries = count,
            "Blocklist loaded"
        );

        Ok(())
    }

    /// Check if an IP is in the blocklist.
    fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Ok(entries) = self.entries.read() {
            entries.iter().any(|e| e.contains(ip))
        } else {
            false
        }
    }
}

#[async_trait]
impl ReputationProvider for BlocklistProvider {
    async fn check(&self, ip: &IpAddr) -> Result<ReputationResult, ProviderError> {
        // Refresh if needed
        if let Err(e) = self.refresh_if_needed() {
            warn!(
                blocklist = %self.config.name,
                error = %e,
                "Failed to refresh blocklist"
            );
        }

        if self.is_blocked(ip) {
            debug!(ip = %ip, blocklist = %self.config.name, "IP found in blocklist");

            let action = match self.config.action {
                BlocklistAction::Block => Action::Block,
                BlocklistAction::Flag => Action::Flag,
            };

            Ok(ReputationResult {
                score: Some(100), // Max score for blocklist matches
                action,
                reason: Some(format!("Listed in blocklist: {}", self.config.name)),
                provider: self.name().to_string(),
                cached: false,
                is_tor: false,
                is_proxy: false,
            })
        } else {
            Ok(ReputationResult::allow(self.name()))
        }
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Load a blocklist from a file.
fn load_blocklist(path: &Path, format: BlocklistFormat) -> Result<HashSet<BlocklistEntry>, ProviderError> {
    let content = std::fs::read_to_string(path)?;

    match format {
        BlocklistFormat::Plain => load_plain_blocklist(&content),
        BlocklistFormat::Csv => load_csv_blocklist(&content),
        BlocklistFormat::Json => load_json_blocklist(&content),
    }
}

/// Load a plain text blocklist (one IP/CIDR per line).
fn load_plain_blocklist(content: &str) -> Result<HashSet<BlocklistEntry>, ProviderError> {
    let entries = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| parse_entry(line.trim()))
        .collect();

    Ok(entries)
}

/// Load a CSV blocklist (first column is IP/CIDR).
fn load_csv_blocklist(content: &str) -> Result<HashSet<BlocklistEntry>, ProviderError> {
    let entries = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| {
            let first_column = line.split(',').next()?.trim();
            parse_entry(first_column)
        })
        .collect();

    Ok(entries)
}

/// Load a JSON blocklist (array of IP/CIDR strings).
fn load_json_blocklist(content: &str) -> Result<HashSet<BlocklistEntry>, ProviderError> {
    let ips: Vec<String> = serde_json::from_str(content)
        .map_err(|e| ProviderError::InvalidResponse(format!("Invalid JSON: {}", e)))?;

    let entries = ips
        .iter()
        .filter_map(|ip| parse_entry(ip.trim()))
        .collect();

    Ok(entries)
}

/// Parse a string into a blocklist entry.
fn parse_entry(s: &str) -> Option<BlocklistEntry> {
    // Try parsing as IpAddr first
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(BlocklistEntry::Single(ip));
    }

    // Try parsing as CIDR
    if let Ok(net) = s.parse::<IpNet>() {
        return Some(BlocklistEntry::Network(net));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_blocklist(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_parse_entry_ip() {
        let entry = parse_entry("192.168.1.1").unwrap();
        assert!(matches!(entry, BlocklistEntry::Single(_)));
    }

    #[test]
    fn test_parse_entry_cidr() {
        let entry = parse_entry("10.0.0.0/8").unwrap();
        assert!(matches!(entry, BlocklistEntry::Network(_)));
    }

    #[test]
    fn test_parse_entry_invalid() {
        assert!(parse_entry("not-an-ip").is_none());
    }

    #[test]
    fn test_blocklist_entry_contains() {
        let single = BlocklistEntry::Single("192.168.1.1".parse().unwrap());
        assert!(single.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!single.contains(&"192.168.1.2".parse().unwrap()));

        let network = BlocklistEntry::Network("10.0.0.0/8".parse().unwrap());
        assert!(network.contains(&"10.0.0.1".parse().unwrap()));
        assert!(network.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!network.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_load_plain_blocklist() {
        let content = r#"
# Comment
192.168.1.1
10.0.0.0/8

# Another comment
1.2.3.4
"#;
        let entries = load_plain_blocklist(content).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_load_csv_blocklist() {
        let content = r#"
192.168.1.1,reason1,date1
10.0.0.0/8,reason2,date2
1.2.3.4,reason3,date3
"#;
        let entries = load_csv_blocklist(content).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_load_json_blocklist() {
        let content = r#"["192.168.1.1", "10.0.0.0/8", "1.2.3.4"]"#;
        let entries = load_json_blocklist(content).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_blocklist_provider() {
        let file = create_temp_blocklist("192.168.1.1\n10.0.0.0/8\n");

        let config = BlocklistConfig {
            name: "test".to_string(),
            enabled: true,
            path: file.path().to_path_buf(),
            format: BlocklistFormat::Plain,
            action: BlocklistAction::Block,
            refresh_interval_seconds: 300,
        };

        let provider = BlocklistProvider::new(config).unwrap();

        // Should be blocked
        let result = provider.check(&"192.168.1.1".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Block);
        assert_eq!(result.score, Some(100));

        // Should be blocked (in CIDR range)
        let result = provider.check(&"10.0.0.1".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Block);

        // Should be allowed
        let result = provider.check(&"8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[tokio::test]
    async fn test_blocklist_flag_action() {
        let file = create_temp_blocklist("192.168.1.1\n");

        let config = BlocklistConfig {
            name: "test".to_string(),
            enabled: true,
            path: file.path().to_path_buf(),
            format: BlocklistFormat::Plain,
            action: BlocklistAction::Flag,
            refresh_interval_seconds: 300,
        };

        let provider = BlocklistProvider::new(config).unwrap();

        let result = provider.check(&"192.168.1.1".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Flag);
    }
}
