//! Tor exit node detection provider.

use super::{Action, ProviderError, ReputationProvider, ReputationResult};
use crate::config::{BlocklistAction, TorConfig};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Tor exit node detection provider.
pub struct TorProvider {
    config: TorConfig,
    client: Client,
    exit_nodes: RwLock<HashSet<IpAddr>>,
    last_refresh: RwLock<Option<Instant>>,
}

impl TorProvider {
    /// Create a new Tor provider.
    pub fn new(config: TorConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            exit_nodes: RwLock::new(HashSet::new()),
            last_refresh: RwLock::new(None),
        }
    }

    /// Initialize the provider by fetching the exit node list.
    pub async fn init(&self) -> Result<(), ProviderError> {
        self.refresh().await
    }

    /// Refresh the Tor exit node list if needed.
    pub async fn refresh_if_needed(&self) -> Result<(), ProviderError> {
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
            self.refresh().await?;
        }

        Ok(())
    }

    /// Force refresh the Tor exit node list.
    pub async fn refresh(&self) -> Result<(), ProviderError> {
        debug!(url = %self.config.exit_node_list_url, "Fetching Tor exit node list");

        let response = self
            .client
            .get(&self.config.exit_node_list_url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(ProviderError::InvalidResponse(format!(
                "HTTP {}",
                status
            )));
        }

        let content = response.text().await.map_err(|e| {
            ProviderError::InvalidResponse(format!("Failed to read response: {}", e))
        })?;

        let exit_nodes: HashSet<IpAddr> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| line.trim().parse().ok())
            .collect();

        let count = exit_nodes.len();

        if let Ok(mut nodes) = self.exit_nodes.write() {
            *nodes = exit_nodes;
        }

        if let Ok(mut last) = self.last_refresh.write() {
            *last = Some(Instant::now());
        }

        info!(exit_nodes = count, "Tor exit node list loaded");

        Ok(())
    }

    /// Check if an IP is a known Tor exit node.
    fn is_tor_exit(&self, ip: &IpAddr) -> bool {
        if let Ok(nodes) = self.exit_nodes.read() {
            nodes.contains(ip)
        } else {
            false
        }
    }

    /// Get the number of loaded exit nodes.
    pub fn exit_node_count(&self) -> usize {
        self.exit_nodes.read().map(|n| n.len()).unwrap_or(0)
    }
}

#[async_trait]
impl ReputationProvider for TorProvider {
    async fn check(&self, ip: &IpAddr) -> Result<ReputationResult, ProviderError> {
        // Refresh if needed (but don't fail the check if refresh fails)
        if let Err(e) = self.refresh_if_needed().await {
            warn!(error = %e, "Failed to refresh Tor exit node list");
        }

        if self.is_tor_exit(ip) {
            debug!(ip = %ip, "IP is a Tor exit node");

            let action = match self.config.action {
                BlocklistAction::Block => Action::Block,
                BlocklistAction::Flag => Action::Flag,
            };

            Ok(ReputationResult {
                score: Some(100),
                action,
                reason: Some("Tor exit node".to_string()),
                provider: self.name().to_string(),
                cached: false,
                is_tor: true,
                is_proxy: false,
            })
        } else {
            Ok(ReputationResult::allow(self.name()))
        }
    }

    fn name(&self) -> &str {
        "tor"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TorConfig {
        TorConfig {
            enabled: true,
            action: BlocklistAction::Flag,
            exit_node_list_url: "https://check.torproject.org/torbulkexitlist".to_string(),
            refresh_interval_seconds: 3600,
        }
    }

    #[test]
    fn test_provider_name() {
        let provider = TorProvider::new(create_test_config());
        assert_eq!(provider.name(), "tor");
    }

    #[test]
    fn test_provider_enabled() {
        let mut config = create_test_config();
        config.enabled = true;
        let provider = TorProvider::new(config);
        assert!(provider.is_enabled());

        let mut config2 = create_test_config();
        config2.enabled = false;
        let provider2 = TorProvider::new(config2);
        assert!(!provider2.is_enabled());
    }

    #[tokio::test]
    async fn test_check_non_tor_ip() {
        let provider = TorProvider::new(create_test_config());

        // Without loading the list, any IP should be allowed
        let result = provider.check(&"8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Allow);
        assert!(!result.is_tor);
    }

    #[test]
    fn test_is_tor_exit_after_manual_load() {
        let provider = TorProvider::new(create_test_config());

        // Manually add an IP to the exit nodes
        {
            let mut nodes = provider.exit_nodes.write().unwrap();
            nodes.insert("1.2.3.4".parse().unwrap());
        }

        assert!(provider.is_tor_exit(&"1.2.3.4".parse().unwrap()));
        assert!(!provider.is_tor_exit(&"5.6.7.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_check_tor_exit_block() {
        let mut config = create_test_config();
        config.action = BlocklistAction::Block;
        let provider = TorProvider::new(config);

        // Manually add an IP to the exit nodes and set last_refresh to prevent network call
        {
            let mut nodes = provider.exit_nodes.write().unwrap();
            nodes.insert("1.2.3.4".parse().unwrap());
        }
        {
            let mut last = provider.last_refresh.write().unwrap();
            *last = Some(Instant::now());
        }

        let result = provider.check(&"1.2.3.4".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Block);
        assert!(result.is_tor);
        assert_eq!(result.score, Some(100));
    }

    #[tokio::test]
    async fn test_check_tor_exit_flag() {
        let mut config = create_test_config();
        config.action = BlocklistAction::Flag;
        let provider = TorProvider::new(config);

        // Manually add an IP to the exit nodes and set last_refresh to prevent network call
        {
            let mut nodes = provider.exit_nodes.write().unwrap();
            nodes.insert("1.2.3.4".parse().unwrap());
        }
        {
            let mut last = provider.last_refresh.write().unwrap();
            *last = Some(Instant::now());
        }

        let result = provider.check(&"1.2.3.4".parse().unwrap()).await.unwrap();
        assert_eq!(result.action, Action::Flag);
        assert!(result.is_tor);
    }
}
