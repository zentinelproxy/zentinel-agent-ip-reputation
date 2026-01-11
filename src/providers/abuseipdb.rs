//! AbuseIPDB reputation provider.

use super::{Action, ProviderError, ReputationProvider, ReputationResult};
use crate::cache::ReputationCache;
use crate::config::{AbuseIPDBConfig, Thresholds};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// AbuseIPDB API response.
#[derive(Debug, Deserialize)]
struct AbuseIPDBResponse {
    data: AbuseIPDBData,
}

/// AbuseIPDB API response data.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields parsed from API response for future use
struct AbuseIPDBData {
    /// Abuse confidence score (0-100).
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,

    /// Total number of reports.
    #[serde(rename = "totalReports")]
    total_reports: u32,

    /// Whether the IP is a known Tor exit node.
    #[serde(rename = "isTor")]
    is_tor: bool,

    /// Whether the IP is a known public proxy.
    #[serde(rename = "isPublicProxy", default)]
    is_public_proxy: bool,

    /// Country code.
    #[serde(rename = "countryCode", default)]
    country_code: Option<String>,

    /// ISP name.
    #[serde(default)]
    isp: Option<String>,

    /// Usage type (e.g., "Data Center/Web Hosting/Transit").
    #[serde(rename = "usageType", default)]
    usage_type: Option<String>,
}

/// AbuseIPDB reputation provider.
pub struct AbuseIPDBProvider {
    config: AbuseIPDBConfig,
    thresholds: Thresholds,
    client: Client,
    cache: Arc<ReputationCache>,
}

impl AbuseIPDBProvider {
    /// Create a new AbuseIPDB provider.
    pub fn new(
        config: AbuseIPDBConfig,
        thresholds: Thresholds,
        cache: Arc<ReputationCache>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            thresholds,
            client,
            cache,
        }
    }

    /// Determine action based on score and thresholds.
    fn score_to_action(&self, score: u8) -> Action {
        if score >= self.thresholds.block_score {
            Action::Block
        } else if score >= self.thresholds.flag_score {
            Action::Flag
        } else {
            Action::Allow
        }
    }
}

#[async_trait]
impl ReputationProvider for AbuseIPDBProvider {
    async fn check(&self, ip: &IpAddr) -> Result<ReputationResult, ProviderError> {
        // Check cache first
        if let Some(cached) = self.cache.get(ip) {
            debug!(ip = %ip, score = cached.score, "AbuseIPDB cache hit");
            let action = self.score_to_action(cached.score);
            return Ok(ReputationResult {
                score: Some(cached.score),
                action,
                reason: Some(format!("AbuseIPDB score: {}", cached.score)),
                provider: self.name().to_string(),
                cached: true,
                is_tor: cached.is_tor,
                is_proxy: cached.is_proxy,
            });
        }

        // Make API request
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays={}",
            ip, self.config.max_age_days
        );

        debug!(ip = %ip, "Querying AbuseIPDB");

        let response = self
            .client
            .get(&url)
            .header("Key", &self.config.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        // Check for rate limiting
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("AbuseIPDB rate limit exceeded");
            return Err(ProviderError::RateLimited);
        }

        // Check for other errors
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        // Parse response
        let api_response: AbuseIPDBResponse = response.json().await.map_err(|e| {
            ProviderError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        let data = api_response.data;
        let score = data.abuse_confidence_score;
        let action = self.score_to_action(score);

        // Cache the result
        self.cache.set(
            *ip,
            score,
            self.name(),
            data.is_tor,
            data.is_public_proxy,
        );

        debug!(
            ip = %ip,
            score = score,
            is_tor = data.is_tor,
            is_proxy = data.is_public_proxy,
            reports = data.total_reports,
            "AbuseIPDB lookup complete"
        );

        let reason = if data.total_reports > 0 {
            format!(
                "AbuseIPDB score: {} ({} reports)",
                score, data.total_reports
            )
        } else {
            format!("AbuseIPDB score: {}", score)
        };

        Ok(ReputationResult {
            score: Some(score),
            action,
            reason: Some(reason),
            provider: self.name().to_string(),
            cached: false,
            is_tor: data.is_tor,
            is_proxy: data.is_public_proxy,
        })
    }

    fn name(&self) -> &str {
        "abuseipdb"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AbuseIPDBConfig {
        AbuseIPDBConfig {
            enabled: true,
            api_key: "test-key".to_string(),
            max_age_days: 90,
            cache_ttl_seconds: 3600,
            timeout_ms: 5000,
        }
    }

    fn create_test_thresholds() -> Thresholds {
        Thresholds {
            block_score: 80,
            flag_score: 50,
        }
    }

    #[test]
    fn test_score_to_action() {
        let cache = Arc::new(ReputationCache::new(3600, 1000));
        let provider = AbuseIPDBProvider::new(
            create_test_config(),
            create_test_thresholds(),
            cache,
        );

        assert_eq!(provider.score_to_action(0), Action::Allow);
        assert_eq!(provider.score_to_action(49), Action::Allow);
        assert_eq!(provider.score_to_action(50), Action::Flag);
        assert_eq!(provider.score_to_action(79), Action::Flag);
        assert_eq!(provider.score_to_action(80), Action::Block);
        assert_eq!(provider.score_to_action(100), Action::Block);
    }

    #[test]
    fn test_provider_name() {
        let cache = Arc::new(ReputationCache::new(3600, 1000));
        let provider = AbuseIPDBProvider::new(
            create_test_config(),
            create_test_thresholds(),
            cache,
        );

        assert_eq!(provider.name(), "abuseipdb");
    }

    #[test]
    fn test_provider_enabled() {
        let cache = Arc::new(ReputationCache::new(3600, 1000));

        let mut config = create_test_config();
        config.enabled = true;
        let provider = AbuseIPDBProvider::new(config, create_test_thresholds(), cache.clone());
        assert!(provider.is_enabled());

        let mut config2 = create_test_config();
        config2.enabled = false;
        let provider2 = AbuseIPDBProvider::new(config2, create_test_thresholds(), cache);
        assert!(!provider2.is_enabled());
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache = Arc::new(ReputationCache::new(3600, 1000));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Pre-populate cache
        cache.set(ip, 75, "abuseipdb", true, false);

        let provider = AbuseIPDBProvider::new(
            create_test_config(),
            create_test_thresholds(),
            cache,
        );

        let result = provider.check(&ip).await.unwrap();
        assert!(result.cached);
        assert_eq!(result.score, Some(75));
        assert!(result.is_tor);
        assert!(!result.is_proxy);
        assert_eq!(result.action, Action::Flag); // 75 is >= 50 but < 80
    }
}
