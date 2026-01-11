//! IP Reputation agent implementation.

use crate::cache::ReputationCache;
use crate::config::{AllowlistEntry, Config, FailAction, IpExtractionConfig};
use crate::providers::abuseipdb::AbuseIPDBProvider;
use crate::providers::blocklist::BlocklistProvider;
use crate::providers::tor::TorProvider;
use crate::providers::{Action, ProviderError, ReputationProvider, ReputationResult};
use async_trait::async_trait;
use sentinel_agent_sdk::{Agent, Decision, Request, Response};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// IP Reputation agent.
pub struct IpReputationAgent {
    config: Arc<Config>,
    providers: Vec<Box<dyn ReputationProvider>>,
    allowlist: Vec<AllowlistEntry>,
    #[allow(dead_code)] // Cache is held for providers' shared access
    cache: Arc<ReputationCache>,
}

impl IpReputationAgent {
    /// Create a new IP Reputation agent.
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let allowlist = config.parse_allowlist();
        let config = Arc::new(config);

        // Create shared cache
        let cache_ttl = config
            .abuseipdb
            .as_ref()
            .map(|a| a.cache_ttl_seconds)
            .unwrap_or(3600);
        let cache = Arc::new(ReputationCache::new(cache_ttl, 10000));

        // Initialize providers
        let mut providers: Vec<Box<dyn ReputationProvider>> = Vec::new();

        // Add AbuseIPDB provider
        if let Some(ref abuseipdb_config) = config.abuseipdb {
            if abuseipdb_config.enabled {
                let provider = AbuseIPDBProvider::new(
                    abuseipdb_config.clone(),
                    config.thresholds.clone(),
                    cache.clone(),
                );
                providers.push(Box::new(provider));
                info!("AbuseIPDB provider enabled");
            }
        }

        // Add blocklist providers
        for blocklist_config in &config.blocklists {
            if blocklist_config.enabled {
                match BlocklistProvider::new(blocklist_config.clone()) {
                    Ok(provider) => {
                        info!(name = %blocklist_config.name, "Blocklist provider enabled");
                        providers.push(Box::new(provider));
                    }
                    Err(e) => {
                        warn!(
                            name = %blocklist_config.name,
                            error = %e,
                            "Failed to load blocklist"
                        );
                    }
                }
            }
        }

        // Add Tor provider
        if let Some(ref tor_config) = config.tor {
            if tor_config.enabled {
                let provider = TorProvider::new(tor_config.clone());
                // Try to initialize, but don't fail if we can't reach the Tor project
                if let Err(e) = provider.init().await {
                    warn!(error = %e, "Failed to initialize Tor provider (will retry)");
                }
                providers.push(Box::new(provider));
                info!("Tor exit node detection enabled");
            }
        }

        let enabled_providers = providers.iter().filter(|p| p.is_enabled()).count();
        info!(
            providers = enabled_providers,
            allowlist_entries = allowlist.len(),
            "IP Reputation agent initialized"
        );

        Ok(Self {
            config,
            providers,
            allowlist,
            cache,
        })
    }

    /// Extract client IP from request headers.
    fn extract_client_ip(
        &self,
        headers: &HashMap<String, String>,
    ) -> Option<IpAddr> {
        extract_client_ip(headers, &self.config.ip_extraction)
    }

    /// Check if an IP is in the allowlist.
    fn is_allowlisted(&self, ip: &IpAddr) -> bool {
        self.allowlist.iter().any(|entry| entry.contains(ip))
    }

    /// Check all providers and combine results.
    async fn check_reputation(&self, ip: &IpAddr) -> Result<CombinedResult, ProviderError> {
        let mut results = Vec::new();
        let mut highest_score: Option<u8> = None;
        let mut most_severe_action = Action::Allow;
        let mut any_error = false;

        for provider in &self.providers {
            if !provider.is_enabled() {
                continue;
            }

            match provider.check(ip).await {
                Ok(result) => {
                    // Track highest score
                    if let Some(score) = result.score {
                        highest_score = Some(highest_score.map_or(score, |h| h.max(score)));
                    }

                    // Track most severe action
                    if result.action.is_more_severe_than(&most_severe_action) {
                        most_severe_action = result.action;
                    }

                    results.push(result);
                }
                Err(e) => {
                    warn!(
                        provider = provider.name(),
                        error = %e,
                        ip = %ip,
                        "Provider lookup failed"
                    );
                    any_error = true;
                }
            }
        }

        // If all providers failed, return error
        if results.is_empty() && any_error {
            return Err(ProviderError::Other("All providers failed".to_string()));
        }

        Ok(CombinedResult {
            results,
            highest_score,
            action: most_severe_action,
        })
    }
}

/// Combined result from all providers.
struct CombinedResult {
    results: Vec<ReputationResult>,
    highest_score: Option<u8>,
    action: Action,
}

impl CombinedResult {
    /// Get reason string combining all provider reasons.
    fn reason(&self) -> Option<String> {
        let reasons: Vec<&str> = self
            .results
            .iter()
            .filter_map(|r| r.reason.as_deref())
            .collect();

        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
    }

    /// Check if any result indicates Tor.
    fn is_tor(&self) -> bool {
        self.results.iter().any(|r| r.is_tor)
    }

    /// Check if any result indicates proxy.
    fn is_proxy(&self) -> bool {
        self.results.iter().any(|r| r.is_proxy)
    }
}

/// Extract client IP from request headers.
pub fn extract_client_ip(
    headers: &HashMap<String, String>,
    config: &IpExtractionConfig,
) -> Option<IpAddr> {
    for header_name in &config.headers {
        let header_lower = header_name.to_lowercase();
        if let Some(value) = headers.get(&header_lower) {
            let ip_str = if config.use_first_ip {
                // X-Forwarded-For: client, proxy1, proxy2
                value.split(',').next()?.trim()
            } else {
                // Use the last IP (closest proxy)
                value.split(',').last()?.trim()
            };

            if let Ok(ip) = ip_str.parse() {
                return Some(ip);
            }
        }
    }
    None
}

/// Flatten multi-value headers to single values.
fn flatten_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.first().cloned().unwrap_or_default()))
        .collect()
}

#[async_trait]
impl Agent for IpReputationAgent {
    async fn on_request(&self, request: &Request) -> Decision {
        // Check global kill switch
        if !self.config.settings.enabled {
            debug!("IP Reputation agent disabled globally");
            return Decision::allow();
        }

        let headers = flatten_headers(request.headers());

        // Extract client IP
        let ip = match self.extract_client_ip(&headers) {
            Some(ip) => ip,
            None => {
                debug!("No client IP found in request headers");
                return Decision::allow();
            }
        };

        // Check allowlist
        if self.is_allowlisted(&ip) {
            debug!(ip = %ip, "IP is allowlisted");
            return Decision::allow()
                .with_tag("ip-reputation:allowlisted");
        }

        // Check reputation with all providers
        let combined = match self.check_reputation(&ip).await {
            Ok(result) => result,
            Err(e) => {
                warn!(ip = %ip, error = %e, "Reputation lookup failed");

                // Apply fail action
                return match self.config.settings.fail_action {
                    FailAction::Allow => {
                        Decision::allow()
                            .with_tag("ip-reputation:lookup-failed:allowed")
                    }
                    FailAction::Block => {
                        Decision::block(403)
                            .with_block_header("x-ip-reputation-error", "lookup-failed")
                            .with_tag("ip-reputation:lookup-failed:blocked")
                    }
                };
            }
        };

        // Determine final decision
        match combined.action {
            Action::Block => {
                let score_str = combined
                    .highest_score
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                if self.config.settings.log_blocked {
                    info!(
                        ip = %ip,
                        score = ?combined.highest_score,
                        reason = ?combined.reason(),
                        is_tor = combined.is_tor(),
                        is_proxy = combined.is_proxy(),
                        "Blocking request"
                    );
                }

                let mut decision = Decision::block(403)
                    .with_block_header("x-ip-reputation-blocked", "true")
                    .with_block_header("x-ip-reputation-score", &score_str)
                    .with_tag("ip-reputation:blocked");

                if let Some(reason) = combined.reason() {
                    decision = decision.with_block_header("x-ip-reputation-reason", &reason);
                }

                if combined.is_tor() {
                    decision = decision.with_block_header("x-ip-reputation-tor", "true");
                }

                decision
            }
            Action::Flag => {
                let score_str = combined
                    .highest_score
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                debug!(
                    ip = %ip,
                    score = ?combined.highest_score,
                    reason = ?combined.reason(),
                    "Flagging request"
                );

                let mut decision = Decision::allow()
                    .add_request_header("x-ip-reputation-flagged", "true")
                    .add_request_header("x-ip-reputation-score", &score_str)
                    .with_tag("ip-reputation:flagged");

                if combined.is_tor() {
                    decision = decision.add_request_header("x-ip-reputation-tor", "true");
                }

                if combined.is_proxy() {
                    decision = decision.add_request_header("x-ip-reputation-proxy", "true");
                }

                decision
            }
            Action::Allow => {
                if self.config.settings.log_allowed {
                    debug!(ip = %ip, "Allowing request");
                }

                Decision::allow()
                    .with_tag("ip-reputation:allowed")
            }
        }
    }

    async fn on_response(&self, _request: &Request, _response: &Response) -> Decision {
        // IP Reputation agent only operates on requests
        Decision::allow()
    }
}

// Safety: IpReputationAgent is Send + Sync because all its fields are Send + Sync
unsafe impl Send for IpReputationAgent {}
unsafe impl Sync for IpReputationAgent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpExtractionConfig;

    #[test]
    fn test_extract_client_ip_xff() {
        let config = IpExtractionConfig {
            headers: vec!["x-forwarded-for".to_string()],
            use_first_ip: true,
        };

        let mut headers = HashMap::new();
        headers.insert(
            "x-forwarded-for".to_string(),
            "1.2.3.4, 5.6.7.8, 9.10.11.12".to_string(),
        );

        let ip = extract_client_ip(&headers, &config);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_xff_last() {
        let config = IpExtractionConfig {
            headers: vec!["x-forwarded-for".to_string()],
            use_first_ip: false,
        };

        let mut headers = HashMap::new();
        headers.insert(
            "x-forwarded-for".to_string(),
            "1.2.3.4, 5.6.7.8, 9.10.11.12".to_string(),
        );

        let ip = extract_client_ip(&headers, &config);
        assert_eq!(ip, Some("9.10.11.12".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_x_real_ip() {
        let config = IpExtractionConfig {
            headers: vec!["x-forwarded-for".to_string(), "x-real-ip".to_string()],
            use_first_ip: true,
        };

        let mut headers = HashMap::new();
        headers.insert("x-real-ip".to_string(), "192.168.1.1".to_string());

        let ip = extract_client_ip(&headers, &config);
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_priority() {
        let config = IpExtractionConfig {
            headers: vec!["x-forwarded-for".to_string(), "x-real-ip".to_string()],
            use_first_ip: true,
        };

        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "1.2.3.4".to_string());
        headers.insert("x-real-ip".to_string(), "5.6.7.8".to_string());

        // Should use x-forwarded-for since it's first in the list
        let ip = extract_client_ip(&headers, &config);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_none() {
        let config = IpExtractionConfig::default();
        let headers = HashMap::new();

        let ip = extract_client_ip(&headers, &config);
        assert!(ip.is_none());
    }

    #[test]
    fn test_flatten_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );
        headers.insert(
            "X-Test".to_string(),
            vec!["value1".to_string(), "value2".to_string()],
        );

        let flat = flatten_headers(&headers);
        assert_eq!(flat.get("content-type"), Some(&"application/json".to_string()));
        assert_eq!(flat.get("x-test"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_combined_result_reason() {
        let results = vec![
            ReputationResult {
                score: Some(50),
                action: Action::Flag,
                reason: Some("Reason 1".to_string()),
                provider: "provider1".to_string(),
                cached: false,
                is_tor: false,
                is_proxy: false,
            },
            ReputationResult {
                score: Some(80),
                action: Action::Block,
                reason: Some("Reason 2".to_string()),
                provider: "provider2".to_string(),
                cached: false,
                is_tor: true,
                is_proxy: false,
            },
        ];

        let combined = CombinedResult {
            results,
            highest_score: Some(80),
            action: Action::Block,
        };

        assert_eq!(combined.reason(), Some("Reason 1; Reason 2".to_string()));
        assert!(combined.is_tor());
        assert!(!combined.is_proxy());
    }
}
