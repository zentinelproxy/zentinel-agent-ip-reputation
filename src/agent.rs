//! IP Reputation agent implementation.

use crate::cache::ReputationCache;
use crate::client_ip::{resolve_client_ip, TrustedProxies};
use crate::config::{AllowlistEntry, Config, FailAction};
use crate::providers::abuseipdb::AbuseIPDBProvider;
use crate::providers::blocklist::BlocklistProvider;
use crate::providers::tor::TorProvider;
use crate::providers::{Action, ProviderError, ReputationProvider, ReputationResult};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason, GaugeMetric,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::EventType;
use zentinel_agent_sdk::prelude::*;

/// IP Reputation agent.
pub struct IpReputationAgent {
    config: Arc<Config>,
    providers: Vec<Box<dyn ReputationProvider>>,
    allowlist: Vec<AllowlistEntry>,
    /// Proxies whose forwarding headers are believed
    trusted_proxies: TrustedProxies,
    #[allow(dead_code)] // Cache is held for providers' shared access
    cache: Arc<ReputationCache>,
    /// Total requests processed.
    requests_total: AtomicU64,
    /// Total requests blocked.
    requests_blocked: AtomicU64,
    /// Total requests allowed.
    requests_allowed: AtomicU64,
    /// Total requests flagged.
    requests_flagged: AtomicU64,
    /// Total lookup failures.
    lookup_failures: AtomicU64,
    /// Total allowlist matches.
    allowlist_matches: AtomicU64,
    /// Whether the agent is draining (not accepting new requests).
    draining: AtomicBool,
}

impl IpReputationAgent {
    /// Create a new IP Reputation agent.
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let allowlist = config.parse_allowlist();
        let trusted_proxies = TrustedProxies::parse(&config.ip_extraction.trusted_proxies)
            .map_err(|e| anyhow::anyhow!("ip_extraction.trusted_proxies: {}", e))?;
        if config.ip_extraction.use_first_ip.is_some() {
            warn!(
                "ip_extraction.use_first_ip is no longer used: the client IP is the connection \
                 address, or behind ip_extraction.trusted_proxies the right-most untrusted hop"
            );
        }
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
            trusted_proxies,
            cache,
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_flagged: AtomicU64::new(0),
            lookup_failures: AtomicU64::new(0),
            allowlist_matches: AtomicU64::new(0),
            draining: AtomicBool::new(false),
        })
    }

    /// Check if the agent is currently draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Get total requests processed.
    pub fn total_requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get total requests blocked.
    pub fn total_blocked(&self) -> u64 {
        self.requests_blocked.load(Ordering::Relaxed)
    }

    /// Get total requests allowed.
    pub fn total_allowed(&self) -> u64 {
        self.requests_allowed.load(Ordering::Relaxed)
    }

    /// Get total requests flagged.
    pub fn total_flagged(&self) -> u64 {
        self.requests_flagged.load(Ordering::Relaxed)
    }

    /// Resolve the client IP: the connection address from the event metadata,
    /// or behind a trusted proxy the right-most untrusted forwarding hop.
    fn client_ip(&self, request: &Request) -> Option<IpAddr> {
        resolve_client_ip(
            request.client_ip(),
            request.headers(),
            &self.config.ip_extraction.headers,
            &self.trusted_proxies,
        )
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

#[async_trait]
impl Agent for IpReputationAgent {
    fn name(&self) -> &str {
        "ip-reputation"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Increment request counter
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Check global kill switch
        if !self.config.settings.enabled {
            debug!("IP Reputation agent disabled globally");
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            return Decision::allow();
        }

        // Check if draining - skip processing for new requests
        if self.is_draining() {
            debug!("Agent is draining, allowing request without checks");
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            return Decision::allow();
        }

        // Resolve client IP. Without a usable address nothing can be checked;
        // treat it like a failed lookup rather than a clean client.
        let ip = match self.client_ip(request) {
            Some(ip) => ip,
            None => {
                warn!(
                    client_ip = %request.client_ip(),
                    "No usable client IP in request metadata"
                );
                self.lookup_failures.fetch_add(1, Ordering::Relaxed);
                return match self.config.settings.fail_action {
                    FailAction::Allow => {
                        self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                        Decision::allow().with_tag("ip-reputation:no-client-ip:allowed")
                    }
                    FailAction::Block => {
                        self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                        Decision::block(403)
                            .with_block_header("x-ip-reputation-error", "no-client-ip")
                            .with_tag("ip-reputation:no-client-ip:blocked")
                    }
                };
            }
        };

        // Check allowlist
        if self.is_allowlisted(&ip) {
            debug!(ip = %ip, "IP is allowlisted");
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            self.allowlist_matches.fetch_add(1, Ordering::Relaxed);
            return Decision::allow().with_tag("ip-reputation:allowlisted");
        }

        // Check reputation with all providers
        let combined = match self.check_reputation(&ip).await {
            Ok(result) => result,
            Err(e) => {
                warn!(ip = %ip, error = %e, "Reputation lookup failed");
                self.lookup_failures.fetch_add(1, Ordering::Relaxed);

                // Apply fail action
                return match self.config.settings.fail_action {
                    FailAction::Allow => {
                        self.requests_allowed.fetch_add(1, Ordering::Relaxed);
                        Decision::allow().with_tag("ip-reputation:lookup-failed:allowed")
                    }
                    FailAction::Block => {
                        self.requests_blocked.fetch_add(1, Ordering::Relaxed);
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
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);

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
                self.requests_flagged.fetch_add(1, Ordering::Relaxed);

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
                self.requests_allowed.fetch_add(1, Ordering::Relaxed);

                if self.config.settings.log_allowed {
                    debug!(ip = %ip, "Allowing request");
                }

                Decision::allow().with_tag("ip-reputation:allowed")
            }
        }
    }

    async fn on_response(&self, _request: &Request, _response: &Response) -> Decision {
        // IP Reputation agent only operates on requests
        Decision::allow()
    }

    async fn on_configure(&self, config: serde_json::Value) -> Result<(), String> {
        // v2 configuration update support
        if config.is_null() {
            return Ok(());
        }

        // Log the configuration update
        info!(
            config = %config,
            "Received configuration update"
        );

        // For now, we just acknowledge the config - full hot-reload would require
        // more complex state management
        Ok(())
    }
}

/// v2 Protocol implementation for IpReputationAgent.
#[async_trait]
impl AgentHandlerV2 for IpReputationAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "ip-reputation",
            "IP Reputation Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_features(AgentFeatures {
            streaming_body: false,
            websocket: false,
            guardrails: false,
            config_push: true,
            health_reporting: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
        })
    }

    fn health_status(&self) -> HealthStatus {
        // Report healthy unless we're draining
        if self.is_draining() {
            HealthStatus::degraded("ip-reputation", vec!["ip-checks".to_string()], 1.0)
        } else {
            HealthStatus::healthy("ip-reputation")
        }
    }

    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("ip-reputation", 10_000);

        // Add counter metrics
        report.counters.push(CounterMetric::new(
            "ip_reputation_requests_total",
            self.total_requests(),
        ));

        report.counters.push(CounterMetric::new(
            "ip_reputation_requests_blocked_total",
            self.total_blocked(),
        ));

        report.counters.push(CounterMetric::new(
            "ip_reputation_requests_allowed_total",
            self.total_allowed(),
        ));

        report.counters.push(CounterMetric::new(
            "ip_reputation_requests_flagged_total",
            self.total_flagged(),
        ));

        report.counters.push(CounterMetric::new(
            "ip_reputation_lookup_failures_total",
            self.lookup_failures.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ip_reputation_allowlist_matches_total",
            self.allowlist_matches.load(Ordering::Relaxed),
        ));

        // Add gauge metrics
        report.gauges.push(GaugeMetric::new(
            "ip_reputation_providers_enabled",
            self.providers.iter().filter(|p| p.is_enabled()).count() as f64,
        ));

        report.gauges.push(GaugeMetric::new(
            "ip_reputation_agent_enabled",
            if self.config.settings.enabled {
                1.0
            } else {
                0.0
            },
        ));

        report.gauges.push(GaugeMetric::new(
            "ip_reputation_agent_draining",
            if self.is_draining() { 1.0 } else { 0.0 },
        ));

        report.gauges.push(GaugeMetric::new(
            "ip_reputation_allowlist_entries",
            self.allowlist.len() as f64,
        ));

        report.gauges.push(GaugeMetric::new(
            "ip_reputation_cache_entries",
            self.cache.len() as f64,
        ));

        Some(report)
    }

    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "IP Reputation agent shutdown requested"
        );
        // Set draining flag to stop processing new requests
        self.draining.store(true, Ordering::SeqCst);
    }

    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        warn!(
            reason = ?reason,
            duration_ms = duration_ms,
            "IP Reputation agent drain requested - stopping IP checks"
        );
        self.draining.store(true, Ordering::SeqCst);
    }

    async fn on_stream_closed(&self) {
        debug!("gRPC stream closed");
    }
}

// Safety: IpReputationAgent is Send + Sync because all its fields are Send + Sync
unsafe impl Send for IpReputationAgent {}
unsafe impl Sync for IpReputationAgent {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Agent with a blocklist holding `blocked`, behind `trusted` proxies.
    async fn agent_blocking(
        blocked: &str,
        trusted: &[&str],
        allowlist: &[&str],
        fail_action: FailAction,
    ) -> (IpReputationAgent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocklist.txt");
        std::fs::write(&path, format!("{}\n", blocked)).unwrap();
        let yaml = format!(
            "settings:\n  fail_action: {}\nip_extraction:\n  trusted_proxies: [{}]\nblocklists:\n  - name: test\n    path: {}\n",
            match fail_action {
                FailAction::Allow => "allow",
                FailAction::Block => "block",
            },
            trusted
                .iter()
                .map(|t| format!("\"{}\"", t))
                .collect::<Vec<_>>()
                .join(", "),
            path.display()
        );
        let mut config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.allowlist = allowlist.iter().map(|a| a.to_string()).collect();
        config.validate().unwrap();
        (IpReputationAgent::new(config).await.unwrap(), dir)
    }

    fn request(client_ip: &str, headers: &[(&str, &str)]) -> Request {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in headers {
            map.entry(k.to_string()).or_default().push(v.to_string());
        }
        let event = zentinel_agent_protocol::RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test".to_string(),
                request_id: "test".to_string(),
                client_ip: client_ip.to_string(),
                client_port: 40000,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2026-10-22T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: map,
        };
        Request::from_headers_event(&event)
    }

    fn is_block(decision: Decision) -> bool {
        matches!(
            decision.build().decision,
            zentinel_agent_protocol::Decision::Block { .. }
        )
    }

    #[tokio::test]
    async fn test_blocked_peer_cannot_escape_with_spoofed_xff() {
        let (agent, _dir) = agent_blocking("203.0.113.7", &[], &[], FailAction::Allow).await;
        let req = request(
            "203.0.113.7",
            &[
                ("X-Forwarded-For", "198.51.100.1"),
                ("X-Real-IP", "198.51.100.1"),
            ],
        );
        assert!(is_block(agent.on_request(&req).await));
    }

    #[tokio::test]
    async fn test_spoofed_xff_cannot_frame_another_ip() {
        let (agent, _dir) = agent_blocking("203.0.113.7", &[], &[], FailAction::Allow).await;
        let req = request("198.51.100.1", &[("X-Forwarded-For", "203.0.113.7")]);
        assert!(!is_block(agent.on_request(&req).await));
    }

    #[tokio::test]
    async fn test_trusted_proxy_right_most_untrusted_hop() {
        let (agent, _dir) =
            agent_blocking("203.0.113.7", &["10.0.0.0/8"], &[], FailAction::Allow).await;
        // Client 203.0.113.7 prepended a clean-looking hop; the proxies at
        // 10.0.0.2 and 10.0.0.1 appended what they saw.
        let req = request(
            "10.0.0.1",
            &[("x-forwarded-for", "198.51.100.1, 203.0.113.7, 10.0.0.2")],
        );
        assert!(is_block(agent.on_request(&req).await));

        let req = request(
            "10.0.0.1",
            &[("x-forwarded-for", "203.0.113.7, 198.51.100.1")],
        );
        assert!(!is_block(agent.on_request(&req).await));
    }

    #[tokio::test]
    async fn test_no_usable_ip_is_not_allowlisted() {
        // An allowlist of everything must not admit a request with no address,
        // nor one whose address is only claimed in a header.
        let (agent, _dir) = agent_blocking(
            "203.0.113.7",
            &[],
            &["0.0.0.0/0", "::/0"],
            FailAction::Block,
        )
        .await;
        for ip in ["", "unknown"] {
            let req = request(ip, &[("x-forwarded-for", "198.51.100.1")]);
            assert!(is_block(agent.on_request(&req).await), "client_ip {:?}", ip);
        }
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
