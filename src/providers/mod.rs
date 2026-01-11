//! IP reputation providers.

pub mod abuseipdb;
pub mod blocklist;
pub mod tor;

use async_trait::async_trait;
use std::net::IpAddr;

/// Result of a reputation check.
#[derive(Debug, Clone)]
pub struct ReputationResult {
    /// Abuse/reputation score (0-100, higher = worse).
    /// None if this provider doesn't use scores.
    pub score: Option<u8>,

    /// Recommended action based on this provider's check.
    pub action: Action,

    /// Reason for this action.
    pub reason: Option<String>,

    /// Which provider returned this result.
    pub provider: String,

    /// Whether this result was served from cache.
    pub cached: bool,

    /// Additional flags.
    pub is_tor: bool,
    pub is_proxy: bool,
}

impl ReputationResult {
    /// Create a new "allow" result.
    pub fn allow(provider: &str) -> Self {
        Self {
            score: None,
            action: Action::Allow,
            reason: None,
            provider: provider.to_string(),
            cached: false,
            is_tor: false,
            is_proxy: false,
        }
    }

    /// Create a new "block" result.
    pub fn block(provider: &str, reason: &str) -> Self {
        Self {
            score: None,
            action: Action::Block,
            reason: Some(reason.to_string()),
            provider: provider.to_string(),
            cached: false,
            is_tor: false,
            is_proxy: false,
        }
    }

    /// Create a new "flag" result.
    pub fn flag(provider: &str, reason: &str) -> Self {
        Self {
            score: None,
            action: Action::Flag,
            reason: Some(reason.to_string()),
            provider: provider.to_string(),
            cached: false,
            is_tor: false,
            is_proxy: false,
        }
    }

    /// Set the score.
    pub fn with_score(mut self, score: u8) -> Self {
        self.score = Some(score);
        self
    }

    /// Mark as cached.
    pub fn from_cache(mut self) -> Self {
        self.cached = true;
        self
    }

    /// Mark as Tor exit node.
    pub fn with_tor(mut self) -> Self {
        self.is_tor = true;
        self
    }

    /// Mark as proxy.
    pub fn with_proxy(mut self) -> Self {
        self.is_proxy = true;
        self
    }
}

/// Action to take based on reputation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Allow the request.
    Allow,
    /// Flag the request (add warning header) but allow.
    Flag,
    /// Block the request.
    Block,
}

impl Action {
    /// Returns true if this action is more severe than the other.
    pub fn is_more_severe_than(&self, other: &Action) -> bool {
        match (self, other) {
            (Action::Block, Action::Flag | Action::Allow) => true,
            (Action::Flag, Action::Allow) => true,
            _ => false,
        }
    }
}

/// Error from a reputation provider.
#[derive(Debug)]
pub enum ProviderError {
    /// HTTP request failed.
    Http(reqwest::Error),
    /// Timeout.
    Timeout,
    /// Rate limited.
    RateLimited,
    /// Invalid response.
    InvalidResponse(String),
    /// IO error.
    Io(std::io::Error),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Http(e) => write!(f, "HTTP error: {}", e),
            ProviderError::Timeout => write!(f, "Request timed out"),
            ProviderError::RateLimited => write!(f, "Rate limited"),
            ProviderError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            ProviderError::Io(e) => write!(f, "IO error: {}", e),
            ProviderError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<reqwest::Error> for ProviderError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            ProviderError::Timeout
        } else {
            ProviderError::Http(e)
        }
    }
}

impl From<std::io::Error> for ProviderError {
    fn from(e: std::io::Error) -> Self {
        ProviderError::Io(e)
    }
}

/// Trait for IP reputation providers.
#[async_trait]
pub trait ReputationProvider: Send + Sync {
    /// Check the reputation of an IP address.
    async fn check(&self, ip: &IpAddr) -> Result<ReputationResult, ProviderError>;

    /// Provider name for logging and metrics.
    fn name(&self) -> &str;

    /// Whether this provider is enabled.
    fn is_enabled(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_severity() {
        assert!(Action::Block.is_more_severe_than(&Action::Flag));
        assert!(Action::Block.is_more_severe_than(&Action::Allow));
        assert!(Action::Flag.is_more_severe_than(&Action::Allow));
        assert!(!Action::Allow.is_more_severe_than(&Action::Flag));
        assert!(!Action::Flag.is_more_severe_than(&Action::Block));
    }

    #[test]
    fn test_reputation_result_builders() {
        let result = ReputationResult::allow("test");
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.provider, "test");
        assert!(result.score.is_none());

        let result = ReputationResult::block("test", "bad ip")
            .with_score(95)
            .from_cache();
        assert_eq!(result.action, Action::Block);
        assert_eq!(result.score, Some(95));
        assert!(result.cached);

        let result = ReputationResult::flag("test", "suspicious").with_tor();
        assert_eq!(result.action, Action::Flag);
        assert!(result.is_tor);
    }
}
