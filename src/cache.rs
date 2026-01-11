//! TTL-based cache for IP reputation lookups.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Cached reputation result.
#[derive(Debug, Clone)]
pub struct CachedReputation {
    /// Abuse/reputation score (0-100, higher = worse).
    pub score: u8,
    /// Provider that returned this result.
    pub provider: String,
    /// Additional flags.
    pub is_tor: bool,
    pub is_proxy: bool,
    /// When this entry was cached.
    pub cached_at: Instant,
    /// TTL for this entry.
    pub ttl: Duration,
}

impl CachedReputation {
    /// Check if this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// Thread-safe TTL cache for IP reputation lookups.
pub struct ReputationCache {
    cache: RwLock<HashMap<IpAddr, CachedReputation>>,
    default_ttl: Duration,
    max_entries: usize,
}

impl ReputationCache {
    /// Create a new reputation cache.
    pub fn new(default_ttl_seconds: u64, max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            default_ttl: Duration::from_secs(default_ttl_seconds),
            max_entries,
        }
    }

    /// Get a cached reputation result if available and not expired.
    pub fn get(&self, ip: &IpAddr) -> Option<CachedReputation> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(ip)?;

        if entry.is_expired() {
            // Don't remove here to avoid write lock, cleanup will handle it
            None
        } else {
            Some(entry.clone())
        }
    }

    /// Store a reputation result in the cache.
    pub fn set(&self, ip: IpAddr, score: u8, provider: &str, is_tor: bool, is_proxy: bool) {
        self.set_with_ttl(ip, score, provider, is_tor, is_proxy, self.default_ttl);
    }

    /// Store a reputation result with a custom TTL.
    pub fn set_with_ttl(
        &self,
        ip: IpAddr,
        score: u8,
        provider: &str,
        is_tor: bool,
        is_proxy: bool,
        ttl: Duration,
    ) {
        let entry = CachedReputation {
            score,
            provider: provider.to_string(),
            is_tor,
            is_proxy,
            cached_at: Instant::now(),
            ttl,
        };

        if let Ok(mut cache) = self.cache.write() {
            // Evict if at capacity
            if cache.len() >= self.max_entries && !cache.contains_key(&ip) {
                self.evict_expired_entries(&mut cache);

                // If still at capacity, remove oldest entry
                if cache.len() >= self.max_entries {
                    if let Some(oldest_ip) = cache
                        .iter()
                        .min_by_key(|(_, v)| v.cached_at)
                        .map(|(k, _)| *k)
                    {
                        cache.remove(&oldest_ip);
                    }
                }
            }

            cache.insert(ip, entry);
        }
    }

    /// Remove expired entries from the cache.
    pub fn cleanup(&self) {
        if let Ok(mut cache) = self.cache.write() {
            self.evict_expired_entries(&mut cache);
        }
    }

    fn evict_expired_entries(&self, cache: &mut HashMap<IpAddr, CachedReputation>) {
        cache.retain(|_, v| !v.is_expired());
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_set_and_get() {
        let cache = ReputationCache::new(3600, 1000);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        cache.set(ip, 75, "abuseipdb", false, false);

        let result = cache.get(&ip).unwrap();
        assert_eq!(result.score, 75);
        assert_eq!(result.provider, "abuseipdb");
        assert!(!result.is_tor);
        assert!(!result.is_proxy);
    }

    #[test]
    fn test_cache_miss() {
        let cache = ReputationCache::new(3600, 1000);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(cache.get(&ip).is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = ReputationCache::new(0, 1000); // 0 second TTL
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        cache.set(ip, 75, "abuseipdb", false, false);

        // Entry should be immediately expired
        thread::sleep(Duration::from_millis(10));
        assert!(cache.get(&ip).is_none());
    }

    #[test]
    fn test_cache_custom_ttl() {
        let cache = ReputationCache::new(3600, 1000);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Set with very short TTL
        cache.set_with_ttl(ip, 75, "test", false, false, Duration::from_millis(1));

        thread::sleep(Duration::from_millis(10));
        assert!(cache.get(&ip).is_none());
    }

    #[test]
    fn test_cache_max_entries() {
        let cache = ReputationCache::new(3600, 2);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        cache.set(ip1, 10, "test", false, false);
        thread::sleep(Duration::from_millis(1)); // Ensure different timestamps
        cache.set(ip2, 20, "test", false, false);
        thread::sleep(Duration::from_millis(1));
        cache.set(ip3, 30, "test", false, false);

        // Should have evicted the oldest (ip1)
        assert!(cache.len() <= 2);
        assert!(cache.get(&ip3).is_some());
    }

    #[test]
    fn test_cache_cleanup() {
        let cache = ReputationCache::new(0, 1000); // 0 second TTL
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        cache.set(ip1, 10, "test", false, false);
        cache.set(ip2, 20, "test", false, false);

        thread::sleep(Duration::from_millis(10));
        cache.cleanup();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_clear() {
        let cache = ReputationCache::new(3600, 1000);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        cache.set(ip1, 10, "test", false, false);
        cache.set(ip2, 20, "test", false, false);

        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cached_reputation_is_expired() {
        let entry = CachedReputation {
            score: 50,
            provider: "test".to_string(),
            is_tor: false,
            is_proxy: false,
            cached_at: Instant::now() - Duration::from_secs(100),
            ttl: Duration::from_secs(60),
        };

        assert!(entry.is_expired());

        let entry2 = CachedReputation {
            score: 50,
            provider: "test".to_string(),
            is_tor: false,
            is_proxy: false,
            cached_at: Instant::now(),
            ttl: Duration::from_secs(60),
        };

        assert!(!entry2.is_expired());
    }
}
