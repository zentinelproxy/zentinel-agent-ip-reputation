# IP Reputation Agent for Sentinel

An IP reputation agent for [Sentinel](https://sentinel.raskell.io) that checks client IPs against threat intelligence feeds and blocklists.

## Features

- **AbuseIPDB Integration** - Query AbuseIPDB API for IP reputation scores
- **Custom Blocklists** - Load blocklists from CSV, JSON, or plain text files
- **Tor Exit Node Detection** - Check against Tor exit node list
- **Reputation Thresholds** - Block/allow based on configurable score thresholds
- **Caching** - Cache lookups with configurable TTL
- **Fail-Open/Closed** - Configurable behavior when lookup fails
- **Allowlist Support** - Always allow specific IPs or CIDR ranges

## Installation

```bash
cargo install sentinel-agent-ip-reputation
```

Or build from source:

```bash
git clone https://github.com/raskell-io/sentinel-agent-ip-reputation.git
cd sentinel-agent-ip-reputation
cargo build --release
```

## Usage

```bash
# Run with default config file (ip-reputation.yaml)
sentinel-agent-ip-reputation

# Specify config file
sentinel-agent-ip-reputation -c /path/to/config.yaml

# Specify socket path
sentinel-agent-ip-reputation -s /tmp/ip-reputation.sock

# Print example configuration
sentinel-agent-ip-reputation --print-config

# Validate configuration
sentinel-agent-ip-reputation --validate
```

## Configuration

### Basic Structure

```yaml
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

# IP allowlist - always allowed, skips all checks
allowlist:
  - "127.0.0.1"
  - "10.0.0.0/8"
  - "192.168.0.0/16"
  - "172.16.0.0/12"
```

### AbuseIPDB Provider

Query the [AbuseIPDB](https://www.abuseipdb.com/) API for IP reputation scores:

```yaml
abuseipdb:
  enabled: true
  api_key: "${ABUSEIPDB_API_KEY}"  # Use environment variable
  max_age_days: 90             # Only consider reports from last 90 days
  cache_ttl_seconds: 3600      # Cache results for 1 hour
  timeout_ms: 5000             # API timeout
```

### File-Based Blocklists

Load blocklists from files:

```yaml
blocklists:
  - name: "internal-blocklist"
    enabled: true
    path: "/etc/sentinel/blocklist.txt"
    format: plain              # plain, csv, or json
    action: block              # block or flag
    refresh_interval_seconds: 300
```

Supported formats:
- **plain** - One IP/CIDR per line (comments with `#`)
- **csv** - First column is IP/CIDR
- **json** - Array of IP/CIDR strings

### Tor Exit Node Detection

Detect Tor exit nodes:

```yaml
tor:
  enabled: true
  action: flag                 # block or flag
  exit_node_list_url: "https://check.torproject.org/torbulkexitlist"
  refresh_interval_seconds: 3600
```

## Response Headers

When blocking or flagging requests, the following headers are added:

| Header | Description |
|--------|-------------|
| `x-ip-reputation-blocked` | Set to `"true"` when request is blocked |
| `x-ip-reputation-flagged` | Set to `"true"` when request is flagged |
| `x-ip-reputation-score` | The reputation score (0-100) |
| `x-ip-reputation-reason` | Why the action was taken |
| `x-ip-reputation-tor` | Set to `"true"` if IP is a Tor exit node |
| `x-ip-reputation-proxy` | Set to `"true"` if IP is a known proxy |

## Sentinel Configuration

Add the agent to your Sentinel proxy configuration:

```yaml
agents:
  - name: ip-reputation
    socket: /tmp/sentinel-ip-reputation.sock
    on_request: true
    on_response: false
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | API key for AbuseIPDB (required if AbuseIPDB is enabled) |

## Best Practices

1. **Always use an allowlist** - Add your infrastructure IPs (load balancers, internal services)
2. **Start with fail-open** - Use `fail_action: allow` until you trust your configuration
3. **Use appropriate thresholds** - 80+ for blocking, 50+ for flagging is a good start
4. **Cache API responses** - Reduce API calls and latency with caching
5. **Monitor blocked IPs** - Enable `log_blocked: true` to track what's being blocked

## Testing

Run the test suite:

```bash
cargo test
```

## License

MIT License - see [LICENSE](LICENSE) for details.
