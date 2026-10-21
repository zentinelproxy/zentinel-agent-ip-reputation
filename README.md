<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">IP reputation agent</h3>

<p align="center">Checks the client IP of each request against AbuseIPDB, local blocklists and the Tor exit list, at the request-headers stage.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-ip-reputation/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-ip-reputation/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/ip-reputation/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For operators who want to turn away traffic from known-bad addresses before it reaches the upstream. The agent reads the client IP from request headers, skips anything on its allowlist, asks every enabled provider, and applies the most severe answer: block with a 403, flag (allow and add headers for the upstream), or allow. If every provider fails, `settings.fail_action` decides (`allow` by default); if the agent itself is unreachable, the `failure-mode` of the Zentinel filter decides.

## Quick start

```bash
zentinel bundle install ip-reputation

printf '203.0.113.7\n' > blocklist.txt
cat > ip-reputation.yaml <<'EOF'
blocklists:
  - name: local
    path: ./blocklist.txt
EOF

zentinel-ip-reputation-agent -c ip-reputation.yaml -s /tmp/zentinel-ip-reputation.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "ip-reputation" type="custom" {
        unix-socket "/tmp/zentinel-ip-reputation.sock"
        events "request_headers"
        timeout-ms 1000
    }
}

filters {
    filter "ip-reputation" {
        type "agent"
        agent "ip-reputation"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "ip-reputation"
    }
}
```

`curl -H 'X-Forwarded-For: 203.0.113.7' http://localhost:8080/` now returns 403 with `x-ip-reputation-blocked: true`. The `timeout-ms` leaves room for an AbuseIPDB lookup on a cache miss; with local blocklists only, it can be much lower.

## Install

### Bundle (recommended)

```bash
zentinel bundle install ip-reputation
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-ip-reputation-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-ip-reputation/releases).

### From source

`cargo install --git` does not work for this crate: it depends on a sibling checkout of [`zentinel-agent-rust-sdk`](https://github.com/zentinelproxy/zentinel-agent-rust-sdk) by path.

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-rust-sdk
git clone https://github.com/zentinelproxy/zentinel-agent-ip-reputation
cd zentinel-agent-ip-reputation
cargo build --release   # needs protoc
```

## Configuration

The agent reads a YAML file (`-c`, default `ip-reputation.yaml`; it must exist). It also accepts configuration over the protocol (`on_configure`), but only logs it, and Zentinel 0.6.50 does not forward an `agent { config { ... } }` block anyway, so set everything in the file.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `ip-reputation.yaml` | Path to the YAML configuration file. |
| `-s`, `--socket` | `/tmp/zentinel-ip-reputation.sock` | Unix socket to listen on. |
| `--grpc-address` | none | Also listen for gRPC on this address, e.g. `0.0.0.0:50051`. |
| `-L`, `--log-level` | `info` | Log level; `RUST_LOG` takes precedence. |
| `--print-config` | | Print an example configuration and exit. |
| `--validate` | | Load and validate the configuration, then exit. |

Configuration file keys (unknown keys are ignored, so check spelling). `${VAR}` in the file is replaced with the environment variable, or an empty string if unset.

| Option | Default | Meaning |
|---|---|---|
| `settings.enabled` | `true` | Master switch; `false` allows everything. |
| `settings.fail_action` | `allow` | `allow` or `block` (403 with `x-ip-reputation-error: lookup-failed`) when every provider lookup fails. |
| `settings.log_blocked` | `true` | Log blocked requests at info level. |
| `settings.log_allowed` | `false` | Log allowed requests at debug level. |
| `ip_extraction.headers` | `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip` | Headers to read the client IP from, first match wins. |
| `ip_extraction.use_first_ip` | `true` | Take the first (`true`) or last (`false`) address of a comma-separated header. |
| `thresholds.block_score` | `80` | Block when the AbuseIPDB score is at least this (0 to 100). |
| `thresholds.flag_score` | `50` | Flag when the score is at least this; must not exceed `block_score`. |
| `abuseipdb.enabled` | `true` | Enable AbuseIPDB lookups (the section itself is optional). |
| `abuseipdb.api_key` | required | API key; validation fails if empty while enabled. Use `"${ABUSEIPDB_API_KEY}"`. |
| `abuseipdb.max_age_days` | `90` | Only count reports from the last N days. |
| `abuseipdb.cache_ttl_seconds` | `3600` | How long a score is cached (in-memory, up to 10,000 IPs). |
| `abuseipdb.timeout_ms` | `5000` | HTTP timeout for the API call. |
| `blocklists[].name` | required | Name used in logs and the reason header. |
| `blocklists[].enabled` | `true` | Enable this list. |
| `blocklists[].path` | required | File path; validation fails if it does not exist. |
| `blocklists[].format` | `plain` | `plain` (one IP or CIDR per line, `#` comments), `csv` (first column), or `json` (array of strings). |
| `blocklists[].action` | `block` | `block` or `flag` on a match. |
| `blocklists[].refresh_interval_seconds` | `300` | Re-read the file on the first request after this interval. |
| `tor.enabled` | `true` | Enable Tor exit node detection (the section itself is optional). |
| `tor.action` | `flag` | `block` or `flag` for a Tor exit node. |
| `tor.exit_node_list_url` | `https://check.torproject.org/torbulkexitlist` | Where the exit list is fetched from. |
| `tor.refresh_interval_seconds` | `3600` | Re-fetch the list on the first request after this interval. |
| `allowlist` | empty | IPs or CIDRs that skip all checks. |

Full reference: <https://registry.zentinelproxy.io/ip-reputation/>

## How it works

- **Client IP comes from headers only.** The agent does not use the connection address Zentinel reports. A request with none of the configured headers is allowed unchecked, and a header the client sets itself is trusted, so put the agent behind something that overwrites `X-Forwarded-For`, or list only headers your edge controls.
- **Providers.** [AbuseIPDB](https://www.abuseipdb.com/) (score mapped through the thresholds, cached), file blocklists, and the Tor exit list. Lookups run in sequence on the request path; a cache miss waits for the AbuseIPDB call, and a due Tor refresh waits for the download.
- **Block** returns 403 with `x-ip-reputation-blocked`, `x-ip-reputation-score` (`N/A` without a score), `x-ip-reputation-reason` and, for Tor, `x-ip-reputation-tor`.
- **Flag** allows the request and adds `x-ip-reputation-flagged`, `x-ip-reputation-score`, and where known `x-ip-reputation-tor` and `x-ip-reputation-proxy` (AbuseIPDB public proxy) to the request sent upstream.

## Development

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-rust-sdk ../zentinel-agent-rust-sdk
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs stable Rust (CI uses `dtolnay/rust-toolchain@stable`) and `protoc` (CI installs `protobuf-compiler`).

## Related

- [Registry page](https://registry.zentinelproxy.io/ip-reputation/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Denylist agent](https://github.com/zentinelproxy/zentinel-agent-denylist), for static IP and path rules
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

MIT (declared in Cargo.toml; this repository has no LICENSE file yet).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
