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

For operators who want to turn away traffic from known-bad addresses before it reaches the upstream. The agent takes the client IP Zentinel reports for the connection, skips anything on its allowlist, asks every enabled provider, and applies the most severe answer: block with a 403, flag (allow and add headers for the upstream), or allow. If every provider fails, `settings.fail_action` decides (`allow` by default); if the agent itself is unreachable, the `failure-mode` of the Zentinel filter decides.

## Quick start

```bash
zentinel bundle install ip-reputation

printf '127.0.0.1\n' > blocklist.txt   # block yourself, to see it work
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

`curl http://localhost:8080/` now returns 403 with `x-ip-reputation-blocked: true`, and so does `curl -H 'X-Forwarded-For: 198.51.100.1' http://localhost:8080/`: the header is ignored. The `timeout-ms` leaves room for an AbuseIPDB lookup on a cache miss; with local blocklists only, it can be much lower.

## Install

### Bundle (recommended)

```bash
zentinel bundle install ip-reputation
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-ip-reputation-agent`.

> [!WARNING]
> The published `0.4.0` release, which Zentinel 26.10_7's bundle lock pins,
> was not built from its tag (it reports `zentinel-agent-ip-reputation 0.2.0`)
> and exits at startup unless `ip-reputation.yaml` exists in its working
> directory. Given a file, it speaks the removed v1 framing on the Unix
> socket, so the proxy never completes a handshake and, under
> `failure-mode "closed"`, refuses every request (`503`); `--grpc-address`
> does not listen either.
> Use `0.5.0` or later, the first release built and smoke-tested by the shared
> release pipeline (below).

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

The agent reads a YAML file: `-c <path>` (which must exist), or else `ip-reputation.yaml` in the working directory if there is one. Without either it starts with the defaults: no provider enabled, every request allowed. It also accepts configuration over the protocol (`on_configure`), but only logs it, and Zentinel 0.6.50 does not forward an `agent { config { ... } }` block anyway, so set everything in the file.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `ip-reputation.yaml` if present | Path to the YAML configuration file. An explicit path that does not exist is an error. |
| `-s`, `--socket` | `/tmp/zentinel-ip-reputation.sock` | Unix socket to listen on. |
| `--grpc-address` | none | Also listen for gRPC on this address, e.g. `0.0.0.0:50051`. |
| `-L`, `--log-level` | `info` | Log level; `RUST_LOG` takes precedence. |
| `--print-config` | | Print an example configuration and exit. |
| `--validate` | | Load and validate the configuration, then exit. |
| `-V`, `--version` | | Print `zentinel-ip-reputation-agent <version>` and exit. |

Configuration file keys (unknown keys are ignored, so check spelling). `${VAR}` in the file is replaced with the environment variable, or an empty string if unset.

| Option | Default | Meaning |
|---|---|---|
| `settings.enabled` | `true` | Master switch; `false` allows everything. |
| `settings.fail_action` | `allow` | `allow` or `block` (403 with `x-ip-reputation-error: lookup-failed`) when every provider lookup fails. |
| `settings.log_blocked` | `true` | Log blocked requests at info level. |
| `settings.log_allowed` | `false` | Log allowed requests at debug level. |
| `ip_extraction.trusted_proxies` | empty | IPs or CIDRs of proxies in front of Zentinel whose forwarding headers are believed. Empty: forwarding headers are ignored. |
| `ip_extraction.headers` | `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip` | Forwarding headers read when the connection comes from a trusted proxy, first present wins. |
| `ip_extraction.use_first_ip` | none | No longer used (a warning is logged); the right-most untrusted hop is always taken. |
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

- **Client IP** is the connection address Zentinel reports in the request metadata; `X-Forwarded-For` and similar headers, which the client can set, are ignored. If Zentinel sits behind your own load balancer, list it in the listener's `trusted-proxies` in Zentinel (0.6.48 and later): Zentinel then reports the real client in the metadata, and the agent needs nothing more. `ip_extraction.trusted_proxies` is for older Zentinel versions, which pass forwarding headers through unchanged: for connections from those addresses the agent reads the forwarding headers right to left and takes the first hop that is not a trusted proxy. A request without a usable address is never allowlisted; it is handled like a failed lookup (`settings.fail_action`).
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

## Releases and smoke test

Releases go through the shared agent pipeline
([`zentinelproxy/.github`](https://github.com/zentinelproxy/.github/tree/main/agent-smoke)):
pushing a tag `vX.Y.Z` that matches `Cargo.toml` builds `zentinel-ip-reputation-agent` with
`--locked` for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64`, checks
that `zentinel-ip-reputation-agent --version` prints `zentinel-ip-reputation-agent X.Y.Z`, runs
[`scripts/smoke-test.sh`](scripts/smoke-test.sh) behind the latest Zentinel
release on every platform, and only then publishes the tarballs
`zentinel bundle install` downloads. CI runs the same pipeline on
`linux-x86_64` for every push and pull request.

The smoke test runs the release binary behind a real Zentinel with the agent,
filter and route all `failure-mode "closed"`, over the Unix socket (the
transport `zentinel bundle install` uses) and gRPC, with local blocklist files only. It checks that the agent starts and
allows without a config file, that a blocklisted client gets `403` and never
reaches the upstream (also when it claims another address in
`X-Forwarded-For`), that the allowlist wins over the blocklist, that an
unlisted client is forwarded, and that the request is refused once the agent
is stopped (so the agent really is on the request path).

Run it locally:

```bash
gh release download 26.10_7 --repo zentinelproxy/zentinel --pattern 'zentinel-26.10_7-darwin-arm64.tar.gz*'
shasum -a 256 -c zentinel-26.10_7-darwin-arm64.tar.gz.sha256 && tar xzf zentinel-26.10_7-darwin-arm64.tar.gz
cargo build --release --locked
AGENT_SMOKE=../.github/agent-smoke/smoke.py scripts/smoke-test.sh target/release/zentinel-ip-reputation-agent ./zentinel
```

## Related

- [Registry page](https://registry.zentinelproxy.io/ip-reputation/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Denylist agent](https://github.com/zentinelproxy/zentinel-agent-denylist), for static IP and path rules
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

MIT, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
