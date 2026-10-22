#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Only local blocklist files are used (no AbuseIPDB key, no Tor list fetch).
# Every request comes from 127.0.0.1, and Zentinel replaces a client's
# X-Forwarded-For with the TCP peer unless the listener trusts it, so each
# list gets its own run:
#   1. no config file: the agent starts with its defaults and allows;
#   2. 127.0.0.0/8 blocklisted (over the Unix socket and over gRPC): the
#      client gets 403 and never reaches the upstream, also when it claims
#      another address in X-Forwarded-For;
#   3. the same blocklist with 127.0.0.1 allowlisted: forwarded (200);
#   4. only 203.0.113.0/24 blocklisted: forwarded, also when the client
#      claims to be forwarded for 203.0.113.7.
# Each run also checks that with the agent stopped the request is refused.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

# The first run changes directory, so make the paths absolute.
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
AGENT_BIN=$(abs "$AGENT_BIN"); ZENTINEL_BIN=$(abs "$ZENTINEL_BIN"); AGENT_SMOKE=$(abs "$AGENT_SMOKE")

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

printf '# smoke-test blocklist\n127.0.0.0/8\n' > "$dir/loopback.txt"
printf '# smoke-test blocklist\n203.0.113.0/24\n' > "$dir/other.txt"
cat > "$dir/blocked.yaml" <<YAML
blocklists:
  - name: smoke-loopback
    path: $dir/loopback.txt
YAML
cat > "$dir/allowlisted.yaml" <<YAML
blocklists:
  - name: smoke-loopback
    path: $dir/loopback.txt
allowlist: ["127.0.0.1"]
YAML
cat > "$dir/other.yaml" <<YAML
blocklists:
  - name: smoke-other
    path: $dir/other.txt
YAML

smoke() {
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name ip-reputation "$@"
}

echo "=== ip-reputation agent, no config file: defaults allow"
# Run from an empty directory so no ip-reputation.yaml is picked up.
(cd "$dir" && mkdir -p empty && cd empty && smoke --clean '{"name": "ordinary request", "path": "/smoke"}')

for transport in uds grpc; do
    echo "=== ip-reputation agent over $transport: blocklisted client IP"
    smoke --transport "$transport" --agent-arg=--config="$dir/blocked.yaml" \
        --clean '{"name": "request from a blocklisted IP", "path": "/smoke", "expect": 403}' \
        --case '{"name": "blocklisted IP claiming another address", "path": "/smoke", "headers": {"X-Forwarded-For": "198.51.100.1"}, "expect": 403}'
done

echo "=== ip-reputation agent: allowlist wins over the blocklist"
smoke --agent-arg=--config="$dir/allowlisted.yaml" \
    --clean '{"name": "allowlisted IP in a blocklisted range", "path": "/smoke"}'

echo "=== ip-reputation agent: client not on the blocklist"
smoke --agent-arg=--config="$dir/other.yaml" \
    --clean '{"name": "request from an unlisted IP", "path": "/smoke"}' \
    --case '{"name": "unlisted IP claiming a blocklisted address", "path": "/smoke", "headers": {"X-Forwarded-For": "203.0.113.7"}, "expect": 200}'
