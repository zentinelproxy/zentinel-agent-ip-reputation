# syntax=docker/dockerfile:1.4

# Sentinel IP Reputation Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-ip-reputation /sentinel-agent-ip-reputation

LABEL org.opencontainers.image.title="Sentinel IP Reputation Agent" \
      org.opencontainers.image.description="Sentinel IP Reputation Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-ip-reputation"

ENV RUST_LOG=info,sentinel_agent_ip_reputation=debug \
    SOCKET_PATH=/var/run/sentinel/ip-reputation.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-ip-reputation"]
