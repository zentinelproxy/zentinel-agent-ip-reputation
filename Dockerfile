# syntax=docker/dockerfile:1.4

# Zentinel IP Reputation Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-ip-reputation-agent /zentinel-ip-reputation-agent

LABEL org.opencontainers.image.title="Zentinel IP Reputation Agent" \
      org.opencontainers.image.description="Zentinel IP Reputation Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-ip-reputation"

ENV RUST_LOG=info,zentinel_agent_ip_reputation=debug \
    SOCKET_PATH=/var/run/zentinel/ip-reputation.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-ip-reputation-agent"]
