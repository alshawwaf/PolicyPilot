#!/usr/bin/env bash
#
# Re-point the SIEM syslog forwarders at the DC Integration Simulator app container.
#
# Why this exists
# ---------------
# On Dokploy/Swarm the portal runs on an overlay network the host can't route to, so external
# Check Point Log Exporter traffic (host:5514) is bridged into the container by two host-network
# `socat` forwarders that target the app's docker_gwbridge IP. That IP changes on EVERY redeploy,
# so the forwarders must be re-pointed afterward — otherwise they forward to a dead address and the
# SIEM page silently stops receiving. Run this once after each portal deploy.
#
# Prerequisite that bites: the host firewall must ACTUALLY allow 5514/udp+tcp. A ufw in an
# "active but not enabled" state lists the rule in `ufw status` yet never loads it, so external UDP
# is dropped while every local test passes. See docs/integrations/siem.md -> Troubleshooting.
#
# Usage:  sudo tools/siem-host-socat.sh [name-filter] [port]
#   name-filter  docker ps --filter name=...  (default: dcsim)
#   port         syslog port                  (default: 5514)
set -euo pipefail

NAME_FILTER="${1:-dcsim}"
PORT="${2:-5514}"

APP="$(docker ps --filter "name=${NAME_FILTER}" --format '{{.Names}}' | head -1)"
if [ -z "${APP}" ]; then
  echo "No running container matches name filter '${NAME_FILTER}'." >&2
  exit 1
fi

PID="$(docker inspect "${APP}" --format '{{.State.Pid}}')"
# The slim app image has no `ip`; run the host's `ip` inside the container's network namespace.
GW="$(sudo nsenter -t "${PID}" -n ip -4 -o addr show \
  | grep -oE '172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+' | head -1)"
if [ -z "${GW}" ]; then
  echo "No docker_gwbridge (172.x) IP found on '${APP}'. Is it attached to docker_gwbridge?" >&2
  exit 1
fi

echo "App container : ${APP}"
echo "Forward target: ${GW}:${PORT}"

docker rm -f siem-host-udp siem-host-tcp >/dev/null 2>&1 || true
docker run -d --name siem-host-udp --restart unless-stopped --network host \
  alpine/socat "UDP-LISTEN:${PORT},fork,reuseaddr" "UDP:${GW}:${PORT}" >/dev/null
docker run -d --name siem-host-tcp --restart unless-stopped --network host \
  alpine/socat "TCP-LISTEN:${PORT},fork,reuseaddr" "TCP:${GW}:${PORT}" >/dev/null

echo "Forwarders up: host:${PORT} (udp+tcp) -> ${GW}:${PORT}"
echo "Verify: docker logs -f siem-host-udp   (watch for the real gateway IP on the next burst)"
