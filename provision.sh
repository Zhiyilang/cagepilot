#!/bin/bash
# CagePilot VM provisioning - Vultr cloud-init user-data (bash) or SSH bootstrap.
#
# What it builds:
#   * unprivileged user `cage` (no login shell) that owns the agent
#   /opt/cagepilot/src/cagepilot (repo checkout with vmagent.py + codeguard.py)
#   * a random bearer token in /opt/cagepilot/token.env (root:root 0600)
#   * systemd unit cagepilot-vmagent.service (hardened: NoNewPrivileges,
#     ProtectSystem, PrivateTmp, Restart=always)
#   * ufw default-deny incoming; agent port reachable only from CAGE_HOST_IP
#
# Paste this whole file as the instance "User Data" (Vultr accepts bash
# user-data), or scp + run it over SSH as root on an existing VM.
#
# After first boot, retrieve the token exactly once:
#   ssh root@<vm-ip> 'cat /opt/cagepilot/token.env'
# then check liveness (token stays secret - it is only in the header):
#   curl -s -H "Authorization: Bearer <token>" http://<vm-ip>:8787/healthz
#
# Vultr-side hardening (console, not scriptable here): also attach a Vultr
# Firewall Group allowing only the CagePilot host IP to the agent port, so a
# leaked token still cannot be reached from the open internet.

set -euo pipefail

CAGE_REPO_URL="${CAGE_REPO_URL:-https://github.com/Zhiyilang/cagepilot.git}"
CAGE_REPO_REF="${CAGE_REPO_REF:-main}"
CAGE_HOST_IP="${CAGE_HOST_IP:-}"        # CagePilot host public IP (recommended)
CAGE_SSH_IP="${CAGE_SSH_IP:-}"          # optional: restrict SSH too
CAGE_PORT="${CAGE_PORT:-8787}"
CAGE_USER="cage"
CAGE_DIR="/opt/cagepilot"
CAGE_SRC="$CAGE_DIR/src"

log() { echo "[cagepilot-provision] $*"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (cloud-init runs this as root)" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
log "installing base packages"
apt-get update -qq
apt-get install -y -qq python3 git ufw curl >/dev/null

log "creating unprivileged user $CAGE_USER"
if ! id -u "$CAGE_USER" >/dev/null 2>&1; then
    useradd -r -m -s /usr/sbin/nologin "$CAGE_USER"
fi

log "fetching agent code from $CAGE_REPO_URL ($CAGE_REPO_REF)"
install -d -o root -g root -m 755 "$CAGE_DIR"
if [ -d "$CAGE_SRC/.git" ]; then
    git -C "$CAGE_SRC" fetch -q origin "$CAGE_REPO_REF"
    git -C "$CAGE_SRC" checkout -q FETCH_HEAD
else
    rm -rf "$CAGE_SRC"
    git clone -q --depth 1 -b "$CAGE_REPO_REF" "$CAGE_REPO_URL" "$CAGE_SRC"
fi
chown -R "$CAGE_USER:$CAGE_USER" "$CAGE_SRC"

# The agent refuses to start without a token; generate once, keep on rotate.
if [ ! -s "$CAGE_DIR/token.env" ]; then
    log "generating bearer token"
    (umask 077; openssl rand -hex 32 | sed 's/^/CAGEPILOT_VM_TOKEN=/' \
        > "$CAGE_DIR/token.env")
    chown root:root "$CAGE_DIR/token.env"
    chmod 600 "$CAGE_DIR/token.env"
else
    log "keeping existing token"
fi

log "installing systemd unit"
cat > /etc/systemd/system/cagepilot-vmagent.service <<'UNIT'
[Unit]
Description=CagePilot VM sandbox agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cage
Group=cage
EnvironmentFile=/opt/cagepilot/token.env
Environment=CAGEPILOT_VM_HOST=0.0.0.0
Environment=CAGEPILOT_VM_PORT=8787
WorkingDirectory=/opt/cagepilot/src/cagepilot
ExecStart=/usr/bin/python3 -I vmagent.py
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryMax=512M

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable -q cagepilot-vmagent.service
systemctl restart cagepilot-vmagent.service

log "configuring firewall (default deny incoming)"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
if [ -n "$CAGE_SSH_IP" ]; then
    ufw allow from "$CAGE_SSH_IP" to any port 22 proto tcp >/dev/null
else
    ufw allow OpenSSH >/dev/null
fi
if [ -n "$CAGE_HOST_IP" ]; then
    ufw allow from "$CAGE_HOST_IP" to any port "$CAGE_PORT" proto tcp >/dev/null
    log "agent port $CAGE_PORT open to $CAGE_HOST_IP only"
else
    ufw allow "$CAGE_PORT"/tcp >/dev/null
    log "WARNING: CAGE_HOST_IP empty - agent port open to the internet"
fi
ufw --force enable >/dev/null

log "waiting for the agent to come up"
for _ in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:$CAGE_PORT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if curl -sf "http://127.0.0.1:$CAGE_PORT/healthz"; then
    echo
    log "agent is live on port $CAGE_PORT"
    log "token (retrieve once): ssh root@<vm-ip> 'cat $CAGE_DIR/token.env'"
else
    log "agent did not answer - inspect: journalctl -u cagepilot-vmagent"
    exit 1
fi
