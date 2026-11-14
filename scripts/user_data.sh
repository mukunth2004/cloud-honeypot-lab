#!/bin/bash
# Installs Docker and starts Cowrie. Runs once, as root, on first boot.
set -euxo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io
systemctl enable --now docker

# Free port 22 for Cowrie (admin access is via SSM, not SSH)
systemctl disable --now ssh || true
systemctl disable --now ssh.socket || true

# Create the log folder BEFORE starting the container, owned by Cowrie's user (999)
mkdir -p /var/log/cowrie
chown 999:999 /var/log/cowrie

# Cowrie pinned to the exact image we tested, not "latest"
docker run -d \
  --name cowrie \
  --restart always \
  -p 22:2222 \
  -v /var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie@sha256:99dc2531f317b0d1a44feccd1cdd2a5ec8fc456b31cb0ed59e7bed1a35dbd345