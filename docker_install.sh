#!/usr/bin/env bash
set -euo pipefail

# install_docker.sh — Install Docker CE & Docker Compose Plugin on Ubuntu

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "⚠️  Please run this script with sudo or as root."
  exit 1
fi

echo "🚀 Updating package index..."
apt update

echo "📦 Installing prerequisites..."
apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

echo "🔑 Adding Docker’s official GPG key..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "📋 Setting up the Docker repository..."
ARCH=$(dpkg --print-architecture)
UBU_CODENAME=$(lsb_release -cs)
echo \
  "deb [arch=${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
   https://download.docker.com/linux/ubuntu \
   ${UBU_CODENAME} stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "🚀 Refreshing package index..."
apt update

echo "🐳 Installing Docker Engine, CLI, and Containerd..."
apt install -y docker-ce docker-ce-cli containerd.io

echo "🔧 Installing Docker Compose plugin..."
apt install -y docker-compose-plugin

echo "✅ Installation complete! Verifying versions..."

echo -n "Docker version: "
docker version --format '{{.Server.Version}}'

echo -n "Docker Compose version: "
docker compose version

echo "🎉 Docker & Docker Compose Plugin are installed and ready to use."
