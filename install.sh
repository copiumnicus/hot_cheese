#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

cargo install --force --locked --profile release --bin hot_cheese --path crates/hc-cli
cargo install --force --locked --profile release --bin hot_cheese_mcp --path crates/hc-mcp

echo "installed hot_cheese and hot_cheese_mcp"
