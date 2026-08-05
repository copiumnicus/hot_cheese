#!/usr/bin/env bash
set -euo pipefail

cargo build --locked --release
cargo test --locked --release
cargo deny check
cargo audit
