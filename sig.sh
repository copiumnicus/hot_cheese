#!/bin/sh
cargo test --tests $1 --release -- --nocapture
