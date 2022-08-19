#!/bin/sh

export RUSTFLAGS=
export RUSTC_BOOTSTRAP=0
cargo build
cargo test --
rm ./target/debug/lcov.info
rm -rf ./target/debug/result
grcov . -s . --ignore "$HOME/.cargo/registry/*" --binary-path ./target/debug/packet_sniffer -t lcov --branch --ignore-not-existing -o ./target/debug/lcov.info
genhtml -o ./target/debug/result --show-details --highlight --ignore-errors source --legend ./target/debug/lcov.info