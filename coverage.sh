#!/bin/sh

grcov . -s . --ignore "$HOME/.cargo/registry/*" --binary-path ./target/debug/packet_sniffer -t lcov --branch --ignore-not-existing -o ./target/debug/lcov.info
genhtml -o ./target/debug/result --show-details --highlight --ignore-errors source --legend ./target/debug/lcov.info