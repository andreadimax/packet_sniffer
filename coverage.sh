#!/bin/sh
cargo tarpaulin --rustflags="-C opt-level=0" --ignore-tests --out Lcov
genhtml -o ./coverage --show-details --highlight --ignore-errors source --legend ./lcov.info