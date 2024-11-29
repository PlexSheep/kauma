#!/bin/bash
export CARGO_PROFILE_RELEASE_DEBUG=true
cargo flamegraph --bin kauma -- $@
xdg-open ./flamegraph.svg
