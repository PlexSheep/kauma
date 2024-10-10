#!/bin/bash
set -e
cargo check --all-features
echo ">>>>>>>> PUBLISHING RELEASE FOR REPO"
bash scripts/release.sh
echo ">>>>>>>> PUBLISHING TO CRATES.IO NEXT"
sleep 2
cargo publish
echo ">>>>>>>> PUBLISHING TO CSCHERR.DE NEXT"
sleep 2
cargo publish --registry cscherr
