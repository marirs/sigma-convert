#!/bin/bash

CURRENT_VER=$(head Cargo.toml | grep version | cut -f2 -d'=' | cut -f2 -d\")

# apple silicon binary
cargo b --release--target aarch64-apple-darwin
# apple intel binary
cargo b --release --target x86_64-apple-darwin
# windows binary intel 64bit
cargo b --release --target x86_64-pc-windows-gnu
# linux binary aarch64
cargo b --release --target aarch64-unknown-linux-gnu
# linux binary intel 64bit
cargo b --release --target x86_64-unknown-linux-gnu

# remove existing files
rm -rf dist
# make the folder again
mkdir -p dist

# copy files to the dist folder
# win
cp target/x86_64-pc-windows-gnu/release/sigmac.exe dist/sigmac_x86-64.exe
cp target/x86_64-pc-windows-gnu/release/sigmac_api_server.exe dist/sigmac_api_server_x86-64.exe
# macos
cp target/aarch64-apple-darwin/release/sigmac dist/sigmac_macos_aarch64
cp target/aarch64-apple-darwin/release/sigmac_api_server dist/sigmac_api_server_macos_aarch64
cp target/x86_64-apple-darwin/release/sigmac dist/sigmac_macos_x86-64
cp target/x86_64-apple-darwin/release/sigmacsigmac_api_server dist/sigmacsigmac_api_server_macos_x86-64
# linux
cp target/aarch64-unknown-linux-gnu/release/sigmac dist/sigmac_linux_aarch64
cp target/aarch64-unknown-linux-gnu/release/sigmac_api_server dist/sigmac_api_server_linux_aarch64
cp target/x86_64-unknown-linux-gnu/release/sigmac dist/sigmac_linux_x86-64
cp target/x86_64-unknown-linux-gnu/release/sigmac_api_server dist/sigmac_api_server_linux_x86-64

