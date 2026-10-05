#!/bin/sh
# Build the browser version into crates/pkgimg-gui/web/ (serve that directory statically).
set -e
cd "$(dirname "$0")/../.."
cargo build --profile web -p pkgimg-gui --target wasm32-unknown-unknown
out=crates/pkgimg-gui/web
mkdir -p "$out"
"${WASM_BINDGEN:-wasm-bindgen}" --target web --no-typescript --out-dir "$out" \
    target/wasm32-unknown-unknown/web/pkgimg-gui.wasm
cp crates/pkgimg-gui/web-index.html "$out/index.html"
ls -la "$out"
