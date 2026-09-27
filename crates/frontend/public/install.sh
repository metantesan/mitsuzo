#!/bin/sh
set -eu

REPO="metantesan/mitsuzo"
INSTALL_DIR="${MITSUZO_INSTALL_DIR:-$HOME/.local/bin}"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

fail() {
    printf 'mitsuzo installer: %s\n' "$1" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v unzip >/dev/null 2>&1 || fail "unzip is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

os=$(uname -s)
arch=$(uname -m)
case "${os}:${arch}" in
    Linux:x86_64) target="x86_64-unknown-linux-gnu" ;;
    Linux:aarch64|Linux:arm64) target="aarch64-unknown-linux-gnu" ;;
    Darwin:arm64) target="aarch64-apple-darwin" ;;
    *)
        fail "unsupported platform ${os}/${arch}; download a release manually from https://github.com/${REPO}/releases"
        ;;
esac

tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t mitsuzo)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

asset="mitsuzo-${target}.zip"
printf 'Downloading mitsuzo for %s...\n' "$target"
curl -fsSL "${BASE_URL}/${asset}" -o "${tmp_dir}/${asset}"
curl -fsSL "${BASE_URL}/checksums.txt" -o "${tmp_dir}/checksums.txt"

expected=$(grep -F "$asset" "${tmp_dir}/checksums.txt" | head -n 1 | awk '{print $1}')
[ -n "$expected" ] || fail "checksum for ${asset} was not found"
actual=$(sha256sum "${tmp_dir}/${asset}" | awk '{print $1}')
[ "$actual" = "$expected" ] || fail "checksum verification failed"

unzip -q "${tmp_dir}/${asset}" -d "$tmp_dir/unpacked"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp_dir/unpacked/mitsuzo" "$INSTALL_DIR/mitsuzo"

printf 'Installed mitsuzo to %s/mitsuzo\n' "$INSTALL_DIR"
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) printf 'Add %s to PATH if the command is not found.\n' "$INSTALL_DIR" ;;
esac
