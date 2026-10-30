#!/bin/sh
# KeyTap bridge installer for macOS and Linux — https://keytap.me/install
#
#   curl -fsSL https://keytap.me/install.sh | sh                 # install the bridge
#   curl -fsSL https://keytap.me/install.sh | sh -s -- --shim    # … and route age's YubiKey plugin through it
#
# Downloads age-plugin-yubikey-phone from the latest GitHub release of keytap-me/keytap, verifies
# it against the release's SHA256SUMS and installs it into ~/.local/bin (KEYTAP_BIN overrides,
# KEYTAP_VERSION=vX.Y.Z pins a release). Nothing else on the system is changed; with --shim it also
# creates ~/.local/bin/age-plugin-yubikey -> age-plugin-yubikey-phone, but never over an existing file.
set -eu

repo="keytap-me/keytap"
bin_dir="${KEYTAP_BIN:-$HOME/.local/bin}"
shim=0
for arg in "$@"; do
  case "$arg" in
    --shim) shim=1 ;;
    -h|--help) echo "usage: install.sh [--shim]   (KEYTAP_BIN, KEYTAP_VERSION override the target dir and release)"; exit 0 ;;
    *) echo "keytap: unknown option $arg" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'keytap: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) die "unsupported system $(uname -s) — on Windows use https://keytap.me/install.ps1" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=amd64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
command -v curl >/dev/null || die "curl is required"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "sha256sum or shasum is required to verify the download"; fi

asset="age-plugin-yubikey-phone-$os-$arch.tar.gz"
if [ -n "${KEYTAP_VERSION:-}" ]; then base="https://github.com/$repo/releases/download/$KEYTAP_VERSION"
else base="https://github.com/$repo/releases/latest/download"; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
say "Downloading $asset …"
curl -fsSL "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "$asset is not listed in SHA256SUMS"
[ "$(sha "$tmp/$asset")" = "$want" ] || die "checksum mismatch for $asset — not installing"
say "Checksum verified."

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$bin_dir"
install -m 755 "$tmp/age-plugin-yubikey-phone" "$bin_dir/age-plugin-yubikey-phone"
say "Installed $bin_dir/age-plugin-yubikey-phone ($("$bin_dir/age-plugin-yubikey-phone" version 2>/dev/null || echo unknown version))"

if [ "$shim" = 1 ]; then
  link="$bin_dir/age-plugin-yubikey"
  if [ -L "$link" ] && [ "$(readlink "$link")" = "$bin_dir/age-plugin-yubikey-phone" ]; then
    say "Shim already in place: $link"
  elif [ -e "$link" ] || [ -L "$link" ]; then
    say "Not creating the shim: $link already exists (another relay?). Use its phone mode, or remove it first."
  else
    ln -s "$bin_dir/age-plugin-yubikey-phone" "$link"
    say "Shim created: $link -> age-plugin-yubikey-phone"
  fi
fi

say ""
command -v age >/dev/null || say "Note: 'age' is not installed yet (macOS: brew install age)."
real=""
IFS=:; for d in $PATH; do
  [ "$d" = "$bin_dir" ] && continue
  if [ -x "$d/age-plugin-yubikey" ]; then real="$d/age-plugin-yubikey"; break; fi
done; unset IFS
[ -n "$real" ] || say "Note: the real age-plugin-yubikey is not installed yet (macOS: brew install age-plugin-yubikey)."
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) say "Note: $bin_dir is not on your PATH. Add it first in your shell profile:  export PATH=\"$bin_dir:\$PATH\"" ;;
esac
say ""
say "Next: open KeyTap on your iPhone and run"
say "  age-plugin-yubikey-phone pair --host <IP address of this computer>"
say "Guide: https://keytap.me/install"
