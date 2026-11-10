#!/usr/bin/env bash
# Package the Linux release artifacts from an already-built binary:
# the portable tarball, the .deb for Ubuntu/Debian and the .rpm for Fedora/RHEL.
#
#   scripts/package-linux.sh 2.0.0
#
# The binary must come from `cargo build --release --locked --target
# x86_64-unknown-linux-gnu` on Ubuntu 22.04 (glibc 2.35). This script refuses to
# package a binary that needs a newer glibc, because it would then fail on
# Ubuntu 22.04/24.04 and older Fedora releases. nfpm is taken from $NFPM or PATH.
set -euo pipefail

version="${1:?usage: package-linux.sh <version without leading v>}"
case "$version" in
  v*) echo "error: pass the version without a leading v" >&2; exit 1 ;;
esac

target=x86_64-unknown-linux-gnu
tag="v${version}"
bin="target/${target}/release/neuralyzer"
nfpm="${NFPM:-nfpm}"

if [ ! -x "$bin" ]; then
  echo "error: $bin is missing; build it first" >&2
  exit 1
fi

max="$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -uV | tail -1)"
echo "binary requires glibc <= ${max}"
if [ "$(printf '2.35\n%s\n' "$max" | sort -V | tail -1)" != "2.35" ]; then
  echo "error: $bin needs glibc ${max}, newer than the 2.35 floor; it won't run on Ubuntu 22.04 or Fedora 36+" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist/stage
cp "$bin" README.md LICENSE dist/stage/
cp -R docs dist/stage/docs

tar -C dist/stage -czf "$PWD/dist/neuralyzer-${tag}-${target}.tar.gz" neuralyzer README.md LICENSE

ARCH=amd64 VERSION="$version" "$nfpm" package --config packaging/nfpm.yaml --packager deb \
  --target "dist/neuralyzer_${version}_amd64.deb"
ARCH=amd64 VERSION="$version" "$nfpm" package --config packaging/nfpm.yaml --packager rpm \
  --target "dist/neuralyzer-${version}-1.x86_64.rpm"

rm -rf dist/stage
(cd dist && sha256sum *.tar.gz *.deb *.rpm > linux.sha256 && cat linux.sha256)
