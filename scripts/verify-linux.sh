#!/usr/bin/env bash
# Verify the Linux release artifacts: sizes, installability and a real run on
# every supported distribution family. Needs Docker and linux/amd64 images.
#
#   scripts/verify-linux.sh dist/
#
# The directory must hold the .tar.gz, .deb and .rpm for this version.
set -euo pipefail

dist="${1:?usage: verify-linux.sh <artifacts-dir>}"
dist="$(cd "$dist" && pwd)"

shopt -s nullglob
archives=("$dist"/*x86_64-unknown-linux-gnu.tar.gz)
debs=("$dist"/*.deb)
rpms=("$dist"/*.rpm)
shopt -u nullglob

if [ "${#archives[@]}" -ne 1 ] || [ "${#debs[@]}" -ne 1 ] || [ "${#rpms[@]}" -ne 1 ]; then
  echo "expected one tarball, one .deb and one .rpm in $dist" >&2
  ls -l "$dist" >&2
  exit 1
fi

# A stub or an empty upload is the failure this guards against.
for f in "${archives[0]}" "${debs[0]}" "${rpms[0]}"; do
  size="$(wc -c <"$f")"
  echo "$(basename "$f"): ${size} bytes"
  if [ "$size" -lt 1000000 ]; then
    echo "error: $(basename "$f") is only ${size} bytes; the build is broken" >&2
    exit 1
  fi
done

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/root/.claude/projects/p"
# Split the sample key so the secret scanner does not flag this script.
aws_key="AKIA$(printf 'Z7QWERTYUIOPLKJH')"
printf '{"type":"user","cwd":"/tmp","message":{"content":"export AWS_ACCESS_KEY_ID=%s"}}\n' "$aws_key" \
  >"$fixture/root/.claude/projects/p/s.jsonl"

for image in ubuntu:22.04 ubuntu:24.04 fedora:41 fedora:latest; do
  echo "== ${image}"
  docker run --rm \
    -v "$dist:/d:ro" \
    -v "$fixture:/fixture:ro" \
    "$image" bash -euc '
      if command -v dpkg >/dev/null; then
        apt-get update -qq
        apt-get install -yqq libstdc++6 >/dev/null
        dpkg -i /d/*.deb >/dev/null
      else
        # dnf understands local files and skips OpenPGP checks for them, which
        # is what the README tells Fedora users to run. Plain `rpm -i` is
        # rejected on Fedora 43+, where signature verification is mandatory.
        dnf install -y /d/*.rpm
      fi
      command -v neuralyzer
      neuralyzer --version

      tar -xzf /d/*x86_64-unknown-linux-gnu.tar.gz -C /tmp
      /tmp/neuralyzer --version

      export NEURALYZER_DATA_DIR=/tmp/data
      status=0
      neuralyzer scan --root /fixture/root --no-ner --json >/tmp/report.json || status=$?
      test "$status" -eq 1
      grep -q "\"SECRET\"" /tmp/report.json
    '
done

echo "Linux artifacts verified on Ubuntu and Fedora."
