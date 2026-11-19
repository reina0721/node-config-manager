#!/usr/bin/env bash
# Build a pinned optional proxy adapter from its source and toolchain locks.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: bash scripts/build-proxy-adapter.sh {xray-masque|xray-amneziawg|mtg-multi} OUTPUT" >&2
  exit 2
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
component=$1
case "$component" in
  xray-masque) patch_name=xray-masque-peer-isolation.patch ;;
  xray-amneziawg) patch_name=xray-amneziawg.patch ;;
  mtg-multi) patch_name=mtg-browser-gateway.patch ;;
  *) echo "Unknown adapter" >&2; exit 2 ;;
esac
output=$(realpath -m "$2")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
manifest="$repo/versions.lock.toml"
patch="$repo/patches/$patch_name"
value() {
  awk -F '"' -v key="$1" -v component="[$component]" '
    /^\[/ { found = ($0 == component) }
    found && $1 == key " = " { print $2; exit }
  ' "$manifest"
}
arch=$(uname -m)
case "$arch" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "Unsupported MASQUE architecture" >&2; exit 1 ;;
esac
check() {
  printf '%s  %s\n' "$1" "$2" | sha256sum --check --status
}
commit=$(value source_commit)
check "$(value patch_sha256)" "$patch"
git -c init.templateDir= init -q "$work/source"
git -C "$work/source" -c core.hooksPath=/dev/null fetch --depth=1 --no-tags "$(value repository)" "$commit"
git -C "$work/source" -c core.hooksPath=/dev/null checkout -q --detach FETCH_HEAD
test "$(git -C "$work/source" rev-parse HEAD)" = "$commit"
git -C "$work/source" apply "$patch"
if [ "$component" = xray-amneziawg ]; then
  parameters="$repo/patches/amneziawg-parameters.conf"
  check "$(value parameters_sha256)" "$parameters"
  awk -F ' = ' '{ print tolower($1) "=" $2 }' "$parameters" > "$work/source/proxy/wireguard/nodectl_amnezia.uapi"
fi
(
  cd "$work/source"
  export GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
  export GOTOOLCHAIN="go$(value go_version)" GOENV=off GOWORK=off GOFLAGS=
  package=./main
  if [ "$component" = mtg-multi ]; then package=.; fi
  go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$work/adapter" "$package"
)
check "$(value "linux_${arch}_binary_sha256")" "$work/adapter"
install -m 0755 "$work/adapter" "$output"
