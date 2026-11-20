#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
target=${1:?Specify an empty destination for the Windows source}
upstream=c83f7ad529c7c9cb3d2d54a0955ef8c1b22a411b

git -c core.autocrlf=false clone --depth 1 --branch v2.5.10 \
  https://github.com/clash-verge-rev/clash-verge-rev.git "$target"
test "$(git -C "$target" rev-parse HEAD)" = "$upstream"
git -C "$target" -c core.autocrlf=false apply "$here/integration.patch"
cp -- "$here/nodectl.rs" "$target/src-tauri/src/cmd/nodectl.rs"
cp -- "$here/nodectl-enrollment.tsx" "$target/src/components/layout/nodectl-enrollment.tsx"
