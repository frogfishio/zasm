#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
manifest="$root_dir/docs/integrator_pack/manifest.txt"
out_dir="${1:-$root_dir/dist/integrator_pack}"

if [ ! -f "$manifest" ]; then
  echo "missing manifest: $manifest" >&2
  exit 2
fi

mkdir -p "$out_dir"
rsync -a --files-from="$manifest" "$root_dir"/ "$out_dir"/

echo "Wrote integrator pack to $out_dir"
