#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

out_root="${1:-$root_dir/dist/integration-pack}"
platform="${2:-macos-arm64}"

tool_src="$root_dir/bin/$platform"
if [ ! -d "$tool_src" ]; then
  echo "missing tool dir: $tool_src" >&2
  echo "available platforms under bin/:" >&2
  ls -1 "$root_dir/bin" >&2 || true
  exit 2
fi

zing_root="$root_dir/src/zingcore/2.5"
zing_dist="$zing_root/dist/debug"

# Prefer the archive produced by the zingcore build (contains host shim helpers).
zing_lib="$zing_root/build/libzingcore25.a"
if [ ! -f "$zing_lib" ]; then
  zing_lib="$zing_dist/lib/libzingcore25.a"
fi
if [ ! -f "$zing_lib" ]; then
  echo "missing zingcore runtime archive (tried build/ and dist/debug):" >&2
  echo "  $zing_root/build/libzingcore25.a" >&2
  echo "  $zing_dist/lib/libzingcore25.a" >&2
  exit 2
fi

zing_include_dir="$zing_dist/include"
if [ ! -d "$zing_include_dir" ]; then
  echo "missing zingcore include dir: $zing_include_dir" >&2
  exit 2
fi

hostlib_header_src="$zing_root/zingcore/include/zi_hostlib25.h"
if [ ! -f "$hostlib_header_src" ]; then
  echo "missing zi_hostlib25 header: $hostlib_header_src" >&2
  exit 2
fi

platform_out="$out_root/$platform"

rm -rf "$platform_out"
mkdir -p \
  "$platform_out/bin" \
  "$platform_out/lib" \
  "$platform_out/include" \
  "$platform_out/docs" \
  "$platform_out/docs/spec" \
  "$platform_out/docs/tools" \
  "$platform_out/docs/zingcore25" \
  "$platform_out/schema/ir" \
  "$platform_out/conformance" \
  "$platform_out/examples"

# Pack-level docs + legal
mkdir -p "$out_root"
rsync -a "$root_dir/docs/integration_pack/README.md" "$out_root/README.md"

for f in LICENSE LICENSE-ASM COPYRIGHT TRADEMARK VERSION CHANGELOG.md; do
  if [ -f "$root_dir/$f" ]; then
    rsync -a "$root_dir/$f" "$out_root/"
  fi
done

# Tools
for tool in lower zem zld; do
  if [ ! -f "$tool_src/$tool" ]; then
    echo "missing tool: $tool_src/$tool" >&2
    exit 2
  fi
  rsync -a "$tool_src/$tool" "$platform_out/bin/"
done

# Libraries
rsync -a "$zing_lib" "$platform_out/lib/"

# Headers (whitelist: avoid legacy/unused surfaces)
for f in version.h wat.h zasm_ir.h; do
  if [ -f "$root_dir/include/$f" ]; then
    rsync -a "$root_dir/include/$f" "$platform_out/include/"
  fi
done
rsync -a "$zing_include_dir/" "$platform_out/include/"
rsync -a "$hostlib_header_src" "$platform_out/include/"

# Docs (curated for integrators: zem + lower + zld + zABI spec)
for f in abi.md ir.md isa.md; do
  if [ -f "$root_dir/docs/spec/$f" ]; then
    rsync -a "$root_dir/docs/spec/$f" "$platform_out/docs/spec/$f"
  fi
done
for f in zem.md lower.md zld.md; do
  if [ -f "$root_dir/docs/tools/$f" ]; then
    rsync -a "$root_dir/docs/tools/$f" "$platform_out/docs/tools/$f"
  fi
done

for f in README.md STABILITY.md MIGRATION.md; do
  if [ -f "$zing_root/$f" ]; then
    rsync -a "$zing_root/$f" "$platform_out/docs/zingcore25/$f"
  fi
done

# Schemas (v1.1 is the supported contract for `zem` and recommended for integration)
if [ -d "$root_dir/schema/ir/v1.1" ]; then
  rsync -a "$root_dir/schema/ir/v1.1" "$platform_out/schema/ir/"
else
  echo "missing IR schema: $root_dir/schema/ir/v1.1" >&2
  exit 2
fi

# Conformance (JSONL-only). Intentionally excludes asm/wat-based runtime tests.
if [ -f "$root_dir/test/conform_zld.sh" ]; then
  rsync -a "$root_dir/test/conform_zld.sh" "$platform_out/conformance/conform_zld.sh"
fi
if [ -d "$root_dir/test/conform_zld" ]; then
  rsync -a "$root_dir/test/conform_zld/" "$platform_out/conformance/fixtures/"
fi

# Examples (host shim template for native `lower` outputs)
if [ -d "$root_dir/docs/integration_pack/examples" ]; then
  rsync -a "$root_dir/docs/integration_pack/examples/" "$platform_out/examples/"
  find "$platform_out/examples" -maxdepth 3 -type f -name '*.sh' -exec chmod +x {} \; || true
fi

echo "Wrote integration pack to $platform_out"
