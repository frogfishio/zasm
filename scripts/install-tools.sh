#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tools_dir="${root_dir}/tools"
bin_dir="${tools_dir}/bin"
versions_file="${tools_dir}/versions.env"

if [[ -f "${versions_file}" ]]; then
  # shellcheck disable=SC1090
  source "${versions_file}"
fi

if [[ -z "${WASM_TOOLS_VERSION:-}" || -z "${BINARYEN_VERSION:-}" ]]; then
  echo "Missing tool versions. Set WASM_TOOLS_VERSION and BINARYEN_VERSION in ${versions_file}." >&2
  exit 2
fi

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "${uname_s}" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *)
    echo "Unsupported OS: ${uname_s}" >&2
    exit 2
    ;;
esac

case "${uname_m}" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)
    echo "Unsupported architecture: ${uname_m}" >&2
    exit 2
    ;;
esac

case "${os}-${arch}" in
  linux-x86_64)
    wasm_tools_target="x86_64-linux"
    binaryen_target="x86_64-linux"
    ;;
  linux-arm64)
    wasm_tools_target="aarch64-linux"
    binaryen_target="aarch64-linux"
    ;;
  macos-x86_64)
    wasm_tools_target="x86_64-macos"
    binaryen_target="x86_64-macos"
    ;;
  macos-arm64)
    wasm_tools_target="aarch64-macos"
    binaryen_target="arm64-macos"
    ;;
esac

mkdir -p "${bin_dir}"
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

fetch() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL "${url}" -o "${out}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${out}" "${url}"
  else
    echo "Neither curl nor wget is available." >&2
    exit 2
  fi
}

wasm_tools_name="wasm-tools-${WASM_TOOLS_VERSION}-${wasm_tools_target}.tar.gz"
wasm_tools_url="https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VERSION}/${wasm_tools_name}"
wasm_tools_tar="${tmpdir}/${wasm_tools_name}"

echo "Downloading wasm-tools ${WASM_TOOLS_VERSION}..."
fetch "${wasm_tools_url}" "${wasm_tools_tar}"
tar -xzf "${wasm_tools_tar}" -C "${tmpdir}"
wasm_tools_bin="$(find "${tmpdir}" -type f -name wasm-tools -maxdepth 3 | head -n 1)"
if [[ -z "${wasm_tools_bin}" ]]; then
  echo "wasm-tools binary not found in ${wasm_tools_name}" >&2
  exit 2
fi
install -m 0755 "${wasm_tools_bin}" "${bin_dir}/wasm-tools"

binaryen_name="binaryen-version_${BINARYEN_VERSION}-${binaryen_target}.tar.gz"
binaryen_url="https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/${binaryen_name}"
binaryen_tar="${tmpdir}/${binaryen_name}"

echo "Downloading Binaryen ${BINARYEN_VERSION}..."
fetch "${binaryen_url}" "${binaryen_tar}"
tar -xzf "${binaryen_tar}" -C "${tmpdir}"
binaryen_root="${tmpdir}/binaryen-version_${BINARYEN_VERSION}"
if [[ ! -d "${binaryen_root}/bin" ]]; then
  echo "Binaryen bin directory not found in ${binaryen_name}" >&2
  exit 2
fi
cp -a "${binaryen_root}/bin/." "${bin_dir}/"

cat > "${tools_dir}/env.sh" <<EOF
export PATH="${bin_dir}:\$PATH"
EOF

echo "Installed tools to ${bin_dir}"
echo "Run: source ${tools_dir}/env.sh"
