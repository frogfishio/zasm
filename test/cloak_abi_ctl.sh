#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak"
build_dir="$root_dir/build/cloak_tests"
platform_dir=""

if [ ! -x "$zcloak_bin" ]; then
  echo "missing executable: $zcloak_bin" >&2
  exit 2
fi

link_target="$(readlink "$zcloak_bin" || true)"
if [ -n "$link_target" ]; then
  platform_dir="$root_dir/bin/$(dirname "$link_target")"
fi

guest_path() {
  local name="$1"
  if [ -f "$build_dir/$name.dylib" ]; then
    echo "$build_dir/$name.dylib"
  else
    echo "$build_dir/$name.so"
  fi
}

run_guest() {
  local name="$1"
  local out="$build_dir/$name.out"
  local guest
  guest="$(guest_path "$name")"
  if [ -n "$platform_dir" ]; then
    DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
    LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
    "$zcloak_bin" "$guest" > "$out"
  else
    "$zcloak_bin" "$guest" > "$out"
  fi
  echo "$out"
}

check_envelope() {
  local name="$1"
  local trace="$2"
  local op="$3"
  local rid="$4"
  local out
  out="$(run_guest "$name")"
  python3 - "$out" "$trace" "$op" "$rid" <<'PY'
import sys
path, trace, op, rid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
data = open(path, "rb").read()
if len(data) < 24:
    raise SystemExit(f"{path}: short response ({len(data)})")
if data[:4] != b"ZCL1":
    raise SystemExit(f"{path}: bad magic {data[:4]!r}")
def u16(off):
    return int.from_bytes(data[off:off+2], "little")
def u32(off):
    return int.from_bytes(data[off:off+4], "little")
if u16(4) != 1:
    raise SystemExit(f"{path}: bad version {u16(4)}")
if u16(6) != op:
    raise SystemExit(f"{path}: bad op {u16(6)}")
if u32(8) != rid:
    raise SystemExit(f"{path}: bad rid {u32(8)}")
payload_len = u32(16)
if len(data) != 20 + payload_len:
    raise SystemExit(f"{path}: length mismatch {len(data)} != {20 + payload_len}")
payload = data[20:]
if payload_len < 4:
    raise SystemExit(f"{path}: short payload {payload_len}")
if payload[0] != 0:
    raise SystemExit(f"{path}: expected ok=0, got {payload[0]}")
trace_len = int.from_bytes(payload[4:8], "little")
trace_bytes = payload[8:8+trace_len]
try:
    got = trace_bytes.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(f"{path}: trace not ascii")
if got != trace:
    raise SystemExit(f"{path}: trace mismatch {got} != {trace}")
PY
}

check_small_resp() {
  local name="$1"
  local out
  out="$(run_guest "$name")"
  python3 - "$out" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
if len(data) != 11:
    raise SystemExit(f"{sys.argv[1]}: expected 11 bytes, got {len(data)}")
if data[:4] != b"\xff\xff\xff\xff":
    raise SystemExit(f"{sys.argv[1]}: expected -1 return, got {data[:4]!r}")
if data[4:] != b"PATTERN":
    raise SystemExit(f"{sys.argv[1]}: response buffer mutated {data[4:]!r}")
PY
}

check_oob_returns() {
  local name="$1"
  local out
  out="$(run_guest "$name")"
  python3 - "$out" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
if len(data) != 12:
    raise SystemExit(f"{sys.argv[1]}: expected 12 bytes, got {len(data)}")
for i in range(0, 12, 4):
    if data[i:i+4] != b"\xff\xff\xff\xff":
        raise SystemExit(f"{sys.argv[1]}: expected -1 at {i}, got {data[i:i+4]!r}")
PY
}

check_envelope ctl_bad_magic "t_ctl_bad_frame" 1 1
check_envelope ctl_bad_version "t_ctl_bad_version" 1 1
check_envelope ctl_bad_payload_len "t_ctl_bad_frame" 1 1
check_small_resp ctl_resp_cap_small
check_oob_returns ctl_oob_returns

echo "Cloak ABI ctl/error-envelope tests passed."
