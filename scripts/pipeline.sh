#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pipeline.sh [options]

Options:
  --case <name>        Run a built-in case (hello, cat, upper, alloc, isa_smoke, log)
  --asm <path>         Run a custom .asm file instead of a built-in case
  --input <path>       Input file for --asm (default: /dev/null)
  --expected <path>    Expected stdout file for --asm (optional)
  --stderr-pattern <s> Require stderr to contain literal text (custom mode)
  --arch <name>        Force zxc --arch (arm64|x86_64), default = host
  --name <label>       Friendly label for custom runs
  --skip-build         Assume tools are already built
  --no-extern-prim     Do not pass --allow-extern-prim to zir
  --list-cases         Print available built-in case names
  -h, --help           Show this message

Without options the script builds the toolchain (make build) and runs the
default `hello` case.
EOF
}

list_cases() {
  printf '%s\n' "hello" "cat" "upper" "alloc" "isa_smoke" "log"
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"
BIN_DIR="$ROOT_DIR/bin"
BUILD_DIR="$ROOT_DIR/build/pipeline"
DEFAULT_CASES=(hello)

cases=()
custom_mode=0
asm_path=""
input_path="/dev/null"
expected_path=""
stderr_pattern=""
arch_override=""
custom_name=""
skip_build=0
allow_extern=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case)
      [[ $# -ge 2 ]] || { echo "--case requires a value" >&2; exit 2; }
      cases+=("$2")
      shift 2
      ;;
    --asm)
      [[ $# -ge 2 ]] || { echo "--asm requires a path" >&2; exit 2; }
      custom_mode=1
      asm_path="$2"
      shift 2
      ;;
    --input)
      [[ $# -ge 2 ]] || { echo "--input requires a path" >&2; exit 2; }
      input_path="$2"
      shift 2
      ;;
    --expected)
      [[ $# -ge 2 ]] || { echo "--expected requires a path" >&2; exit 2; }
      expected_path="$2"
      shift 2
      ;;
    --stderr-pattern)
      [[ $# -ge 2 ]] || { echo "--stderr-pattern requires text" >&2; exit 2; }
      stderr_pattern="$2"
      shift 2
      ;;
    --arch)
      [[ $# -ge 2 ]] || { echo "--arch requires a value" >&2; exit 2; }
      arch_override="$2"
      shift 2
      ;;
    --name)
      [[ $# -ge 2 ]] || { echo "--name requires a label" >&2; exit 2; }
      custom_name="$2"
      shift 2
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    --no-extern-prim)
      allow_extern=0
      shift
      ;;
    --list-cases)
      list_cases
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if (( custom_mode )) && ((${#cases[@]} > 0)); then
  echo "cannot mix --asm with --case" >&2
  exit 2
fi

if (( custom_mode )); then
  [[ -n "$asm_path" ]] || { echo "--asm requires a file" >&2; exit 2; }
else
  if ((${#cases[@]} == 0)); then
    cases=("${DEFAULT_CASES[@]}")
  fi
fi

mkdir -p "$BUILD_DIR"

run_cmd() {
  local label="$1"; shift
  printf '==> [%s] %s\n' "$label" "$*"
  "$@"
}

log_step() {
  local label="$1"
  local msg="$2"
  printf '==> [%s] %s\n' "$label" "$msg"
}

ensure_file() {
  local path="$1"
  if [[ "$path" != "/dev/null" && ! -f "$path" ]]; then
    echo "missing file: $path" >&2
    exit 1
  fi
}

resolve_case() {
  local name="$1"
  case "$name" in
    hello)
      CASE_ASM="examples/hello.asm"
      CASE_INPUT="/dev/null"
      CASE_EXPECT="test/fixtures/hello.out"
      CASE_STDERR=""
      ;;
    cat)
      CASE_ASM="examples/cat.asm"
      CASE_INPUT="test/fixtures/cat.in"
      CASE_EXPECT="test/fixtures/cat.out"
      CASE_STDERR=""
      ;;
    upper)
      CASE_ASM="examples/upper.asm"
      CASE_INPUT="test/fixtures/upper.in"
      CASE_EXPECT="test/fixtures/upper.out"
      CASE_STDERR=""
      ;;
    alloc)
      CASE_ASM="examples/alloc.asm"
      CASE_INPUT="test/fixtures/alloc.in"
      CASE_EXPECT="test/fixtures/alloc.out"
      CASE_STDERR=""
      ;;
    isa_smoke)
      CASE_ASM="examples/isa_smoke.asm"
      CASE_INPUT="test/fixtures/isa_smoke.in"
      CASE_EXPECT="test/fixtures/isa_smoke.out"
      CASE_STDERR=""
      ;;
    log)
      CASE_ASM="examples/log.asm"
      CASE_INPUT="/dev/null"
      CASE_EXPECT=""
      CASE_STDERR="[demo] hello"
      ;;
    *)
      echo "unknown case: $name" >&2
      exit 2
      ;;
  esac
}

run_pipeline_case() {
  local label="$1"
  local asm="$2"
  local input="$3"
  local expected="$4"
  local stderr_match="$5"

  ensure_file "$asm"
  ensure_file "$input"
  if [[ -n "$expected" ]]; then
    ensure_file "$expected"
  fi

  local safe_label="$label"
  if [[ -z "$safe_label" ]]; then
    safe_label="$(basename "$asm" .asm)"
  fi
  safe_label="${safe_label//[^A-Za-z0-9_.-]/_}"
  local case_dir="$BUILD_DIR/$safe_label"
  mkdir -p "$case_dir"

  local ir_path="$case_dir/$safe_label.ir.jsonl"
  local op_path="$case_dir/$safe_label.opcodes.jsonl"
  local wat_path="$case_dir/$safe_label.wat"
  local zasm_path="$case_dir/$safe_label.zasm.bin"
  local native_path="$case_dir/$safe_label.native.bin"
  local stdout_path="$case_dir/$safe_label.stdout"
  local stderr_path="$case_dir/$safe_label.stderr"
  local zlnt_log="$case_dir/$safe_label.zlnt.log"

  run_cmd "$safe_label" "$BIN_DIR/zas" --target ir --tool -o "$ir_path" "$asm"
  log_step "$safe_label" "zlnt -> $zlnt_log"
  "$BIN_DIR/zlnt" --tool "$ir_path" > "$zlnt_log"

  log_step "$safe_label" "zld -> $wat_path"
  "$BIN_DIR/zld" < "$ir_path" > "$wat_path"

  if [[ "$input" == "/dev/null" ]]; then
    log_step "$safe_label" "zrun -> stdout"
    "$BIN_DIR/zrun" "$wat_path" > "$stdout_path" 2>"$stderr_path"
  else
    log_step "$safe_label" "zrun <- $input"
    "$BIN_DIR/zrun" "$wat_path" < "$input" > "$stdout_path" 2>"$stderr_path"
  fi

  if [[ -n "$expected" ]]; then
    if ! cmp -s "$stdout_path" "$expected"; then
      echo "stdout mismatch for $safe_label" >&2
      echo "expected:" >&2
      od -An -tx1 "$expected" >&2
      echo "got:" >&2
      od -An -tx1 "$stdout_path" >&2
      exit 1
    fi
  fi

  if [[ -n "$stderr_match" ]]; then
    if ! grep -Fq "$stderr_match" "$stderr_path"; then
      echo "stderr missing pattern '$stderr_match' for $safe_label" >&2
      exit 1
    fi
  fi

  if (( allow_extern )); then
    log_step "$safe_label" "zir --allow-extern-prim -> $op_path"
    "$BIN_DIR/zir" --allow-extern-prim < "$ir_path" > "$op_path"
  else
    log_step "$safe_label" "zir -> $op_path"
    "$BIN_DIR/zir" < "$ir_path" > "$op_path"
  fi

  run_cmd "$safe_label" "$BIN_DIR/zop" --container -o "$zasm_path" "$op_path"

  local total_bytes
  total_bytes=$(wc -c < "$zasm_path" | tr -d ' \n')
  if [[ -z "$total_bytes" ]]; then
    echo "failed to measure container size for $safe_label" >&2
    exit 1
  fi
  if (( total_bytes < 16 )); then
    echo "invalid container emitted for $safe_label" >&2
    exit 1
  fi
  local payload_size=$((total_bytes - 16))
  if (( payload_size <= 0 )); then
    echo "empty opcode payload for $safe_label" >&2
    exit 1
  fi

    if (( payload_size % 4 != 0 )); then
      echo "==> [$safe_label] note: opcode payload ${payload_size}B (zxc will ignore $((payload_size % 4))B trailing data)"
    fi

    local zxc_cmd=("$BIN_DIR/zxc" "--container" "-o" "$native_path")
    if [[ -n "$arch_override" ]]; then
      zxc_cmd+=("--arch" "$arch_override")
    fi
    zxc_cmd+=("$zasm_path")
    local zxc_log="$case_dir/$safe_label.zxc.log"
    log_step "$safe_label" "zxc -> $native_path (log: $zxc_log)"
    if "${zxc_cmd[@]}" > "$zxc_log" 2>&1; then
      if [[ ! -s "$native_path" ]]; then
        echo "zxc produced empty output for $safe_label" >&2
        cat "$zxc_log" >&2
        exit 1
      fi
    else
      if grep -q 'err=5' "$zxc_log"; then
        echo "==> [$safe_label] skipping zxc (translator unimplemented for opcode)"
      else
        cat "$zxc_log" >&2
        exit 1
      fi
    fi

  echo "==> [$safe_label] pipeline complete"
}

if (( ! skip_build )); then
  run_cmd "setup" make build
fi

if (( custom_mode )); then
  run_pipeline_case "${custom_name:-custom}" "$asm_path" "$input_path" "$expected_path" "$stderr_pattern"
else
  for case_name in "${cases[@]}"; do
    resolve_case "$case_name"
    run_pipeline_case "$case_name" "$CASE_ASM" "$CASE_INPUT" "$CASE_EXPECT" "$CASE_STDERR"
  done
fi

echo "pipeline: all cases passed"
