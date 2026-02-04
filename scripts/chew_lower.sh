#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/chew_lower.sh [options] --input <program.ir.jsonl> [--] [guest-argv...]

Goal:
  Prototype a "zem-first" pre-pass for lower:
    1) run zem to collect coverage
    2) strip uncovered IR (conservative by default)
    3) run lower on both baseline + stripped IR
    4) (optional) link + run both and compare stdout

Options:
  --input PATH          Input IR JSONL (zasm v1.1 strongly preferred)
  --mode MODE           Strip mode: uncovered-ret | uncovered-delete (default: uncovered-ret)
  --stdin PATH          Provide guest stdin from PATH (default: /dev/null)
  --out-dir DIR         Write artifacts into DIR (default: mktemp)
  --keep                Do not delete temp out-dir when using default mktemp

  --rep-scan            Also run zem repetition scan (n-grams) on baseline + stripped
  --rep-n N             N-gram length (default: 8)
  --rep-mode MODE       exact | shape (default: shape)
  --rep-max-report N    Emit up to N repeated n-grams (default: 20)
  --rep-html            Render HTML reports (requires python3)

  --no-run              Only build artifacts; do not run executables
  --compare-exit        Also require exit codes match (default: stdout-only)

Examples:
  scripts/chew_lower.sh --input build/hello.ir.jsonl
  scripts/chew_lower.sh --input build/cat.ir.jsonl --stdin test/fixtures/cat.in
  scripts/chew_lower.sh --input build/prog.ir.jsonl -- --flag1 value
EOF
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

input=""
mode="uncovered-ret"
stdin_path="/dev/null"
out_dir=""
keep=0
no_run=0
compare_exit=0
rep_scan=0
rep_n=8
rep_mode="shape"
rep_max_report=20
rep_html=0

argv=("$@")
guest_argv=()

# Split options vs guest argv: everything after -- is guest argv.
opt_argv=()
seen_params=0
for a in "${argv[@]}"; do
  if (( seen_params )); then
    guest_argv+=("$a")
    continue
  fi
  if [[ "$a" == "--" ]]; then
    seen_params=1
    continue
  fi
  opt_argv+=("$a")
done

idx=0
while (( idx < ${#opt_argv[@]} )); do
  a="${opt_argv[$idx]}"
  case "$a" in
    -h|--help)
      usage
      exit 0
      ;;
    --input)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--input requires a value" >&2; exit 2; }
      input="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --mode)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--mode requires a value" >&2; exit 2; }
      mode="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --stdin)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--stdin requires a value" >&2; exit 2; }
      stdin_path="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --out-dir)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--out-dir requires a value" >&2; exit 2; }
      out_dir="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --keep)
      keep=1
      idx=$((idx+1))
      ;;
    --no-run)
      no_run=1
      idx=$((idx+1))
      ;;
    --compare-exit)
      compare_exit=1
      idx=$((idx+1))
      ;;
    --rep-scan)
      rep_scan=1
      idx=$((idx+1))
      ;;
    --rep-n)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--rep-n requires a value" >&2; exit 2; }
      rep_n="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --rep-mode)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--rep-mode requires a value" >&2; exit 2; }
      rep_mode="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --rep-max-report)
      (( idx + 1 < ${#opt_argv[@]} )) || { echo "--rep-max-report requires a value" >&2; exit 2; }
      rep_max_report="${opt_argv[$((idx+1))]}"
      idx=$((idx+2))
      ;;
    --rep-html)
      rep_html=1
      idx=$((idx+1))
      ;;
    *)
      echo "unknown option: $a" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$input" ]]; then
  echo "--input is required" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$input" ]]; then
  echo "missing input: $input" >&2
  exit 2
fi
if [[ "$stdin_path" != "/dev/null" && ! -f "$stdin_path" ]]; then
  echo "missing stdin file: $stdin_path" >&2
  exit 2
fi

zem_bin="$root_dir/bin/zem"
lower_bin="$root_dir/bin/lower"
runner_c="$root_dir/test/repro/zabi25_native_runner.c"
zingcore25_a="$root_dir/build/zingcore25/libzingcore25.a"
zingcore25_inc="$root_dir/src/zingcore/2.5/zingcore/include"

if [[ ! -x "$zem_bin" ]]; then
  echo "missing executable: $zem_bin (hint: make zem)" >&2
  exit 2
fi
if [[ ! -x "$lower_bin" ]]; then
  echo "missing executable: $lower_bin (hint: make lower)" >&2
  exit 2
fi
if [[ ! -f "$runner_c" ]]; then
  echo "missing runner: $runner_c" >&2
  exit 2
fi

if [[ -z "$out_dir" ]]; then
  out_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-chew-lower-XXXXXX")"
  if (( ! keep )); then
    trap 'rm -rf "$out_dir"' EXIT
  else
    echo "out-dir: $out_dir" >&2
  fi
else
  mkdir -p "$out_dir"
fi

cov_jsonl="$out_dir/zem.coverage.jsonl"
cov_stripped_jsonl="$out_dir/zem.coverage.stripped.jsonl"
strip_stats="$out_dir/zem.strip_stats.jsonl"
stripped_ir="$out_dir/stripped.ir.jsonl"

rep_base_jsonl="$out_dir/zem.rep.base.jsonl"
rep_strip_jsonl="$out_dir/zem.rep.stripped.jsonl"
rep_base_html="$out_dir/zem.rep.base.html"
rep_strip_html="$out_dir/zem.rep.stripped.html"

base_obj="$out_dir/base.o"
base_exe="$out_dir/base.exe"
strip_obj="$out_dir/stripped.o"
strip_exe="$out_dir/stripped.exe"

base_stdout="$out_dir/base.stdout"
base_stderr="$out_dir/base.stderr"
strip_stdout="$out_dir/stripped.stdout"
strip_stderr="$out_dir/stripped.stderr"

run_exe() {
  local exe="$1"; shift
  local stdout_path="$1"; shift
  local stderr_path="$1"; shift

  if [[ "$stdin_path" == "/dev/null" ]]; then
    if (( ${#guest_argv[@]} > 0 )); then
      "$exe" "${guest_argv[@]}" >"$stdout_path" 2>"$stderr_path"
    else
      "$exe" >"$stdout_path" 2>"$stderr_path"
    fi
  else
    if (( ${#guest_argv[@]} > 0 )); then
      "$exe" "${guest_argv[@]}" <"$stdin_path" >"$stdout_path" 2>"$stderr_path"
    else
      "$exe" <"$stdin_path" >"$stdout_path" 2>"$stderr_path"
    fi
  fi
}

file_size() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo 0
    return
  fi
  stat -f%z "$path" 2>/dev/null || wc -c <"$path" | tr -d ' '
}

# 1) Baseline build (lower -> obj -> exe)
"$lower_bin" --input "$input" --o "$base_obj" >/dev/null
if [[ ! -f "$zingcore25_a" ]]; then
  echo "missing hostlib archive: $zingcore25_a" >&2
  echo "hint: build with: make zingcore25" >&2
  exit 2
fi
cc -I"$zingcore25_inc" \
  "$runner_c" \
  "$base_obj" \
  "$zingcore25_a" \
  -o "$base_exe" >/dev/null

# 2) Coverage collection on baseline IR using zem.
zem_args=("$zem_bin" "--coverage" "--coverage-out" "$cov_jsonl")
if [[ "$stdin_path" != "/dev/null" ]]; then
  zem_args+=("--stdin" "$stdin_path")
fi
# Pass guest argv via --params.
if (( ${#guest_argv[@]} > 0 )); then
  zem_args+=("--params" "${guest_argv[@]}")
fi
zem_args+=("$input")
"${zem_args[@]}" >/dev/null

if (( rep_scan )); then
  "$zem_bin" --rep-scan \
    --rep-n "$rep_n" --rep-mode "$rep_mode" --rep-max-report "$rep_max_report" \
    --rep-coverage-jsonl "$cov_jsonl" \
    --rep-out "$rep_base_jsonl" \
    --rep-diag \
    "$input" >/dev/null
  if (( rep_html )); then
    python3 tools/zem_repetition_scan.py \
      --from-report-jsonl "$rep_base_jsonl" \
      --max-report "$rep_max_report" \
      --report-html "$rep_base_html" >/dev/null
  fi
fi

# 3) Strip IR using coverage profile.
"$zem_bin" --strip "$mode" \
  --strip-profile "$cov_jsonl" \
  --strip-out "$stripped_ir" \
  --strip-stats-out "$strip_stats" \
  "$input" >/dev/null

# 4) Stripped build (lower -> obj -> exe)
"$lower_bin" --input "$stripped_ir" --o "$strip_obj" >/dev/null
cc -I"$zingcore25_inc" \
  "$runner_c" \
  "$strip_obj" \
  "$zingcore25_a" \
  -o "$strip_exe" >/dev/null

if (( rep_scan )); then
  zem_args2=("$zem_bin" "--coverage" "--coverage-out" "$cov_stripped_jsonl")
  if [[ "$stdin_path" != "/dev/null" ]]; then
    zem_args2+=("--stdin" "$stdin_path")
  fi
  if (( ${#guest_argv[@]} > 0 )); then
    zem_args2+=("--params" "${guest_argv[@]}")
  fi
  zem_args2+=("$stripped_ir")
  "${zem_args2[@]}" >/dev/null

  "$zem_bin" --rep-scan \
    --rep-n "$rep_n" --rep-mode "$rep_mode" --rep-max-report "$rep_max_report" \
    --rep-coverage-jsonl "$cov_stripped_jsonl" \
    --rep-out "$rep_strip_jsonl" \
    --rep-diag \
    "$stripped_ir" >/dev/null
  if (( rep_html )); then
    python3 tools/zem_repetition_scan.py \
      --from-report-jsonl "$rep_strip_jsonl" \
      --max-report "$rep_max_report" \
      --report-html "$rep_strip_html" >/dev/null
  fi
fi

# 5) Optional run + compare stdout.
if (( ! no_run )); then
  set +e
  run_exe "$base_exe" "$base_stdout" "$base_stderr"
  base_rc=$?
  run_exe "$strip_exe" "$strip_stdout" "$strip_stderr"
  strip_rc=$?
  set -e

  if ! cmp -s "$base_stdout" "$strip_stdout"; then
    echo "stdout mismatch (baseline vs stripped)" >&2
    echo "baseline stdout (hex):" >&2
    od -An -tx1 "$base_stdout" >&2 || true
    echo "stripped stdout (hex):" >&2
    od -An -tx1 "$strip_stdout" >&2 || true
    exit 1
  fi
  if (( compare_exit )) && [[ "$base_rc" -ne "$strip_rc" ]]; then
    echo "exit code mismatch: baseline=$base_rc stripped=$strip_rc" >&2
    exit 1
  fi
fi

base_obj_sz=$(file_size "$base_obj")
strip_obj_sz=$(file_size "$strip_obj")
base_exe_sz=$(file_size "$base_exe")
strip_exe_sz=$(file_size "$strip_exe")

INPUT_PATH="$input" \
MODE="$mode" \
OUT_DIR="$out_dir" \
STRIP_STATS="$strip_stats" \
BASE_OBJ_SZ="$base_obj_sz" \
STRIP_OBJ_SZ="$strip_obj_sz" \
BASE_EXE_SZ="$base_exe_sz" \
STRIP_EXE_SZ="$strip_exe_sz" \
python3 - <<PY
import json
import os

strip_stats = os.environ.get('STRIP_STATS')
rec = None
if strip_stats and os.path.exists(strip_stats):
  with open(strip_stats, 'r', encoding='utf-8') as f:
    for line in f:
      line=line.strip()
      if not line:
        continue
      try:
        r=json.loads(line)
      except Exception:
        continue
      if r.get('k')=='zem_strip':
        rec=r
        break

print('chew_lower summary:')
print(f'  input:     {os.environ.get("INPUT_PATH")}')
print(f'  mode:      {os.environ.get("MODE")}', flush=True)
if rec:
  print(f'  strip:     changed_instr={rec.get("changed_instr")} removed_instr={rec.get("removed_instr")} dead_by_profile_instr={rec.get("dead_by_profile_instr")}')
  print(f'  strip:     bytes_in={rec.get("bytes_in")} bytes_out={rec.get("bytes_out")}')
print(f'  base:      obj={int(os.environ.get("BASE_OBJ_SZ") or 0)}B exe={int(os.environ.get("BASE_EXE_SZ") or 0)}B')
print(f'  stripped:  obj={int(os.environ.get("STRIP_OBJ_SZ") or 0)}B exe={int(os.environ.get("STRIP_EXE_SZ") or 0)}B')
if rec:
  try:
    bi=int(rec.get('bytes_in') or 0)
    bo=int(rec.get('bytes_out') or 0)
    if bi>0:
      pct=100.0*(1.0-float(bo)/float(bi))
      print(f'  ir shrink: {pct:.2f}%')
  except Exception:
    pass
print(f'  artifacts: {os.environ.get("OUT_DIR")}')
PY