<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zem

IR JSONL emulator + debugger for ZASM IR v1.1.

`zem` executes ZASM IR JSONL directly (the output of `zas`, and an input to tools like `zld`/`zir`). It is also used as a developer-experience tool: it can trace execution, expose a CLI debugger, and emit machine-readable debugger stop events suitable for feeding into external tooling (e.g. a DAP adapter).

## Usage

```sh
bin/zem /tmp/program.jsonl
```

Inputs are one or more IR JSONL files:

```sh
bin/zem file1.jsonl file2.jsonl
```

Or stdin (useful for pipes):

```sh
compiler | bin/zem --source-name program.jsonl
```

Notes:

- If you omit input files, `zem` reads program IR JSONL from stdin (stream mode).
- `-` explicitly means “read program IR JSONL from stdin” (same as stream mode).
- `--source-name` controls the `source.name` reported in `dbg_stop` events for stdin inputs.
- `--debug-script -` reads debugger commands from stdin, so it cannot be combined with reading program IR from stdin (either stream mode or `-`).

## Integration

`zem` is designed to be easy to embed in pipelines. The key is to keep the streams straight:

- **stdout**: the guest program’s stdout (what the emulated program writes via `_out` and similar).
- **stderr**: `zem` diagnostics and (optionally) JSONL event streams like `dbg_stop`, `trace`, `mem_read`, `mem_write`.

If you want to consume machine-readable events, use `--debug-events-only` so stderr is clean JSONL.

### Recipe 1: file input (program from file)

Use this when you want the guest program to read runtime stdin (e.g. echo/cat programs):

```sh
printf 'hello\n' | bin/zem examples/echo.jsonl > /tmp/program.out
```

- Read the emulated program’s output from stdout (`/tmp/program.out` above).
- Unless you enable tracing/debug events, stderr is just `zem` diagnostics.

### Recipe 2: pipe input (program IR from stdin)

Use this when another tool produces IR JSONL and you want to run it immediately:

```sh
compiler | bin/zem --source-name program.jsonl
```

Notes:

- When you use stream mode (or `-`), `zem` consumes stdin to read the program IR JSONL. That means the guest program effectively has no runtime stdin available.
- If the guest needs runtime stdin, prefer Recipe 1 (program from a file) so stdin can be used for program input.

### Recipe 3: pipe + breakpoints + events-only (tooling mode)

Use this when you want a pipeline-friendly run that produces only JSONL debugger stop events on stderr.
Because stdin is used for the program IR (`-`), drive the debugger from a script file:

```sh
cat > /tmp/zem.script <<'EOF'
blabel main
c
quit
EOF

compiler | bin/zem --debug-events-only --source-name program.jsonl --debug-script /tmp/zem.script - \
  2> /tmp/zem.events.jsonl \
  > /tmp/program.out
```

- Read debugger events from stderr (`/tmp/zem.events.jsonl`).
- Read the guest program output from stdout (`/tmp/program.out`).

## Common flags

### Tracing

- `--trace` emits per-instruction JSONL events to stderr.
- `--trace-mem` adds `mem_read`/`mem_write` JSONL events to stderr.

### Coverage

`zem` can record per-PC instruction hit counts and write them as JSONL.

```sh
bin/zem --coverage --coverage-out /tmp/zem.coverage.jsonl /tmp/program.jsonl
```

Print a quick “black holes” summary (labels with uncovered instructions):

```sh
bin/zem --coverage --coverage-blackholes 20 --coverage-out /tmp/zem.coverage.jsonl /tmp/program.jsonl
```

Merge multiple runs (useful for CI shards or multi-phase pipelines):

```sh
bin/zem --coverage --coverage-merge /tmp/zem.coverage.jsonl \
  --coverage-out /tmp/zem.coverage.merged.jsonl \
  /tmp/program.jsonl
```

Notes:

- Coverage is per IR record index (`pc`). Only instruction records (`kind == instr`) are reported.
- The JSONL report also includes per-label aggregates (`k == "zem_cov_label"`) to support black-hole analysis.
- When `--debug-events-only` is used, `--coverage` requires `--coverage-out` (to keep stderr clean JSONL).

### Debugging (CLI)

- `--debug` starts the interactive CLI debugger (starts paused).
- `--break-pc N` breaks when `pc == N` (where `pc` is the IR record index).
- `--break-label L` breaks at label `L`.
- `--debug-script PATH` runs debugger commands from PATH (no prompt; exit on EOF). Use `-` for stdin.

If you want to run a piped program _and_ drive the debugger with a script, put the script in a file:

```sh
printf 'blabel main\nc\nquit\n' > /tmp/zem.script
compiler | bin/zem --debug-events-only --source-name program.jsonl --debug-script /tmp/zem.script -
```

### Debugger stop events (JSONL)

- `--debug-events` emits JSONL `dbg_stop` events to stderr on each debugger stop.
- `--debug-events-only` like `--debug-events`, but suppresses human-oriented debugger output (prompt/help/regs/disasm/etc) and suppresses zem lifecycle telemetry.

### Diagnostics (trap reports)

When `zem` fails (e.g. out-of-bounds memory access), it prints a human-oriented trap report to stderr including:

- the failing IR record (`pc`, label/line if present)
- register dump + backtrace
- a short “recent instruction” history
- for instructions that dereference memory, the base register value and its provenance (where that register was last written)

In some cases `zem` can also emit a targeted diagnosis if it recognizes a high-signal signature (e.g. return-slot loaded with `LD32`, sign-extended, then used as an address and traps out-of-bounds).

This is intended to make “trap, identify, explain” workflows fast when debugging compiler lowering bugs.

### Sniffer mode (proactive warnings)

- `--sniff` enables heuristic warnings for high-signal bug signatures (currently: return-slot pointer truncation patterns).
- `--sniff-fatal` like `--sniff`, but turns a warning into a failing trap.

The warning includes the detected pattern PCs, the suspect register’s current value, and its provenance.

## Debugger REPL quickstart

Run, then interact:

```sh
bin/zem --debug /tmp/program.jsonl
```

Typical commands:

- `help` list commands
- `continue` / `c` run until breakpoint/exit
- `step` / `s` execute one instruction
- `next` / `n` step over CALL (best-effort)
- `finish` run until returning from the current frame
- `regs` show registers
- `bt` show call stack
- `pc` show current pc/label
- `bpc N` add breakpoint at pc N
- `blabel NAME` add breakpoint at label NAME
- `bp` list breakpoints

Scripted debugger (useful for automation):

```sh
printf 'bp\ncontinue\n' | bin/zem --debug-script - /tmp/program.jsonl
```

## `dbg_stop` schema (JSONL)

When `--debug-events` (or `--debug-events-only`) is enabled, `zem` writes one JSON object per line to stderr.

Stop events have `k == "dbg_stop"` and include:

- `k`: always `"dbg_stop"`
- `v`: schema version number (currently `1`)
- `reason`: stop reason string (e.g. `"paused"`, `"breakpoint"`, `"step"`, `"next"`, `"finish"`)
- `frame`: stable frame object
  - `pc`: IR record index (0-based)
  - `id`: frame id (0 is the current frame)
  - `label`: label at `pc` (or `null`)
  - `line`: source line (or `null` if unavailable)
  - `col`: source column (currently always `1`)
  - `kind`: record kind (`"instr"`, `"dir"`, `"label"`, ...)
  - plus one of: `m` (mnemonic), `d` (directive), `name` (label/dir name) when applicable
  - `source`: source identity object
    - `name`: display name (filename or `"<stdin>"`)
    - `path`: path if known (null for stdin)
- `sp`: call stack depth
- `bp`: matched breakpoint metadata (or `null`)
  - `pc`: breakpoint pc
  - `cond`: breakpoint condition expression (or `null`)
  - `cond_ok`: condition parsed/evaluated successfully
  - `result`: condition result (true/false)
- `bps`: array of active breakpoint PCs (numbers)
- `frames`: call stack frames, for DAP/tooling
  - `id`: frame id (stable within a stop event)
  - `pc`: frame pc (current frame first)
  - `name`: nearest label at-or-before `pc` (or `null`)
  - `label`: label exactly at `pc` (or `null`)
  - `line`: source line (or `null`)
  - `col`: source column (currently always `1`)
  - `m`: mnemonic at `pc` if `pc` points to an instruction (or `null`)
  - `source`: `{name,path}` as above
- `regs`: register snapshot (`HL`, `DE`, `BC`, `IX`, `A`)
- `regprov`: register provenance map (register -> provenance object or `null`)
- `watches`: watch values (empty unless watches are configured)
  - each watch may include `written_by` with `{pc,label,line,op}`

Notes:

- Fields under `frame` and the top-level `k/reason/pc/label/sp/bps/regs` are intended to be stable for DAP/tooling.
- `rec` is included as a best-effort mirror of the current IR record and may evolve.

Example (pretty-printed; actual output is one line):

```json
{
  "k": "dbg_stop",
  "v": 1,
  "reason": "paused",
  "frame": {"pc": 0, "id": 0, "label": null, "line": null, "col": 1, "kind": "dir", "d": "EXTERN"},
  "pc": 0,
  "label": null,
  "sp": 0,
  "bp": null,
  "bps": [0],
  "frames": [{"id": 0, "pc": 0, "name": null, "label": null, "line": null, "col": 1, "m": null}],
  "regs": {"HL": 0, "DE": 0, "BC": 0, "IX": 0, "A": 0},
  "regprov": {"HL": null, "DE": null, "BC": null, "IX": null, "A": null},
  "watches": []
}
```
