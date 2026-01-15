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

## Common flags

### Tracing

- `--trace` emits per-instruction JSONL events to stderr.
- `--trace-mem` adds `mem_read`/`mem_write` JSONL events to stderr.

### Debugging (CLI)

- `--debug` starts the interactive CLI debugger (starts paused).
- `--break-pc N` breaks when `pc == N` (where `pc` is the IR record index).
- `--break-label L` breaks at label `L`.
- `--debug-script PATH` runs debugger commands from PATH (no prompt; exit on EOF). Use `-` for stdin.

### Debugger stop events (JSONL)

- `--debug-events` emits JSONL `dbg_stop` events to stderr on each debugger stop.
- `--debug-events-only` like `--debug-events`, but suppresses human-oriented debugger output (prompt/help/regs/disasm/etc) and suppresses zem lifecycle telemetry.

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
- `reason`: stop reason string (e.g. `"paused"`, `"breakpoint"`, `"step"`, `"next"`, `"finish"`)
- `frame`: stable frame object
  - `pc`: IR record index (0-based)
  - `label`: label at `pc` (or `null`)
  - `line`: source line (or `null` if unavailable)
  - `kind`: record kind (`"instr"`, `"dir"`, `"label"`, ...)
  - plus one of: `m` (mnemonic), `d` (directive), `name` (label/dir name) when applicable
- `bps`: array of active breakpoint PCs (numbers)
- `sp`: call stack depth
- `regs`: register snapshot (`HL`, `DE`, `BC`, `IX`, `A`)
- `watches`: watch values (empty unless watches are configured)

Notes:

- Fields under `frame` and the top-level `k/reason/pc/label/sp/bps/regs` are intended to be stable for DAP/tooling.
- `rec` is included as a best-effort mirror of the current IR record and may evolve.

Example (pretty-printed; actual output is one line):

```json
{
  "k": "dbg_stop",
  "reason": "paused",
  "frame": {"pc": 0, "label": null, "line": null, "kind": "dir", "d": "EXTERN"},
  "pc": 0,
  "label": null,
  "sp": 0,
  "bps": [0],
  "regs": {"HL": 0, "DE": 0, "BC": 0, "IX": 0, "A": 0},
  "watches": []
}
```
