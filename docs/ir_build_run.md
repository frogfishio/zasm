# IR Build and Run Cheatsheet

## Toolchain build
- Full toolchain: `make build` (zas, zld, zir, zop, zxc, zlnt, zrun).
- Individual tools: `make zas zld zir zop zxc zlnt zrun`.
- Cloak (native host/JIT, separate): `make -C __cloak__`.

## Assemble and link (IR → WAT)
1) Assemble IR JSONL: `bin/zas examples/hello.asm > /tmp/hello.jsonl`
2) Static analysis (recommended): `bin/zlnt --tool /tmp/hello.jsonl`
3) Lint schema (optional but recommended): `bin/zld --conform /tmp/hello.jsonl`
4) Emit WAT: `bin/zld /tmp/hello.jsonl > /tmp/hello.wat`

Stream form (useful for quick iteration):

`cat examples/hello.asm | bin/zas | bin/zlnt | bin/zld > /tmp/hello.wat`

## Opcode container path (IR → opcodes → container)
1) IR → opcode JSONL: `bin/zir /tmp/hello.jsonl > /tmp/hello.op.jsonl`
2) Opcode JSONL → container bytes: `bin/zop /tmp/hello.op.jsonl > /tmp/hello.zasm.bin`

## Execution options
- Wasm path: `bin/zrun /tmp/hello.wat`
- IR emulator/debugger (JSONL interpreter): `bin/zem /tmp/hello.jsonl`
- Native translation (opcode JIT to host ISA): `bin/zxc /tmp/hello.zasm.bin > /tmp/hello.native.bin`
- Native runner (if built): `build/native_runner /tmp/hello.zasm.bin`
- Cloak JIT host (separate build): `__cloak__/bin/<platform>/zcloak-jit /tmp/hello.zasm.bin`
- Cloak shared-object host (legacy `.so/.dylib` entrypoint): `__cloak__/bin/<platform>/zcloak guest.dylib`

### zem debugging + events

See also: `docs/tools/zem.md`.

Common flags:

- `--trace` emits per-instruction JSONL events to stderr.
- `--trace-mem` adds `mem_read`/`mem_write` JSONL events to stderr.
- `--debug` starts an interactive CLI debugger (starts paused).
- `--break-pc N` breaks when `pc == N` (where `pc` is the IR record index).
- `--break-label L` breaks at label `L`.
- `--debug-script PATH` runs debugger commands from a file/stdin (no prompt; exit on EOF).
- `--shake` runs the program multiple times with deterministic perturbations (useful for surfacing uninitialized reads / layout sensitivity).

Machine-readable debugger stops:

- `--debug-events` emits JSONL `dbg_stop` events to stderr on each debugger stop.
- `--debug-events-only` like `--debug-events`, but suppresses human-oriented debugger output.

#### `dbg_stop` schema (JSONL)

`zem` writes one JSON object per line to stderr. For stop events:

- `k`: always `"dbg_stop"`
- `reason`: stop reason string (e.g. `"paused"`, `"breakpoint"`, `"step"`, `"next"`, `"finish"`)
- `frame`: stable frame object for debugger/DAP integration
	- `pc`: IR record index (0-based)
	- `label`: label at `pc` (or `null`)
	- `line`: source line (or `null` if unavailable)
	- `kind`: record kind (`"instr"`, `"dir"`, `"label"`, ...)
	- plus one of: `m` (mnemonic), `d` (directive), `name` (label/dir name) when applicable
- `bps`: array of active breakpoint PCs (numbers)
- `regs`: register snapshot (`HL`, `DE`, `BC`, `IX`, `A`)
- `watches`: array of watch values (empty unless watches are configured)

Notes:

- Fields under `frame` and the top-level `k/reason/pc/label/sp/bps/regs` are intended to be stable.
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

## Common test targets
- All tests: `make test-all`
- ABI suites: `make test-abi-alloc test-abi-stream test-abi-log test-abi-entry test-abi-imports test-abi-ctl` (or `make test-abi` if defined)
- IR conformance: `make test-conform-zld`
- Opcode golden: `make test-opcode-golden`
- Cloak tests (separate): in `__cloak__`, run `make` then its scripts/targets as needed.

## Quick smoke sequence
```
make build
bin/zas examples/hello.asm > /tmp/hello.jsonl
bin/zld /tmp/hello.jsonl > /tmp/hello.wat
bin/zrun /tmp/hello.wat
bin/zir /tmp/hello.jsonl > /tmp/hello.op.jsonl
bin/zop /tmp/hello.op.jsonl > /tmp/hello.zasm.bin
__cloak__/bin/<platform>/zcloak-jit /tmp/hello.zasm.bin
```

## Notes
- Outputs live under `bin/<platform>/` (e.g., `bin/macos-arm64`).
- For cloak binaries, use the ones under `__cloak__/bin/<platform>/` after building there.
- Temporary paths (`/tmp/...`) are just examples; pick any writable location.
