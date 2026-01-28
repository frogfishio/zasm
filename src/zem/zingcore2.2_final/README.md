# Dist Pack (Alpha)

The `dist/` folder is a copy/paste “compiler pack” that contains everything you
need to compile and run Zing programs on the host:

- `dist/bin/zingc` — compiler
- `dist/bin/lower` — ZASM JSONL → object file (Mach-O)
- `dist/bin/zem` — optional fast emulator (if present in repo)
- `dist/bin/zing-runner` — multi-guest runner (Sprint 5)
- `dist/bin/zing-wasm-imports` — list required wasm imports from `.zir.jsonl`
- `dist/lib/libzingcore.a` — minimal runtime
- `dist/lib/libzingcore_debug.a` — debug runtime (includes all caps)
- `dist/lib/libinstrument.a` — Instrument runner runtime (test/instrumentation main)
- `dist/stdlib/*` — full stdlib snapshot (Zing + Types + Algos + others)
- `dist/abi/ABI_V2.md` — host ABI spec (used to update zem/hosts)
- `dist/include/zingcore/*.h` — ABI headers for host tooling
- `dist/zingcore/zingcore` — reference zingcore integrator-pack source snapshot
- `dist/schema/ir/v1.1` — ZASM IR schema + mnemonics reference
- `dist/schema/ir/v1` — legacy schema (back-compat)
- `dist/schema/diag/v1` — `--diag json` schema
- `dist/docs/ZINGC_USER_GUIDE.md` — build/run/test guide (includes Regex + string tools quickstarts)
- `dist/docs/regex.md` — staged regex spec + current implementation status

## Build `dist/`

From the repo root:

`make dist`

## Minimal compile/run (host linker)

This repo’s test harness builds like:

`dist/bin/zingc --emit-zasm -o out.zir.jsonl hello.zing`

`dist/bin/lower --input out.zir.jsonl --o out.o`

`cc -o hello out.o dist/lib/libzingcore.a`

`./hello`

## Host-wired stdin/stdout (native)

Zing treats `stdin`/`stdout` as default stream handles (typically `0` and `1`).
On native builds you can wire them using shell redirection (no code changes):

`./hello < input.bin > output.bin`

## file/fs root mapping (native debug runtime)

The debug runtime supports an optional host mapping for the guest-visible root (`/`):

`ZI_FS_ROOT=/some/host/folder ./hello`

When set, guest paths like `/a/b.txt` are translated to:
`/some/host/folder/a/b.txt` (and `..` traversal is rejected).

## Diagnostics JSON

`dist/bin/zingc --diag json bad.zing 2> diag.json`

Schema: `schema/diag/v1/diagnostics.schema.json` (in the source repo).

## Rebuilding `zem` (notes)

`zem` is a separate tool; when updating it for a new ABI, the key references are:

- ABI spec: `dist/abi/ABI_V2.md`
- ABI headers: `dist/include/zingcore/*.h`
- IR schema + mnemonic reference: `dist/schema/ir/v1.1/*`

## WASM integration (IR → wasm + wasmtime)

Zing’s wasm path treats the guest as a sandboxed wasm module and treats `zingcore` as the **host ABI implementation** (provided by the embedder via imports).

**Contract**
- The Zing guest emits `EXTERN` records for every host call under module `"env"`.
- The wasm lowerer must map those records to wasm imports with the exact same module/name.
- The host (wasmtime) must implement those imports and read/write the guest linear memory using the passed `*_ptr` offsets.
- The compiler no longer leaks runtime internals as imports (e.g. `buffer_pool`, `vec_pool`, `hopper_arena`). All host calls must go through `env.zi_*` (and a small set of `env.res_*` helpers while they remain in the ABI).

**Required imports**
- Implement exactly the set of `EXTERN` records in the program’s `.zir.jsonl` (that is the complete host surface for that build).
- The compiler also emits a small “baseline” set of imports (I/O + memory + telemetry + managed vars), so hosts should expect at least:
  - `env.zi_alloc(i32) -> i32`
  - `env.zi_free(i32) -> i32`
  - `env.zi_read(i32 h, i32 dst_ptr, i32 cap) -> i32`
  - `env.zi_write(i32 h, i32 src_ptr, i32 len) -> i32`
  - `env.zi_end(i32 h) -> i32`
  - `env.zi_telemetry(i32 topic_ptr, i32 topic_len, i32 msg_ptr, i32 msg_len) -> i32`
  - `env.zi_mvar_get_u64(i64 key) -> i64`
  - `env.zi_mvar_set_default_u64(i64 key, i64 value) -> i64`

**Expected exports**
- `memory` (linear memory)
- `main` (program entry)

## zABI stability + future integration notes

This repo treats zABI v2.0 as the “cornerstone” boundary for reuse across projects.
Within v2.0, the expectation is:
- no breaking changes; and
- new functionality only via new `zi_*` functions + feature bits.

For wider integration (WASM/JIT/multi-guest runners), some areas are expected to
evolve over time without breaking v2.0:
- pointer model unification across targets (native/JIT vs WASM offsets)
- expansion of typed async and filesystem entrypoints
- more explicit determinism/runtime-configuration conventions

Canonical spec (normative): `zingcore/ABI_V2.md`.

## WASM import listing helper

To show the required import surface for a particular `.zir.jsonl`:

`dist/bin/zing-wasm-imports out.zir.jsonl`

JSON output:

`dist/bin/zing-wasm-imports --json out.zir.jsonl`

## Instrument runner (tests + metrics)

When you link a `--test` build against `libinstrument.a`, the resulting executable supports:

- `--list-tests`
- `--test <name>` (prints metrics to stderr)
- `--test <name> --jsonl` (prints one JSON object per run to stdout)
- `--test <name> --repeat N` (runs the test N times; stops early on first failure)
- `--test <name> --trace-async` (emits JSONL async events; in `--json/--jsonl` mode this is written to stdout unless `--trace-async-out` is set)
- `--test <name> --trace-async-out <path>` (writes JSONL async events to a file)

Notes:
- Normal (non-test) apps should link only `dist/lib/libzingcore.a`.
- Test binaries should link `dist/lib/libinstrument.a` + `dist/lib/libzingcore.a`.
- `dist/lib/libzingcore.a` includes a weak no-op `zi_instrument_async_event` hook; it becomes active only when `libinstrument.a` is linked.
