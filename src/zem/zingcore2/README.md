# Dist Pack (Alpha)

The `dist/` folder is a copy/paste “compiler pack” that contains everything you
need to compile and run Zing programs on the host:

- `dist/bin/zingc` — compiler
- `dist/bin/lower` — ZASM JSONL → object file (Mach-O)
- `dist/bin/zem` — optional fast emulator (if present in repo)
- `dist/bin/zing-runner` — multi-guest runner (Sprint 5)
- `dist/lib/libzingcore.a` — minimal runtime
- `dist/lib/libzingcore_debug.a` — debug runtime (includes all caps)
- `dist/stdlib/Zing` — stdlib snapshot used by the compiler pack
- `dist/abi/ABI_V2.md` — host ABI spec (used to update zem/hosts)
- `dist/include/zingcore/*.h` — ABI headers for host tooling
- `dist/zingcore/zingcore` — reference zingcore integrator-pack source snapshot
- `dist/schema/ir/v1` — ZASM IR schema + mnemonics reference
- `dist/schema/diag/v1` — `--diag json` schema

## Build `dist/`

From the repo root:

`make dist`

## Minimal compile/run (host linker)

This repo’s test harness builds like:

`dist/bin/zingc --emit-zasm -o out.zir.jsonl hello.zing`

`dist/bin/lower --input out.zir.jsonl --o out.o`

`cc -o hello out.o dist/lib/libzingcore.a`

`./hello`

## Diagnostics JSON

`dist/bin/zingc --diag json bad.zing 2> diag.json`

Schema: `schema/diag/v1/diagnostics.schema.json` (in the source repo).

## Rebuilding `zem` (notes)

`zem` is a separate tool; when updating it for a new ABI, the key references are:

- ABI spec: `dist/abi/ABI_V2.md`
- ABI headers: `dist/include/zingcore/*.h`
- IR schema + mnemonic reference: `dist/schema/ir/v1/*`
