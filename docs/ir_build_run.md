# IR Build and Run Cheatsheet

## Toolchain build
- Full toolchain: `make build` (zas, zld, zir, zop, zxc, zlnt, zrun).
- Individual tools: `make zas zld zir zop zxc zlnt zrun`.
- Cloak (native host/JIT, separate): `make -C __cloak__`.

## Assemble and link (IR → WAT)
1) Assemble IR JSONL: `bin/zas examples/hello.asm > /tmp/hello.jsonl`
2) Lint schema (optional but recommended): `bin/zld --conform /tmp/hello.jsonl`
3) Emit WAT: `bin/zld /tmp/hello.jsonl > /tmp/hello.wat`

## Opcode container path (IR → opcodes → container)
1) IR → opcode JSONL: `bin/zir /tmp/hello.jsonl > /tmp/hello.op.jsonl`
2) Opcode JSONL → container bytes: `bin/zop /tmp/hello.op.jsonl > /tmp/hello.zasm.bin`

## Execution options
- Wasm path: `bin/zrun /tmp/hello.wat`
- Native translation (opcode JIT to host ISA): `bin/zxc /tmp/hello.zasm.bin > /tmp/hello.native.bin`
- Native runner (if built): `build/native_runner /tmp/hello.zasm.bin`
- Cloak JIT host (separate build): `__cloak__/bin/<platform>/zcloak-jit /tmp/hello.zasm.bin`
- Cloak shared-object host (for lembeh_handle .so/.dylib): `__cloak__/bin/<platform>/zcloak guest.dylib`

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
