# TO DO

- [ ] Zem vs Lower: define ownership + contracts
  - [ ] Write a short “ownership” doc: target-independent transforms live in `zem`; target-specific codegen + regalloc/peepholes live in each `lower`
  - [ ] Define the interchange contract(s): optimized IR JSONL, optional hint JSONL(s), versioning rules, and backward compatibility expectations
  - [ ] Decide stable profile/hint keys (prefer `ir_id` or explicit site ids over record-index `pc` when IR can be rewritten)
  - [ ] Decide what must be verified by hash (module identity) vs what can be best-effort

- [ ] Zem: target-independent optimization pipeline (for zasm JSONL)
  - [x] Add `zem --opt-out <path>` to emit optimized JSONL (semantic-preserving) (`--opt dead-cf`)
  - [x] Build basic blocks + CFG from labels/terminators (initial use: `--opt cfg-simplify` reachability + trivial JR cleanup)
  - [ ] Reachability + CFG simplification
    - [x] Unreachable removal (whole-program)
    - [x] Jump threading through one-instr trampolines
    - [x] Label alias cleanup (multiple labels bound to same instruction)
    - [x] Fold unconditional `JR <lbl>` to `RET` when target is a `RET`
    - [ ] Block merge (true empty-block / fallthrough merge beyond label cleanup)
  - [ ] Block-local redundant load elimination
    - [x] Remove consecutive identical loads from sym-based mem slots (`--opt local-ldst`)
    - [ ] Extend beyond adjacent loads (requires reg clobber + alias barriers)
  - [ ] Block-local redundant store elimination
    - [x] Dead-store elimination for sym-based mem slots overwritten within a block (`--opt local-ldst`)
    - [ ] Extend to broader alias rules / non-adjacent cases
  - [ ] Copy propagation / temp forwarding (within block first)
  - [ ] Constant folding + simple instcombine on common zasm idioms
  - [ ] Dead code elimination for pure computations (requires def/use; start block-local)
  - [ ] Dead store elimination for slots proven never read (conservative alias rules)
  - [x] Add “do-no-harm” validation mode: run original vs optimized in `zem` and compare stdout/stderr/rc (`--opt-validate`)

- [ ] Zem: reusable profiling + facts emission
  - [ ] Extend beyond `--pgo-len-out`: add optional hotness (block/edge counts) output
  - [ ] Emit conservative “facts” usable by all backends (e.g. slot not address-taken, constant-at-site)
  - [ ] Define and document hint schemas (JSONL `k:` records) and version them
  - [ ] Add fuzz/robust-ingest tests for new hint JSONL shapes

- [ ] Lower (arm64): consume hints + improve backend quality
  - [ ] Add `--debug-pgo-len` (or similar) to report: sites loaded, bulk ops seen, rewired count, specialized count + rejection reasons
  - [ ] Make `--pgo-len-profile` loader robust to whitespace/ordering (stop relying on exact substrings like `"k":"zem_pgo_len_rec"`)
  - [ ] Use hotness hints for layout (hot/cold ordering) and conservative “keep in regs” decisions
  - [ ] Add more AArch64 addressing-mode folding peepholes (addr calc + load/store)
  - [ ] Add block-local register allocation for temps (small pool), spill around calls, shrink reload/store churn
  - [ ] Add backend peepholes for compare/branch canonicalization (`cbz/cbnz` where legal)
  - [ ] Decide bulk-mem policy knobs: inline vs helper thresholds per target, guided by hints

- [ ] Tests + size tracking (close the LLVM gap with guardrails)
  - [ ] Add a small loop-heavy corpus and record baseline code sizes for `lower` and LLVM (so improvements are measurable)
  - [ ] Add differential tests: `zem`-optimized JSONL must match `zem` original output
  - [ ] Add “no regression” size checks for key fixtures (tolerant thresholds, per-target)

- New spec impact (legacy cloak integrator guide):
  - Rename/adjust linker WAT emission to use `_alloc/_free/_ctl` names and update allowlist/manifest.
  - Update `docs/tools/zrun.md` to document `_ctl`, handle semantics, and determinism guarantees.
  - Add ABI tests for handle rules: opaque handles, reserved 0–2, nonblocking timeout_ms=0.
  - Add manifest tests for `_ctl` primitive discovery.

- Add `zas --format` and define canonical style rules in `POETICS.md` (formatter output must match the style guide).
- Build a VS Code extension with syntax highlighting, linting, and formatting using tool mode + JSON diagnostics.
- Document the JSON diagnostics schema and include examples for editor tooling integration.
- Add tests for tool mode: multi-file input, `-o` output parity with stream mode, and `--json` diagnostics shape.
- Expand the conformance suite to cover all mnemonic/directive operand shapes from `schema/ir/v1/mnemonics.html`.
- Add JSONL shape validator tests against the normative schema (instr/dir/label shapes, ops arrays, loc.line).
- Add register validation tests for invalid registers and operand positions (including mem base and CALL/JR targets).
- Add memory operand edge-case tests (nested parentheses, non-ID bases).
- Add numeric literal boundary tests (hex/decimal, min/max, overflow) across numeric operands.
- Add semantic control-flow tests (JR conditions, invalid conditions, missing/forward/backward labels).
- Add ABI contract tests for FILL/LDIR (register usage, len=0 behavior, overlap cases).
- Add a dedicated ABI test suite (separate target/dir) to lock current ABI behavior before planned ABI changes.
- ABI tests (spec-needed):
  - `_alloc` zero-size behavior (return 0 vs current heap pointer).
  - `_alloc` alignment guarantee (4/8/16) and whether it is part of the ABI.
  - `_free` NULL/0 handling (reject vs no-op).
  - alloc/free reuse/fragmentation guarantees (if any).

- ABI tests (implementation-needed):
  - `_alloc` returns non-zero for positive sizes.
  - `_free` rejects non-allocated pointers and leaves allocator state consistent.
  - `_out` uses HL/DE slice boundaries correctly (no overflow) in strict mode.
  - `_in` respects DE length and DE=0 edge cases with short read/EOF behavior.
  - `_log` register requirements + preservation under `zlnt` and runtime.
- Add data directive tests for DB/DW/STR/RESB/EQU/PUBLIC/EXTERN (argument counts/types, label binding, zero/negative sizes).
- Add linker tests for duplicate labels, undefined symbols, export/import conflicts, and name collisions across multi-file assembly.
- Add WAT emission golden tests for each mnemonic (including trap/strict paths).
- Add end-to-end run tests per feature class (assemble → link → run).
- Expand fuzzing coverage for lexer/parser and JSONL ingestion with invariant checks.

- Audit: determinism, auditability, security (project-wide; prioritize codegen determinism):
  - Define audit scope + threat model with primary focus on deterministic code generation; document assumptions.
  - Inventory all non-deterministic inputs (time, RNG, I/O, env, filesystem, network) and pin/ban them.
  - Add codegen determinism tests (same source/config -> byte-identical output across runs).
  - Add cross-machine codegen determinism tests (same source/config -> identical output on macOS/Linux).
  - Verify deterministic ordering for `_ctl`, `req_read`, `res_write`, and handle allocation; add tests.
  - Review alloc/free and memory bounds checks for OOB, overflow, and integer wrap; add tests.
  - Audit error handling for closed streams, invalid handles, and invalid pointers; ensure no crashes.
  - Add reproducible build checklist (compiler flags, timestamps, build paths, version embedding).
  - Add structured logging guidance for audit trails (what events, format, redaction policy).
  - Add security review for input parsers (asm, JSONL, WAT) with fuzzing + sanitizer runs.
  - Add dependency audit + version pinning policy (vendored libs, licenses, CVE checks).
  - Define and publish a conformance/security regression test suite for CI gating.

## IMPORTANT

- Add cross-compilation guidance and build scripts for the C cloak.


# FUTURE TASKS
- Build `zxc` (ZASM Cross Compiler) + embeddable library:
  - Implement `zxc` ingestion of raw opcode bytes (core reader/decoder).
  - Add a `zas --target` mode to emit JSONL in the opcode stream format (e.g., `--target opcodes`).
  - Add a `zas --emit-bin` mode to emit raw opcode bytes for `zxc`.
  - Implement opcode groups iteratively (to full conformance) for x86_64 beyond Group A:
    - mul/div/rem, shifts/rotates, immediate loads, loads/stores, compare/branch, control flow, macro-ops.
  - Add full Group J parity tests for x86_64 once memory ops exist (OOB, div0, invalid encodings).
  - Define output targets (macOS arm64, Linux x86_64) and a target selection API.
  - Implement opcode-to-native translation pipeline (opcode-by-opcode, ahead-of-time on load).
  - Add an embeddable C API (`libzxc`) for translation + execution within a custom cloak.
  - Create a CLI `zxc` wrapper that uses `libzxc` for standalone translation.
  - Define how translated code binds to cloak ABI (req_read/res_write/etc) without WASM.
  - Add verification tests comparing behavior with the interpreter/VM (or reference runner).
  - Add test fixtures for platform parity and deterministic outputs.
  - Document binary format, API usage, and supported targets; add a roadmap for new targets.
  - Add backend validation suites for `--target wasm`, `--target zasm`, and `--target rv64i`:
    - Encode/decode golden tests for every opcode in `docs/spec/opcode_encoding.md`.
    - Small backend corpus for arithmetic/logic (32/64), loads/stores (sign/zero), div/rem traps.
    - Compare/set + branch behavior tests (EQ/NE/LT/GT + JR).
    - Cross-backend equivalence tests (same program, same output).
    - Pseudo-op expansion determinism tests (LDIR/FILL/DROP).
- Cortex-M (nice-to-have):
  - Implement `--target cortex-m` per `docs/spec/cortex_m.md`.
  - Define the minimal runtime ABI and linker script for bare-metal output.
  - Add conformance tests for 32-bit ops, bounds traps, and determinism.
