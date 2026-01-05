# TO DO

- New spec impact (lembeh/CLOAK_INTEGRATOR_GUIDE.md):
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
  - Define a two-stage input: JSONL opcode stream for tooling/authoring, raw opcode bytes for the compiler.
  - Add a `zas --target` mode to emit JSONL in the opcode stream format (e.g., `--target opcodes`).
  - Add a `zas --emit-bin` mode to emit raw opcode bytes for `zxc`.
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
