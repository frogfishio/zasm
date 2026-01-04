# TO DO

- New spec impact (lembeh/CLOAK_INTEGRATOR_GUIDE.md):
  - Align ABI imports to exact surface: `req_read`, `res_write`, `res_end`, `log`, `_alloc`, `_free`, `_ctl` (no extras).
  - Rename/adjust linker WAT emission to use `_alloc/_free/_ctl` names and update allowlist/manifest.
  - Implement `_ctl` handling in zrun host ABI with ZCL1 framing + Hopper payloads (CAPS_LIST required).
  - Add ZCL1 parsing/response validation helpers (magic, version, payload_len, error envelopes).
  - Enforce guest memory model in zrun for non-WASM hosts: flat byte space + bounds checks.
  - Make `_alloc` deterministic and return offsets within guest space; `_free` must not crash on invalid ptr.
  - Reserve handles 0–2 semantics in runtime/tests (stdin/stdout/log) and ensure new handles never collide.
  - Update `docs/spec/abi.md` to match the new canonical guide (or add a v1.0.0 Cloak section pointing to it).
  - Update `docs/tools/zrun.md` to document `_ctl`, handle semantics, and determinism guarantees.
  - Update `docs/integrator_pack.md` + C cloak to reflect `_ctl`, `_alloc/_free`, and guest memory model.
  - Add conformance tests for `_ctl`:
    - CAPS_LIST with n=0 success response
    - unknown op returns `t_ctl_unknown_op` envelope
    - malformed frame returns `-1` and writes nothing
    - response too large for resp_cap returns `-1`
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

## IMPORTANT

- Finalize the normative C integration cloak (memory model + alloc/free hooks + invoke contract) and update docs/spec accordingly.
- Add a reference host harness in the cloak pack (pure C embedding).
- Add cross-compilation guidance and build scripts for the C cloak.
