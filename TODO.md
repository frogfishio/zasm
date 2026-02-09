# TO DO

## JIT ROADMAP

- [ ] Track 0 — Artifact + spec baseline (.zasm.bin v2)
  - [x] Define `.zasm.bin` v2 (sectioned container) as the ship-able module format (see `docs/spec/zasm_bin.md`)
  - [x] Archive/retire `.zasm.bin` v1 spec (`docs/spec/zasm_bin_v1.md`)
  - [x] Update `zop --container` to emit `.zasm.bin` v2 (at minimum: header+dir+`CODE`)
  - [x] Teach the parser/runtime to parse + apply optional `DATA` section initializers
  - [x] Teach the `zir | zop --container` path to emit optional `DATA` (keep `CODE.len % 4 == 0`)
  - [x] Update `zxc` to parse `.zasm.bin` v2 by extracting `CODE`
  - [x] Align tool docs to v2 (`docs/tools/zop.md`, `docs/tools/zir.md`, `docs/spec/zxc.md`, `docs/tools/zxc_lib.md`)
  - [ ] Decide v1 support policy (dev-only vs hard reject) and enforce consistently across tools
  - [ ] Decide if we need `zas --emit-bin` (raw opcode bytes) in addition to `.zasm.bin` containers

- [x] Track 1 — Loader + verifier library (zero-trust core)
  - [x] Create a small C library target for parsing `.zasm.bin` v2 (no global state)
  - [x] Implement bounded parsing (header + directory + required `CODE`) with explicit size caps
  - [x] Implement verifier MVP:
    - [x] Opcode decode validity (reserved opcode/fields/regs/ext arity) per `docs/spec/opcode_encoding.md`
    - [x] Control-flow target validation for `JR`/`CALL` (in-bounds, instruction boundary)
    - [x] Module preflight checks (`IMPT` primitive mask agreement, if present)
  - [x] Add structured error codes (no printf-only failures) for embedder integration
  - [x] Add fuzz harness for parser+verifier (crash-free, OOM-safe) and wire into CI target

- [x] Track 2 — Embeddable runtime API (what integrators call)
  - [x] Define a stable C header for the “engine/module/instance” API (create/destroy; load; instantiate; run)
  - [x] Define the policy object (mem limits, step/fuel limit, strictness knobs) and default behavior
  - [x] Define the host interface binding to zingcore/zABI (imports + policing + fail-closed behavior)
  - [x] Determinism: ensure identical module+policy yields deterministic results (no timestamps/env by default)

- [ ] Track 3 — Arm64 JIT backend MVP (fast path)
  - [x] Integrate current translation backend (`libzxc` arm64) behind the runtime API
  - [x] Ensure `zxc` ingests raw opcode bytes as an input format (non-container)
  - [x] Enforce W^X code memory discipline in the runtime (no executable+writable at once)
  - [x] Define a target selection API for translation (arm64 first; x86_64 next)
  - [ ] Contract + measurement baseline (powerful but nimble)
    - [ ] Publish VM/JIT contract doc as normative runtime boundary (`docs/spec/vm_jit_contract.md`)
    - [ ] Publish VM/JIT roadmap with measurable targets (`docs/spec/vm_jit_roadmap.md`)
    - [ ] Define a benchmark corpus + reporting format (startup, throughput, RSS)
    - [ ] Add CI target to run benchmarks and record baselines (tolerant thresholds)
  - [ ] Diagnostics + trap model (structured, stable)
    - [ ] Define stable trap/error codes (decode/verify, OOB, div0, unsupported-op, ABI failure, OOM/fuel)
      - [x] Fuel exhaustion (structured trap)
      - [x] Out-of-bounds memory access (structured trap)
      - [x] Division/mod by zero (structured trap)
      - [x] Unsupported opcode (structured trap)
      - [x] ABI misuse / host-call failure (structured trap)
      - [x] OOM (structured trap)
    - [x] Extend runtime diagnostics to include trap category + best-effort PC/offset
      - [x] Translation failure diagnostics include err/off/opcode/insn
      - [x] Exec trap diagnostics include best-effort trap offset (arm64)
    - [ ] Ensure all failures are fail-closed (no host crashes, no UB)
  - [ ] Implement code cache keyed by (module hash, mem_base, mem_size, policy flags)
    - [ ] Define cache key precisely (target arch + any codegen-affecting policy bits)
    - [ ] Implement engine-owned cache (reuse translated code across instances)
    - [ ] Add max cache size / eviction policy (simple LRU or cap-by-bytes)
  - [ ] Define and implement trap/abort behavior (decode error, OOB, div0, unsupported op)
    - [ ] Plumb trap reporting from translated code back to runtime API (no printf-only failures)
    - [ ] Add negative tests for each trap category (including edge-case pointer/len ABI misuse)
      - [x] Fuel trap smoke coverage
      - [x] OOB trap smoke coverage (JIT-only)
      - [x] DIV0 trap smoke coverage (JIT-only)
      - [x] Translate-fail smoke coverage (diag: translate: ...)
      - [x] Unsupported-op smoke coverage
      - [x] ABI misuse smoke coverage
      - [x] OOM trap smoke coverage
  - [x] Add differential test harness: run the same module under a reference runner and under the JIT; compare rc/stdout/stderr
    - [x] Add a tiny `zrt` CLI runner (executes `.zasm.bin` via `zasm_rt`) for test harness usage
    - [ ] Compare against a reference runner (choose one):
      - [x] WASM path: `zrun` (behavioral oracle for ABI-visible semantics)
      - [ ] Interpreter path: `zem` (only where it matches runtime semantics; do not treat as VM design source)
      - [x] Run over example corpus (hello/cat/upper/alloc/isa_smoke/log/bytes/loop/arithmetic) + selected fixtures (currently: ret_only + hello + cat + upper + alloc + isa_smoke + log + bytes + loop + arithmetic)
    - [ ] Add minimization hook (optional) for shrinking divergent cases

  - [x] Fix arm64 bounds-check trailer (was trapping unconditionally due to `b +1; brk` sequence)

- [ ] Track 4 — Nanoservice hardening (multi-tenant runner ready)
  - [ ] Resource controls: instruction budget/fuel (deterministic accounting) + memory cap enforcement
    - [x] `zrt --mem-size` guest memory cap (with hard ceiling + smoke)
    - [x] `zrt --max-jit-bytes` cap executable JIT output (bounded by hard ceiling + smoke)
  - [ ] DoS defenses: max module size, max code size, max sections/exports/imports; fail fast
    - [x] Hard ceilings on parse/verify caps (file/dir/code/insn words) even if policy says “unlimited”
    - [x] Remove arm64 JIT outbuf heuristic; allocate exact measured output size
  - [ ] Observability: stable lifecycle events + counters (start/stop/trap) routed via telemetry
  - [ ] Abuse cases: hostile pointer/len inputs to zABI calls never crash host; add regression tests

- [ ] VM/JIT competitive baseline (powerful but nimble)
  - [ ] Set and track targets (startup <10ms small modules; overhead <10MB; deterministic-by-default)
  - [ ] Ensure baseline JIT is within a practical factor of Wasmtime/V8 on a small published microbench suite
  - [ ] Keep feature creep contained: new features require a measurable win or a safety guarantee

- [ ] Track 5 — Multi-arch expansion
  - [ ] Add x86_64 JIT backend path (reuse existing `libzxc` x86_64)
  - [ ] Reach opcode parity guided by the conformance suite (Track 6)

- [ ] Track 6 — Tooling + release surface
  - [ ] Provide a one-liner build pipeline for shippable modules:
    - [ ] `zas | zem --opt ... | zir | zop --container > out.zasm.bin`
  - [ ] Publish a compatibility/conformance suite for `.zasm.bin` v2 (verifier + runtime)
    - [ ] Validation + parity suite (x86_64 coverage, cross-backend equivalence, negative-encoding + trap tests) for `--target wasm`, `--target zasm`, and `--target rv64i`:
      - [ ] Encode/decode golden tests for every opcode in `docs/spec/opcode_encoding.md`
      - [ ] Small arithmetic/logic corpus (32/64), loads/stores (sign/zero), div/rem traps
      - [ ] Compare/set + branch behavior tests (EQ/NE/LT/GT + JR)
      - [ ] Pseudo-op expansion determinism tests (LDIR/FILL/DROP)
  - [ ] Define versioning/back-compat story for `.zasm.bin` v2 extensions (new sections/tags)
  - [ ] Package embeddable artifacts (headers + static lib) with a minimal integration guide



## OPTIMIZATION

- [ ] Zem vs Lower: define ownership + contracts
  - [x] Write a short “ownership” doc: target-independent transforms live in `zem`; target-specific codegen + regalloc/peepholes live in each `lower` (see `docs/ownership.md`)
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
  - Moved to `## JIT ROADMAP` above (single source of truth).
- Cortex-M (nice-to-have):
  - Implement `--target cortex-m` per `docs/spec/cortex_m.md`.
  - Define the minimal runtime ABI and linker script for bare-metal output.
  - Add conformance tests for 32-bit ops, bounds traps, and determinism.
