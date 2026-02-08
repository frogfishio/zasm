<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# VM/JIT Roadmap (Powerful but Nimble)

This roadmap targets a small, fast runtime that can compete on practical
benchmarks without growing into a heavyweight platform. It emphasizes
predictable performance, clear safety guarantees, and a tight embedder API.

## Guiding Principles

- Ship a lean baseline JIT that is reliable and fast on common workloads.
- Make determinism and safety defaults, with explicit opt-in for variability.
- Avoid multi-tier complexity until a strong baseline exists.
- Prefer measurable gains over speculative features.

## Success Metrics (initial targets)

- Startup: module load + verify + instantiate under 10ms for small modules.
- Baseline speed: within 2-4x of optimized V8 on representative microbenchmarks.
- Memory: runtime overhead under 10MB for small programs.
- Determinism: identical input and policy produce identical outputs.
- Trap fidelity: 100% of negative tests yield correct error codes.

## Phase 0: Contract and Measurement (now)

Deliverables:
- Formalize the VM/JIT contract (done in vm_jit_contract.md).
- Define error codes and diagnostics structure.
- Define benchmark corpus and reporting format.
- Add a minimal differential harness to compare VM/JIT vs reference runner.

Exit criteria:
- Deterministic runs with stable diagnostics.
- Benchmarks run in CI with recorded baselines.

## Phase 1: Baseline VM (safe + correct)

Deliverables:
- Verified module ingest with bounded parsing.
- Strict policy enforcement (mem size, strict ABI checks).
- Trap model: decode error, OOB, div0, unsupported op, ABI failure.
- Minimal host surface wired to zABI 2.5.
- Code cache keyed by module hash and policy flags.

Exit criteria:
- Full negative-test coverage for traps and ABI misuse.
- Stable exit status + diagnostics for all failures.

## Phase 2: Nimble JIT (fast path)

Deliverables:
- Arm64 JIT baseline with W^X discipline.
- Tight calling convention and register usage.
- Block-local register allocator to reduce spills.
- Fast memory access helpers and bounds checks.

Exit criteria:
- 2-4x of V8 performance on a targeted microbench suite.
- No regression in determinism or safety tests.

## Phase 3: Practical Power Features

Deliverables:
- Optional fuel/step limits for multi-tenant safety.
- Lightweight telemetry counters (start/stop/trap).
- Fast startup optimizations (lazy init, pooled allocators).
- Basic A/B differential tests on example corpus.

Exit criteria:
- A stable and documented embedder API for production use.
- Demonstrable speed and stability on a public corpus.

## Phase 4: Expansion Without Bloat

Deliverables:
- x86_64 JIT path with shared lower-level infrastructure.
- Opcode parity guided by conformance suite.
- Optional tiering only if needed and justified by benchmarks.

Exit criteria:
- Cross-arch determinism where possible.
- Consistent diagnostics across architectures.

## What We Intentionally Skip

- Multi-tier optimizing pipeline until baseline is strong.
- Large host libraries or embedded ecosystem tooling.
- Debugger complexity; analysis remains in separate tools.

## Roadmap Notes

- This roadmap is intentionally conservative on features and aggressive on
  correctness, determinism, and measurable speed.
- Any new feature must include a measurable win or a safety guarantee.
