<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# VM/JIT Contract (Draft)

This document defines a clean-room runtime contract for the zasm VM/JIT.
It is intentionally minimal and does not inherit behavior from zem except
where explicitly stated. The VM/JIT is a precision execution environment
focused on safety, determinism, and performance.

## 1. Goals

- Provide a stable execution contract for .zasm.bin v2 modules.
- Enforce strict safety checks with clear, structured error reporting.
- Enable high-performance execution with W^X memory discipline.
- Remain deterministic by default (no time/env unless opted in).

## 2. Non-goals

- Debugger UX, source-level tracing, or heavy analysis tooling.
- Compatibility with zem features beyond ABI compatibility.
- Policy hidden in global state or implicit side effects.

## 3. Inputs and Outputs

Inputs:
- Module bytes (.zasm.bin v2), validated by the verifier.
- Policy object (memory limits, target, strictness, determinism flags).
- Optional host hooks for zABI syscalls.
- Optional stdin bytes (for deterministic replay).

Outputs:
- Exit status and structured diagnostics.
- Captured stdout/stderr (if caller chooses to capture).

## 4. Determinism Contract

- Default policy must be deterministic.
- No time, env, or nondeterministic I/O unless explicitly enabled.
- Identical module + policy + stdin must yield identical outputs.

## 5. Safety Contract

- All guest memory accesses must be bounds-checked.
- All host ABI calls must validate pointer and length parameters.
- Any violation produces a trap with a structured error code.
- Host hooks must fail closed on unsupported features.

## 6. ABI Surface

- The VM/JIT uses zABI 2.5 as defined in docs/spec/abi.md.
- The VM/JIT may provide a lightweight host implementation, but only the
  ABI surface is normative. The implementation is intentionally separate
  from zem.

## 7. Memory Model

- Memory is a single linear region with an explicit base and size.
- The VM/JIT must honor policy.mem_base and policy.mem_size.
- Allocator behavior is policy-governed and must be deterministic.
- Memory growth is either disabled or strictly capped by policy.

## 8. Trap and Error Model

The VM/JIT must report failure through structured errors, not by
undefined behavior or host crashes.

Required error categories:
- Decode/verify error (invalid encoding, unknown opcode)
- OOB memory access (guest read/write)
- Divide by zero
- Unsupported operation or target
- Host ABI failure (negative zABI return)
- Resource exhaustion (OOM, fuel, code cache limits)

Errors must carry:
- A stable error code
- A short reason string
- Optional location data (pc offset) when available

## 9. Policy Contract

Policy fields (minimum):
- target: host, arm64, x86_64
- mem_base, mem_size
- allow_time, allow_env (default false)
- strict (tighten ABI checks)
- fuel or step limit (optional but reserved)
- cache policy flags (for code cache keys)

The policy object is the only source of runtime behavior.

## 10. Code Cache Contract

The JIT code cache key must be stable and include:
- Module hash
- Target architecture
- mem_base and mem_size
- Any policy flags that affect code generation or semantics

Cache entries must be invalidated if any key component changes.

## 11. Telemetry Contract

Telemetry is optional and best-effort. If enabled:
- It must be stable and low-volume.
- It must not leak nondeterminism into execution.
- It must never crash the runtime on bad pointers.

## 12. Conformance and Testing

- Differential tests compare VM/JIT output to a reference interpreter,
  but the VM/JIT must remain architecturally independent.
- Minimal smoke suite should cover: hello/cat/upper/alloc/isa_smoke/log.
- Negative tests should cover: invalid encodings, OOB, div0, and ABI misuse.

## 13. Compatibility Notes

- zem is not a reference runtime; it is a tooling interpreter.
- Shared code is acceptable only where it does not import zem behavior.
- ABI compatibility is mandatory; execution model is separate.
