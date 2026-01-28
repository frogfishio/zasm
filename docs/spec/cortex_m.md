<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Cortex-M Backend Support (Future, Draft Spec)

This document defines a **future** target profile for generating Cortex-M
microcontroller binaries from ZASM opcodes. It is a **nice-to-have** roadmap
specification and is not implemented yet. Profile name: **zASM32**.

## 1. Scope

- Target family: ARM Cortex-M (M0/M0+/M3/M4/M7/M33).
- Output: bare-metal ARM Thumb/Thumb-2 machine code.
- No OS syscalls. Runtime is a tiny host shim with explicit entrypoint.

## 2. Target Profile

The Cortex-M backend is a new ZASM target profile:

- `--target cortex-m` (future)
- 32-bit registers and pointers.
- Flat memory model with 32-bit address space.
- Little-endian.

### 2.1 Width Semantics

- ZASM 64-bit ops MUST be rejected in Cortex-M profile.
- 32-bit ops map to native 32-bit arithmetic.
- Loads/stores are 8/16/32-bit only (no 64-bit memory ops).

## 3. Calling Convention

Minimal ABI to call a single entrypoint:

- Entry function: `main(req_handle, res_handle)`.
- Arguments passed in r0/r1; return value in r0 (if used).
- Caller-saved: r0-r3, r12; callee-saved: r4-r11.
- Stack pointer: r13; link register: r14; PC: r15.

## 4. Memory Model and Safety

- Guest memory is a single flat region `[mem_base, mem_base + mem_size)`.
- Bounds checks are enforced at translation time for all loads/stores.
- On OOB, control jumps to a trap handler that returns a structured error.

## 5. Instruction Mapping (High Level)

ZASM opcodes map to Thumb/Thumb-2 sequences:

- `ADD/SUB/AND/OR/XOR` -> `adds/subs/ands/orrs/eors`
- `MUL` -> `muls` (M3+); for M0, use library helper.
- `DIVS/DIVU/REMS/REMU` -> library helper (no hardware div on M0/M3).
- `SLA/SRA/SRL` -> `lsl/asr/lsr`
- `EQ/NE/LT*/GT*` -> `cmp` + conditional set (sequence).
- `JR` -> `b`/`b<cond>` with relative offset.
- `LD*`/`ST*` -> `ldr/ldrb/ldrh` and `str/strb/strh`.

### 5.1 Unsupported Ops

Until explicitly mapped, the backend MUST reject:

- 64-bit ops and 64-bit loads/stores.
- `ROL/ROR` unless a sequence is defined.
- Macro-ops unless lowered in the frontend.

## 6. Runtime Integration

The runtime is a tiny C shim that:

- Provides `_alloc/_free` as no-ops or a fixed arena (optional).
- Provides `req_read/res_write/res_end/log` as stubs or platform hooks.
- Exposes a single entry function for host integration.

No `_ctl` is required for the minimal profile. If `_ctl` is desired, it
must be a small fixed-capability stub with static responses.

## 7. Tooling and Build

- A new backend in `zxc` emits raw Thumb/Thumb-2 bytes.
- A minimal linker script is required for bare-metal output.
- Output format: raw `.bin` plus optional `.elf` via external toolchain.

## 8. Conformance Tests (Future)

- Encode/decode parity tests for 32-bit ops only.
- Load/store bounds OOB traps.
- Deterministic codegen across runs.
- Micro test programs for arithmetic, branching, and memory ops.

## 9. Open Questions

- Decide the minimal runtime ABI: which imports are required?
- How to provide deterministic time/IO on MCUs?
- Whether to support M0 (Thumb-1 only) or require M3+ (Thumb-2).
