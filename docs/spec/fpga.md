<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# FPGA Profile (Draft, Future)

This document defines a **future** FPGA profile for Frogfish. It is a parked
specification for later implementation and is not active yet. Profile name:
**zASMF** (FPGA). The goal is a
single hardware-oriented IR/profile that can be lowered to:

- HLS C/C++ (Vivado HLS, Intel HLS)
- RTL (Verilog/VHDL) via a backend or HLS toolchain

## 1. Scope

- Separate from ZASM CPU and accelerator profiles.
- Hardware description model: pipelines, streams, and explicit memory ports.
- Deterministic behavior for identical inputs.
- Host-driven orchestration (load, feed, collect).

### 1.1 Target FPGA Families (Simulatable First)

To keep this profile practical, the initial scope is **simulator-first** and
limited to families with reliable open-source simulation flows:

- Lattice iCE40
- Lattice ECP5

Additional families can be added later once verified with stable simulation
toolchains.

## 2. Conceptual Model

```
[ Host program (ZASM CPU profile) ]
      |
      +--> Configure + run FPGA kernels (FPGA profile)
```

The host configures an FPGA kernel, streams data in, and consumes outputs.

## 3. Execution Model

The FPGA profile is dataflow/pipeline oriented:

- Kernels are **static pipelines** with explicit initiation interval (II).
- Parallelism is expressed through unrolling and concurrent stages.
- Control flow is limited to bounded loops and static branches.

### 3.1 Determinism

- All behavior is cycle-deterministic for identical inputs.
- No nondeterministic primitives are allowed.

## 4. Memory and I/O

Memory is explicit and ported:

- `mem` : external memory interface (AXI-like).
- `local` : on-chip scratch (BRAM/URAM).
- `stream` : FIFO-like streaming channels.

All loads/stores must declare memory space and port usage.

## 5. Kernel ABI

Each kernel defines:

- A name and a fixed interface.
- Input/output streams and/or memory buffers.
- Optional control registers (scalars).

No dynamic allocation is allowed.

## 6. Instruction Classes (High Level)

The FPGA profile includes:

- Integer ALU ops (add/sub/and/or/xor, shifts).
- Fixed-point ops (optional).
- Compare/select.
- Load/store with explicit memory ports.
- Stream read/write.
- Bounded loops with static trip counts.
- Pipeline directives (unroll, pipeline, II).

## 7. Host Interface (Required)

The host runtime provides:

- `fpga_load(bitstream_or_kernel)` -> kernel handle
- `fpga_bind_mem(handle, slot, ptr, bytes)`
- `fpga_bind_stream(handle, slot, reader/writer)`
- `fpga_launch(handle)`
- `fpga_wait(handle)`

## 8. Backend Mapping (Summary)

### 8.1 HLS C/C++

- Kernel maps to top-level HLS function.
- Streams map to `hls::stream` or vendor FIFOs.
- Memory maps to AXI master ports.
- Pipeline/unroll directives map to HLS pragmas.

### 8.2 RTL

- Kernel maps to RTL module with explicit ports.
- Streams map to valid/ready handshake.
- Memory maps to AXI or native BRAM ports.

## 9. Constraints

- No recursion.
- No unbounded loops.
- No dynamic memory allocation.
- No system calls or I/O outside declared ports.

## 10. Versioning

This profile is versioned independently of ZASM.
Any changes require a new versioned spec.

## 11. Conformance Tests (Future)

- Interface layout tests (streams/memory ports).
- Pipeline determinism tests (II behavior).
- Backend equivalence tests (HLS vs RTL).
- Golden functional tests for arithmetic and streaming kernels.

## 12. Open Questions

- Do we require a single portable stream/memory ABI?
- How strict should pipeline directives be (must vs may)?
- Which fixed-point formats are required?
