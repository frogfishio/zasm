<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Accelerator Profile (Draft, Future)

This document defines a **future** GPU/accelerator profile for Frogfish.
It is a parked specification for later implementation and is not active yet.
Profile name: **zASMA** (accelerator).
The goal is a single accelerator IR/profile that can be lowered to:

- CUDA (PTX)
- Vulkan (SPIR-V)
- Metal (MSL or Metal IR)

## 1. Scope

- Separate from ZASM CPU profile.
- Kernel-only execution model (no OS, no syscalls).
- Deterministic execution for identical inputs.
- Host-controlled launching and memory management.

## 2. Conceptual Model

```
[ Host program (ZASM CPU profile) ]
      |
      +--> Launch kernel(s) (Accelerator profile)
```

The host program orchestrates data movement and kernel launches. The
accelerator profile describes kernels only.

## 3. Execution Model

The accelerator profile is SIMT-style:

- Threads are grouped into blocks (or workgroups).
- Each kernel launch specifies a grid size and block size.
- Each thread has:
  - `tid.x/y/z` (thread index within block)
  - `bid.x/y/z` (block index within grid)
  - `gdim.x/y/z` (grid dimensions)
  - `bdim.x/y/z` (block dimensions)

### 3.1 Barriers and Synchronization

- `barrier` synchronizes threads within a block/workgroup only.
- No global barrier is provided.

### 3.2 Determinism

- All kernel-visible nondeterminism is forbidden by default.
- Atomic ops are allowed but must be explicit.
- Floating-point behavior should be deterministic where possible; if not,
  the profile must define rounding and exceptional behavior.

## 4. Memory Spaces

The profile defines explicit address spaces:

- `global`  : device memory visible to all threads.
- `shared`  : block/workgroup-local memory.
- `local`   : per-thread local memory (spills, private arrays).
- `const`   : read-only constant memory (optional).

All pointers are tagged by address space. Mixing address spaces is illegal.

## 5. Kernel ABI

Each kernel has:

- A name (string).
- A signature with explicit address spaces.
- A fixed parameter block layout (ABI-defined).

Arguments:

- Scalars (i32, u32, i64, u64, f32, f64)
- Pointers in a declared address space
- Fixed-size vectors (e.g., v4f32) as needed

Variable-length or heap allocation is not allowed inside kernels.

## 6. Instruction Classes (High Level)

The accelerator profile includes:

- Integer ALU ops (add/sub/and/or/xor, shifts).
- Integer multiply and divide (div may be lowered to helpers).
- Floating-point ops (f32/f64 basic arithmetic).
- Compare + select (predicated execution).
- Memory load/store in explicit address spaces.
- Barrier.
- Atomic ops on `global` and `shared` (optional extension).
- Control flow: structured branches and early return.

## 7. Host Interface (Required)

The host runtime provides:

- `accel_load(kernel_blob)` -> kernel handle
- `accel_alloc(bytes, space)` -> device pointer
- `accel_copy_in/out` for buffers
- `accel_launch(handle, grid, block, args)`
- `accel_free(ptr)`

The host is responsible for:

- Validating kernel ABI and argument layout.
- Ensuring deterministic ordering of launches.

## 8. Backend Mapping (Summary)

### 8.1 CUDA (PTX)

- Kernel maps to PTX entry.
- Address spaces map to PTX global/shared/local/const.
- `barrier` -> `bar.sync`.
- Atomics -> `atom.*`.

### 8.2 Vulkan (SPIR-V)

- Kernel maps to SPIR-V compute shader entry.
- Address spaces map to StorageBuffer (global) and Workgroup (shared).
- `barrier` -> `OpControlBarrier`.
- Atomics -> `OpAtomic*`.

### 8.3 Metal

- Kernel maps to `kernel` function.
- Address spaces map to `device`, `threadgroup`, `thread`, `constant`.
- `barrier` -> `threadgroup_barrier`.

## 9. Constraints

- No recursion.
- No dynamic memory allocation inside kernels.
- No I/O inside kernels.
- No system calls.
- Kernel code must be free of undefined behavior.

## 10. Versioning

This profile is versioned independently of ZASM.
Any changes require a new versioned spec.

## 11. Conformance Tests (Future)

- Kernel ABI layout tests (args alignment/packing).
- Memory space correctness tests (illegal space errors).
- Barrier correctness tests (within workgroup only).
- Determinism tests (identical inputs -> identical outputs).
- Backend equivalence tests (CUDA vs Vulkan vs Metal).

## 12. Open Questions

- Do we define a single textual assembly for kernels, or only a binary form?
- How do we express vector types and memory layout for struct parameters?
- Do we allow limited FP nondeterminism, or enforce strict IEEE rules?
