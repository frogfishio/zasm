# zABI v2.5 hardening plan (from code reality)

This is a forward plan derived from the current exported ABI in `zingcore2.2_final`.
It intentionally does not treat the historical v2.0 spec as normative.

## v2.5 goals

- **Portable** across native, WASM, and JIT.
- **Unbreakable**: a single canonical header + conformance runner makes drift impossible.
- **Explicit** about pointer model, endianness, integer widths, and object layouts.

## Phase 0 — Freeze reality (v2.2 legacy)

- Treat `libzingcore.a` / `libzingcore_debug.a` exports as the current contract.
- Maintain a generated/snapshotted export list and signatures.
  - Snapshot: `abi/ABI_REALITY_SNAPSHOT.md`

## Phase 1 — Define v2.5 ABI primitives

1. **Pointer type**
   - Define `zi_ptr_t` as a fixed-width integer.
   - Recommended: `uint64_t` offset into guest linear memory.
   - Note: on **wasm32**, linear memory is indexed with 32-bit offsets; passing pointers as `i64` still works if the guest **zero-extends** (`i64.extend_i32_u`) and the host rejects values > `0xFFFFFFFF`. On **wasm64** (memory64), the full `u64` range may be usable.

2. **Endianness**
   - Define all packed data structures as **little-endian** (already a pattern in cap/fs packing).

3. **Error model**
   - Keep negative `zi_err_t` and make all invalid pointers/lengths return a specific error consistently.

4. **No host-size types**
   - Forbid `size_t`, `long`, `uintptr_t`, and `void*` in the ABI surface.

5. **No host pointers in guest-visible layouts**
   - Replace `sizeof(void*)`/`sizeof(uintptr_t)` dependent headers with fixed-width fields.

## Phase 2 — Implement v2.5 in the runtime

- Add a new canonical header for v2.5 (and make the runtime compile against it).
- Provide translation helpers for native:
  - `(zi_ptr_t ptr,len) -> uint8_t* host_ptr` with bounds checks.
- For wasm/jit embeddings:
  - enforce the same pointer/length validation rules in the embedder.

## Phase 3 — Conformance runner (gates the ABI)

- Add a small test executable that validates:
  - exported symbol set
  - function signatures (compile-time)
  - pointer validation behavior (runtime)
  - handle lifecycle invariants
  - deterministic ordering of enumerations (caps/fs)

## Phase 4 — Migration strategy

- Keep v2.2 legacy entrypoints available during transition.
- Introduce v2.5 entrypoints with clear naming/version return.
- Allow Zing to catch up gradually while hosts can implement v2.5 immediately.
