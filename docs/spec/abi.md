<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zABI 2.0 (Normative)

This document defines the required host ABI for ZASM-generated modules (**zABI 2.0**).
All conforming modules and hosts MUST follow this contract.

zABI 2.0 replaces the retired legacy “stream ABI” (`req_read/res_write/_ctl`).

## Module interface

### Exports

- `lembeh_handle(req: i32, res: i32) -> ()` (WASM runner entrypoint wrapper)
  - Required for `zrun` today.
  - Must call the module’s internal `$main` and then close `res` via `zi_end(res)`.
  - Note: the export name is legacy; the ABI surface is zABI 2.0.
- `memory` (WASM linear memory)
  - Required for any ABI calls that read/write guest memory.

### Imports

All zABI imports live under module name `"env"`.

Core syscalls (required):

- `zi_abi_version() -> i32`
  - Must return `0x00020000` for zABI 2.0.
- `zi_abi_features() -> i64`
  - Feature bitset (0 for “no optional features”).
- `zi_alloc(size: i32) -> i64`
  - Allocates `size` bytes in guest memory; returns guest pointer/offset or negative error.
- `zi_free(ptr: i64) -> i32`
  - Frees a prior `zi_alloc` result; returns `0` or negative error.
- `zi_read(h: i32, dst_ptr: i64, cap: i32) -> i32`
  - Reads up to `cap` bytes into guest memory at `dst_ptr`; returns bytes read or negative error.
- `zi_write(h: i32, src_ptr: i64, len: i32) -> i32`
  - Writes `len` bytes from guest memory at `src_ptr`; returns bytes written or negative error.
- `zi_end(h: i32) -> i32`
  - Closes a handle/stream; returns `0` or negative error.
- `zi_telemetry(topic_ptr: i32, topic_len: i32, msg_ptr: i32, msg_len: i32) -> i32`
  - Best-effort debug/telemetry channel; returns `0` or negative error.

Notes:

- In wasm32, `*_ptr` values are passed as `i64` but represent a **u32 linear-memory offset**.
- Optional subsystems (caps/fs/async/etc.) extend the `env.zi_*` surface and must be negotiated via `zi_abi_features()`.

## Globals

- `__heap_base: i32`
  - Exported by modules.
  - Marks the first free byte after static data.
  - Hosts may use it to seed allocators for deterministic bump allocation.

## Memory policy (zABI baseline)

- Linear memory minimum: **1 page** (64KiB).
- Static data base offset: **8**.
- Static data alignment: **4 bytes**.
- Offsets `0..7` are reserved for future ABI use.
- Dynamic growth may be performed by the guest via `memory.grow` (subject to host caps).
- All ABI calls that read/write guest memory MUST bounds-check pointers and lengths
  against the guest memory cap.
- On out-of-bounds pointer/length, calls with return values MUST return a negative error.

## Capability gating

- Hosts MUST provide at least the core syscalls above.
- Optional syscalls must be feature-gated and must fail closed when not supported.

## ABI decisions

- `zi_write` to a closed/invalid handle MUST return a negative error. Hosts may trap in strict mode.
- When a handle is closed, hosts SHOULD NOT perform partial writes.

## I/O Semantics

- `zi_read` MAY return fewer bytes than `cap` (short read).
- If `cap == 0`, `zi_read` MUST return `0` and MUST NOT write any bytes.
- `zi_write` MAY return fewer bytes than `len` (short write).
- If `len == 0`, `zi_write` MUST return `0` and MUST NOT write any bytes.
- `zi_end` MUST be idempotent: calling it on a closed handle MUST be a no-op.
- `zi_telemetry` is best-effort; hosts may drop messages but MUST NOT crash on bad pointers.

## Handles

- 0 = stdin (`zi_read`)
- 1 = stdout (`zi_write/zi_end`)
- 2 = stderr/log (`zi_write/zi_end`)
- Handles MUST be stable within a run and MUST NOT alias active handles.

## Versioning

- Hosts and guests MUST reject unknown or mismatched ABI versions.
- Feature negotiation is via `zi_abi_features()` (bitset).

## Compatibility

- zABI version is **2.0** (`0x00020000`).
- Backward-compatible additions MAY be introduced in later minor versions gated by `zi_abi_features()`.
