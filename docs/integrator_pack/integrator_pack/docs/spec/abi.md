<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zABI 2.0 (Normative)

This document defines the required host ABI for ZASM-generated modules (**zABI 2.0**).
All conforming modules and hosts MUST follow this contract.

zABI 2.0 replaces the retired legacy “stream ABI” (`req_read/res_write`).

## Module interface

### Exports

- `lembeh_handle(req: i32, res: i32) -> ()` (WASM runner entrypoint wrapper)
  - Required for `zrun` today.
  - Must call the module’s internal `$main` and then close `res` via `zi_end(res)`.
  - Note: the export name is legacy; the ABI surface is zABI 2.0.
- `memory` (WASM linear memory)
  - Required for ABI calls that read/write guest memory.

### Imports

All zABI imports live under module name `"env"`.

Core syscalls (required):

- `zi_abi_version() -> i32` (must return `0x00020000`)
- `zi_abi_features() -> i64`
- `zi_alloc(size: i32) -> i64`
- `zi_free(ptr: i64) -> i32`
- `zi_read(h: i32, dst_ptr: i64, cap: i32) -> i32`
- `zi_write(h: i32, src_ptr: i64, len: i32) -> i32`
- `zi_end(h: i32) -> i32`
- `zi_telemetry(topic_ptr: i32, topic_len: i32, msg_ptr: i32, msg_len: i32) -> i32`

## Globals

- `__heap_base: i32`
  - Exported by modules.
  - Marks the first free byte after static data.
  - Hosts SHOULD use it to seed allocators.

## Memory policy (zABI baseline)

- Linear memory minimum: **1 page** (64KiB).
- Static data base offset: **8**.
- Static data alignment: **4 bytes**.
- Offsets `0..7` are reserved for future ABI use.
- Dynamic growth may be performed by the guest via `memory.grow` (subject to host caps).

## Capability gating

- Hosts MUST provide at least the core syscalls above.
- Optional syscalls must be feature-gated and fail closed when not supported.

## Compatibility

- zABI version is **2.0** (`0x00020000`).
- Backward-compatible additions MAY be introduced in later minor versions gated by `zi_abi_features()`.
