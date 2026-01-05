<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Stream ABI v1.0.0 (Normative)

This document defines the required host ABI for zASM-generated modules.
All conforming modules and hosts MUST follow this contract.

## Module interface

### Exports

- `lembeh_handle(req: i32, res: i32) -> ()`
  - Required entrypoint.
  - The host MUST call this function to run the module.

### Imports

All imports live under module name `"lembeh"`.

- `req_read(req: i32, ptr: i32, cap: i32) -> i32`
  - Reads up to `cap` bytes into memory at `ptr`.
  - Returns bytes read, `0` on EOF, `-1` on error.
- `res_write(res: i32, ptr: i32, len: i32) -> i32`
  - Writes `len` bytes from memory at `ptr`.
  - Returns bytes written or `-1` on error.
- `res_end(res: i32) -> ()`
  - Ends the response stream.
- `log(topic_ptr: i32, topic_len: i32, msg_ptr: i32, msg_len: i32) -> ()`
  - Optional debug log. Hosts MAY deny this capability.
- `alloc(size: i32) -> i32`
  - Returns pointer to `size` bytes or `-1` on OOM.
- `free(ptr: i32) -> ()`
  - Frees a pointer (may be a no-op in bump allocators).

## Globals

- `__heap_base: i32`
  - Exported by modules.
  - Marks the first free byte after static data.
  - Hosts SHOULD use it to seed allocators.

## Memory policy (v1 baseline)

- Linear memory minimum: **1 page** (64KiB).
- Static data base offset: **8**.
- Static data alignment: **4 bytes**.
- Offsets `0..7` are reserved for future ABI use.
- No dynamic memory growth is performed by the toolchain in v1.

## Capability gating

- Host primitives are explicit and MUST be allowlisted by the build/runtime.
- If a primitive is disallowed, module instantiation MUST fail (fail closed).

## ABI decisions

- `res_write` to a closed/invalid response stream MUST return `-1` (error). Hosts MAY surface this as a trap in strict mode.
- When the stream is closed, hosts SHOULD NOT perform partial writes; returning `-1` indicates no bytes were accepted.
- Hosts MAY additionally emit a diagnostic message in strict/debug mode, but MUST NOT write partial data to the closed stream.

## Versioning and compatibility

- ABI version is **v1.0.0**.
- Backward-compatible additions MAY be introduced in later minor versions.
- Hosts and modules MUST reject unknown/forward ABI versions by default.
