<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Stream ABI v1.0.0 (Normative)

This document defines the required host ABI for ZASM-generated modules.
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
- `_alloc(size: i32) -> i32`
  - Returns pointer to `size` bytes or `-1` on OOM.
- `_free(ptr: i32) -> ()`
  - Frees a pointer (may be a no-op in bump allocators).
- `_ctl(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_cap: i32) -> i32`
  - Control plane (ZCL1 + Hopper). Returns bytes written or `-1`.

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

## I/O Semantics

- `req_read` MAY return fewer bytes than `cap` (short read).
- `req_read` MUST return `0` on EOF and `-1` on error.
- `res_write` MAY return fewer bytes than `len` (short write).
- `res_write` MUST return `-1` on error.
- If a handle is invalid, `req_read/res_write/res_end` MUST return `-1` and MUST NOT crash.

## Control Plane (`_ctl`)

- `_ctl` MUST parse ZCL1 frames and Hopper payloads.
- If the frame is too short to read `op` and `rid`, `_ctl` MUST return `-1`.
- If `payload_len` exceeds available bytes, `_ctl` MUST return `-1`.
- If the response does not fit `resp_cap`, `_ctl` MUST return `-1` and MUST NOT write a partial response.
- On success or error envelopes, `_ctl` MUST return the number of bytes written to `resp_ptr`.
- `timeout_ms = 0` MUST be nonblocking; `timeout_ms > 0` MUST NOT be exceeded.

## Handles

- 0 = stdin (`req_read`)
- 1 = stdout (`res_write/res_end`)
- 2 = log stream (`res_write/res_end`)
- Newly created handles returned by `_ctl` MUST NOT be 0–2.
- Handles MUST be stable within a run and MUST NOT alias active handles.

## Versioning

- Hosts and guests MUST reject unknown or mismatched ABI versions.
- There is no runtime ABI negotiation in v1.

## Versioning and compatibility

- ABI version is **v1.0.0**.
- Backward-compatible additions MAY be introduced in later minor versions.
- Hosts and modules MUST reject unknown/forward ABI versions by default.
