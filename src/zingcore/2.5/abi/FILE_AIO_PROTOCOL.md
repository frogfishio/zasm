# file/aio v1 Protocol Specification

**Capability Name:** `file/aio`  
**Version:** 1  
**Kind:** `"file"`  
**Name:** `"aio"`

## Overview

`file/aio@v1` provides completion-based filesystem I/O that fits the single-wait model:

- Operations are submitted as ZCL1 request frames written to the `file/aio` handle.
- Submission is acknowledged immediately with an OK or ERROR response frame.
- Completion is delivered asynchronously as a ZCL1 frame with `op = EV_DONE` and `rid` equal to the original request `rid`.
- The `file/aio` handle is pollable for readability via `sys/loop`.

Sandboxing is identical to `file/fs@v1`:

- If `ZI_FS_ROOT` is set, guest paths must be absolute and are resolved under that root.
- `..` traversal is rejected.
- Symlinks are rejected in any path segment.

## Handle lifecycle

Open:

- `zi_cap_open(kind="file", name="aio", params_len=0)` → returns a stream handle.

Close:

- `zi_end(handle)` closes the queue and releases all host resources.

## ZCL1 framing

Requests and responses are ZCL1 frames (`zi_zcl1.h`).

- Request `rid` is the **job id** chosen by the guest.
- Immediate response uses the same `(op, rid)` as the request.

Completion frames:

- `op = EV_DONE (100)`
- `rid = original request rid`

## Operations

All integers are little-endian.

### OPEN (op=1)

Request payload (20 bytes):

- `u64 path_ptr` (UTF-8 bytes, not NUL-terminated)
- `u32 path_len`
- `u32 oflags` (`ZI_FILE_O_*`)
- `u32 create_mode` (POSIX mode bits; used if `ZI_FILE_O_CREATE` is set)

Immediate response:

- OK with empty payload, or ERROR.

Completion (`EV_DONE`, rid=job id):

OK payload:

- `u16 orig_op = 1`
- `u16 reserved = 0`
- `u32 result = 0`
- `u64 file_id`

### CLOSE (op=2)

Request payload (8 bytes):

- `u64 file_id`

Immediate response:

- OK with empty payload, or ERROR.

Completion (`EV_DONE`):

OK payload:

- `u16 orig_op = 2`
- `u16 reserved = 0`
- `u32 result = 0`

### READ (op=3)

Request payload (24 bytes):

- `u64 file_id`
- `u64 offset`
- `u32 max_len`
- `u32 flags` (must be 0)

Immediate response:

- OK with empty payload, or ERROR.

Completion (`EV_DONE`):

OK payload:

- `u16 orig_op = 3`
- `u16 reserved = 0`
- `u32 result = nbytes`
- `bytes[nbytes]` (inline)

### WRITE (op=4)

Request payload (32 bytes):

- `u64 file_id`
- `u64 offset`
- `u64 src_ptr`
- `u32 src_len`
- `u32 flags` (must be 0)

Immediate response:

- OK with empty payload, or ERROR.

Completion (`EV_DONE`):

OK payload:

- `u16 orig_op = 4`
- `u16 reserved = 0`
- `u32 result = nbytes_written`

## Error handling

- Submission errors (bad payload, out-of-bounds pointers, queue full) are returned as an immediate ERROR response.
- Execution errors (open/read/write failures, unknown `file_id`, sandbox denial) are returned as an `EV_DONE` ERROR frame.

## Notes

- This version returns READ data inline in completion frames. Large reads may be truncated by the runtime.
- Guests should WATCH the queue handle for readability and use `sys/loop.POLL` to await completions without busy-waiting.
