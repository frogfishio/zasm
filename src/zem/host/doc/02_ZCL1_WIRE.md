# ZCL1 Wire Protocol Specification

**Status:** NORMATIVE  
**Version:** 1.0.0  
**Protocol:** ZCL1 (Zing Control Link v1)

---

## 1. Overview

ZCL1 is the binary wire protocol for `_ctl` messages between guest and host.

**Design principles:**
- All multi-byte integers are **little-endian**
- All lengths are explicit (no null-termination assumed)
- Frames are self-describing (magic + version + length)
- Responses echo request identifiers for correlation
- All payloads are **flat Hopper bytes** (no pointers, no JSON, no implicit padding)
- No CRC in v1: `_ctl` is a guest↔host in-process boundary; integrity is enforced by bounds checks and deterministic parsing.

---

## 1.1 Hopper Byte Layout Rules (Normative)

ZCL1 payloads are **raw Hopper records**. Every field has a **fixed byte size** or an explicit **length prefix**. There are **no native ints** or host pointers on the wire.

### 1.1.1 Scalar Fields

| Name | Size | Meaning | Encoding |
|------|------|---------|----------|
| H1 | 1 | Hopper byte | Unsigned byte |
| H2 | 2 | Hopper word | Little-endian unsigned |
| H4 | 4 | Hopper dword | Little-endian unsigned |
| H8 | 8 | Hopper qword | Little-endian unsigned |

**Law:** All multi-byte scalars MUST be encoded little-endian.

### 1.1.2 Variable Fields

| Name | Layout | Meaning |
|------|--------|---------|
| HSTR | `H4 len` + `len bytes` | UTF-8 string (no null terminator) |
| HBYTES | `H4 len` + `len bytes` | Raw bytes (binary payload) |

**Law:** `len` MUST NOT exceed the remaining payload bytes. Zero-length is valid.

### 1.1.3 Layout Discipline

- **Packed:** No implicit alignment or padding. If padding is required, it MUST be explicit and documented.
- **Offsets:** Offsets are absolute within the payload start (byte 0 of the payload).
- **Bounds:** Any length prefix that would exceed the payload bounds is invalid.

---

## 2. Request Frame

Bytes written by guest at `req_ptr`, length `req_len`:

```
Offset  Size  Field         Description
──────  ────  ────────────  ───────────────────────────────
0       4     magic         "ZCL1" (0x5A 0x43 0x4C 0x31)
4       2     v             Protocol version (1)
6       2     op            Operation code
8       4     rid           Request ID (caller-chosen, monotonic recommended)
12      4     timeout_ms    Timeout in milliseconds (0 = nonblocking)
16      4     flags         Reserved (0)
20      4     payload_len   Length of payload in bytes
24      var   payload       Operation-specific request payload
```

**Total size:** 24 + payload_len bytes

**Law:** `payload_len` MUST equal the remaining bytes in the frame.
**Law:** `flags` MUST be 0 in v1. Non-zero flags are a `#t_ctl_bad_frame` error.
**Law:** Hosts MAY enforce a maximum `payload_len` and MUST return `#t_ctl_overflow` if exceeded.
**Law:** If the frame is too short to read `op` and `rid`, host MUST return `-1` (fatal).

---

## 3. Response Frame

Bytes written by host at `resp_ptr`:

```
Offset  Size  Field         Description
──────  ────  ────────────  ───────────────────────────────
0       4     magic         "ZCL1" (0x5A 0x43 0x4C 0x31)
4       2     v             Protocol version (1)
6       2     op            Echoed from request
8       4     rid           Echoed from request
12      4     flags         Reserved (0)
16      4     payload_len   Length of payload in bytes
20      var   payload       Response payload (begins with status header)
```

**Total size:** 20 + payload_len bytes
**Law:** `flags` MUST be 0 in v1. Senders MUST set 0; receivers MUST ignore non-zero.
**Law:** Response `op` and `rid` MUST echo the request.

---

## 4. Response Payload Structure

Every response payload begins with a universal status header:

```
Offset  Size  Field     Description
──────  ────  ────────  ───────────────────────────────
0       1     ok        1 = success, 0 = fail
1       1     rsv8      Reserved (0)
2       2     rsv16     Reserved (0)
```

**Law:** If `ok == 0`, the payload MUST contain only the error envelope defined below.  
**Law:** If `ok == 1`, the payload MUST contain only the operation-specific success payload.
**Law:** `payload_len` MUST be at least 4 (status header size).
**Law:** On success, `op_payload_len = payload_len - 4`. On failure, the error envelope MUST consume the remaining bytes exactly.

### 4.1 On Failure (ok == 0)

Following the status header:

```
Offset  Size  Field     Description
──────  ────  ────────  ───────────────────────────────
4       var   trace     sym: greppable error identifier
var     var   msg       str: human-readable message
var     var   cause     bytes: optional opaque cause data
```

No further payload follows on failure.
**Law:** `trace` and `msg` MUST be present (non-empty). `cause` MAY be empty.
**Law:** The sum of `trace`, `msg`, and `cause` lengths MUST equal `payload_len - 4`.

### 4.2 On Success (ok == 1)

Following the status header:

```
Offset  Size  Field           Description
──────  ────  ────────────────  ───────────────────────────────
4       var   op_payload      Operation-specific success payload
```

---

## 5. Primitive Type Encodings

### 5.1 str (UTF-8 string)

```
Offset  Size  Field   Description
──────  ────  ──────  ───────────────────────────────
0       4     len     Length in bytes
4       len   bytes   UTF-8 encoded string data
```

### 5.2 sym (trace symbol)

```
Offset  Size  Field   Description
──────  ────  ──────  ───────────────────────────────
0       4     len     Length in bytes
4       len   bytes   ASCII [a-z0-9_] only (e.g., "t_ctl_timeout")
```

**Rule:** Trace symbols MUST be stable identifiers, not human prose.
**Rule:** `sym` is encoded exactly like `HSTR`, with an ASCII-only constraint.

### 5.3 bytes (raw byte array)

```
Offset  Size  Field   Description
──────  ────  ──────  ───────────────────────────────
0       4     len     Length in bytes
4       len   bytes   Raw binary data
```

### 5.4 Integers

| Type | Size | Encoding |
|------|------|----------|
| u8 | 1 | Unsigned byte |
| u16 | 2 | Little-endian unsigned |
| u32 | 4 | Little-endian unsigned |
| i32 | 4 | Little-endian signed (two's complement) |

---

## 6. Error Payload (ZCL1)

When `_ctl` returns with `ok=0`, the payload after the status header follows this format:

```
Offset  Size  Field             Description
──────  ────  ────────────────  ───────────────────────────────
0       var   trace             sym: greppable identifier
var     var   msg               str: human-readable message
var     var   cause             bytes: optional (may be len=0)
```

**Law:** No extra error magic is permitted in ZCL1 v1. The status header `ok=0` is the only error discriminator.

---

## 7. Versioning and Forward Compatibility

### 7.1 Version Handling

- Host MUST reject unknown magic with `#t_ctl_bad_frame`
- Host MUST reject unsupported `v` with `#t_ctl_bad_version`
- Host MUST reject unknown `op` with `#t_ctl_unknown_op`
- Host MUST reject malformed payload lengths with `#t_ctl_bad_frame`

### 7.2 Reserved Fields

All fields marked "Reserved (0)" MUST be set to 0 by senders and MUST be ignored by receivers (allowing future extension).

---

## 8. Timeout Semantics

### 8.1 Rules

1. Any operation that may block MUST respect `timeout_ms`
2. `timeout_ms = 0` means **nonblocking**: succeed immediately or return `#t_ctl_timeout`
3. Timeout failure is **recoverable** and returns a standard failure envelope

### 8.2 Timeout Failure Response

```
ok = 0
trace = "t_ctl_timeout"
msg = "operation timed out"
cause = <optional stage info>
```

---

## 9. Frame Size Limits

### 9.1 Request Limits

The guest is responsible for ensuring the request fits in its allocated buffer.
Hosts MAY enforce an implementation-defined `MAX_REQ_BYTES` (>= 24). If `payload_len` exceeds this limit, host MUST return `#t_ctl_overflow`.

### 9.2 Response Limits

- If the response doesn't fit in `resp_cap`, host MUST return `-1`
- No partial frames are ever written
- Host MUST NOT truncate responses

### 9.3 Fatal vs Recoverable Failures

- **Recoverable** errors MUST be encoded in ZCL1 error payloads (`ok = 0`).
- **Fatal** errors (e.g., invalid pointers, `resp_cap` too small, or malformed frame that cannot yield `op`/`rid`) MUST return `-1`.

---

## 10. Example Frame

### 10.1 CAPS_LIST Request

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
01 00          ; op = 1 (CAPS_LIST)
01 00 00 00    ; rid = 1
00 00 00 00    ; timeout_ms = 0 (nonblocking)
00 00 00 00    ; flags = 0
00 00 00 00    ; payload_len = 0
               ; (no payload)
```

Total: 24 bytes

### 10.2 CAPS_LIST Response (Success, 0 caps)

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
01 00          ; op = 1 (echoed)
01 00 00 00    ; rid = 1 (echoed)
00 00 00 00    ; flags = 0
08 00 00 00    ; payload_len = 8
               ; --- payload ---
01             ; ok = 1
00             ; rsv8 = 0
00 00          ; rsv16 = 0
00 00 00 00    ; n = 0 (zero capabilities)
```

Total: 28 bytes

### 10.3 Unknown Op Response (Failure)

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
FF 00          ; op = 255 (echoed, unknown)
01 00 00 00    ; rid = 1 (echoed)
00 00 00 00    ; flags = 0
XX XX XX XX    ; payload_len
               ; --- payload ---
00             ; ok = 0
00             ; rsv8 = 0
00 00          ; rsv16 = 0
               ; trace: sym "t_ctl_unknown_op"
10 00 00 00    ; len = 16
74 5F 63 74 6C 5F 75 6E 6B 6E 6F 77 6E 5F 6F 70
               ; msg: str "unknown operation"
11 00 00 00    ; len = 17
75 6E 6B 6E 6F 77 6E 20 6F 70 65 72 61 74 69 6F 6E
               ; cause: bytes (empty)
00 00 00 00    ; len = 0
```
