# Conformance Tests and Trace Codes

**Status:** NORMATIVE  
**Version:** 1.0.0

---

## 1. Conformance Test Requirements

A host is conforming **only** if it passes ALL of these tests.

### 1.1 Stream Semantics Tests

#### Test: EOF Stickiness

After first `req_read(...) = 0`, all subsequent reads **MUST** return `0`.

```
Setup: Stream with 5 bytes "hello"
Call: req_read(h, ptr, 10) → 5, "hello"
Call: req_read(h, ptr, 10) → 0 (EOF)
Call: req_read(h, ptr, 10) → 0 (must still be EOF)
Call: req_read(h, ptr, 10) → 0 (forever EOF)
PASS if all post-EOF reads return 0
```

#### Test: Closed Write Failure

After `res_end(h)`, `res_write(h, ...)` **MUST** return `-1` deterministically.

```
Setup: Writable stream handle h
Call: res_write(h, "hello", 5) → 5
Call: res_end(h)
Call: res_write(h, "world", 5) → -1
Call: res_write(h, "x", 1) → -1
PASS if all post-end writes return -1
```

#### Test: res_end Idempotence

Repeated `res_end(h)` calls **MUST** be safe.

```
Call: res_end(h)
Call: res_end(h)
Call: res_end(h)
PASS if no crash/trap
```

### 1.2 Memory Safety Tests

#### Test: Bounds Safety - Read

Invalid `ptr`/`len` causes `-1`, not crash.

```
Call: req_read(0, -1, 10) → -1
Call: req_read(0, 0, -1) → -1
Call: req_read(0, memory_size+1, 10) → -1
PASS if all return -1 without crash
```

#### Test: Bounds Safety - Write

Invalid `ptr`/`len` causes `-1`, not crash.

```
Call: res_write(1, -1, 10) → -1
Call: res_write(1, 0, -1) → -1
Call: res_write(1, memory_size+1, 10) → -1
PASS if all return -1 without crash
```

#### Test: Bounds Safety - Log

Invalid pointers cause silent drop, not crash.

```
Call: log(-1, 5, valid_ptr, 5) → (no crash)
Call: log(valid_ptr, 5, -1, 5) → (no crash)
PASS if no crash, messages dropped
```

### 1.3 Determinism Tests

#### Test: Chunk Schedule Determinism

With fixed schedule, stdout bytes identical across runs.

```
Input: "hello world"
Schedule: byte-at-a-time
Run 1: Output = "..."
Run 2: Output = "..."
PASS if Run1.output == Run2.output
```

#### Test: Allocation Determinism

Same allocation sequence yields same pointers.

```
Run 1: _alloc(100)=ptr1, _alloc(50)=ptr2
Run 2: _alloc(100)=ptr1', _alloc(50)=ptr2'
PASS if ptr1==ptr1' and ptr2==ptr2'
```

### 1.4 Control Plane Tests

#### Test: Frame Strictness

Unknown op/version returns FAIL with proper Err frame.

```
Send: ZCL1 frame with op=255
Expect: FAIL response with trace=#t_ctl_unknown_op

Send: ZCL1 frame with v=99
Expect: FAIL response with trace=#t_ctl_bad_version
```

#### Test: No Partial Frames

Too-small response buffer yields `-1`, not partial frame.

```
Call: _ctl(valid_req, req_len, resp_ptr, 1) → -1
PASS if returns -1 (not partial frame written)
```

#### Test: CAPS_LIST Empty Contract

Zero capabilities returns success with `n=0`.

```
Call: CAPS_LIST
Expect: ok=1, n=0
PASS
```

#### Test: Timeout Nonblocking

`timeout_ms=0` must not block.

```
Call: _ctl(blocking_op, timeout_ms=0)
Measure: < 10ms elapsed
Expect: Either success OR #t_ctl_timeout
PASS if no actual blocking
```

### 1.5 Specimen Tests

#### Test: Replay Bit-for-Bit

A recorded specimen replays identically.

```
Record: Run program, capture transcript
Replay: Run with transcript
PASS if output bytes identical
```

---

## 2. Standard Trace Codes

### 2.1 Control Plane Errors (Required)

These trace codes **MUST** exist and remain stable.

| Code | Meaning | When |
|------|---------|------|
| `#t_ctl_bad_frame` | Malformed ZCL1 frame | Invalid magic, truncated |
| `#t_ctl_bad_version` | Unsupported protocol version | Unknown `v` field |
| `#t_ctl_unknown_op` | Unknown operation code | Unrecognized `op` |
| `#t_ctl_timeout` | Operation timed out | Timeout expired |
| `#t_ctl_overflow` | Response exceeds buffer | Response > `resp_cap` |
| `#t_ctl_bad_params` | Invalid operation params | Malformed payload |

### 2.2 Capability Errors (Required)

| Code | Meaning | When |
|------|---------|------|
| `#t_cap_missing` | Capability not available | CAPS_OPEN for missing cap |
| `#t_cap_denied` | Capability access denied | Permission refused |

### 2.3 File Errors (If file capability provided)

| Code | Meaning | When |
|------|---------|------|
| `#t_file_not_found` | File does not exist | FILE_OPEN fails |
| `#t_file_not_readable` | Read access denied | Can't read file |
| `#t_file_not_writable` | Write access denied | Can't write file |
| `#t_file_denied` | General file access denied | Permission error |

### 2.4 Network Errors (If net capability provided)

| Code | Meaning | When |
|------|---------|------|
| `#t_net_denied` | Network access denied | Connection refused by policy |
| `#t_net_unreachable` | Host unreachable | Can't reach destination |

### 2.5 Crypto Errors (If crypto capability provided)

| Code | Meaning | When |
|------|---------|------|
| `#t_crypto_bad_alg` | Unknown algorithm | Unsupported hash/cipher |

### 2.6 Specimen Errors

| Code | Meaning | When |
|------|---------|------|
| `#t_specimen_ctl_mismatch` | CTL request doesn't match transcript | Replay divergence |
| `#t_specimen_write_mismatch` | Write bytes don't match transcript | Output divergence |
| `#t_specimen_eof` | Unexpected end of transcript | More calls than recorded |

---

## 3. Trace Code Format

### 3.1 Naming Convention

Trace codes follow this pattern:

```
#t_<domain>_<specific>
```

| Domain | Meaning |
|--------|---------|
| `ctl` | Control plane errors |
| `cap` | Capability system errors |
| `file` | File capability errors |
| `net` | Network capability errors |
| `crypto` | Crypto capability errors |
| `specimen` | Test harness errors |
| `user` | User-defined errors |

### 3.2 Character Set

Trace symbols use: `[a-z0-9_]`

- Lowercase letters only
- Digits allowed
- Underscores for separation
- No spaces, hyphens, or special characters

### 3.3 Examples

```
#t_ctl_timeout
#t_cap_missing
#t_file_not_found
#t_user_auth_failed
#t_user_dbinsert_002
```

---

## 4. Test Implementation Guide

### 4.1 Test Harness Requirements

A conformance test harness **MUST**:

1. Provide controlled stdin input
2. Capture stdout output
3. Capture log events
4. Record/replay `_ctl` calls
5. Support chunk schedule variations
6. Compare byte-for-byte outputs

### 4.2 Test Categories

| Category | Purpose | Count |
|----------|---------|-------|
| Stream | Verify req_read/res_write/res_end | 5 |
| Memory | Verify _alloc/_free/bounds | 4 |
| Control | Verify _ctl basics | 5 |
| Determinism | Verify reproducibility | 3 |
| Capability | Verify cap negotiation | 3 |
| **Total** | | **20+** |

### 4.3 Test Vectors

Each test should include:

```yaml
name: eof_stickiness
category: stream
setup:
  stdin: "hello"
steps:
  - call: req_read(0, ptr, 10)
    expect_ret: 5
    expect_data: "hello"
  - call: req_read(0, ptr, 10)
    expect_ret: 0
  - call: req_read(0, ptr, 10)
    expect_ret: 0
pass_condition: all_expectations_met
```

---

## 5. Conformance Levels

### 5.1 Level 1: Minimal (Required)

- All 7 imports present
- Basic stream semantics correct
- `_ctl` parses ZCL1 frames
- `CAPS_LIST` works (even if `n=0`)
- Deterministic for fixed inputs

### 5.2 Level 2: Standard (Recommended)

- Level 1 + all conformance tests pass
- Specimen record/replay works
- Multiple chunk schedules produce identical output
- At least `CAPS_DESCRIBE` implemented

### 5.3 Level 3: Full (Complete)

- Level 2 + file, net, crypto capabilities
- Full Specimen integration with shrinking
- All standard trace codes implemented
- Schema discovery via `CAPS_DESCRIBE`

---

## 6. Non-Conformance Examples

### 6.1 Fails: Adding Extra Imports

```
// NON-CONFORMING: Host provides _file_read import
extern i32 _file_read(i32 fd, i32 ptr, i32 len);
```

**Why:** ABI must not grow. File access goes through `_ctl`.

### 6.2 Fails: Nondeterministic Output

```
// NON-CONFORMING: Different runs produce different output
Run 1: "result: 42"
Run 2: "result: 17"
```

**Why:** Same input must produce same output.

### 6.3 Fails: Blocking Without Timeout

```
// NON-CONFORMING: _ctl blocks forever on network connect
_ctl(NET_CONNECT, timeout_ms=0) → hangs
```

**Why:** `timeout_ms=0` means nonblocking. Must return immediately.

### 6.4 Fails: res_end Terminates Execution

```
// NON-CONFORMING: res_end(1) causes program to exit
res_end(1);
// ... more code that never runs ...
```

**Why:** `res_end` only ends the stream. `main` return terminates execution.
