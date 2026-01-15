# Determinism and Specimen Integration

**Status:** NORMATIVE  
**Version:** 1.0.0

---

## 1. Core Determinism Laws

### 1.1 The Fundamental Law

For identical:
- Guest code (WASM bytes)
- Capability set and their deterministic behavior
- Input bytes (for all readable handles)
- Chunk schedule (read segmentation)
- Specimen replay transcript

The observable output events **MUST** be identical:
- Bytes written to handles
- Log events (in Specimen mode)
- `_ctl` responses (in Specimen mode)

### 1.2 No Ambient Nondeterminism

The host **MUST NOT** leak ambient nondeterminism into deterministic runs unless explicitly exposed as a capability.

**Examples that MUST NOT affect deterministic runs:**
- System clock
- OS environment variables
- Filesystem outside the presented view
- DNS / network ordering
- Thread scheduling
- Process ID / random addresses

If the host exposes a nondeterministic capability (e.g., live network), it **MUST** do so behind `_ctl`, and tests **MUST** record/replay it.

---

## 2. Determinism by Construction

### 2.1 Deterministic Operations

These operations are deterministic by design:

| Operation | Guarantee |
|-----------|-----------|
| `CAPS_LIST` | Stable ordering by (kind, name) |
| `CAPS_DESCRIBE` | Stable schema for same cap |
| `CRYPTO_HASH` | Same input → same output |
| `CRYPTO_HMAC` | Same key + input → same output |
| `CRYPTO_RANDOM` | Same seed + n → same output |
| `FILE_LIST` | Stable ordering by (display, id) |

### 2.2 Operations Requiring Transcript

These operations may have nondeterministic real-world behavior but **MUST** be recorded for replay:

| Operation | Real Behavior | Specimen Behavior |
|-----------|---------------|-------------------|
| `FILE_OPEN` | OS filesystem | Recorded fixture |
| `NET_CONNECT` | Network I/O | Recorded transcript |
| `CLOCK_NOW` | Wall clock | Recorded timestamp |
| Stream reads | Variable chunks | Recorded chunks |

---

## 3. Specimen Architecture

### 3.1 What is Specimen?

Specimen is the test rig that makes the entire system debuggable and replayable.

**Modes:**

| Mode | Description |
|------|-------------|
| **Record** | Capture all interactions to transcript |
| **Replay** | Reproduce exact behavior from transcript |
| **Stub** | Use deterministic policy without transcript |

### 3.2 Core Approach

Specimen replaces the host's `_ctl` and stream operations with transcript-driven fakes.

**Recording:**
1. Every `_ctl` request/response is captured
2. Every stream read/write is captured
3. Handles are assigned stable IDs

**Replay:**
1. `_ctl` request bytes matched exactly
2. Recorded response bytes returned exactly
3. Stream operations return recorded data

---

## 4. Transcript Format

### 4.1 Record Types

All records are JSONL (one JSON object per line).

**Control Plane Records:**

```jsonl
{"k":"ctl_req","i":0,"b64":"<base64 ZCL1 request frame>"}
{"k":"ctl_res","i":0,"b64":"<base64 ZCL1 response frame>"}
```

**Stream Read Records:**

```jsonl
{"k":"read","i":1,"h":0,"cap":1024,"ret":5,"b64":"SGVsbG8="}
```

| Field | Meaning |
|-------|---------|
| `k` | Record kind |
| `i` | Monotonic index |
| `h` | Handle number |
| `cap` | Requested capacity |
| `ret` | Actual return value |
| `b64` | Base64 bytes read |

**Stream Write Records:**

```jsonl
{"k":"write","i":2,"h":1,"ret":6,"b64":"SGVsbG8K"}
```

**Stream End Records:**

```jsonl
{"k":"end","i":3,"h":1}
```

**Log Records:**

```jsonl
{"k":"log","i":4,"topic_b64":"aW5mbw==","msg_b64":"c3RhcnRlZA=="}
```

**Handle Mapping (Optional, for debugging):**

```jsonl
{"k":"handle","h":7,"kind":"file","name":"view","note":"opened report.csv"}
```

### 4.2 Handle Allocation

Specimen allocates handles deterministically:
- Reserved: 0, 1, 2
- First created handle: 3
- Increment by 1 per new handle

If the real host returns different handle numbers, Specimen remaps internally. The transcript stores Specimen handles (stable).

---

## 5. Replay Rules

### 5.1 Control Plane Replay

When `_ctl(req)` is called during replay:

1. Find next `ctl_req` record by index
2. Compare request bytes exactly
3. If mismatch: **FAIL** with `#t_specimen_ctl_mismatch`
4. Return recorded response bytes from `ctl_res` exactly

### 5.2 Stream Replay

When `req_read(h, ptr, cap)` is called:

1. Find next `read` record for handle `h`
2. Verify `cap` matches (or warn if different)
3. Copy recorded bytes to `ptr`
4. Return recorded `ret` value

When `res_write(h, ptr, len)` is called:

1. Find next `write` record for handle `h`
2. Compare written bytes to recorded bytes
3. If mismatch: **FAIL** with `#t_specimen_write_mismatch`
4. Return recorded `ret` value

### 5.3 Mismatch Handling

On any mismatch, Specimen **MUST**:
1. Report the first divergence point
2. Provide hexdump context (before/after)
3. Fail the test with a clear trace code

---

## 6. Chunk Schedules

### 6.1 What are Chunk Schedules?

A chunk schedule determines how `req_read` returns data in chunks. Same total bytes, different chunk boundaries.

### 6.2 Standard Schedules

| Schedule | Description |
|----------|-------------|
| `all` | Return all bytes in one read |
| `byte` | Return one byte at a time |
| `pow2` | Return in power-of-two chunks |
| `crlf` | Break at CR/LF boundaries |
| `random` | Seeded random chunk sizes |

### 6.3 Fuzzing with Schedules

Specimen **MUST** support testing with multiple chunk schedules:

1. Run test with `all` schedule
2. Run test with `byte` schedule
3. Run test with `crlf` schedule
4. etc.

All runs **MUST** produce identical output bytes (chunk boundaries may differ, output content must not).

### 6.4 Schedule Application

Initially, chunk schedules target stdin (`h=0`). Extensions:
- Apply to all readable streams
- Key by `(handle, mode)` for per-handle scheduling

---

## 7. Specimen Laws

### 7.1 Control Law

> Given a Specimen artifact, `_ctl` **MUST** return identical bytes for identical request bytes, and any stream handles obtained via `_ctl` **MUST** produce identical read/write event sequences under replay.

### 7.2 Chunk Law

> For any chunk schedule, the total bytes read from a handle **MUST** be identical. Only the number of `req_read` calls and their individual return counts may vary.

### 7.3 Output Law

> For identical inputs and transcript, all `res_write` calls **MUST** produce identical byte sequences.

---

## 8. Timeout Handling in Specimen

### 8.1 Recording

When recording, `_ctl` calls with timeouts produce actual results (success or `#t_ctl_timeout`). The outcome is recorded.

### 8.2 Replay

During replay:
- Specimen does NOT use wall-clock
- It returns the recorded response exactly
- If recorded response was timeout, replay returns timeout

### 8.3 Time as Capability

If `CLOCK_NOW` or tick streams are used:
- Record the values/events
- Replay returns recorded values exactly

---

## 9. Stub Mode

### 9.1 Policy-Based Stubs

For unit tests without full transcripts:

```
Specimen Stub Configuration:
- CAPS_LIST returns: [file/view, crypto/hash]
- FILE_LIST returns: fixed fixture list
- FILE_OPEN returns: handle backed by fixture bytes
- CRYPTO_HASH: actual implementation (deterministic)
```

### 9.2 Stub Rules

Stubs **MUST**:
- Expose only declared capabilities
- Return stable, sorted lists
- Use deterministic handle allocation
- Back streams with fixture bytes

---

## 10. Practical Workflow

### 10.1 Development

```
1. Write Zing program
2. Run with real cloak (file/net access)
3. Observe behavior
```

### 10.2 Testing

```
1. Record: Run program, capture transcript
2. Verify: Replay transcript, check identical output
3. Fuzz: Replay with different chunk schedules
4. Shrink: Minimize failing input
```

### 10.3 Debugging

```
1. Load failing transcript
2. Step through in debugger
3. See exact _ctl calls and responses
4. Find divergence point
```

---

## 11. What This Design Achieves

- **No `_file`, `_net`, `_db` imports** — everything goes through `_ctl`
- **Capability-driven, discoverable, testable** — tooling can introspect
- **Specimen replays the whole world** — `_ctl` is just another transcripted call
- **Determinism is testable** — not assumed, verified
- **Shrinking works** — minimize stdin and/or handle streams
