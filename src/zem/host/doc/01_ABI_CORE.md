# ABI Core Specification

**Status:** NORMATIVE  
**Version:** 1.0.0

---

## 1. Terminology

| Term | Definition |
|------|------------|
| **Guest** | The Zing guest code linked against the host (native or WASM) |
| **Host / Cloak** | The runtime embedding/linking the guest and providing imports |
| **Handle** | An `i32` identifying a host-backed stream endpoint |
| **Capability** | A named resource or service exposed via `_ctl` discovery/opening |
| **Determinism** | For identical inputs + schedule + capability set, outputs are identical |

---

## 2. The Complete ABI Surface

A conforming host **MUST** provide exactly these imports. No more, no less.

### 2.1 Data Plane (Streams)

```c
// Read up to `cap` bytes from stream `handle` into memory at `ptr`
// Returns: n (0 <= n <= cap) on success, 0 = EOF, -1 = failure
extern int32_t req_read(int32_t handle, void* ptr, size_t cap);

// Write `len` bytes from memory at `ptr` to stream `handle`
// Returns: n (0 <= n <= len) on success, -1 = failure
extern int32_t res_write(int32_t handle, const void* ptr, size_t len);

// Mark stream `handle` as ended (no more writes accepted)
// Idempotent. Does NOT terminate execution.
extern void res_end(int32_t handle);

// Emit telemetry (best-effort, may be dropped in production)
extern void telemetry(const char* topic_ptr, int32_t topic_len,
					  const char* msg_ptr, int32_t msg_len);
```

### 2.2 Memory

```c
// Allocate `size` bytes.
// Returns: non-zero pointer on success, 0 on failure
extern uintptr_t _alloc(size_t size);

// Free previously allocated memory at `ptr`.
// No-op if ptr is 0.
extern void _free(uintptr_t ptr);
```

### 2.3 Control Plane

```c
// Synchronous capability request/response
// Returns: bytes written (>= 0) on success, -1 on fatal failure
extern int32_t _ctl(const void* req_ptr, size_t req_len,
					void* resp_ptr, size_t resp_cap);

// Capability discovery (optional surface; zingcore returns no caps).
// Returns: -1 when idx is out of range.
extern int32_t _cap(int32_t idx);
```

---

## 3. No ABI Growth Rule

**MUST NOT:** A conforming host MUST NOT add new required imports for additional features.

**MUST:** All "new things" (filesystem, networking, UI, clocks, databases, compression, etc.) MUST be exposed via `_ctl` operations and/or streams obtained via `_ctl`.

If a host provides extra imports for convenience, Zing **MUST NOT** depend on them. They are non-normative.

---

## 4. Reserved Stream Handles

The following handle numbers are **reserved** and MUST be honored:

| Handle | Name | Purpose | Direction |
|--------|------|---------|-----------|
| 0 | `_in` | stdin-equivalent request stream | Readable |
| 1 | `_out` | stdout-equivalent response stream | Writable |
| 2 | `telemetry` | Telemetry sink | Writable |

**Rules:**
- Negative handles are invalid
- Handles 0–2 MUST NOT be returned by `_ctl` as newly-created handles
- First dynamically allocated handle: 3

---

## 5. Stream Semantics

### 5.1 req_read(handle, ptr, cap) → i32

Reads up to `cap` bytes from readable stream `handle` into memory at `ptr`.

**Returns:**
- `n` where `0 <= n <= cap`: success, `n` bytes read
- `0`: EOF (end of stream)
- `-1`: read failure

**Laws:**
- EOF is sticky: once `0` is returned, all future reads MUST return `0`
- Chunk boundaries MUST be deterministic for a given test run with fixed schedule

### 5.2 res_write(handle, ptr, len) → i32

Writes `len` bytes from memory at `ptr` into writable stream `handle`.

**Returns:**
- `n` where `0 <= n <= len`: success, `n` bytes written
- `-1`: write failure

**Laws:**
- Writes MUST preserve byte order
- If stream is closed via `res_end(handle)`, all future writes MUST return `-1`

### 5.3 res_end(handle) → unit

Marks stream `handle` as closed for further writes.

**Laws:**
- After `res_end(handle)`, `res_write(handle, ...)` MUST return `-1` deterministically
- `res_end` is idempotent: calling it multiple times is safe
- `res_end` MUST NOT terminate execution (program ends only when `main` returns)

### 5.4 telemetry(topic_ptr, topic_len, msg_ptr, msg_len) → unit

Best-effort telemetry emission.

**Laws:**
- Host MAY drop/reorder across processes, but within one run MUST be deterministic if captured
- Host MUST NOT block indefinitely on `log`
- Invalid pointers/lengths cause message to be dropped (no crash)

---

## 6. Memory Safety

### 6.0 Guest Memory Model (WASM and non-WASM)

The ABI defines a **flat guest byte space**. For WASM guests this is the linear
memory. For non-WASM guests, the host MUST provide an equivalent contiguous
byte buffer and the same pointer semantics apply.

**Law:** All pointers are offsets into the guest byte space `[0 .. mem_cap)`.

### 6.1 Pointer Bounds Rules

For any import taking `(ptr, len/cap)`:
- If `ptr < 0` or `len/cap < 0`: invalid
- If `ptr + len/cap` exceeds linear memory bounds: invalid

**Conforming behavior:**
- For `req_read` / `res_write` / `_ctl`: return `-1` on invalid pointer/length
- For `log`: drop silently on invalid pointer/length

### 6.2 _alloc / _free

**_alloc(size):**
- Returns non-negative pointer on success
- Returns `-1` on failure
- Results MUST be deterministic for identical call sequences
- Allocation occurs within the guest byte space (WASM linear memory or host-provided buffer)

**_free(ptr):**
- No-op if ptr is invalid (in release mode)
- MUST NOT crash the host process
- Host MAY implement as no-op (arena allocator) but MUST preserve determinism

---

## 7. Termination Model

**Rule:** Execution terminates when `main` returns.

- Ending stdout (`res_end(1)`) only prevents further writes
- It does NOT terminate execution
- There is no "after main" in WASM — host MAY discard output after `main` returns

---

## 8. Control Plane (_ctl)

### 8.1 Signature

```c
i32 _ctl(i32 req_ptr, i32 req_len, i32 resp_ptr, i32 resp_cap);
```

### 8.2 Semantics

- Reads request bytes from `[req_ptr .. req_ptr+req_len)`
- Writes response bytes into `[resp_ptr .. resp_ptr+resp_cap)`
- Returns number of bytes written (`>= 0`) on success
- Returns `-1` for fatal failure (invalid pointers, insufficient buffer for even error frame)

### 8.3 Laws

- `_ctl` MUST be deterministic for identical request bytes and capability state
- `_ctl` MUST NOT perform hidden I/O beyond what the capability model declares
- `_ctl` MUST NOT allocate unbounded memory internally
- `_ctl` MUST NOT block beyond the request's `timeout_ms`
- `_ctl` MUST NOT return partial frames — if response doesn't fit, return `-1`

---

## 9. Handle Lifecycle

Handles are owned by the host. The guest can:

| Operation | Function | Requirement |
|-----------|----------|-------------|
| Read | `req_read(h, ...)` | Handle is readable |
| Write | `res_write(h, ...)` | Handle is writable |
| End | `res_end(h)` | Handle is endable |

Handle closing semantics are capability-specific but MUST obey:
- After `res_end(h)`, subsequent `res_write(h, ...)` returns `-1`
- Repeated `res_end(h)` is idempotent

---

## 10. Language Surface Integration

The compiler and stdlib SHOULD expose:
- `__caps` as the reserved capability root receiver
- `stdin`, `stdout`, `log` as conveniences over handles

User code **MUST NOT** be allowed to shadow or assign to:
- `__caps`
- `stdin`, `stdout`, `log`

---

## 11. Rationale

- **`_in/_out/telemetry`** give the universal pipeline model
- **`_alloc/_free`** is unavoidable (explicit memory, no GC)
- **`res_end`** is about protocol finalization, not scheduling
- **`_ctl`** prevents ABI explosion: files, net, crypto, compression, images, DB views... all become capabilities
- **Specimen** makes the whole system debuggable and replayable
