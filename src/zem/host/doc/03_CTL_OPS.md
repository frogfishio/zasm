# Control Plane Operations Specification

**Status:** NORMATIVE  
**Version:** 1.0.0

---

## 1. Overview

The `_ctl` control plane exposes host capabilities through a fixed set of operations. This document defines the standard operation codes and their payloads.

**All payloads are Hopper byte layouts.** See `02_ZCL1_WIRE.md` §1.1 for H1/H2/H4/H8, HSTR, and HBYTES.

**Notation:**
- `u32` == **H4** (4 bytes, little-endian)
- `i32` == **H4** (two's complement)
- `str` == **HSTR** (H4 length + bytes)
- `bytes` == **HBYTES** (H4 length + bytes)

**Law:** Payloads are packed; any extra bytes beyond the specified layout are invalid.

---

## 2. Operation Code Registry

### 2.1 Core Operations (Required)

| Op | Name | Purpose | Required |
|----|------|---------|----------|
| 1 | `CAPS_LIST` | Discover available capabilities | MUST |
| 2 | `CAPS_DESCRIBE` | Get capability schema | SHOULD |
| 3 | `CAPS_OPEN` | Open capability, get handle | MUST |

### 2.2 File Operations (Optional)

| Op | Name | Purpose |
|----|------|---------|
| 10 | `FILE_LIST` | List files in scope |
| 11 | `FILE_OPEN` | Open file by ID |

### 2.3 Network Operations (Optional)

| Op | Name | Purpose |
|----|------|---------|
| 20 | `NET_CONNECT` | TCP connect |
| 21 | `NET_POLL` | Poll connection state |

### 2.4 Crypto Operations (Optional)

| Op | Name | Purpose |
|----|------|---------|
| 50 | `CRYPTO_HASH` | Compute hash |
| 51 | `CRYPTO_HMAC` | Compute HMAC |
| 52 | `CRYPTO_RANDOM` | Deterministic random bytes |

---

## 3. Core Operations

### 3.1 CAPS_LIST (op = 1)

Discover all capabilities available to this program instance.

**Request Payload:** empty

**Success Payload:**

```
H4 n                     ; number of capabilities
repeat n times:
  HSTR kind              ; capability kind (e.g., "file", "net", "crypto")
  HSTR name              ; capability name (e.g., "view", "tcp", "hash")
  H4 cap_flags           ; capability flags
  HBYTES meta            ; optional metadata (may be empty)
```

**cap_flags bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `CAN_OPEN` | Supports `CAPS_OPEN` |
| 1 | `PURE` | Deterministic given inputs |
| 2 | `MAY_BLOCK` | Requires timeout discipline |
| 3 | `PRODUCES_HANDLES` | Returns stream handles |

**Ordering Law:** Results MUST be sorted lexicographically by `(kind, name)`.

**Empty Contract:** `n = 0` is valid and MUST succeed.

**Byte Layout (Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      n
4       var    entries[0..n-1] (packed)
```

Each entry is:

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      kind_len
4       k      kind bytes
4+k     4      name_len
8+k     m      name bytes
8+k+m   4      cap_flags
12+k+m  4      meta_len
16+k+m  x      meta bytes
```

**Law:** `kind_len`, `name_len`, and `meta_len` MUST be within remaining payload bounds.

---

### 3.2 CAPS_DESCRIBE (op = 2)

Get detailed information about a specific capability.

**Request Payload:**

```
HSTR kind                ; capability kind
HSTR name                ; capability name
```

**Success Payload:**

```
H4 cap_flags             ; capability flags (same as CAPS_LIST)
HBYTES schema            ; opaque schema bytes (JSON optional)
```

**Failure:** If capability not found, return `#t_cap_missing`.

**Schema Format:** Opaque bytes. If the host chooses JSON, the recommended structure contains:
- Supported open modes
- Parameter variants
- Handle flags returned
- Determinism characteristics

**Byte Layout (Request Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      kind_len
4       k      kind bytes
4+k     4      name_len
8+k     m      name bytes
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      cap_flags
4       4      schema_len
8       s      schema bytes
```

---

### 3.3 CAPS_OPEN (op = 3)

Universal capability open — the "give me a handle" operation.

**Request Payload:**

```
HSTR kind                ; capability kind
HSTR name                ; capability name
H4 mode                  ; capability-specific mode
HBYTES params            ; capability-specific parameters
```

**Success Payload:**

```
H4 handle                ; stream handle (>= 3), two's complement i32
H4 hflags                ; handle flags
HBYTES meta              ; capability-specific metadata
```

**hflags bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `READABLE` | `req_read(handle, ...)` allowed |
| 1 | `WRITABLE` | `res_write(handle, ...)` allowed |
| 2 | `ENDABLE` | `res_end(handle)` allowed |
| 3 | `SEEKABLE` | Future: seeking supported |
| 4 | `CTL_BACKED` | For debugging/provenance |

**Timeout:** Bound by request frame's `timeout_ms`.

**Failure Codes:**
- `#t_cap_missing` — capability not available
- `#t_cap_denied` — capability exists but access denied
- `#t_ctl_timeout` — operation timed out

**Byte Layout (Request Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      kind_len
4       k      kind bytes
4+k     4      name_len
8+k     m      name bytes
8+k+m   4      mode
12+k+m  4      params_len
16+k+m  p      params bytes
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      handle (i32)
4       4      hflags
8       4      meta_len
12      x      meta bytes
```

---

## 4. File Operations

### 4.1 FILE_LIST (op = 10)

List files available in a given scope.

**Request Payload:**

```
HSTR scope               ; "" means default/root scope
```

**Success Payload:**

```
H4 n                     ; number of files
repeat n times:
  HBYTES id              ; opaque file identifier (stable within run)
  HSTR display           ; human-friendly display name
  H4 flags               ; file flags
```

**flags bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `IS_DIR` | Entry is a directory |
| 1 | `READABLE` | File is readable |
| 2 | `WRITABLE` | File is writable |

**Ordering Law:** Results MUST be sorted by `(display, id)`.

**ID Stability:** `id` MUST be stable within a run. MAY be stable across runs.

**Byte Layout (Request Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      scope_len
4       s      scope bytes
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      n
4       var    entries[0..n-1] (packed)
```

Each entry is:

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      id_len
4       i      id bytes
4+i     4      display_len
8+i     d      display bytes
8+i+d   4      flags
```

---

### 4.2 FILE_OPEN (op = 11)

Open a file by its identifier.

**Request Payload:**

```
HBYTES id                ; file identifier from FILE_LIST
H4 mode                  ; open mode
```

**mode bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `READ` | Open for reading |
| 1 | `WRITE` | Open for writing |
| 2 | `CREATE` | Create if not exists |
| 3 | `TRUNCATE` | Truncate existing content |

**Success Payload:**

```
H4 handle                ; stream handle (i32)
H4 hflags                ; handle flags
```

**Usage:** Use `req_read(handle, ...)` to read, `res_write(handle, ...)` to write, `res_end(handle)` to close.

**Failure Codes:**
- `#t_file_not_found` — file does not exist
- `#t_file_not_readable` — read access denied
- `#t_file_not_writable` — write access denied

**Byte Layout (Request Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      id_len
4       i      id bytes
4+i     4      mode
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      handle (i32)
4       4      hflags
```

---

## 5. Network Operations

### 5.1 NET_CONNECT (op = 20)

Establish a TCP connection.

**Request Payload (via CAPS_OPEN params):**

For `kind="net"`, `name="tcp"`, `mode=1` (connect):

```
H1 variant               ; 1 = connect
HSTR host                ; hostname or IP address
H2 port                  ; port number
H4 connect_flags         ; connection flags
```

**connect_flags bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `ALLOW_DNS` | Allow DNS resolution (if 0, host must be literal IP) |
| 1 | `PREFER_IPV6` | Prefer IPv6 if available |
| 2 | `NODELAY` | Disable Nagle's algorithm |

**Success Payload:**

```
H4 handle                ; bidirectional stream handle (i32)
H4 hflags                ; READABLE | WRITABLE | ENDABLE
HBYTES meta              ; may contain peer info
```

**Timeout:** Bound by request frame's `timeout_ms`.

**Failure Codes:**
- `#t_net_denied` — network access denied
- `#t_net_unreachable` — host unreachable
- `#t_ctl_timeout` — connection timed out

**Byte Layout (CAPS_OPEN params for NET_CONNECT):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       1      variant (1 = connect)
1       4      host_len
5       h      host bytes
5+h     2      port
7+h     4      connect_flags
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      handle (i32)
4       4      hflags
8       4      meta_len
12      m      meta bytes
```

---

### 5.2 NET_POLL (op = 21)

Poll a pending connection (for nonblocking connect).

**Request Payload:**

```
H4 handle                ; handle from nonblocking connect
```

**Success Payload:**

```
H1 status                ; 0 = pending, 1 = ready, 2 = failed
if status == 2:
  HSTR trace             ; failure trace code
  HSTR msg               ; failure message
  HBYTES cause           ; optional cause
```

**Byte Layout (Request Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      handle (i32)
```

**Byte Layout (Success Payload):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       1      status
1       var    if status==2: error envelope (trace/msg/cause)
```

---

## 6. Crypto Operations

### 6.1 CRYPTO_HASH (op = 50)

Compute a cryptographic hash.

**Request Payload:**

```
HSTR alg                 ; algorithm: "sha256", "blake3", etc.
HBYTES data              ; data to hash
```

**Success Payload:**

```
HBYTES digest            ; hash digest
```

**Failure:** `#t_crypto_bad_alg` if algorithm not supported.

**Determinism:** MUST be deterministic — same input, same output.

---

### 6.2 CRYPTO_HMAC (op = 51)

Compute an HMAC.

**Request Payload:**

```
HSTR alg                 ; algorithm: "sha256", "blake3", etc.
HBYTES key               ; HMAC key
HBYTES data              ; data to authenticate
```

**Success Payload:**

```
HBYTES mac               ; MAC value
```

---

### 6.3 CRYPTO_RANDOM (op = 52)

Generate deterministic pseudo-random bytes.

**Request Payload:**

```
HBYTES seed              ; seed value (REQUIRED)
H4 n                     ; number of bytes to generate
```

**Success Payload:**

```
HBYTES out               ; exactly n random bytes
```

**Determinism Law:** Identical `seed` + `n` MUST produce identical `out`.

**Byte Layout (CRYPTO_HASH Request):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      alg_len
4       a      alg bytes
4+a     4      data_len
8+a     d      data bytes
```

**Byte Layout (CRYPTO_HASH Success):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      digest_len
4       d      digest bytes
```

**Byte Layout (CRYPTO_HMAC Request):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      alg_len
4       a      alg bytes
4+a     4      key_len
8+a     k      key bytes
8+a+k   4      data_len
12+a+k  d      data bytes
```

**Byte Layout (CRYPTO_HMAC Success):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      mac_len
4       m      mac bytes
```

**Byte Layout (CRYPTO_RANDOM Request):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      seed_len
4       s      seed bytes
4+s     4      n
```

**Byte Layout (CRYPTO_RANDOM Success):**

```
Offset  Size   Field
──────  ─────  ───────────────────────────
0       4      out_len (MUST == n)
4       n      out bytes
```

---

## 7. Empty Cloak Behavior

A cloak that provides no capabilities MUST still:

1. Implement `_ctl` and parse ZCL1 frames
2. Support `CAPS_LIST` (op = 1) returning `n = 0`
3. Return `#t_cap_missing` for `CAPS_DESCRIBE` and `CAPS_OPEN`
4. Return `#t_ctl_unknown_op` for unknown operations

This ensures tooling can always safely call `_ctl` to discover "nothing available".

---

## 8. Timeout Behavior

### 8.1 Blocking Operations

Operations that may block (network, file I/O on slow media):
- MUST respect `timeout_ms` from request frame
- `timeout_ms = 0` means nonblocking: succeed immediately or return `#t_ctl_timeout`

### 8.2 Nonblocking Operations

Operations that never block (CAPS_LIST, CRYPTO_HASH, in-memory ops):
- MAY ignore `timeout_ms`
- SHOULD complete immediately

### 8.3 Two-Phase Pattern (Optional)

For maximum determinism with networking:

1. `CAPS_OPEN(kind="net", mode=START)` with `timeout_ms=0` in the ZCL1 frame — returns handle in pending state
2. `NET_POLL(handle)` — check if ready

This allows explicit polling without hidden blocking.
