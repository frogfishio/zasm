# Capability: cap.files.v1 (Normative)

**Status:** NORMATIVE  
**Version:** 1.0.0  
**Primary transport:** `cap.async.v1` (ZAX1) via `cap.async.selectors.v1`

This document defines the sandboxed **file view** capability for ABI v1.x.
All **MUST/SHOULD/MUST NOT** requirements are normative.

---

## 1. Overview

`cap.files.v1` exposes a **read-only sandboxed file view** suitable for:
- JIT / sandboxed execution
- deterministic replay (Specimen)
- tool-controlled “project file” access

This capability is **not** a general-purpose POSIX filesystem API.

### 1.1 How guests use files (normative)

Guests MUST access files through the **async hub**:

1. Open the async hub stream using `_ctl`:
   - `CAPS_OPEN(kind="async", name="default")` (defined in `CAP_ASYNC_v1.md`).
2. Submit work by sending ZAX1 `REGISTER_FUTURE` commands.
3. Encode work requests using **CAP_SELECTOR** sources:
   - `(cap_kind="file", cap_name="view", selector="files.*.v1")` (defined in `cap.async.selectors.v1`).
4. Read results from ZAX1 `FUTURE_OK` / `FUTURE_FAIL` events.

**Law (no ambient access):** Guests MUST NOT assume any ambient filesystem, cwd, or host paths. All access is mediated by this capability.

### 1.2 Terminology

- **Entry**: an item in the file view (typically a `.zing` source file).
- **id**: an opaque, stable-per-run identifier returned by `files.list.v1`.
- **display**: a human-friendly UTF-8 string (usually a filename).
- **handle**: a lembeh stream handle returned by `files.open.v1`.

---

## 2. Capability identity

- kind: `file`
- name: `view`
- version: `1`
- canonical id: `cap.files.v1`

Hosts MUST advertise this capability via `_ctl` `CAPS_LIST` when implemented.

**Note (naming):** The canonical id (`cap.files.v1`) names this specification. The wire identity is the tuple `(kind="file", name="view")`.

---

## 3. Wire primitives

All payload layouts in this document use **Hopper byte layouts**:

- **H1**: 1 byte unsigned
- **H2**: 2 bytes unsigned, little-endian
- **H4**: 4 bytes unsigned, little-endian
- **H8**: 8 bytes unsigned, little-endian
- **HSTR**: `H4 len` + `len bytes` (UTF-8, no NUL terminator)
- **HBYTES**: `H4 len` + `len bytes` (raw bytes)

**Law (packed):** Payloads are packed; no padding.

**Law (bounds):** Any length prefix that would exceed the remaining bytes in the enclosing payload is invalid.

**Law (UTF-8 validation):** Any field described as UTF-8 MUST be valid UTF-8 and MUST NOT contain NUL (`0x00`) or control bytes `< 0x20`.

---

## 4. CAPS_DESCRIBE schema (informational)

`CAPS_DESCRIBE("file","view")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not interpreted by the ABI.

Recommended keys (optional, tooling only):
- `max_scope_len`   : maximum bytes for `scope` in `files.list.v1`
- `max_entries`     : maximum `n` returned by list (hard limit)
- `max_id_len`      : maximum bytes for entry `id`
- `max_display_len` : maximum bytes for `display`
- `max_read_bytes`  : maximum bytes readable from an opened handle (0 = unlimited)
- `extensions`      : allowlisted suffixes (recommended: [".zing"])
- `flags`           : bit0=list_enabled, bit1=open_enabled, bit2=paths_enabled

**Law (limits):** If the host publishes any of these limits, it MUST enforce them deterministically.

**Law (paths):** v1 does not define any host-path-based selectors. If `flags.bit2` (`paths_enabled`) is present, it MUST be set to `0` for v1.

---

## 5. Async selector surface (normative)

All file operations are defined as selectors carried inside `cap.async.v1` `REGISTER_FUTURE`.
The selector catalog and CAP_SELECTOR encoding are defined in `cap.async.selectors.v1`.

This document is authoritative for the **meaning** and **payload layouts** of the following selectors:

- `files.list.v1`
- `files.open.v1`

### 5.1 Common validation laws

These rules apply to all selectors in this capability unless a selector overrides them.

- Hosts MUST validate Hopper layouts and reject malformed payloads.
- Hosts MUST reject trailing bytes (payload must be consumed exactly).
- Hosts MUST enforce any published limits (`CAPS_DESCRIBE`) deterministically.
- Hosts MUST NOT interpret host filesystem paths unless explicitly documented (v1 does not define path selectors).

On validation failure, the host MUST complete the future with `FUTURE_FAIL` trace `t_async_bad_params`.

### 5.2 Canonical selector tuples (normative)

The selectors in this document are dispatched via the CAP_SELECTOR tuple:

- `cap_kind = "file"`
- `cap_name = "view"`

Therefore the canonical tuples are:

| selector | cap_kind | cap_name |
|---|---|---|
| `files.list.v1` | `file` | `view` |
| `files.open.v1` | `file` | `view` |

**Law (dispatch):** Hosts MUST dispatch file requests by the tuple `(cap_kind, cap_name, selector)`.

**Law (guest encoding):** Guests MUST encode file requests as `CAP_SELECTOR` Async Sources as defined in `cap.async.selectors.v1`.

---

## 6. Selector: files.list.v1

Lists entries visible in the sandboxed file view.

### 6.1 Params (request)

```
HSTR scope        ; "" = default/root; otherwise host-defined namespace token
```

Scope laws:
- `scope` MUST be valid UTF-8 and MUST NOT contain NUL or control bytes `< 0x20`.
- `scope` MUST NOT contain `/`.
- `scope` MUST NOT contain `..`.
- If the host publishes `max_scope_len` in CAPS_DESCRIBE, the host MUST reject any scope whose byte length exceeds `max_scope_len` with `FUTURE_FAIL` trace `t_async_bad_params`.

**Law (policy):** If the host does not support non-empty scopes, it MUST fail with `t_file_denied`.

### 6.2 FUTURE_OK payload (success)

```
H4 n
repeat n:
  HBYTES id         ; opaque identifier
  HSTR   display    ; human-friendly name
  H4     flags      ; bit0=is_dir, bit1=readable, bit2=writable
```

Laws:
- `n` MAY be 0.
- Ordering MUST be deterministic and MUST be lexicographic by `(display, id)` using raw UTF-8 byte ordering (not locale collation).
- `id` MUST be stable for the duration of the current run/session and MUST be accepted by `files.open.v1`.
- `display` MUST be non-empty.
- If a host filters entries (e.g., only `.zing` files), it MUST do so deterministically.
- If the host publishes `extensions`, entries whose `display` does not match an allowlisted suffix MUST NOT be returned.
- If the host publishes `max_entries` in CAPS_DESCRIBE, it MUST ensure `n <= max_entries`; otherwise it MUST complete the future with `FUTURE_FAIL` trace `t_async_overflow`.
- Hosts MUST NOT truncate lists as a fallback. They MUST either succeed within limits or fail with `t_async_overflow`.
- If the host publishes `max_id_len` and/or `max_display_len` in CAPS_DESCRIBE, it MUST ensure each returned `id` and `display` respects those byte limits; otherwise it MUST complete the future with `FUTURE_FAIL` trace `t_async_overflow`.
- **Law (read-only):** In v1, hosts MUST set `flags.bit2` (writable) to `0` for all entries.

### 6.3 Errors

Returned via `FUTURE_FAIL`:
- `t_cap_missing`
- `t_cap_denied`
- `t_file_denied`
- `t_async_bad_params`
- `t_async_overflow`

### 6.4 Example: list root

Params bytes for `scope=""` (HSTR empty):

```
00 00 00 00
```

Example `FUTURE_OK` payload with one entry `main.zing` (readable):

```
01 00 00 00                                ; n=1
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; id = "main.zing"
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; display = "main.zing"
02 00 00 00                                ; flags = bit1(readable)
```

#### 6.4.1 CAP_SELECTOR body example (payload bytes)

This is the CAP_SELECTOR **body** for a list-root request.

Fields:
- cap_kind = "file"
- cap_name = "view"
- selector = "files.list.v1"
- params = HSTR scope=""  (4 bytes, all zero)

Hex (body only):

```
04 00 00 00 66 69 6C 65                    ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                    ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6C 69 73 74 2E 76 31  ; selector HBYTES("files.list.v1")
04 00 00 00                                ; params_len = 4
00 00 00 00                                ; params = HSTR("")
```

#### 6.4.2 Async Source wrapper example (payload bytes)

Async Source payload = `H1 src_kind` + `H4 body_len` + `body`.

For the body above, `body_len = 41` bytes (`0x29`). Therefore the Async Source payload bytes are:

```
02 29 00 00 00                                ; src_kind=2 (CAP_SELECTOR), body_len=0x29
04 00 00 00 66 69 6C 65                       ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                       ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6C 69 73 74 2E 76 31  ; selector HBYTES("files.list.v1")
04 00 00 00                                   ; params_len=4
00 00 00 00                                   ; params = HSTR("")
```

This Async Source payload is then carried as the **payload bytes** of a ZAX1 `REGISTER_FUTURE` command (see `CAP_ASYNC_v1.md`).

---

## 7. Selector: files.open.v1

Opens an entry for reading and returns a lembeh handle.

### 7.1 Params (request)

```
HBYTES id
H4     mode
```

Mode laws:
- v1 is **read-only**: `mode` MUST equal `1` (READ).
- Any other value MUST fail with `t_async_bad_params`.

### 7.2 FUTURE_OK payload (success)

```
H4 handle
H4 hflags
HBYTES meta
```

Semantics:
- `handle` is a lembeh stream handle.
- `handle` MUST be `>= 3` (handles 0..2 are reserved by the base ABI).
- `hflags` is a bitmask with the following v1 meaning:
  - bit0 = READABLE
  - bit1 = WRITABLE
  - bit2 = ENDABLE
- For `files.open.v1`, the host MUST set `hflags.bit0 = 1` and MUST set `hflags.bit1 = 0` (read-only).
- For `files.open.v1`, the host MUST set `hflags.bit2 = 0` (ENDABLE is not applicable to read-only sources).
- `meta` is optional and may be empty. If present, it MUST be treated as informational only. Suggested contents (if present):
  - content length (if known)
  - stable hash (if available)
  - mime/type hint

**Law (handle validity):** `handle` MUST refer to a valid stream for subsequent `req_read` calls.

### 7.3 Stream semantics (normative)

The handle returned by `files.open.v1` is a **read-only lembeh source**.

- The guest reads file bytes using `req_read(handle, ptr, cap)`.
- EOF is indicated by `req_read` returning `0`.
- On read handles, `res_write(handle, ...)` MUST fail deterministically (return `-1`).
- Calling `res_end(handle)` on a read handle MUST be a no-op (it MUST NOT change subsequent read results). This permits generic guest code that calls `res_end` without needing handle-type branching.
- The host MUST NOT yield structured records; the stream is raw file bytes.
- The host MUST preserve byte order.
- The host MUST make EOF sticky: once EOF has occurred, subsequent reads MUST return `0`.

**Law (bounded reads):** If the host publishes `max_read_bytes` in `CAPS_DESCRIBE`, it MUST enforce it deterministically across the lifetime of the handle. Once the limit is reached, the host MUST behave as if EOF has been reached (subsequent reads return `0`).

**Law (invalid handle):** If the guest calls `req_read` on a handle that is not valid (never granted, already closed, or outside host policy), the host MUST return `-1`.

### 7.4 Errors

Returned via `FUTURE_FAIL`:
- `t_cap_missing`
- `t_cap_denied`
- `t_file_not_found`
- `t_file_not_readable`
- `t_async_bad_params` (malformed payloads, bad mode, or trailing bytes)
- `t_async_overflow`

### 7.5 Example: open + read

Params for `id="main.zing"`, `mode=READ`:

```
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; HBYTES id
01 00 00 00                                ; H4 mode = 1
```

Example `FUTURE_OK` payload (handle=11, readable, meta empty):

```
0B 00 00 00                                ; handle=11
01 00 00 00                                ; hflags (bit0=READABLE)
00 00 00 00                                ; meta len=0
```

#### 7.5.1 CAP_SELECTOR body example (payload bytes)

This is the CAP_SELECTOR **body** for an open request with `id="main.zing"` and `mode=READ`.

Fields:
- cap_kind = "file"
- cap_name = "view"
- selector = "files.open.v1"
- params = HBYTES id + H4 mode

Hex (body only):

```
04 00 00 00 66 69 6C 65                    ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                    ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6F 70 65 6E 2E 76 31  ; selector HBYTES("files.open.v1")
10 00 00 00                                ; params_len = 16
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; params: HBYTES id = "main.zing"
01 00 00 00                                ; params: H4 mode = 1 (READ)
```

#### 7.5.2 Async Source wrapper example (payload bytes)

For the body above, `body_len = 49` bytes (`0x31`). Therefore the Async Source payload bytes are:

```
02 31 00 00 00                                ; src_kind=2 (CAP_SELECTOR), body_len=0x31
04 00 00 00 66 69 6C 65                       ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                       ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6F 70 65 6E 2E 76 31  ; selector HBYTES("files.open.v1")
10 00 00 00                                   ; params_len=16
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67        ; params: id
01 00 00 00                                   ; params: mode
```

---

## 8. Determinism & security (normative)

- Given identical inputs and the same sandbox view (or the same Specimen transcript), `files.list.v1` and `files.open.v1` MUST produce identical outputs.
- Hosts MUST NOT allow path traversal, host absolute paths, or implicit cwd use.
- Hosts MUST bound memory and output size; if a response would exceed limits, hosts MUST fail deterministically with `t_async_overflow` or a documented file-specific limit code.
- Hosts SHOULD treat file contents as potentially sensitive and MUST NOT log file bytes.

---

## 9. Extensibility (normative)

- Existing selector strings and payload layouts MUST NOT change.
- New operations MUST be introduced as new selectors with a new `.vN` suffix (e.g., `files.stat.v2`).
- v1 is read-only; any future write semantics MUST be introduced under new selectors and MUST remain sandbox-scoped.

---

## 10. Conformance checklist (normative)

Host MUST:
1. Advertise `("file","view")` via `CAPS_LIST` when implemented.
2. Implement `files.list.v1` and/or `files.open.v1` exactly as specified if claimed.
3. Enforce bounds, reject malformed payloads, and reject trailing bytes.
4. Provide deterministic ordering for lists.
5. Return errors via `FUTURE_FAIL` with stable trace codes.

Guest MUST:
1. Access files via `cap.async.v1` and selectors; no ambient filesystem assumptions.
2. Validate success payload layouts and bounds.
3. Treat `id` as opaque and only use it with `files.open.v1`.
