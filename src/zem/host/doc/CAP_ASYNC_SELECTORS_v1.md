# Capability Pack: cap.async.selectors.v1

**Status:** NORMATIVE
**Version:** 1.0.0
**Depends on:** `CAP_ASYNC_v1.md` (ZAX1 framing and cap.async.v1 semantics)

---

## 1. Overview

This document defines the **selector catalog** for the async hub.

- The async hub is opened via `_ctl` using `CAPS_OPEN(kind="async", name="default")`.
- Once opened, the guest and host communicate over the returned lembeh stream using **ZAX1** frames (defined in `CAP_ASYNC_v1.md`).
- A guest requests work by sending **REGISTER_FUTURE** commands (ZAX1 kind=CMD/op=REGISTER_FUTURE) whose payload encodes an **Async Source**.
- A host completes work by emitting **FUTURE_OK** or **FUTURE_FAIL** events (ZAX1 kind=EVT/op=FUTURE_OK or FUTURE_FAIL) with the same `future_id`.

### 1.1 Normative keywords and scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

This document is **only** the selector catalog and the CAP_SELECTOR/OPAQUE source encoding used inside `cap.async.v1`.
- ZAX1 framing, stream semantics, timeouts, and future lifecycle are defined in `CAP_ASYNC_v1.md`.
- All examples here are **payload bytes** (Async Source bodies and FUTURE payloads), not entire ZAX1 frames unless explicitly stated.

This catalog standardizes:

1. The **Async Source** payload encoding.
2. A stable registry of **selectors**.
3. For each selector:
   - request `params` layout
   - success payload layout (`FUTURE_OK` payload)
   - failure codes (trace symbols) and common error behavior

**Normative law:** A host implementing `cap.async.v1` MUST follow this document for any selector it claims to support.

---

## 2. Wire Primitives

All layouts in this document use **Hopper byte layouts**:

- **H1**: 1 byte unsigned
- **H2**: 2 bytes unsigned, little-endian
- **H4**: 4 bytes unsigned, little-endian
- **H8**: 8 bytes unsigned, little-endian
- **HSTR**: `H4 len` + `len bytes` (UTF-8, no NUL terminator)
- **HBYTES**: `H4 len` + `len bytes` (raw bytes)

**Law (packed):** Payloads are packed; no padding.

**Law (bounds):** Any length prefix that would exceed the remaining bytes in the enclosing payload is invalid.

**Law (UTF-8 validation):** Any field described as “UTF-8” MUST be valid UTF-8 and MUST NOT contain NUL (`0x00`) or control bytes `< 0x20`.

**Note (why HBYTES for strings in CAP_SELECTOR):** CAP_SELECTOR uses HBYTES for `cap_kind`, `cap_name`, and `selector` to match existing guest helpers; they are still required to be valid UTF-8.

---

## 3. Async Source Encoding (normative)

`REGISTER_FUTURE` command payload is an **Async Source**.

### 3.1 Source Header

```
H1  src_kind
H4  body_len
u8[body_len] body
```

- `src_kind` selects how to interpret `body`.
- `body_len` MUST equal the number of bytes following.
- Any extra bytes are invalid.

**Law (size):** The full Async Source payload length MUST be `<= maxPayloadBytes` as declared by `cap.async.v1` (see `CAP_ASYNC_v1.md`). If exceeded, the host MUST complete the future with `FUTURE_FAIL` trace `t_async_overflow`.

**Law (reject trailing bytes):** `body_len` MUST consume the payload exactly. Any trailing bytes after `body` are invalid and MUST yield `t_async_bad_params`.

### 3.2 Source Kinds

| src_kind | Name         | Meaning |
|---------:|--------------|---------|
| 1        | OPAQUE        | Host-defined opaque work item |
| 2        | CAP_SELECTOR  | Standard cap kind/name + selector + params |

#### 3.2.1 OPAQUE (src_kind=1)

Body layout:

```
HBYTES bytes
```

Semantics:
- The host MAY interpret the bytes arbitrarily.
- The host MUST treat OPAQUE as an internal/private contract. No interoperability is implied.
- Tooling MUST treat this as uninterpreted and MUST NOT assume embedded formats.

#### 3.2.2 CAP_SELECTOR (src_kind=2)

Body layout:

```
HBYTES cap_kind        ; UTF-8 (e.g., "file", "net", "config", "exec")
HBYTES cap_name        ; UTF-8 (e.g., "default", "view")
HBYTES selector        ; UTF-8 selector id (e.g., "files.list.v1")
H4     params_len
u8[params_len] params
```

Validation laws:
- `cap_kind`, `cap_name`, and `selector` MUST be valid UTF-8 and MUST NOT contain NUL or control bytes `< 0x20`.
- `selector` MUST be non-empty and MUST match charset `[A-Za-z0-9._-]` only.
- `params_len` MUST match the remaining bytes exactly.
- If any validation fails, the host MUST complete the future with `FUTURE_FAIL` trace `t_async_bad_params`.

Dispatch law:
- The host MUST dispatch on the tuple `(cap_kind, cap_name, selector)`.
- If `(cap_kind, cap_name)` is unknown or unavailable, the host MUST complete the future with `FUTURE_FAIL` trace `t_cap_missing`.
- If `(cap_kind, cap_name)` exists but is denied by policy, the host MUST complete with `t_cap_denied`.
- If `(cap_kind, cap_name, selector)` is unknown, the host MUST complete with `t_async_unknown_selector`.
- If `(cap_kind, cap_name, selector)` is recognized but disabled (policy/version), the host MUST complete with `t_async_unsupported`.

---

## 4. Async Future Completion Payloads

Unless a selector states otherwise, futures are completed as follows.

### 4.1 FUTURE_OK payload

Selector-specific success payload bytes. The payload is defined in the selector sections below.

### 4.2 FUTURE_FAIL payload (universal)

```
HSTR   trace     ; ASCII [a-z0-9_] only (e.g., "t_file_not_found")
HSTR   msg       ; human-readable (UTF-8)
HBYTES cause     ; optional opaque bytes (len=0 permitted)
```

Laws:
- `trace` MUST be non-empty.
- `msg` MUST be non-empty.
- `cause` MAY be empty.
- The payload MUST be consumed exactly; no trailing bytes.

**Law (constant envelope):** This envelope is version-stable across all selectors in `cap.async.selectors.v1`.

#### 4.2.1 FUTURE_FAIL example (payload bytes)

Example values:
- `trace = "t_file_not_found"`
- `msg = "no such file"`
- `cause = (empty)`

Hex (payload only):
```
0F 00 00 00 74 5F 66 69 6C 65 5F 6E 6F 74 5F 66 6F 75 6E 64  ; HSTR trace
0C 00 00 00 6E 6F 20 73 75 63 68 20 66 69 6C 65              ; HSTR msg
00 00 00 00                                                    ; HBYTES cause (len=0)
```

---

## 5. Selector Registry (normative)

Selectors are versioned strings. New selectors MUST use a new `.vN` suffix.

### 5.1 Canonical tuple registry

A host advertising `cap.async.selectors.v1` MUST treat the following selector strings as having the canonical `(cap_kind, cap_name)` pairs shown.

| selector | cap_kind | cap_name | summary |
|---|---|---|---|
| `files.list.v1` | `file` | `view` | list entries in the sandboxed file view |
| `files.open.v1` | `file` | `view` | open an entry for reading (returns lembeh handle) |
| `net.tcp.connect.v1` | `net` | `tcp` | connect TCP and return bidirectional lembeh handle |
| `config.get.v1` | `config` | `default` | read from config snapshot |
| `config.list.v1` | `config` | `default` | list keys under prefix |
| `exec.start.v1` | `exec` | `default` | start sandboxed process (returns handles) |
| `exec.status.v1` | `exec` | `default` | poll process status |

**Law (host restriction):** A host MAY implement any subset of the registry.

**Law (guest restriction):** A guest MUST NOT assume support for any selector unless:
1) the host advertises the corresponding capability and selector support via `CAPS_DESCRIBE` (recommended), or
2) the guest has an out-of-band contract with the host.

### 5.2 Determinism rules

Selectors MUST define deterministic behavior suitable for Specimen.

- If an operation depends on real-world state (filesystem, network, process scheduling), it MUST be transcripted by Specimen.
- Parsing, ordering, error behavior, bounds checks, and max-size behavior MUST remain deterministic.
- For identical inputs under the same transcript, outputs MUST be identical.

---

## 6. File Selectors (cap file/view)

Capability identity:
- `cap_kind = "file"`
- `cap_name = "view"` (canonical sandboxed file namespace)

### 6.1 files.list.v1

Lists files in the file view.

**Params (request):**

```
HSTR scope          ; "" = default/root; otherwise a host-defined sub-scope
```

Scope laws:
- `scope` MUST be valid UTF-8 and MUST NOT contain NUL or control bytes `< 0x20`.
- `scope` MUST NOT contain path traversal sequences (`..`) and MUST NOT contain `/`.
- If `scope` is unsupported, the host MUST fail with `t_file_denied` or `t_async_bad_params` (host MUST document which).

**FUTURE_OK payload:**

```
H4 n
repeat n:
  HBYTES id         ; opaque identifier, stable within run
  HSTR   display    ; human-friendly name
  H4     flags      ; bit0=IS_DIR, bit1=READABLE, bit2=WRITABLE
```

Laws:
- Ordering MUST be deterministic and MUST be lexicographic by `(display, id)` using bytewise UTF-8 ordering.
- `id` MUST be stable within the current run and MUST be accepted by `files.open.v1`.
- `n=0` is valid.
- Hosts MUST document view policy (what is visible/filtered) in `CAPS_DESCRIBE` for `file/view`.

Errors:
- `t_cap_missing`, `t_cap_denied`
- `t_file_denied`
- `t_async_bad_params` (malformed Hopper layout)

**Example (params):** scope="".

Hex (HSTR ""):
- len=0 => `00 00 00 00`

**Example (OK payload, 1 file "main.zing")**
- n=1
- id = bytes("main.zing")
- display = "main.zing"
- flags = READABLE (bit1) => 0b010 = 2

Hex (payload only):
```
01 00 00 00                                ; n=1
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; id_len=8, "main.zing"
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67     ; display_len=8, "main.zing"
02 00 00 00                                ; flags=2
```

### 6.2 files.open.v1

Opens a file by identifier and returns a readable stream handle.

**Params (request):**

```
HBYTES id
H4     mode         ; bit0=READ (v1 requires READ=1 and all other bits=0)
```

Mode laws:
- v1 requires `mode == 1` (READ). Any other value MUST fail.

Laws:
- `handle` MUST be a valid lembeh stream handle and MUST be `>= 3`.
- `hflags` MUST include READABLE.
- The resulting handle MUST obey lembeh semantics (EOF stickiness; post-end writes fail).

Errors:
- `t_file_not_found`
- `t_file_not_readable`
- `t_ctl_bad_params` (bad mode)
- `t_async_bad_params` (malformed)

---

## 7. Network Selectors (cap net/tcp)

Capability identity:
- `cap_kind = "net"`
- `cap_name = "tcp"`

### 7.1 net.tcp.connect.v1

Establishes a TCP connection and returns a bidirectional stream handle.

**Params (request):**

```
HSTR host
H2   port
H4   connect_flags
```

`connect_flags` bits:
- bit0 `ALLOW_DNS`
- bit1 `PREFER_IPV6`
- bit2 `NODELAY`

Validation laws:
- `host` MUST be non-empty UTF-8 and MUST NOT contain NUL or control bytes `< 0x20`.
- `port` MUST be in range `1..65535`.
- Unknown `connect_flags` bits MUST be ignored (v1 forward-compat).

**FUTURE_OK payload:**

```
H4 handle
H4 hflags           ; READABLE|WRITABLE|ENDABLE
HBYTES meta         ; optional peer info
```

Timeout:
- The REGISTER_FUTURE ZAX1 header timeout policy applies (see `CAP_ASYNC_v1.md`).

Errors:
- `t_net_denied`
- `t_net_unreachable`
- `t_ctl_timeout`
- `t_async_bad_params`

---

## 8. Config Selectors (cap config/default)

Capability identity:
- `cap_kind = "config"`
- `cap_name = "default"`

### 8.1 config.get.v1

Fetches a configuration value from the host snapshot.

**Params (request):**

```
HSTR key
```

**FUTURE_OK payload:**

```
HBYTES value
```

Errors:
- `t_config_not_found`
- `t_config_bad_key`
- `t_config_too_large`
- `t_config_redacted`
- `t_config_unsupported`
- `t_async_bad_params`

### 8.2 config.list.v1

Lists keys under a prefix.

**Params (request):**

```
HSTR prefix
```

**FUTURE_OK payload:**

```
H4 n
repeat n:
  HSTR key
  H4   flags     ; bit0=secret, bit1=readonly
```

Laws:
- Ordering MUST be lexicographic by key.
- `n` MUST NOT exceed host policy limits (described via CAPS_DESCRIBE).

Errors:
- `t_config_not_listable`
- plus errors from GET

---

## 9. Exec Selectors (cap exec/default)

Capability identity:
- `cap_kind = "exec"`
- `cap_name = "default"`

### 9.1 exec.start.v1

Launches a sandboxed process.

**Params (request):**

```
HSTR prog_id
H4   flags          ; bit0=want_stdin, bit1=want_stdout, bit2=want_stderr
H4   argc
repeat argc:
  HSTR arg
H4   envc
repeat envc:
  HSTR key
  HSTR val
```

**FUTURE_OK payload:**

```
H4 exec_id
H4 status_flags     ; bit0=started, bit1=detached
H4 stdin_handle     ; 0 if not granted
H4 stdout_handle    ; 0 if not granted
H4 stderr_handle    ; 0 if not granted
```

Errors:
- `t_exec_not_allowed`
- `t_exec_bad_args`
- `t_exec_limits`
- `t_exec_not_found`
- `t_exec_too_many_handles`
- `t_exec_bad_encoding`
- `t_exec_bad_prog`
- `t_exec_busy`
- `t_async_bad_params`

### 9.2 exec.status.v1

Polls process status.

**Params (request):**

```
H4 exec_id
```

**FUTURE_OK payload:**

```
H4 state   ; 0=running,1=exited,2=failed,3=timeout,4=killed
H4 code    ; exit code or host-defined failure/signal
```

Errors:
- `t_exec_not_listable`
- `t_ctl_bad_params`
- `t_async_bad_params`

---

## 10. Standard Async Trace Codes (required)

These trace symbols MUST exist and remain stable for `cap.async.selectors.v1`.

| trace | meaning |
|------|---------|
| `t_async_bad_params` | selector params malformed or violate documented layout |
| `t_async_unknown_selector` | selector string not recognized by the host |
| `t_async_unsupported` | selector recognized but disabled by policy/version |
| `t_async_overflow` | Async Source or result exceeded declared bounds (e.g., `maxPayloadBytes`) |

Hosts SHOULD reuse existing trace codes from control/cap/file/net/config/exec specs.

---

## 11. End-to-end Example (REGISTER_FUTURE → FUTURE_OK)

This section shows the **CAP_SELECTOR body** bytes for a file list request.

### 11.1 CAP_SELECTOR body for (file/view, selector="files.list.v1", scope="")

Fields:
- cap_kind = "file"
- cap_name = "view"
- selector = "files.list.v1"
- params = HSTR scope=""  (4 bytes, all zero)

Body hex:
```
04 00 00 00 66 69 6C 65                    ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                    ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6C 69 73 74 2E 76 31  ; selector HBYTES("files.list.v1")
04 00 00 00                                ; params_len = 4
00 00 00 00                                ; params = HSTR("")
```

### 11.2 Async Source wrapper (src_kind=2)

Async Source payload = `H1 src_kind` + `H4 body_len` + `body`.

For the body in §11.1, `body_len = 41` bytes (`0x29`). Therefore the Async Source payload bytes are:

```
02 29 00 00 00                                ; src_kind=2, body_len=0x29
04 00 00 00 66 69 6C 65                       ; cap_kind HBYTES("file")
04 00 00 00 76 69 65 77                       ; cap_name HBYTES("view")
0D 00 00 00 66 69 6C 65 73 2E 6C 69 73 74 2E 76 31  ; selector HBYTES("files.list.v1")
04 00 00 00                                   ; params_len=4
00 00 00 00                                   ; params = HSTR("")
```

This Async Source payload is then carried as the **payload bytes** of a ZAX1 `REGISTER_FUTURE` command (see `CAP_ASYNC_v1.md`).

---

## 12. Extensibility Rules (normative)

1. **No selector mutation:** Existing selector strings and layouts MUST NOT change.
2. **New functionality:** MUST be introduced as a new selector string with a new `.vN` suffix.
3. **Feature probing:** Hosts SHOULD advertise supported selectors via `CAPS_DESCRIBE` schema bytes for the corresponding capability, or via a host-specific OPAQUE source.
4. **Forward compatibility:** Guests MUST treat unknown selectors as `t_async_unknown_selector`.
5. **Bounds:** Hosts MUST enforce `maxPayloadBytes` (from `CAP_ASYNC_v1.md`) and any per-selector limits declared in CAPS_DESCRIBE.

---

## 13. Additional worked examples (payload bytes)

### 13.1 CAP_SELECTOR body for config.get.v1 (key="app.env")

Params for `config.get.v1` are `HSTR key`.
- key = "app.env" (7 bytes)

Params hex:
```
07 00 00 00 61 70 70 2E 65 6E 76
```

CAP_SELECTOR body hex:
```
06 00 00 00 63 6F 6E 66 69 67              ; cap_kind = "config"
07 00 00 00 64 65 66 61 75 6C 74           ; cap_name = "default"
0D 00 00 00 63 6F 6E 66 69 67 2E 67 65 74 2E 76 31  ; selector = "config.get.v1"
0B 00 00 00                                   ; params_len = 11
07 00 00 00 61 70 70 2E 65 6E 76              ; params = HSTR("app.env")
```

### 13.2 FUTURE_OK payload for config.get.v1 (value="prod")

`config.get.v1` success payload is `HBYTES value`.
- value bytes = "prod" (4 bytes)

Hex (payload only):
```
04 00 00 00 70 72 6F 64
```

### 13.3 files.open.v1 params and success payload (id="main.zing")

Params for `files.open.v1` are `HBYTES id` + `H4 mode`.

Params hex (id="main.zing", mode=1):
```
08 00 00 00 6D 61 69 6E 2E 7A 69 6E 67        ; id
01 00 00 00                                      ; mode=READ
```

Example success payload (handle=11, hflags=1(readable), meta empty):
```
0B 00 00 00                                      ; handle=11
01 00 00 00                                      ; hflags=READABLE
00 00 00 00                                      ; meta len=0
```
