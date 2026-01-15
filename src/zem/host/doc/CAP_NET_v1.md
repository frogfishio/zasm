# Capability: cap.net.v1 (Normative)

**Status:** NORMATIVE  
**Version:** 1.0.0  
**Primary transport:** `cap.async.v1` (ZAX1) via `cap.async.selectors.v1`

This document defines the **network (TCP) capability** for ABI v1.x.
All **MUST/SHOULD/MUST NOT** requirements are normative.

---

## 1. Overview

`cap.net.v1` exposes a **sandboxed TCP client** surface suitable for:
- JIT / sandboxed execution
- deterministic replay (Specimen)
- tool-controlled, policy-bound network access

This capability is **not** a general-purpose sockets API.

### 1.1 How guests use networking (normative)

Guests MUST access networking through the **async hub**:

1. Open the async hub stream using `_ctl`:
   - `CAPS_OPEN(kind="async", name="default")` (defined in `CAP_ASYNC_v1.md`).
2. Submit work by sending ZAX1 `REGISTER_FUTURE` commands.
3. Encode requests using **CAP_SELECTOR** sources:
   - `(cap_kind="net", cap_name="tcp", selector="net.tcp.*.v1")` (defined in `cap.async.selectors.v1`).
4. Observe completion via ZAX1 `FUTURE_OK` / `FUTURE_FAIL` events.

**Law (no ambient network):** Guests MUST assume the default policy is **network disabled** unless explicitly granted by capability advertisement/policy.

### 1.2 Terminology

- **dial / connect**: establish an outbound TCP connection.
- **handle**: a lembeh stream handle representing a bidirectional byte stream.
- **hflags**: handle capabilities bitmask.
- **meta**: optional informational bytes about the connection.

---

## 2. Capability identity

- kind: `net`
- name: `tcp`
- version: `1`
- canonical id: `cap.net.v1`

Hosts MUST advertise this capability via `_ctl` `CAPS_LIST` when implemented.

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

`CAPS_DESCRIBE("net","tcp")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not interpreted by the ABI.

Recommended keys (optional, tooling only):
- `allowlist`        : array of allowed destinations (host-defined format; MUST be documented)
- `host_syntax`      : e.g. `dns` | `ipv4` | `ipv6` | `dns_or_ip`
- `max_host_len`     : maximum UTF-8 bytes for `host`
- `max_meta_bytes`   : maximum bytes in `meta` returned on success
- `max_conns`        : maximum concurrently open net handles per guest/session
- `max_inflight`     : maximum concurrently inflight connect futures
- `flags`            : bit0=dns_allowed_default, bit1=ipv6_allowed, bit2=nodelay_allowed
- `timeouts`         : recommended timeouts (ms) for connect
- `determinism`      : whether the host requires Specimen transcript to permit network

**Law (limits):** If the host publishes any of these limits, it MUST enforce them deterministically.

---

## 5. Async selector surface (normative)

All network operations are selectors carried inside `cap.async.v1` `REGISTER_FUTURE`.
The selector catalog and CAP_SELECTOR encoding are defined in `cap.async.selectors.v1`.

This document is authoritative for the **meaning** and **payload layouts** of:

- `net.tcp.connect.v1`

### 5.1 Common validation laws

- Hosts MUST validate Hopper layouts and reject malformed payloads.
- Hosts MUST reject trailing bytes (payload must be consumed exactly).
- Hosts MUST enforce any published limits (`CAPS_DESCRIBE`) deterministically.

On validation failure, the host MUST complete the future with `FUTURE_FAIL` trace `t_async_bad_params`.

### 5.2 Canonical selector tuple (normative)

The selector in this document is dispatched via the CAP_SELECTOR tuple:

- `cap_kind = "net"`
- `cap_name = "tcp"`

| selector | cap_kind | cap_name |
|---|---|---|
| `net.tcp.connect.v1` | `net` | `tcp` |

**Law (dispatch):** Hosts MUST dispatch by `(cap_kind, cap_name, selector)`.

---

## 6. Selector: net.tcp.connect.v1

Establishes an outbound TCP connection and returns a bidirectional lembeh handle.

### 6.1 Params (request)

```
HSTR host
H2   port
H4   connect_flags
```

#### 6.1.1 `host`

Validation laws:
- `host` MUST be non-empty.
- `host` MUST be valid UTF-8 and MUST NOT contain NUL or bytes `< 0x20`.
- `host` MUST NOT contain whitespace.
- If the host publishes `max_host_len`, the host MUST reject longer hosts with `t_async_bad_params`.
- The host MUST apply an allowlist / policy to `host` and `port`.

**Policy law:** If the destination is not allowed, the host MUST fail with `t_net_denied` (not `t_async_bad_params`).

#### 6.1.2 `port`

- `port` MUST be in the range `1..65535`.
- `port=0` MUST fail with `t_async_bad_params`.

#### 6.1.3 `connect_flags`

Bit assignments (v1):
- bit0 `ALLOW_DNS`     : permit DNS resolution of `host` if it is not a numeric IP.
- bit1 `PREFER_IPV6`   : prefer IPv6 when both families are available.
- bit2 `NODELAY`       : request TCP_NODELAY.

Forward-compat law:
- Unknown bits MUST be ignored (treated as 0).

Policy laws:
- If DNS is not allowed by host policy, the host MUST fail with `t_net_denied` when `ALLOW_DNS` is requested.
- If `NODELAY` is not allowed by host policy, the host MUST ignore it or fail with `t_net_denied`; hosts MUST document which choice they implement.

### 6.2 FUTURE_OK payload (success)

```
H4     handle
H4     hflags
HBYTES meta
```

Semantics:
- `handle` is a lembeh stream handle representing the connected TCP stream.
- `handle` MUST be `>= 3` (handles 0..2 are reserved by the base ABI).
- `hflags` is a bitmask with the following v1 meaning:
  - bit0 = READABLE
  - bit1 = WRITABLE
  - bit2 = ENDABLE
- For `net.tcp.connect.v1`, the host MUST set `hflags.bit0 = 1` and `hflags.bit1 = 1`.
- `meta` MAY be empty. If present, it MUST be informational only.

**Law (meta bounds):** If the host publishes `max_meta_bytes`, it MUST ensure `meta.len <= max_meta_bytes`; otherwise it MUST complete the future with `t_async_overflow`.

Suggested `meta` encoding (optional, not interpreted by ABI):
- `HSTR family` ("ipv4" or "ipv6")
- `HSTR local_addr` / `HSTR peer_addr` (string form)

Hosts MAY choose any meta format, but MUST keep it stable per host/version if tooling depends on it.

### 6.3 Stream semantics (normative)

The handle returned by `net.tcp.connect.v1` is a **bidirectional lembeh stream**.

- The guest reads bytes using `req_read(handle, ptr, cap)`.
- The guest writes bytes using `res_write(handle, ptr, len)`.
- The host MUST preserve byte order on both directions.

EOF and shutdown:
- EOF on reads is indicated by `req_read` returning `0`.
- If `hflags.bit2 (ENDABLE)` is set, the guest MAY call `res_end(handle)` to signal end-of-stream for writes.
  - If implemented, `res_end` MUST be idempotent.
  - After `res_end`, further `res_write` MUST fail deterministically (return `-1`).
- Hosts MUST make EOF sticky: once EOF has occurred, subsequent reads MUST return `0`.

Invalid handle:
- If the guest calls `req_read` or `res_write` on an invalid/closed handle, the host MUST return `-1`.

Backpressure:
- If the host buffers are full, it MUST apply a deterministic policy (block its producer, or fail writes deterministically). Hosts MUST NOT grow buffers without bound.

### 6.4 Errors

Returned via `FUTURE_FAIL`:
- `t_cap_missing`
- `t_cap_denied`
- `t_async_bad_params` (malformed payloads, invalid host/port layout, trailing bytes)
- `t_async_overflow`
- `t_ctl_timeout` (if connect does not complete within the ZAX1 timeout policy)
- `t_net_denied` (policy/allowlist denies destination or DNS)
- `t_net_unreachable` (connect failed: refused/unreachable/reset)

**Law (classification):** Policy denials MUST use `t_net_denied`. Environmental connect failures MUST use `t_net_unreachable`.

---

## 7. Worked examples (payload bytes)

All examples below are **payload bytes**, not whole ZAX1 frames.

### 7.1 Params for net.tcp.connect.v1 (host="127.0.0.1", port=80, flags=ALLOW_DNS=0)

`host` is `HSTR`, `port` is `H2`, `flags` is `H4`.

Hex (params only):
```
09 00 00 00 31 32 37 2E 30 2E 30 2E 31   ; HSTR "127.0.0.1"
50 00                                      ; H2 port=80
00 00 00 00                                ; H4 flags=0
```

### 7.2 CAP_SELECTOR body example (payload bytes)

Fields:
- cap_kind = "net"
- cap_name = "tcp"
- selector = "net.tcp.connect.v1"
- params = from §7.1

Hex (body only):
```
03 00 00 00 6E 65 74                                   ; cap_kind HBYTES("net")
03 00 00 00 74 63 70                                   ; cap_name HBYTES("tcp")
11 00 00 00 6E 65 74 2E 74 63 70 2E 63 6F 6E 6E 65 63 74 2E 76 31  ; selector HBYTES("net.tcp.connect.v1")
13 00 00 00                                             ; params_len = 19
09 00 00 00 31 32 37 2E 30 2E 30 2E 31 50 00 00 00 00 00 ; params
```

### 7.3 Async Source wrapper example (payload bytes)

Async Source payload = `H1 src_kind` + `H4 body_len` + `body`.

For the body in §7.2, `body_len = 57` bytes (`0x39`). Therefore:

```
02 39 00 00 00                                            ; src_kind=2 (CAP_SELECTOR), body_len=0x39
03 00 00 00 6E 65 74                                      ; cap_kind
03 00 00 00 74 63 70                                      ; cap_name
11 00 00 00 6E 65 74 2E 74 63 70 2E 63 6F 6E 6E 65 63 74 2E 76 31  ; selector
13 00 00 00                                                ; params_len
09 00 00 00 31 32 37 2E 30 2E 30 2E 31 50 00 00 00 00 00  ; params
```

This Async Source payload is carried as the **payload bytes** of a ZAX1 `REGISTER_FUTURE` command (see `CAP_ASYNC_v1.md`).

### 7.4 FUTURE_OK example (payload bytes)

Example values:
- handle = 11
- hflags = READABLE|WRITABLE|ENDABLE = 0b111 = 7
- meta empty

Hex:
```
0B 00 00 00     ; handle
07 00 00 00     ; hflags
00 00 00 00     ; meta len=0
```

---

## 8. Determinism & security (normative)

- Network operations are nondeterministic in the real world. If `cap.net.v1` is enabled, nondeterminism MUST be captured by Specimen (or an equivalent transcript) for deterministic replay.
- Hosts MUST enforce allowlists and policy before attempting any connect.
- Hosts MUST NOT allow ambient network access outside this capability.
- Hosts SHOULD treat `host` values as potentially sensitive and MUST NOT log destinations unless policy explicitly allows it.
- Hosts MUST bound resource usage: inflight futures, open handles, meta sizes, and buffering.

---

## 9. Extensibility (normative)

- Existing selector strings and payload layouts MUST NOT change.
- New operations MUST be introduced as new selectors with a new `.vN` suffix.

Reserved selector families (not defined by this document):
- `net.tcp.listen.vN`
- `net.udp.bind.vN`
- `net.dns.resolve.vN`

If implemented, they MUST be documented with packed Hopper layouts and stable trace codes.

---

## 10. Conformance checklist (normative)

Host MUST:
1. Advertise `("net","tcp")` via `CAPS_LIST` when implemented.
2. Implement `net.tcp.connect.v1` exactly as specified if claimed.
3. Enforce allowlist/policy and return `t_net_denied` on disallowed destinations.
4. Enforce bounds and reject malformed payloads (including trailing bytes).
5. Return errors via `FUTURE_FAIL` with stable trace codes.

Guest MUST:
1. Access networking via `cap.async.v1` and selectors; no ambient networking assumptions.
2. Validate payload layouts and bounds.
3. Treat `meta` as informational only.
