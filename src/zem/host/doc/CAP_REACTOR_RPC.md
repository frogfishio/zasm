;; SPDX-FileCopyrightText: 2025 Frogfish
;; SPDX-License-Identifier: GPL-3.0-or-later

# Reactor RPC Addendum (ZRX1-RPC v1)

**Status:** NORMATIVE (Zing formal addendum)  
**Version:** 1.0.0  
**Transport:** ZRX1 reactor frames  
**Depends on:** `CAP_REACTOR_v1.*` (ZRX1 framing + validation rules)

This addendum defines a **minimal, deterministic, bounded** request/response RPC
convention carried **inside** ZRX1 reactor streams.

This document **does not change** ZRX1 framing. It defines:
- which reactor frame kinds are used for RPC,
- how correlation works,
- the exact Hopper byte layouts for request/response payloads,
- mandatory validation rules,
- deterministic timeout/retry expectations.

All **MUST/SHOULD/MAY** keywords are normative.

---

## 1. Terms and non-goals

### 1.1 Terms

- **Reactor frame**: a single ZRX1 frame as defined by `CAP_REACTOR_v1.*`.
- **Frame `id`**: the ZRX1 frame identifier bytes (`id_len` + `id`).
- **Frame `rid`**: the ZRX1 correlation bytes (`rid_len` + `rid`).
- **RPC rid**: the frame `rid` used to correlate an RPC request with its response.

### 1.2 Non-goals

- Streaming RPC (bi-directional streaming) is **reserved** (future).
- Service discovery/IDL is **out of scope**.
- This addendum does not define authentication/authorization; that is host policy.

---

## 2. Transport mapping (normative)

### 2.1 Frame kinds

RPC uses reactor frames as follows:

- **Requests** MUST be sent as **Command** frames:
  - `kind = 2`
- **Responses** MUST be sent as **Event** frames:
  - `kind = 1`

RPC MUST NOT use reactor **Err** frames (`kind = 5`) for application-level RPC
failures. Reactor Err frames are reserved for **transport-level** failures
(invalid ZRX1, sequencing violations, backpressure/overflow policy, etc.).

### 2.2 RPC type tags (frame `id`)

To avoid ambiguity between “service id” and reactor “id”, RPC uses a fixed
**type tag** in the reactor frame `id`.

- Request frames MUST set frame `id` to the UTF-8 bytes:
  - `"rpc.request.v1"`
- Response frames MUST set frame `id` to the UTF-8 bytes:
  - `"rpc.response.v1"`

**Law:** Frame `id` MUST be **exactly** one of the two strings above for RPC.
Anything else is not ZRX1-RPC v1.

### 2.3 Correlation (frame `rid`)

- Each request MUST carry a non-empty frame `rid`.
- Each response MUST echo the exact request `rid` bytes.

If a receiver observes a response with an unknown `rid`, it MUST treat it as
**unsolicited** and MUST NOT treat it as a response to a different request.
Receivers MAY log unsolicited responses.

### 2.4 Deterministic bounds

Implementations MUST be bounded:
- Hosts SHOULD publish `max_inflight_rpc` and `max_rid_len` in reactor describe
  metadata if available.
- Guests MUST respect published bounds when present.

---

## 3. Payload layouts (normative)

All RPC payloads are **Hopper byte layouts**:
- `H1` = 1 byte
- `H4` = 4 bytes little-endian
- `HSTR` = `H4 len` + `len bytes` (UTF-8)
- `HBYTES` = `H4 len` + `len bytes`

No padding. No native pointers. All lengths are explicit.

### 3.1 Request payload (RPCV1)

A request (command frame, `kind=2`, `id="rpc.request.v1"`) has payload:

```
HSTR service
HSTR method
H4   flags
HBYTES data
```

**flags bits (H4):**
- bit0 `IDEMPOTENT`  : request may be retried safely
- bit1 `STREAM`      : reserved, MUST be 0 in v1
- bit2 `NO_RETRY`    : client MUST NOT retry even if idempotent
- bits 3..31         : reserved, MUST be 0 in v1

**Law:** Reserved bits MUST be 0. If not, receiver MUST reject with
`t_rpc_invalid`.

### 3.2 Response payload (RPCV1)

A response (event frame, `kind=1`, `id="rpc.response.v1"`) has payload:

```
H1   ok          ; 1=success, 0=failure
H1   rsv8        ; MUST be 0
H2   rsv16       ; MUST be 0
HBYTES err       ; MUST be empty if ok=1
HBYTES data
```

If `ok = 1`:
- `err.len` MUST be 0.

If `ok = 0`:
- `err.len` MUST be > 0.
- `data` MAY be empty.

#### 3.2.1 Error bytes format (RPCV1)

For `ok = 0`, `err` bytes MUST contain the following inner Hopper layout:

```
HSTR code        ; stable ASCII [a-z0-9_]+ recommended
HSTR msg         ; human-readable UTF-8 (MAY be empty)
```

**Law:** `code` MUST be non-empty.

This yields stable, greppable error codes without requiring reactor Err frames.

---

## 4. Validation rules (normative)

### 4.1 Frame-level validation

Receivers MUST validate the underlying ZRX1 frame according to
`CAP_REACTOR_v1.*` before interpreting RPC payloads.

Additionally for ZRX1-RPC v1:

- Requests MUST be `kind=2` AND `id=="rpc.request.v1"`.
- Responses MUST be `kind=1` AND `id=="rpc.response.v1"`.
- `rid_len` MUST be > 0.

### 4.2 Payload-level validation: request

For request payload:
- `service` MUST be non-empty.
- `method` MUST be non-empty.
- `service` and `method` MUST be valid UTF-8.
- `data` length MUST match remaining bytes exactly (enforced by `HBYTES`).
- Reserved flag bits MUST be 0.

If any rule fails, the receiver MUST respond (if it is acting as the server)
with `ok=0` and `err.code = "t_rpc_invalid"`.

### 4.3 Payload-level validation: response

For response payload:
- `rsv8` and `rsv16` MUST be 0; otherwise reject with `t_rpc_invalid`.
- If `ok=1`, `err.len` MUST be 0.
- If `ok=0`, `err.len` MUST be > 0 and must decode as `HSTR code, HSTR msg`.

Clients MUST reject malformed responses and MUST NOT treat them as valid results.

---

## 5. Timeouts, retries, and duplicates (normative)

### 5.1 Timeouts

ZRX1-RPC has **no ambient clock**.
- The **client** MUST implement timeouts in its own scheduling layer.
- A timeout is a client-local decision: absence of a response within the
  configured duration.

### 5.2 Retries

If a request times out, the client MAY retry only if:
- `flags.IDEMPOTENT = 1`, AND
- `flags.NO_RETRY = 0`.

If `flags.NO_RETRY = 1`, the client MUST NOT retry.

### 5.3 Duplicate `rid`

Servers SHOULD treat duplicate `rid` values as **replays**.

Determinism requirement:
- If a server receives the same `(rid, service, method, data, flags)` again
  while the original is still inflight, it SHOULD respond consistently.

Servers MAY implement one of these policies (but MUST be deterministic):
1. **Replay cache:** return the prior response bytes for that `rid` (recommended).
2. **Reject duplicates:** return `ok=0` with `t_rpc_invalid`.
3. **Treat as overflow:** return `ok=0` with `t_rpc_overflow`.

Servers MUST NOT allow unbounded memory growth when caching.

---

## 6. Concurrency limits (normative)

Hosts SHOULD declare `max_inflight_rpc` in reactor capability metadata.

If a host enforces an inflight limit and a request would exceed it, the host
MUST respond with:
- `ok=0`
- `err.code = "t_rpc_overflow"`

The response MUST use the same `rid` as the request.

---

## 7. Standard error codes (normative)

The following application-level error codes are standardized for v1.
They are carried in `err.code` (see §3.2.1):

- `t_rpc_timeout`        ; client-side synthesized (no response)
- `t_rpc_denied`         ; host policy denied the call
- `t_rpc_unimplemented`  ; service/method not implemented
- `t_rpc_overflow`       ; inflight limit exceeded
- `t_rpc_invalid`        ; malformed frame/payload or reserved bits set

Notes:
- `t_rpc_timeout` is typically generated by the client; servers may also use it
  if they implement bounded internal waits.

---

## 8. Determinism and Specimen (normative)

RPC traffic is carried on the reactor stream and therefore is part of the
observable event sequence.

Hosts MUST capture and replay RPC frames under Specimen according to the base
reactor determinism laws. In replay mode, the same request frames MUST yield
bit-identical response frames from the transcript.

---

## 9. Wire examples (normative)

These examples are **field-level** representations using Hopper layouts.
They are not full hexdumps of the outer ZRX1 frame; they focus on RPC mapping.

### 9.1 Example: request (echo)

Reactor frame (request):
- `kind = 2` (cmd)
- `id = "rpc.request.v1"`
- `rid = "0001"` (UTF-8 bytes; any opaque bytes allowed)

Payload:
```
HSTR service = "tools.echo"
HSTR method  = "say"
H4   flags   = 0x00000001        ; IDEMPOTENT
HBYTES data  = 0x00000002 "hi"   ; len=2, bytes 68 69
```

### 9.2 Example: success response

Reactor frame (response):
- `kind = 1` (event)
- `id = "rpc.response.v1"`
- `rid = "0001"` (echoed)

Payload:
```
H1   ok    = 1
H1   rsv8  = 0
H2   rsv16 = 0
HBYTES err  = len=0
HBYTES data = len=2 "hi"
```

### 9.3 Example: error response (denied)

Reactor frame (response):
- `kind = 1` (event)
- `id = "rpc.response.v1"`
- `rid = "0002"`

Payload:
```
H1 ok    = 0
H1 rsv8  = 0
H2 rsv16 = 0

HBYTES err = <bytes of:
  HSTR code = "t_rpc_denied"
  HSTR msg  = "policy"
>

HBYTES data = len=0
```

---

## 10. Conformance checklist (normative)

### 10.1 Host MUST

1. Accept request frames with `kind=2` and `id="rpc.request.v1"`.
2. Emit response frames with `kind=1` and `id="rpc.response.v1"`.
3. Echo request `rid` bytes exactly in the response.
4. Validate request payloads per §4.2 and reject invalid inputs with `t_rpc_invalid`.
5. Enforce bounded inflight behavior; on overflow return `t_rpc_overflow`.
6. Ensure determinism under Specimen per §8.

### 10.2 Guest MUST

1. Generate non-empty `rid` per request; uniqueness is REQUIRED per client inflight set.
2. Validate response payloads per §4.3.
3. Enforce timeout + retry rules per §5.
4. Treat unsolicited responses (unknown `rid`) as unrelated.

---
