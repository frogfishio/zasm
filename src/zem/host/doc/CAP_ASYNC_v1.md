# cap.async.v1 — Async Capability Pack

Status: NORMATIVE
Version: 1.0.0
Canonical id: cap.async.v1
Kind/Name: kind="async", name="default"
Wire: ZAX1 (Async eXchange v1)

Primary goal: Provide a single async command stream for spawning/awaiting/cancelling work with deterministic framing and transcriptability (Specimen-friendly).
Secondary goal: Make “streams are async” viable by building higher IO layers on top of this.

This document is the normative definition of cap.async.v1 and ZAX1. Implementations MUST follow it exactly.

# 0. Definitions and scope

This capability is accessed ONLY via `_ctl` (ZCL1) to obtain a stream handle. After open, all async traffic uses ZAX1 frames sent over that stream using `res_write` (guest→host) and `req_read` (guest←host).

Terms:
- **CTL / ZCL1**: Control-plane framing used only for `_ctl` requests/responses.
- **Handle / stream**: A lembeh byte stream endpoint returned by `_ctl`.
- **ZAX1**: The data-plane protocol carried on the async handle.
- **Command**: ZAX1 frame with `kind=1` (guest→host).
- **Event**: ZAX1 frame with `kind=2` (host→guest). Includes ACK/FAIL and future resolution.
- **req_id**: Correlates a command to a single immediate acceptance result (ACK/FAIL).
- **future_id**: Correlates long-running work to a later resolution event (FUTURE_OK/FAIL/CANCELLED).
- **Specimen**: Record/replay harness. Determinism is achieved by transcript of stream I/O.

Non-goals:
- ZAX1 is not a general host↔host protocol. ZCL1 remains the high-assurance control plane.
- This document does not define application-level RPC. (RPC MAY be layered above futures.)

## 0.1 The async hub model (normative)

cap.async.v1 is the **async hub** for guest↔host interactions that may block, be slow, or require host policy (files, network, timers, subprocess I/O, etc.).

Law: In ABI v1.x, guests SHOULD prefer routing slow/host-mediated operations through cap.async.v1 futures rather than introducing new ad-hoc stream protocols.

Rationale (informative): This keeps the ABI surface small for sandbox/JIT deployments (one stream handle) while remaining extensible via a stable selector/params scheme.

---

# 1. Capability Overview

cap.async.v1 is exposed via `_ctl` (CAPS_OPEN) and returns one stream handle that is both READABLE and WRITABLE.

- Guest MUST write ZAX1 command frames to the handle (via `res_write`).
- Host MUST read command bytes, parse complete ZAX1 frames, process them, and enqueue ZAX1 event frames that the guest reads (via `req_read`).
- The host MUST NOT trap the guest for protocol-level errors; errors MUST be represented as ZAX1 FAIL events.

Determinism:
- The ZAX1 wire format is deterministic.
- Real-world scheduling is host-defined.
- Specimen MUST record/replay the stream read/write transcript to make async deterministic under replay.

---
 
# 1.1 Extensibility overview (normative)

ZAX1 is intentionally small. Extensibility happens through **source envelopes** (REGISTER_FUTURE payload) and through new ops that remain transcriptable.

cap.async.v1 MUST remain backward compatible within major version 1:
- New command ops MAY be added.
- New event ops MAY be added.
- New source envelope variants MAY be added.
- Existing ops/variants MUST NOT change semantics.

Preferred extension mechanism (normative): Add new functionality by defining new **selectors** within the cap-backed source envelope (Variant B, §5.1). This avoids proliferating “one protocol per capability”.

# 2. Open (`_ctl` CAPS_OPEN)

cap.async.v1 is opened using `_ctl` op=3 (CAPS_OPEN) as defined by ZCL1.

## 2.1 CAPS_OPEN request

Fields (ZCL1 payload):

HSTR kind = "async"
HSTR name = "default"
H4   mode = 1
HBYTES params = cap.async.v1 params

## 2.2 Params

Params layout (inside CAPS_OPEN params):

HBYTES session_id  ; arbitrary bytes (often Str/Bytes)
H4     flags       ; u32 guest flags (host-defined semantics)

Law: `params_len = 4 + session_id_len + 4`.

## 2.3 CAPS_OPEN success

On success, the ZCL1 op=3 success payload is:

H4     handle   ; i32 (>= 3 recommended)
H4     hflags   ; handle flags
HBYTES meta     ; opaque bytes (may be empty)

Handle flags:
- MUST include READABLE and WRITABLE.
- SHOULD include ENDABLE.

## 2.4 CAPS_OPEN failure

- If (kind,name) not supported: `#t_cap_missing`.
- If access denied: `#t_cap_denied`.
- If resources exhausted: `#t_ctl_overflow` (or a capability-specific overflow code documented by the host).

---

# 3. ZAX1 wire protocol

## 3.0 Transport and buffering law

ZAX1 is carried over a byte stream. Stream reads MAY return:
- partial frames,
- multiple frames concatenated,
- or frame boundaries split arbitrarily.

Receiver MUST implement buffering:
1. Buffer until at least 48 bytes are available.
2. Parse header, obtain `payload_len`.
3. Buffer until `48 + payload_len` bytes are available.
4. Consume exactly `48 + payload_len` bytes as one frame.

Law: Extra bytes beyond `48 + payload_len` belong to subsequent frames and MUST NOT be treated as part of the current frame.

---

3.1 Frame header (48 bytes)

All async traffic uses ZAX1 frames. Header layout exactly matches your guest’s asyncEncodeFrame and host’s async_enqueue_frame.

Offset Size Field
0 4 magic = "ZAX1"
4 2 version = 1
6 2 kind (u16)
8 2 op (u16)
10 2 flags (u16)
12 8 req_id (u64) ; correlation for ACK/FAIL
20 8 scope_id (u64) ; reserved (0 in v1 draft)
28 8 task_id (u64) ; reserved (0 in v1 draft)
36 8 future_id(u64) ; target future
44 4 payload_len (u32)
48 N payload bytes

Law: `payload_len` MUST be <= host/guest maximums. If exceeded, receiver MUST emit/return a deterministic error (host: FAIL event; guest: AsyncError).
Law: `version` MUST be 1. Unknown versions MUST be rejected.
Law: `kind` MUST be 1 (Command) or 2 (Event). Unknown kinds MUST be rejected.

Law: `flags`, `scope_id`, and `task_id` are **reserved for extension**. In v1.0.0, senders MUST set them to 0 and receivers MUST ignore non-zero values (but MUST preserve determinism when doing so).

---

## 3.2 kind values

kind | Direction | Meaning
---|---|---
1 | guest → host | Command
2 | host → guest | Event / Reply

---

## 3.3 req_id rules (ACK/FAIL contract)

- `req_id` correlates a command to exactly one immediate acceptance outcome.
- If `req_id != 0`, host MUST emit exactly one of:
  - ACK (op=101, kind=2), or
  - FAIL (op=102, kind=2)
  with the same `req_id`.
- Host MUST emit that ACK/FAIL after it has fully validated the frame header and payload for that command.
- If `req_id == 0`, host MAY perform the action without emitting ACK/FAIL.

Law: For a given command, host MUST NOT emit both ACK and FAIL.

---

## 3.4 future_id rules

`future_id` identifies a guest-visible future.

- Commands that create/act on a future MUST carry a non-zero `future_id`.
- Events that resolve/cancel a future MUST carry the same `future_id`.
- Host MUST NOT emit a resolution event for `future_id=0`.

Law: For each `future_id`, host MUST eventually emit exactly one terminal resolution event:
- FUTURE_OK (110), or
- FUTURE_FAIL (111), or
- FUTURE_CANCELLED (112).

---

# 4. Events (host → guest)

## 4.1 ACK (op=101, kind=2)

Indicates command accepted/processed (not necessarily completed work).

kind=2
op=101
req_id = same as command req_id
payload_len = 0

## 4.2 FAIL (op=102, kind=2)

Indicates command rejected/failed.

Payload layout:

H4 code_len
H4 msg_len
code bytes (not NUL-terminated)
msg bytes (not NUL-terminated)

Law: `code` MUST be a stable trace symbol using `[a-z0-9_]+` without a leading `#` (e.g., `t_async_bad_frame`).

## 4.3 FUTURE_OK (op=110, kind=2)

Resolves a future with a byte payload.

Payload layout:

H4 value_len
value bytes

Law: Entire payload must be exactly 4+value_len.

## 4.4 FUTURE_FAIL (op=111, kind=2)

Resolves a future with an error.

Payload layout (same as FAIL):

H4 code_len
H4 msg_len
code bytes
msg bytes

## 4.5 FUTURE_CANCELLED (op=112, kind=2)

Indicates future cancelled.

Payload: empty.

## 4.6 JOIN_RESULT (op=120, kind=2)

Indicates a successful join for JOIN_BOUNDED.

Payload: empty.

## 4.7 JOIN_LIMIT (op=121, kind=2)

Indicates JOIN_BOUNDED exceeded its fuel/limit.

Payload layout:

H4 code_len
H4 msg_len
code bytes
msg bytes

Recommended: `code = t_async_join_limit`.

---

## 4.8 EXT_EVENT (op=200..299, kind=2)

Event opcodes 200..299 are reserved for future extensions.

Law: Guests that do not understand an EXT_EVENT MUST ignore it (or log it) but MUST NOT treat it as a protocol error.

# 5. Commands (guest → host)

All commands are kind=1.

## 5.1 REGISTER_FUTURE (op=1)

Registers a future computation.

Fields:
• future_id MUST be non-zero.
• payload MUST be a “source envelope” that the host can execute.

Two source envelope variants exist in guest code:

Variant A: opaque source (guest-side asyncSourceOpaque)
Payload:

H1 variant = 1
H4 body_len
body bytes

Variant B: cap-backed source (guest-side asyncSourceCap)
Payload:

H1 variant = 2
H4 body_len ; length of the rest of this envelope
HBYTES cap_kind ; H4 len + bytes
HBYTES cap_name
HBYTES selector
H4 params_len
params bytes

Law: Envelope lengths must match exactly (no trailing bytes).

Host behavior:
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- If accepted, host MUST eventually emit exactly one terminal resolution event for `future_id` per §3.4.
- If `future_id` is unknown/invalid or already resolved, host MUST FAIL deterministically.

## 5.2 CANCEL_FUTURE (op=2)

Requests cancellation of a future.
• future_id MUST identify an existing future.
• Payload is empty in v1.

Host behavior:
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- If cancellation takes effect, host MUST emit FUTURE_CANCELLED (112) for that `future_id` (unless already resolved).
- If `future_id` is unknown, host MUST FAIL with `t_async_missing_future`.

## 5.3 DETACH_TASK (op=3)

Detaches a task from a scope (used for structured concurrency).

Guest payload (from your asyncCmdDetachTask) is:

H4 owner_len
owner bytes

Law: `owner_len` MUST match remaining payload bytes exactly.

Other ids:
• task_id may be used (guest sends taskLo/taskHi)
• scope_id is 0 in your current guest code

Host MUST emit ACK/FAIL for req_id if provided.

## 5.4 JOIN_BOUNDED (op=4)

Attempts to join a scope with bounded fuel (time/steps).

Payload:

H4 fuelLo
H4 fuelHi

Host behavior:
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- Host MUST then emit exactly one of:
  - JOIN_RESULT (120) on success, or
  - JOIN_LIMIT (121) on limit.

---

## 5.5 Extension point: CAP-BACKED futures (normative)

Variant B (cap-backed source, `variant=2`) is the primary extensibility mechanism for the async hub.

### 5.5.1 Selector conventions

`selector` is a UTF-8 string that identifies the sub-operation executed by the host. It MUST be non-empty and MUST NOT contain NUL.

Recommended (normative): selectors SHOULD be ASCII and namespaced with dots:
- `files.read.v1`
- `files.list.v1`
- `net.connect.v1`
- `net.read.v1`
- `net.write.v1`
- `timer.sleep.v1`
- `exec.start.v1`

Law: Selector versioning is part of the selector string. New selector versions MUST use a new suffix (e.g., `.v2`) and MUST NOT change the meaning of an existing selector.

### 5.5.2 Params payload

`params` is opaque bytes interpreted by the selector. Each selector MUST define a deterministic Hopper layout for its params and for its FUTURE_OK/FUTURE_FAIL payloads.

Law: For a given selector version, the params and result layouts MUST be stable and fully specified (no implicit host pointers, no ambient globals).

### 5.5.3 Unknown selector behavior

If the host does not implement a selector, it MUST reject REGISTER_FUTURE with:
- FAIL code `t_async_unimplemented` (or `t_async_unknown_selector`) and a deterministic message.

### 5.5.4 Capability routing

`cap_kind`/`cap_name` identify the logical capability namespace for the selector. For the async hub model, hosts SHOULD accept `cap_kind` values that correspond to high-level domains (e.g., `files`, `net`, `timer`, `exec`).

Law: Hosts MAY use policy to allow/deny specific selector calls based on guest identity/session. Denials MUST be represented as FAIL/FUTURE_FAIL (no traps).

# 6. Standard error codes (normative)

Hosts implementing cap.async.v1 MUST support the following FAIL/FUTURE_FAIL codes:

- `t_async_bad_frame` — malformed ZAX1 frame (magic/version/kind/header/payload)
- `t_async_unknown_op` — unknown command op
- `t_async_payload` — payload too large / exceeds caps
- `t_async_unknown_source` — unknown source envelope variant
- `t_async_unimplemented` — selector or feature not implemented by host
- `t_async_denied` — selector exists but is denied by policy
- `t_async_missing_future` — cancelling/awaiting unknown future
- `t_async_join_limit` — join fuel/limit exceeded

Guests SHOULD treat unknown codes as opaque strings.

---

# 7. Conformance requirements

A conforming host MUST:
1. Implement CAPS_OPEN for ("async","default") and return a READABLE|WRITABLE handle.
2. Implement ZAX1 buffering law (§3.0) for command parsing.
3. Enforce the ACK/FAIL contract for `req_id != 0` (§3.3).
4. Enforce terminal future resolution uniqueness (§3.4).
5. Emit FAIL (not traps) for protocol errors.
6. Enforce a deterministic maximum payload length.

A conforming guest MUST:
1. Encode ZAX1 frames exactly as §3.1.
2. Buffer and decode frames per §3.0.
3. Treat FAIL and FUTURE_FAIL as explicit Result/Err (no traps).
4. Not assume stream read boundaries equal frame boundaries.

---

# 8. Stream semantics and chunking

ZAX1 frames travel over a byte stream. Reads may return partial frames.

Law: Receiver MUST buffer until it has 48 bytes header and then payload_len bytes payload.

Your host currently processes commands only if len-pos >= 48 and waits until full frame is present; good.

---

# 9. Limits

The guest-side AsyncCaps.maxPayloadBytes is enforced by encoding/decoding. Host SHOULD enforce similar caps.
• If payload exceeds max: MUST FAIL deterministically (t_async_bad_frame or t_async_payload).

Your host uses a hard-coded 1MiB check: (1u<<20).

## 9.1 Recommended default limits

- `maxPayloadBytes`: 1,048,576 (1 MiB)
- Receiver MUST reject frames with `payload_len` above this limit using `t_async_payload`.

---

# 10. Specimen / replay

All async command writes and event reads MUST be transcripted.
• Record every res_write to the async handle.
• Record every req_read from the async handle (including chunk boundaries if fuzzing schedule).
• Under replay, the host can be replaced by transcript-driven stream, and `_ctl` open returns stable handle mapping.

---

# 11. Async hub profiles (normative)

To prevent “70 protocols each talking their own lingo”, cap.async.v1 defines a **single hub** with many selector-defined operations.

Law: File I/O, networking, timers, and other potentially blocking host services SHOULD be specified as selector-defined CAP-BACKED futures (§5.5), not as separate byte-stream protocols.

Law: Introducing a new on-stream protocol (new magic/version carried over lembeh streams) is discouraged in v1.x and MUST be justified with a determinism + sandboxing rationale.

# 12. Wire examples (informative)

Mapping to your existing code (sanity check)

This doc matches what you already have:
• Host:
• accepts ZAX1 magic/version=1/kind=1 commands
• emits ACK (101) and FAIL (102)
• emits FUTURE_OK (110) for op=1 with payload [u32 len=3]["ok\n"]
• emits FAIL (op=102) with code t_async_unknown_op for unknown ops
• `_ctl` open path for ("async","default") returns readable|writable handle
• Host SHOULD emit FUTURE_CANCELLED (112) for op=2 when cancellation takes effect (stub currently only ACKs).
• Guest:
• encodes/decodes exactly the 48-byte ZAX1 header + payload
• can open session via `_ctl` (CAPS_OPEN op=3)
• has command helpers matching ops 1..4
• has await helpers expecting ACK 101, FAIL 102, FUTURE_OK 110, FUTURE_FAIL 111, FUTURE_CANCELLED 112, JOIN 120/121

---

## 11.1 ACK for REGISTER_FUTURE

Command (guest→host):
- magic=ZAX1, v=1, kind=1, op=1, flags=0
- req_id=1
- future_id=0x0000000000000007
- payload = opaque source envelope

Event (host→guest): ACK
- kind=2, op=101, req_id=1, payload_len=0

## 11.2 Immediate FUTURE_OK payload

Event (host→guest): FUTURE_OK
- kind=2, op=110
- future_id=7
- payload:
  - H4 value_len=3
  - bytes: 6F 6B 0A  ("ok\n")

# cap.async.v1 — Async Capability Pack

**Status:** NORMATIVE  
**Version:** 1.0.0  
**Canonical id:** `cap.async.v1`  
**Kind/Name:** `kind="async", name="default"`  
**Wire:** **ZAX1** (Async eXchange v1)

Primary goal: provide a **single async command stream** for spawning/awaiting/cancelling work with deterministic framing and transcriptability (Specimen-friendly).  
Secondary goal: make “streams are async” viable by building higher IO layers on top of this hub.

This document is the **normative** definition of `cap.async.v1` and **ZAX1**. Implementations **MUST** follow it exactly.

---

## 0. Definitions and scope

This capability is accessed **ONLY via `_ctl`** (ZCL1) to obtain a **lembeh stream handle**. After open, all async traffic uses **ZAX1 frames** sent over that stream using:

- guest→host: `res_write(handle, ptr, len)`
- host→guest: `req_read(handle, ptr, cap)`

**Terms:**
- **CTL / ZCL1**: control-plane framing used only for `_ctl` requests/responses.
- **Handle / stream**: lembeh byte stream endpoint returned by `_ctl`.
- **ZAX1**: async data-plane protocol carried on the async handle.
- **Command**: ZAX1 frame with `kind=1` (guest→host).
- **Event**: ZAX1 frame with `kind=2` (host→guest).
- **req_id**: correlates a Command to exactly one immediate acceptance result (**ACK**/**FAIL**).
- **future_id**: correlates long-running work to exactly one terminal resolution (**FUTURE_OK/FAIL/CANCELLED**).
- **Specimen**: record/replay harness; determinism achieved by transcript of stream I/O.

**Non-goals:**
- ZAX1 is **not** host↔host. ZCL1 remains the high-assurance control plane.
- This document does not define application-level RPC. (RPC MAY be layered above futures.)

---

## 0.1 The async hub model (normative)

`cap.async.v1` is the **async hub** for guest↔host interactions that may block, be slow, or require host policy (files, network, timers, subprocess I/O, etc.).

**Law:** In ABI v1.x, guests SHOULD route slow/host-mediated operations through `cap.async.v1` futures instead of introducing new ad-hoc stream protocols.

Rationale (informative): this keeps the ABI surface small for sandbox/JIT deployments (one stream handle) while remaining extensible via a stable selector/params scheme.

---

## 1. Capability overview (normative)

`cap.async.v1` is exposed via `_ctl` (CAPS_OPEN) and returns **one** stream handle that is both **READABLE** and **WRITABLE**.

- Guest MUST write ZAX1 **Command** frames to the handle (`res_write`).
- Host MUST parse complete ZAX1 frames from the stream and enqueue ZAX1 **Event** frames that the guest reads (`req_read`).
- Host MUST NOT trap the guest for protocol-level errors; errors MUST be represented as ZAX1 **FAIL** / **FUTURE_FAIL** events.

**Determinism:**
- ZAX1 wire format is deterministic.
- Real-world scheduling is host-defined.
- Specimen MUST record/replay async stream I/O transcript to make execution deterministic under replay.

---

## 1.1 Extensibility overview (normative)

ZAX1 is intentionally small. Extensibility happens through **source envelopes** (REGISTER_FUTURE payload) and through new ops that remain transcriptable.

Backward compatibility within major version 1:
- New command ops MAY be added.
- New event ops MAY be added.
- New source envelope variants MAY be added.
- Existing ops/variants MUST NOT change semantics.

**Preferred extension mechanism (normative):** add new functionality by defining new **selectors** within the cap-backed source envelope (Variant B, §5.5). This avoids proliferating “one protocol per capability”.

---

## 2. Open (`_ctl` CAPS_OPEN) (normative)

`cap.async.v1` is opened using `_ctl` op=3 (CAPS_OPEN) as defined by ZCL1.

### 2.1 CAPS_OPEN request payload (ZCL1)

```
HSTR kind = "async"
HSTR name = "default"
H4   mode = 1
HBYTES params = cap.async.v1 params
```

### 2.2 Params layout (inside `params`)

```
HBYTES session_id
H4     flags        ; guest flags (host-defined semantics)
```

**Law:** `params_len = 4 + session_id_len + 4`.

### 2.3 CAPS_OPEN success payload (ZCL1 op=3)

```
H4     handle   ; i32 (>= 3 recommended)
H4     hflags   ; handle flags
HBYTES meta     ; opaque bytes (may be empty)
```

**Handle flags:**
- MUST include READABLE and WRITABLE.
- SHOULD include ENDABLE.

### 2.4 CAPS_OPEN failure (ZCL1 error envelope)

- Unsupported (kind,name): `#t_cap_missing`
- Access denied: `#t_cap_denied`
- Resources exhausted: `#t_ctl_overflow` (or host-documented equivalent)

---

## 3. ZAX1 wire protocol (normative)

### 3.0 Transport and buffering law (normative)

ZAX1 is carried over a **byte stream**. Reads MAY return partial frames, multiple concatenated frames, or arbitrary splits.

Receiver MUST implement buffering:
1. Buffer until **at least 48 bytes** available.
2. Parse header, obtain `payload_len`.
3. Buffer until **48 + payload_len** bytes available.
4. Consume exactly **48 + payload_len** bytes as one frame.

**Law:** Extra bytes beyond `48 + payload_len` belong to subsequent frames.

---

### 3.1 Frame layout (normative)

All async traffic uses fixed-header ZAX1 frames.

#### 3.1.1 Header (48 bytes)

| Off | Size | Field | Type | Meaning |
|---:|---:|---|---|---|
| 0  | 4  | magic | bytes[4] | ASCII `"ZAX1"` (0x5A 0x41 0x58 0x31) |
| 4  | 2  | version | u16 | MUST be 1 |
| 6  | 2  | kind | u16 | 1=Command, 2=Event |
| 8  | 2  | op | u16 | Operation code |
| 10 | 2  | flags | u16 | Reserved (MUST be 0 in v1.0.0) |
| 12 | 8  | req_id | u64 | Correlates Command → exactly one ACK/FAIL |
| 20 | 8  | scope_id | u64 | Reserved (MUST be 0 in v1.0.0) |
| 28 | 8  | task_id | u64 | Reserved (MUST be 0 in v1.0.0) |
| 36 | 8  | future_id | u64 | Correlates long work → terminal resolution |
| 44 | 4  | payload_len | u32 | Payload bytes following the header |

#### 3.1.2 Payload

Immediately after the 48-byte header:

| Off | Size | Field |
|---:|---:|---|
| 48 | N | payload bytes (`N = payload_len`) |

#### 3.1.3 Little-endian encoding

**Law:** All multi-byte integer fields in ZAX1 are little-endian.

#### 3.1.4 Validation (definitive)

Receiver MUST validate, in order:
1. `magic` MUST equal `"ZAX1"`.
2. `version` MUST equal `1`.
3. `kind` MUST be `1` or `2`.
4. `payload_len` MUST be `<= max_payload_bytes` (§9).
5. Receiver MUST buffer exactly `48 + payload_len` bytes before decoding payload.

If any of (1)–(4) fails:
- **Host:** if it can read a full 48-byte header and the header contains `req_id != 0`, host MUST emit **FAIL** `t_async_bad_frame` for that `req_id`. Otherwise host MUST drop bytes deterministically and MAY close the stream.
- **Guest:** MUST raise AsyncError (`#t_cap_invalid_async`) and MUST NOT treat remaining bytes as valid frames.

#### 3.1.5 Reserved fields (extensibility rule)

`flags`, `scope_id`, and `task_id` are reserved for future extension.

**Law (v1.0.0):** senders MUST set `flags=0`, `scope_id=0`, `task_id=0`.  
**Law (v1.x forward-compat):** receivers MUST ignore non-zero values and continue parsing deterministically.

---

### 3.2 kind values (normative)

| kind | Direction | Meaning |
|---:|---|---|
| 1 | guest → host | Command |
| 2 | host → guest | Event |

---

### 3.3 req_id rules (ACK/FAIL contract) (normative)

- `req_id` correlates a Command to exactly one immediate acceptance outcome.
- If `req_id != 0`, host MUST emit exactly one of:
  - **ACK** (op=101, kind=2), or
  - **FAIL** (op=102, kind=2)
  with the same `req_id`.
- Host MUST emit that ACK/FAIL after fully validating the command header and payload.
- If `req_id == 0`, host MUST NOT emit ACK/FAIL for that command.

**Law:** host MUST NOT emit both ACK and FAIL for the same `req_id`.

---

### 3.4 future_id rules (normative)

`future_id` identifies a guest-visible future.

- Commands that create/act on a future MUST carry a non-zero `future_id`.
- Events that resolve/cancel a future MUST carry the same `future_id`.
- Host MUST NOT emit a resolution event for `future_id=0`.

**Law:** For each `future_id`, host MUST eventually emit exactly one terminal event:
- **FUTURE_OK** (110), or
- **FUTURE_FAIL** (111), or
- **FUTURE_CANCELLED** (112).

---

### 3.5 Boundedness and backpressure (normative)

**Law:** Implementations MUST be bounded; no unbounded buffer growth is permitted.

Minimum host policy:
- Host MUST bound outstanding event bytes and inflight work.
- If bounds are exceeded, host MUST either:
  - (A) reject new commands deterministically with FAIL `t_async_overflow` (when `req_id != 0`), or
  - (B) close the stream (transport-level failure).

Guests MUST be prepared for either policy.

---

## 4. Events (host → guest) (normative)

### 4.0 Event opcode registry (normative)

| op | Name | Terminal? | Payload |
|---:|---|---:|---|
| 101 | ACK | no | empty |
| 102 | FAIL | no | `H4 code_len, H4 msg_len, code, msg` |
| 110 | FUTURE_OK | yes | `H4 value_len, value bytes` |
| 111 | FUTURE_FAIL | yes | `H4 code_len, H4 msg_len, code, msg` |
| 112 | FUTURE_CANCELLED | yes | empty |
| 120 | JOIN_RESULT | no | empty |
| 121 | JOIN_LIMIT | no | `H4 code_len, H4 msg_len, code, msg` |
| 200..299 | EXT_EVENT | n/a | host-defined |

**Law:** Unknown `EXT_EVENT` ops MUST be ignored (or logged) and MUST NOT be treated as protocol errors.

---

### 4.1 ACK (op=101, kind=2)

- `payload_len = 0`
- `req_id` echoed from the command

### 4.2 FAIL (op=102, kind=2)

Payload:

```
H4 code_len
H4 msg_len
code bytes
msg bytes
```

**Law:** `code` MUST match `[a-z0-9_]+` and MUST be stable.

### 4.3 FUTURE_OK (op=110, kind=2)

Payload:

```
H4 value_len
value bytes
```

**Law:** payload length MUST equal `4 + value_len`.

### 4.4 FUTURE_FAIL (op=111, kind=2)

Payload is identical to FAIL.

### 4.5 FUTURE_CANCELLED (op=112, kind=2)

Payload empty.

### 4.6 JOIN_RESULT (op=120, kind=2)

Payload empty.

### 4.7 JOIN_LIMIT (op=121, kind=2)

Payload is identical to FAIL. Recommended code: `t_async_join_limit`.

---

## 5. Commands (guest → host) (normative)

All commands are `kind=1`.

### 5.0 Command opcode registry (normative)

| op | Name | Requires future_id | Payload |
|---:|---|---:|---|
| 1 | REGISTER_FUTURE | yes | Source envelope (Variant A or B) |
| 2 | CANCEL_FUTURE | yes | empty |
| 3 | DETACH_TASK | no | `H4 owner_len, owner bytes` |
| 4 | JOIN_BOUNDED | no | `H4 fuelLo, H4 fuelHi` |

**Law:** Unknown command ops MUST be rejected with FAIL `t_async_unknown_op` when `req_id != 0`.

---

### 5.1 REGISTER_FUTURE (op=1)

Registers a future computation.

**Requirements:**
- `future_id` MUST be non-zero.
- Payload MUST be a “source envelope”.

#### Variant A: opaque source (variant=1)

```
H1 variant = 1
H4 body_len
body bytes
```

#### Variant B: cap-backed source (variant=2)

```
H1 variant = 2
H4 body_len        ; length of the rest of this envelope
HBYTES cap_kind
HBYTES cap_name
HBYTES selector
H4 params_len
params bytes
```

**Law:** Envelope lengths MUST match exactly; no trailing bytes.

**Host behavior:**
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- If accepted, host MUST eventually emit exactly one terminal resolution event for `future_id` (§3.4).
- If `future_id` is 0, host MUST FAIL with `t_async_bad_params`.
- If `future_id` already exists (pending or terminal), host MUST FAIL with `t_async_future_exists`.
- If source variant is unknown, host MUST FAIL with `t_async_unknown_source`.

---

### 5.2 CANCEL_FUTURE (op=2)

Requests cancellation of a future.

- `future_id` MUST be non-zero.
- Payload is empty in v1.

**Host behavior:**
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- If the future is already terminal, host MUST ACK and MUST NOT emit another terminal event.
- Otherwise, host MUST transition the future to terminal state and MUST emit exactly one FUTURE_CANCELLED (112) for that `future_id`.
- If `future_id` is unknown, host MUST FAIL with `t_async_missing_future`.

---

### 5.3 DETACH_TASK (op=3)

Payload:

```
H4 owner_len
owner bytes
```

**Law:** `owner_len` MUST match remaining payload bytes exactly.

---

### 5.4 JOIN_BOUNDED (op=4)

Payload:

```
H4 fuelLo
H4 fuelHi
```

**Host behavior:**
- If `req_id != 0`, host MUST emit ACK or FAIL per §3.3.
- Host MUST then emit exactly one of JOIN_RESULT (120) or JOIN_LIMIT (121).

---

### 5.5 Extension point: CAP-BACKED futures (normative)

Variant B is the primary extensibility mechanism for the async hub.

#### 5.5.1 Selector conventions (normative)

`selector` identifies the sub-operation executed by the host.

- MUST be non-empty UTF-8.
- MUST NOT contain NUL.

Recommended: ASCII dotted namespaces with version suffix:
- `files.read.v1`
- `files.list.v1`
- `net.connect.v1`
- `net.read.v1`
- `net.write.v1`
- `timer.sleep.v1`
- `exec.start.v1`

**Law:** selector versioning is part of the selector string. New versions MUST use a new suffix and MUST NOT change existing meaning.

#### 5.5.2 Params/result layouts (normative)

For each selector version, the spec MUST define deterministic Hopper layouts for:
- `params` bytes (REGISTER_FUTURE payload variant B),
- `FUTURE_OK` value bytes.

**Law:** No implicit host pointers. No ambient globals.

#### 5.5.3 Unknown selector behavior (normative)

If host does not implement a selector, it MUST FAIL REGISTER_FUTURE with code `t_async_unimplemented`.

#### 5.5.4 Policy routing (normative)

Hosts MAY allow/deny specific selectors by session/identity. Denials MUST be expressed as FAIL or FUTURE_FAIL with code `t_async_denied`.

---

## 6. Standard error codes (normative)

Hosts implementing `cap.async.v1` MUST support these codes in FAIL/FUTURE_FAIL:

- `t_async_bad_frame` — malformed ZAX1 frame (magic/version/kind/length/header)
- `t_async_payload` — payload too large / exceeds caps
- `t_async_unknown_op` — unknown command op
- `t_async_bad_params` — invalid payload for op/selector
- `t_async_unknown_source` — unknown source envelope variant
- `t_async_unimplemented` — selector or feature not implemented
- `t_async_denied` — selector exists but denied by policy
- `t_async_future_exists` — REGISTER_FUTURE reused an existing future_id
- `t_async_missing_future` — unknown future referenced
- `t_async_join_limit` — join fuel/limit exceeded
- `t_async_overflow` — bounded buffers/inflight limits exceeded

Guests SHOULD treat unknown codes as opaque.

---

## 7. Conformance requirements (normative)

A conforming **host** MUST:
1. Implement CAPS_OPEN for (`"async"`, `"default"`) and return a READABLE|WRITABLE handle.
2. Implement ZAX1 buffering (§3.0).
3. Enforce the ACK/FAIL contract for `req_id != 0` (§3.3).
4. Enforce terminal future resolution uniqueness (§3.4).
5. Emit FAIL/FUTURE_FAIL (no traps) for protocol errors.
6. Enforce a deterministic maximum payload length (§9).
7. Remain bounded (no unbounded buffer growth) (§3.5).

A conforming **guest** MUST:
1. Encode ZAX1 frames exactly as §3.1.
2. Buffer/decode frames per §3.0.
3. Treat FAIL/FUTURE_FAIL as explicit Result/Err (no traps).
4. Not assume read boundaries equal frame boundaries.

---

## 8. Stream semantics and chunking (normative)

ZAX1 frames travel over a byte stream. Reads may return partial frames.

**Law:** receivers MUST not assume read chunks align to frames; buffering is required (§3.0).

---

## 9. Limits (normative)

Hosts MUST enforce a deterministic maximum payload length.

### 9.1 Recommended default

- `max_payload_bytes = 1,048,576` (1 MiB)

**Law:** If `payload_len` exceeds `max_payload_bytes`, host MUST reject deterministically:
- If `req_id != 0`: emit FAIL `t_async_payload`.
- Otherwise: drop frame deterministically (and MAY close stream).

Guests SHOULD enforce the same bound during encode/decode.

---

## 10. Specimen / replay (normative)

All async command writes and event reads MUST be transcripted.

- Record every `res_write` to the async handle.
- Record every `req_read` from the async handle.
- Under replay, the host may be replaced by transcript-driven stream; `_ctl` open returns stable handle mapping.

---

## 11. Async hub profile rule (normative)

To prevent “70 protocols each talking their own lingo”, `cap.async.v1` defines a single hub with selector-defined operations.

**Law:** File I/O, networking, timers, subprocess control, and other blocking host services SHOULD be specified as selector-defined CAP-BACKED futures (§5.5), not separate stream magics.

---

## 12. Wire examples (informative, byte-exact)

All hex dumps below are complete frames (header + payload). Integers are little-endian.

### 12.1 REGISTER_FUTURE (Variant A opaque) → ACK → FUTURE_OK

Scenario:
- Guest registers `future_id=7` with `req_id=1`.
- Payload is Variant A (opaque) with body = `"hi"`.
- Host accepts and resolves the future with `"ok\n"`.

#### 12.1.1 Command (guest → host): REGISTER_FUTURE

Fields:
- magic=`"ZAX1"`
- version=1
- kind=1 (Command)
- op=1 (REGISTER_FUTURE)
- flags=0
- req_id=1
- scope_id=0
- task_id=0
- future_id=7
- payload = `[01][02 00 00 00][68 69]`
- payload_len=7

Hex:

```
5A 41 58 31  01 00  01 00  01 00  00 00
01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00
07 00 00 00
01 02 00 00 00  68 69
```

#### 12.1.2 Event (host → guest): ACK (op=101)

Fields:
- kind=2
- op=101 (`0x0065`)
- req_id=1
- payload_len=0

Hex:

```
5A 41 58 31  01 00  02 00  65 00  00 00
01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00
```

#### 12.1.3 Event (host → guest): FUTURE_OK (op=110)

Fields:
- kind=2
- op=110 (`0x006E`)
- future_id=7
- payload = `[03 00 00 00][6F 6B 0A]`
- payload_len=7

Hex:

```
5A 41 58 31  01 00  02 00  6E 00  00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00
07 00 00 00
03 00 00 00  6F 6B 0A
```

### 12.2 Unknown command op → FAIL

Scenario:
- Guest sends unknown op=9 with `req_id=2`.
- Host rejects with FAIL `t_async_unknown_op` and msg `"op"`.

FAIL payload:
- code=`"t_async_unknown_op"` (18 bytes)
- msg=`"op"` (2 bytes)
- payload_len = 8 + 18 + 2 = 28 (`0x1C`)

Event (kind=2, op=102 / `0x0066`), `req_id=2`, payload_len=28:

```
5A 41 58 31  01 00  02 00  66 00  00 00
02 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
1C 00 00 00
12 00 00 00  02 00 00 00
74 5F 61 73 79 6E 63 5F 75 6E 6B 6E 6F 77 6E 5F 6F 70
6F 70
```

### 12.3 CANCEL_FUTURE → ACK → FUTURE_CANCELLED

Scenario:
- Future 7 is pending.
- Guest requests cancellation with `req_id=3`.
- Host ACKs and emits terminal FUTURE_CANCELLED.

FUTURE_CANCELLED (kind=2, op=112 / `0x0070`), `future_id=7`, payload_len=0:

```
5A 41 58 31  01 00  02 00  70 00  00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00
00 00 00 00
```

---
