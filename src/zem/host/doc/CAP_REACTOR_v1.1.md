# Capability: cap.reactor.v1 (Normative)

This document defines the reactor capability for ABI v1.x.
Reactor provides a bidirectional event/command stream for interactive
systems (UI, telemetry, robotics, HMI) with deterministic framing.

Design goal: one world-class reactor, no parallel “second reactor.”

Normative rules:
- All multi-byte integers are little-endian.
- Frames are self-describing (magic + version + lengths).
- All payloads use Hopper binary layouts (H1/H2/H4/H8, HSTR, HBYTES).
- No native pointers on the wire; all payload bytes are flat.
- Senders MUST set reserved fields/bits to 0; receivers MUST reject
  frames that violate MUST-level constraints.

---

## 1. Capability identity

- kind: `reactor`
- name: `default`
- version: `1`
- canonical id: `cap.reactor.v1`

---

## 2. Roles and Directionality

- **Host** is the world: emits **events** (kind=1) to the guest.
- **Guest** is the brain: emits **commands** (kind=2) to the host.
- **Acks** (kind=3) can be sent by either side to confirm handling.
- **Log** (kind=4) is guest -> host unless the host explicitly allows both.
- **Err** (kind=5) is host -> guest unless the host explicitly allows both.

---

## 3. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("reactor","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

Recommended keys (optional):
- `event_types`
- `command_ops`
- `max_line_bytes`
- `max_event_queue`
- `max_cmd_queue`
- `supports_ack`
- `supports_batch`
- `supports_sensor`
- `max_id_len`
- `max_rid_len`
- `supports_compress`
- `drop_policy`          ; "drop_oldest" | "reject_new" (deterministic)
- `max_inflight`

If declared, these values are normative limits: guests MUST respect them and
hosts MUST enforce them.

---

## 4. CAPS_OPEN modes

Mode values (H4):
- 1: SESSION

### 4.1 SESSION (mode = 1)

Params:

```
HSTR session_id
H4 idle_timeout_ms    ; 0 = no idle timeout
```

Response:
The opened handle is a duplex reactor stream.

Stream directionality (normative):
- Guest → Host: guest sends frames by calling `res_write(handle, ...)`.
  Those frames MUST be ZRX1 frames with kind = 2 (cmd) or kind = 4 (log)
  unless the host explicitly declares otherwise.
- Host → Guest: guest receives frames by calling `req_read(handle, ...)`.
  Those frames MUST be ZRX1 frames with kind = 1 (event) or kind = 5 (err)
  unless the host explicitly declares otherwise.

Acks (kind=3) MAY be emitted by either side if `supports_ack` is true.

All frames are binary ZRX1 records defined below.

---

## 5. Reactor message envelope (ZRX1)

### 5.1 Frame header (fixed)

A reactor frame is a single self-delimiting ZRX1 record.

All multi-byte integers are **little-endian**.

Header layout (32 bytes):

| Off | Size | Field        | Meaning |
|-----|------|--------------|---------|
| 0   | H4   | magic        | ASCII "ZRX1" (0x5A 0x52 0x58 0x31) |
| 4   | H2   | v            | Protocol version (1) |
| 6   | H2   | kind         | 1=event, 2=cmd, 3=ack, 4=log, 5=err |
| 8   | H4   | flags        | bit0=batch, bit1=compressed, bits>=2 reserved (MUST be 0) |
| 12  | H8   | seq          | Per-sender monotonic sequence number |
| 20  | H4   | id_len       | Bytes of `id` that follow |
| 24  | H4   | rid_len      | Bytes of `rid` that follow |
| 28  | H4   | payload_len  | Bytes of `payload` that follow |

Immediately following the header:

```
u8[id_len]       id
u8[rid_len]      rid
u8[payload_len]  payload
```

The total frame length in bytes is:

```
frame_len = 32 + id_len + rid_len + payload_len
```

### 5.1.1 Header validation (normative)

Receivers MUST validate, in a bounds-checked and deterministic manner:

1. **Minimum length:** input MUST be at least 32 bytes.
2. **Magic:** `magic == "ZRX1"`, otherwise reject.
3. **Version:** `v == 1`, otherwise reject.
4. **Kind:** `kind` MUST be one of `{1,2,3,4,5}`, otherwise reject.
5. **Flags:** bits >= 2 MUST be 0. If any unknown/reserved flag bit is set, receivers MUST reject the frame.
6. **Lengths and bounds:**
   - `frame_len = 32 + id_len + rid_len + payload_len` MUST NOT overflow and MUST be <= input length.
   - If `max_line_bytes` is declared, `frame_len` MUST be `<= max_line_bytes`.
   - If `max_id_len`/`max_rid_len` are declared, `id_len`/`rid_len` MUST be within those bounds.
7. **Presence rules:**
   - `id_len` MUST be > 0 for all kinds.
   - `rid_len` MUST be > 0 for kinds `{2 (cmd), 3 (ack), 5 (err)}`.
   - `rid_len` MAY be 0 for kind `{1 (event), 4 (log)}`.

If any MUST-level validation fails, the receiver MUST treat the frame as invalid (see §14 Stream error handling).

### 5.2 Sequencing (per sender)

Each sender (host, guest) maintains its own monotonically increasing `seq`.

Receiver rules (normative):
- The receiver MUST track `expect_seq` per sender.
- A frame with seq == expect_seq is a duplicate. Receivers MUST reject duplicates
  unless the host declares a policy to drop duplicates deterministically.
- A frame with seq != expect_seq + 1 is a gap. Receivers MUST reject gaps
  unless the host declares `allow_seq_gap` semantics.

Sequencing constraints are enforced per stream direction (host→guest and guest→host).

### 5.3 id / rid rules

- `id` is REQUIRED for all kinds.
- `rid` is REQUIRED for **cmd**, **ack**, and **err**.
- `id="$bridge"` is reserved for session-level messages.
- For correlation:
  - On ack (kind=3) and err (kind=5), `rid` MUST equal the rid of the command being
    acknowledged/failed.
  - A receiver MUST treat an unknown `rid` as unrelated traffic: it MAY ignore or
    log it, but MUST NOT treat it as a valid response to another request.
- `rid` MUST be unique per sender for in-flight commands.
- `rid` MAY be present on **event** frames to model async responses.

### 5.4 Batching (high-throughput)

If `flags.bit0` (batch) is set, the payload bytes contain a compact BatchV1 body.
The outer frame remains a normal ZRX1 frame with its own `seq`, `id`, and optional `rid`.

BatchV1 payload layout (uncompressed form):

```
H4 n
repeat n:
  H2 kind              ; 1/2/3/4/5
  H2 rsv16             ; MUST be 0
  H4 id_len
  H4 rid_len
  H4 payload_len
  u8[id_len]       id
  u8[rid_len]      rid
  u8[payload_len]  payload
```

Batch rules (normative):

- `n` MUST be > 0.
- Each inner record MUST satisfy the same presence rules as a standalone frame (id required; rid required for cmd/ack/err).
- Inner records do **not** carry `magic`, `v`, `flags`, or `seq`.
- Sequencing is derived from the outer `seq`:
  - The outer `seq` is the sequence number of the **first** inner record.
  - Inner record `i` (0-based) is treated as having `seq = outer.seq + i`.
  - Receivers MUST advance their expected sequence by `n` on successful batch acceptance.
- Inner records MUST NOT encode compression or batching inside themselves. (Compression, if used, applies to the outer payload bytes only; see §6.5.1.)

If a batch is invalid, the receiver MUST treat the entire outer frame as invalid.

### 5.5 Frame size bounds (normative)

Receivers MUST enforce:
- `id_len + rid_len + payload_len + header` <= `max_line_bytes`.
- `id_len` and `rid_len` <= `max_id_len` and `max_rid_len` if declared in schema.

---

## 6. Payloads

### 6.1 Event payload (kind = 1)

```
HSTR type       ; event type name (caller-defined)
H8 ts_ms        ; 0 if unknown
H4 data_len
H4 meta_len
u8[data_len] data
u8[meta_len] meta
```

Validation (normative):
- `type` MUST be valid UTF-8 and MUST be non-empty.
- `data_len` + `meta_len` MUST equal the remaining bytes exactly.
- Receivers MUST bounds-check all lengths.

**Law:** `type` is a free-form string. No fixed ontology is required.

**Performance rule:** `data` and `meta` are opaque bytes and MUST NOT be parsed
on the hot path unless the receiver explicitly opts in.

### 6.2 Command payload (kind = 2)

```
HSTR type       ; command type name (caller-defined)
H2 cflags       ; command flags (bit0 echo, bit1 soft, bit2 animate, bit3 async_ok)
H4 data_len
u8[data_len] data
```

Validation (normative):
- `type` MUST be valid UTF-8 and MUST be non-empty.
- Unknown bits in cflags MUST be ignored.
- `data_len` MUST equal the remaining bytes exactly.

**Law:** `type` is a free-form string. No fixed ontology is required.

### 6.3 Ack payload (kind = 3)

```
H1 ok           ; 0 or 1
H4 err_len
u8[err_len] err  ; UTF-8, empty if ok=1
```

Rules (normative):
- If ok == 1, err_len MUST be 0.
- If ok == 0, err_len MUST be > 0 and `err` MUST be valid UTF-8.
- `rid` MUST be present and MUST match the command rid.

`rid` MUST match the command being acknowledged.

### 6.4 Log payload (kind = 4)

```
H1 level        ; 1=debug,2=info,3=warn,4=error
H4 msg_len
H4 meta_len
u8[msg_len]  msg
u8[meta_len] meta
```

### 6.5 Err payload (kind = 5)

Payload layout:

```
H4 code_len
H4 msg_len
u8[code_len] code
u8[msg_len]  msg
```

Rules (normative):
- `code` MUST be ASCII `[a-z0-9_]` and non-empty.
- `msg` MUST be valid UTF-8 and MAY be empty.
- `code_len + msg_len` MUST equal the remaining bytes exactly.
- `rid` MUST be present and MUST match the command rid if the err is correlated.

### 6.5.1 Compression (normative)

If `flags.bit1` (compressed) is set, the sender indicates that the *payload region* (and only the payload region) is compressed.
The fixed 32-byte header and the `id`/`rid` bytes are never compressed.

Compression wrapper (CompressionV1):

```
H4 raw_len
u8[payload_len - 4] lz4_block
```

Where:
- `raw_len` is the exact number of bytes that MUST result after decompression.
- `lz4_block` is a single LZ4 block containing the uncompressed payload bytes (either a normal payload layout or BatchV1).

Requirements:
- Hosts MUST declare `supports_compress=true` in CAPS_DESCRIBE to send compressed frames.
- Receivers that do not support compression MUST reject compressed frames.
- `payload_len` MUST be >= 4.
- Receivers MUST bounds-check `raw_len` against the same limits as uncompressed payloads:
  - If `max_line_bytes` is declared, the *effective* frame length after decompression MUST still be `<= max_line_bytes`.
  - `raw_len` MUST be consistent with the payload layout being decoded (e.g., it MUST contain a full EventV1/CommandV1/etc. or a full BatchV1 body).
- Decompression MUST be deterministic:
  - If decompression fails, or if the produced byte count is not exactly `raw_len`, the receiver MUST reject the frame.

Batch + compression:
- If both `batch` and `compressed` bits are set, the decompressed bytes MUST be a valid BatchV1 body.

### 6.6 Sensor payload (optional pattern)

If `type` is sensor-driven, `data` MAY contain SensorV1 records:

```
H4 n
repeat n:
  HSTR topic
  H8 ts_ns
  HBYTES sample
```

This allows high-rate sensor streams without introducing a second reactor.

---

## 7. Structured Value Encoding (ReactorKV)

If `data` or `meta` needs structured content, use ReactorKV (not JSON):

```
H4 n
repeat n:
  HSTR key
  HBYTES value
```

Keys are UTF-8; values are opaque bytes.

---

## 8. Required Session Hello

The host MUST send a `hello` event as the first host→guest frame of a session.
It MUST be a normal event frame (kind=1) whose event `type` is "hello".
`id` MUST be "$bridge" and `rid` MUST be empty.

The HelloV1 record MUST be carried in the event `data` bytes (meta_len MAY be 0).

```
HSTR proto      ; e.g. "zrx1"
HSTR app        ; host-defined app name
HSTR platform   ; e.g. "web" | "native" | "embedded"
H4 cap_count
repeat cap_count:
  HSTR cap
```

**Law:** `cap` strings MUST include `cap.reactor.v1` and MAY include
`cap.reactor.sensor.v1` if SensorV1 is used.

---

## 9. Minimal UI Semantics (Recommended)

These are recommended mappings for `data` and `meta` using ReactorKV:

- **mount**: `meta` SHOULD include `type` (e.g., "button", "input") and optional props.
- **change**: `data` SHOULD include key `v` for new value.
- **click/submit/focus/blur**: `data` MAY be empty.
- **set_value**: `data` SHOULD include key `v` for new value.
- **set_enabled/set_visible**: `data` SHOULD include key `v` as HBYTES encoding of H1 (0/1).

These are conventions; the ABI only requires binary encoding and determinism.

---

## 10. Backpressure and QoS (Normative)

Reactor is high-throughput. The host MUST implement deterministic backpressure:

- Drop policy: MUST be deterministic and MUST be declared in CAPS_DESCRIBE as
  `drop_policy` = "drop_oldest" or "reject_new".
- Queue bounds: MUST enforce `max_event_queue` and `max_cmd_queue`.
- Priority: Host MAY implement priority by routing topics; if so, priority
  MUST be encoded in `meta` using ReactorKV key `prio` (H4, smaller = higher).
- Acknowledgement: If `supports_ack` is true, host MUST send ack for
  mutating commands unless `flags.bit3` (async_ok) is set.
- Overflow signaling: When a frame is dropped or rejected due to queue bounds,
  the host MUST emit an err (kind=5) with `code = "t_reactor_overflow"`.
  Hosts MAY rate-limit overflow errs but MUST do so deterministically.

---

## 11. Session lifecycle (Normative)

- Idle timeout MUST close the session handle cleanly after `idle_timeout_ms`.
- Host MAY send a final `err` with code `t_reactor_idle_timeout` before closing.
- Guest MAY terminate the session by calling `res_end(handle)`.

---

## 12. Ping-Pong Example (C, client-side)

This example is byte-layout oriented. It constructs a ZRX1 frame into a local
byte buffer. In an actual zingcore/lembeh environment, bytes are written from
linear memory offsets, not native pointers.

```c
// Minimal helpers (little-endian)
static void w32(uint8_t* p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void w16(uint8_t* p, uint16_t v) { p[0]=v; p[1]=v>>8; }

// Build a ZRX1 command frame with type="ping"
// kind=2 (cmd), id="sensor:0", rid="r1", data=empty
int build_ping(uint8_t* out, uint32_t out_cap) {
  const char* id = "sensor:0";
  const char* rid = "r1";
  const char* type = "ping";
  uint32_t id_len = 8, rid_len = 2, type_len = 4;

  uint32_t payload_len = 4 + type_len + 2 + 4 + 0; // HSTR type + H2 cflags + H4 data_len
  uint32_t frame_len = 4+2+2+4+8+4+4+4 + id_len + rid_len + payload_len;
  if (frame_len > out_cap) return -1;

  uint8_t* p = out;
  w32(p+0, 0x3158525A);        // "ZRX1"
  w16(p+4, 1);                 // v
  w16(p+6, 2);                 // kind = cmd
  w32(p+8, 0);                 // flags
  w32(p+12, 1); w32(p+16, 0);  // seq = 1 (H8, little-endian)
  w32(p+20, id_len);
  w32(p+24, rid_len);
  w32(p+28, payload_len);
  memcpy(p+32, id, id_len);
  memcpy(p+32+id_len, rid, rid_len);

  uint8_t* q = p + 32 + id_len + rid_len;
  w32(q+0, type_len);          // HSTR type
  memcpy(q+4, type, type_len);
  w16(q+4+type_len, 0);        // cflags
  w32(q+6+type_len, 0);        // data_len = 0
  return (int)frame_len;
}

// Send ping
uint8_t buf[256];
int n = build_ping(buf, sizeof(buf));
if (n > 0) {
  // NOTE: Replace /*ptr=*/0 with the offset where `buf` resides in guest linear memory.
  // Pseudo-call: in a real guest, `ptr` is a linear-memory offset.
  res_write(h, /*ptr=*/0, n);
}

// Read until a pong event arrives (type="pong")
// In real code, parse ZRX1 frames and match event type.
```

---

## 13. Queueing, backpressure, and fuel

- Hosts MUST enforce `max_line_bytes` for all incoming frames (header + payload).
- Hosts MUST bound event and command queues to `max_event_queue` and `max_cmd_queue`.
- Overflow policy MUST be deterministic (drop oldest or reject new).
- Reactor processing SHOULD account for fuel/budget (implementation-defined).

---

## 14. Stream error handling (Normative)

There are two distinct error planes:

1) `_ctl` plane (open/describe): `_ctl` failures MUST be encoded using the ZCL1 error envelopes defined by the control layer.

2) Reactor stream plane (runtime frames): frame-level failures MUST be handled deterministically.

### 14.1 Invalid frames

A receiver encountering an invalid ZRX1 frame (magic/version/flags/length violations, malformed payload layouts, or failed decompression) MUST do all of the following:

- **Reject the frame**: it MUST NOT be delivered to application handlers.
- **Be deterministic**: for the same byte stream input, the receiver MUST take the same action.

Additionally, the receiver MUST choose exactly one of these policies (and SHOULD declare it in CAPS_DESCRIBE as `bad_frame_policy`):

- **drop**: silently drop the invalid frame and continue.
- **err+drop**: emit a reactor `err` frame (kind=5) with a stable code, then drop.
- **err+close**: emit a reactor `err` frame (kind=5) with a stable code, then close the stream.

If a host does not declare a policy, the RECOMMENDED default is `err+close`.

### 14.2 Standard reactor error codes

When emitting a reactor `err` frame (kind=5), implementations SHOULD use these stable codes for protocol-level failures:

- `t_reactor_bad_magic`
- `t_reactor_bad_version`
- `t_reactor_bad_flags`
- `t_reactor_bad_len`
- `t_reactor_bad_payload`
- `t_reactor_bad_compress`
- `t_reactor_seq_dup`
- `t_reactor_seq_gap`
- `t_reactor_rid_state`
- `t_reactor_overflow`
- `t_reactor_unsupported`

The `msg` field MAY include a short human-readable hint (e.g. "magic", "payload", "lz4").

### 14.3 Recoverable vs fatal

- Protocol-level frame errors are **recoverable** at the stream layer (drop or close as per policy).
- Memory safety or ABI contract violations (invalid pointers, insufficient output buffer capacity in host implementations, etc.) are **fatal** and are outside ZRX1 framing; implementations MAY terminate the session.

---

## 15. Worked wire examples (normative)

### 15.0 Minimal RPC-like cmd/err example (wire)

This is a compact example of a **command** frame followed by an **err** frame.
It demonstrates:
- ZRX1 header lengths
- required `id` and `rid` on cmd/err
- ErrV1 payload encoding

Assumptions:
- id = "ui" (2 bytes)
- rid = "r1" (2 bytes)
- cmd payload is CommandV1 with `type="set"`, `cflags=0`, `data_len=0`

CommandV1 payload bytes:
```
HSTR type="set"  => 03 00 00 00 73 65 74
H2  cflags=0      => 00 00
H4  data_len=0    => 00 00 00 00
```
So `payload_len = 7 + 2 + 4 = 13`.

Frame length:
`32 + id_len(2) + rid_len(2) + payload_len(13) = 49` bytes.

ErrV1 payload example:
- code="t_reactor_bad_payload"
- msg="denied"

ErrV1 payload bytes:
```
H4 code_len
H4 msg_len
u8[code_len] code
u8[msg_len]  msg
```

Implementations MUST validate all lengths exactly; receivers MUST NOT accept trailing bytes.

### 15.1 Minimal hello event (host → guest)

Assumptions:
- id = "$bridge" (7 bytes)
- rid = "" (0 bytes)
- event payload:
  - type = "hello" (5 bytes)
  - ts_ms = 0
  - data = HelloV1 bytes (example below)
  - meta = empty

HelloV1 example (data bytes):
```
HSTR proto    = "zrx1"
HSTR app      = "demo"
HSTR platform = "native"
H4 cap_count  = 1
  HSTR cap    = "cap.reactor.v1"
```

Senders MUST ensure all lengths are consistent and receivers MUST validate:
`payload_len == (len(type)+4) + 8 + 4 + 4 + data_len + meta_len`.

### 15.2 Ack for a command (either direction)

Ack payload for ok=1:
```
H1 ok = 1
H4 err_len = 0
```

Ack payload for ok=0 with err="denied":
```
H1 ok = 0
H4 err_len = 6
u8[6] "denied"
```

In both cases, the ack frame MUST include the same `rid` as the command.

---

## 16. Determinism and replay

If the host exposes nondeterministic event sources, it MUST capture and replay
event streams under Specimen to ensure deterministic outputs.

---

## 17. Conformance checklist (Normative)

A conforming implementation MUST satisfy the following:

### 17.1 Host MUST

1. Implement `_ctl` open for `kind="reactor", name="default"` and return a duplex stream handle.
2. Send exactly one `hello` event as the first host→guest frame of each session (§8).
3. Enforce `max_line_bytes`, `max_id_len`, `max_rid_len`, and queue limits if declared in CAPS_DESCRIBE.
4. Reject frames that violate MUST-level header/payload rules (§5–§6).
5. Apply a deterministic bad-frame policy (§14).
6. Enforce deterministic backpressure and overflow signaling (§10).

### 17.2 Guest MUST

1. Send only valid ZRX1 frames on the reactor stream (guest→host).
2. Provide `id` on all frames; provide `rid` on cmd/ack/err frames.
3. Maintain per-sender monotonic `seq` and obey host-declared gap/dup policy (§5.2).
4. Validate all received frames and payload layouts deterministically (§5–§6).
5. Respect host limits declared in CAPS_DESCRIBE.

### 17.3 Both sides MUST

1. Use little-endian encoding for all multi-byte integers.
2. Set reserved fields/bits to 0 on send.
3. Treat unknown `rid` as unrelated traffic (ignore or log), and MUST NOT mis-correlate it.

