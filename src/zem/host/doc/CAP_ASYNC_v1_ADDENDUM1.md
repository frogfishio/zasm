# cap.async.v1 — Async Capability Pack ADDENDUM1

**Status:** NORMATIVE (this addendum is normative)  
**Applies to:** `cap.async.v1` / ZAX1 version 1 frames  
**Baseline:** `doc/CAP_ASYNC_v1.md` (the main spec)  
**Addendum id:** `cap.async.v1.addendum1`  

This addendum exists to lock down the parts of `cap.async.v1` that are currently implemented “close but not by the book”, and to specify the missing behaviors that the host MUST implement to be considered conformant.

The baseline spec remains the source of truth **except where this addendum explicitly overrides it**.

---

## A1. Terminology used in this addendum

- **Handle**: the lembeh stream returned by `_ctl` CAPS_OPEN.
- **Session**: one logical async hub instance opened by CAPS_OPEN. A session may be accessed by multiple handles (e.g., cloned/duplicated handles or multiple guests) depending on host policy.
- **Owner**: a host-side string label attached to a task (from DETACH_TASK payload). It is informative, but MUST be tracked.

---

## A2. Clarification: the ZAX1 header `flags` field is a timeout

### A2.1 `flags` interpretation (override)

In the baseline spec, `flags` is “reserved”. In practice, guest code has been emitting a per-command timeout value, and host code currently ignores it.

**Override (v1.0.0 + addendum1):**
- `flags` (u16) in the 48-byte ZAX1 header SHALL be interpreted as `timeout_ms`.
- `timeout_ms = 0` means **no timeout**.
- `timeout_ms > 0` means the host MUST treat this command as having a deadline **timeout_ms milliseconds** from the moment the host has fully received and validated the frame.

**Forward-compat note:** This uses the entire 16-bit field. Future v1.x extensions MUST NOT redefine `flags` without a new ZAX magic/version.

### A2.2 Timeout applies to REGISTER_FUTURE

If a REGISTER_FUTURE command (op=1) has `timeout_ms > 0`, then:

- The host MUST start a timer after emitting ACK (if `req_id != 0`) and after the future is placed into the host’s “pending” set.
- If the future is not terminal before the deadline, the host MUST cancel it deterministically:
  - The host MUST transition the future to terminal state.
  - The host MUST emit **FUTURE_CANCELLED (112)** for that `future_id`.

**Law:** A timeout-triggered cancellation is semantically identical to CANCEL_FUTURE.

### A2.3 Timeout applies to JOIN_BOUNDED

If a JOIN_BOUNDED command (op=4) has `timeout_ms > 0`, the host MUST treat this as an additional cap on waiting.

- If JOIN_BOUNDED cannot complete successfully before the deadline, the host MUST emit **JOIN_LIMIT (121)**.
- If both fuel and timeout are provided, the host MUST stop when **either** limit is exceeded.

### A2.4 Determinism constraints

- In non-replay mode, the host MAY use a coarse timer.
- In Specimen/replay mode, the timeout outcome MUST be deterministic under transcript.

Minimal conforming approach:
- Use wall-clock only to decide when to *schedule* a cancel, but record the resulting emitted event bytes in the transcript so replay reproduces it exactly.

---

## A3. DETACH_TASK payload MUST be parsed and tracked

### A3.1 DETACH_TASK payload validation (reinforce)

DETACH_TASK (op=3) payload:

```
H4 owner_len
owner bytes
```

**Law:** `owner_len` MUST exactly equal the remaining payload bytes.

If invalid:
- If `req_id != 0`, host MUST emit FAIL (102) with `code = t_async_bad_params`.

### A3.2 Owner tracking (new)

On a valid DETACH_TASK:
- The host MUST parse the owner bytes as UTF-8.
- The host MUST store this `owner` string associated with the referenced `task_id` (and/or the current task context per host implementation).

If UTF-8 validation fails:
- The host MUST treat it as `t_async_bad_params`.

**Note:** Owner is currently informative-only; future addenda may make owner observable via meta or tracing.

---

## A4. JOIN_BOUNDED payload MUST be parsed and enforced

### A4.1 JOIN_BOUNDED payload parsing (reinforce)

JOIN_BOUNDED (op=4) payload:

```
H4 fuelLo
H4 fuelHi
```

Define:
- `fuel = ((u64)fuelHi << 32) | (u64)fuelLo`.

**Law:** Payload length MUST be exactly 8 bytes.

If invalid:
- If `req_id != 0`, host MUST FAIL with `t_async_bad_params`.

### A4.2 Fuel semantics (new)

Fuel is a **bounded join budget**.

**Law:** Host MUST enforce that JOIN_BOUNDED completes with exactly one of:
- JOIN_RESULT (120), or
- JOIN_LIMIT (121).

**Interpretation:**
- The host may interpret `fuel` as “maximum join work budget” (steps, polls, or time slices). The exact mapping MUST be deterministic for a given host build.
- `fuel = 0` MUST be treated as “no fuel allowed” and MUST immediately yield JOIN_LIMIT unless the scope is already joinable.

**Recommended (but not required):** interpret `fuel` as a maximum number of scheduler/poll iterations.

### A4.3 JOIN_LIMIT payload

JOIN_LIMIT (121) payload MUST follow the standard FAIL payload layout (code+msg).

Recommended:
- `code = t_async_join_limit`
- `msg = "join limit exceeded"`

---

## A5. Cancellation delivery MUST broadcast across handles in the same session

### A5.1 Scope/task semantics (clarify + tighten)

Hosts may internally group futures into scopes/tasks. Implementations that support JOIN_BOUNDED over a scope MUST ensure that cancellation and terminal events are visible consistently.

**Law (session broadcast):** If a future becomes terminal via cancellation (explicit cancel, join-driven cancel, or timeout), the host MUST make that terminal state visible to **all handles within the same session** that could observe that `future_id`.

This closes the current gap where FUTURE_CANCELLED is only emitted to the joining handle.

### A5.2 Join-driven cancellation (required behavior)

If the host implements structured concurrency such that joining a scope implies cancelling unfinished child work, then:

- Upon a successful JOIN_BOUNDED (emitting JOIN_RESULT), the host MUST ensure any still-pending futures in the joined scope are cancelled.
- For each such future, host MUST emit FUTURE_CANCELLED (112) exactly once.

**Law:** Cancellation broadcast MUST be deterministic in ordering within a handle’s event stream.

Recommended deterministic ordering rule:
- Cancel child futures in ascending `future_id`, then emit JOIN_RESULT.

If the host does **not** cancel on join, it MUST document that policy via meta (see A7) and MUST NOT emit FUTURE_CANCELLED as a join side-effect.

---

## A6. Selector cancellation callback MUST be wired

Guest/host selector execution may allocate resources that should be freed on cancellation.

**Requirement:** Host implementations MUST provide a cancellation path to selector implementations.

When a pending future is cancelled for any reason (CANCEL_FUTURE command, timeout, or join-driven cancellation):
- The host MUST invoke the selector’s cancel callback (if provided) exactly once.
- The callback MUST be invoked before emitting the terminal FUTURE_CANCELLED event (so the selector can stop producing output deterministically).

If no cancel callback exists:
- Host MUST still emit FUTURE_CANCELLED and clean up host-side bookkeeping.

---

## A7. Meta MUST advertise operational limits (minimal schema)

The baseline spec allows `meta` to be opaque. For interop and guest adaptability, this addendum defines a minimal meta schema that hosts SHOULD provide.

### A7.1 Meta format

If `meta` is non-empty, it SHOULD be Hopper-packed bytes with the following layout:

```
H4 max_payload_bytes
H4 max_futures_per_handle
H4 max_event_queue_bytes
H4 flags
```

Where:
- `max_payload_bytes` MUST be the enforced maximum frame payload size (recommend 1,048,576).
- `max_futures_per_handle` is the per-handle outstanding future cap (current host behavior: 32).
- `max_event_queue_bytes` is the bounded event buffer capacity.
- `flags` is reserved for future addenda (MUST be 0 in addendum1).

If a host cannot or will not provide this meta:
- It MAY return empty meta.

Guests MUST treat unknown/short meta as “no information”.

---

## A8. Handle end cleanup (required)

Current behavior notes indicate no cleanup beyond “futures owned by that handle”. This addendum standardizes cleanup requirements.

When a handle is ended/closed (via ENDABLE semantics or transport closure):

- The host MUST:
  1. Cancel any still-pending futures **owned by that handle**.
  2. Invoke selector cancel callbacks for those futures (A6).
  3. Transition those futures to terminal state and emit FUTURE_CANCELLED where observable.

- The host MUST release host-side bookkeeping for:
  - the handle,
  - its per-handle future slots,
  - any pending event queue memory owned by that handle.

**Note:** If host policy shares futures across handles, “ownership” MUST be defined consistently. Minimum acceptable definition: “the handle that REGISTER_FUTURE’d the future is the owner.”

---

## A9. Error code alignment (clarify)

Where the baseline spec currently uses broader language, addendum1 requires these specific codes:

- Malformed ZAX1 header/payload length issues: `t_async_bad_frame` or `t_async_payload` (as appropriate).
- Bad command parameters (including invalid DETACH_TASK payload or JOIN_BOUNDED payload): `t_async_bad_params`.
- JOIN_BOUNDED limit exceeded: `t_async_join_limit` (JOIN_LIMIT payload code).

Hosts MUST keep these codes stable.

---

## A10. Conformance checklist (addendum1)

A host claiming conformance to `cap.async.v1` + addendum1 MUST:

1. Interpret ZAX1 `flags` as `timeout_ms` and enforce timeout-driven cancellation (A2).
2. Parse and validate DETACH_TASK owner payload and store owner (A3).
3. Parse and enforce JOIN_BOUNDED fuel and emit JOIN_RESULT or JOIN_LIMIT (A4).
4. Broadcast cancellation terminalization across handles within the same session (A5).
5. Invoke selector cancel callbacks on all cancellation paths (A6).
6. Advertise limits via meta if meta is non-empty, using A7 schema (A7).
7. Cancel and clean up owned pending futures on handle end (A8).

---

## A11. Notes for implementers (informative)

- Timeout implementation can be coarse. The key is that the **resulting event stream** is deterministic and recordable.
- JOIN fuel is intended as a boundedness tool. Even a simple deterministic “poll budget” implementation is acceptable.
- Broadcasting cancellation is easiest if the session has a single authoritative future table, and each handle has its own outgoing event queue.

``` 
