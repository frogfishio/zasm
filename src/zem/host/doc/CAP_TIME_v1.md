# Capability: cap.time.v1 (Normative)

This document defines the time capability for ABI v1.0.

---

## 1. Capability identity

- kind: `time`
- name: `default`
- version: `1`
- canonical id: `cap.time.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("time","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: CLOCK_WALL
- 2: CLOCK_TICK
- 3: SLEEP

All modes return a stream handle.

### 3.1 CLOCK_WALL (mode = 1)

Params: empty (HBYTES len=0)

Stream record (single record):

```
H8 unix_ms
```

This mode is nondeterministic and MUST be recorded/replayed.

### 3.2 CLOCK_TICK (mode = 2)

Params:

```
H4 tick_mode     ; 0 = deterministic, 1 = wallclock
HBYTES params    ; optional, may be empty
```

Stream record (one or more records):

```
H8 tick
```

If `tick_mode=0`, ticks MUST be deterministic and replayable.

### 3.3 SLEEP (mode = 3)

Params:

```
H4 ms
```

Stream record (single record):

```
H1 ok    ; 1 on completion
```

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
