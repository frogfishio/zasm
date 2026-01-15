# Capability: cap.fs.watch.v1 (Normative)

This document defines the filesystem watch capability for ABI v1.0.

---

## 1. Capability identity

- kind: `fs.watch`
- name: `default`
- version: `1`
- canonical id: `cap.fs.watch.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("fs.watch","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: WATCH

### 3.1 WATCH (mode = 1)

Params:

```
HSTR path
H1 recursive    ; 0 or 1
```

Response:
- Returns a stream handle.
- The stream is a concatenation of EventRecord frames.

EventRecord layout:

```
H1  kind         ; 1=create, 2=modify, 3=remove
HSTR path
```

Order MUST be deterministic for a given event stream. If the host cannot
guarantee ordering, it MUST document nondeterminism and require replay.

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
