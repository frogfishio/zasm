# Capability: cap.entropy.v1 (Normative)

This document defines the entropy capability for ABI v1.0.

---

## 1. Capability identity

- kind: `entropy`
- name: `default`
- version: `1`
- canonical id: `cap.entropy.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("entropy","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: RANDOM
- 2: RANDOM_DETERMINISTIC

All modes return a stream handle that yields raw bytes (not HBYTES).

### 3.1 RANDOM (mode = 1)

Params:

```
H4 len
```

The stream yields exactly `len` bytes of entropy.
This mode is nondeterministic and MUST be recorded/replayed.

### 3.2 RANDOM_DETERMINISTIC (mode = 2)

Params:

```
H4 len
HBYTES seed
```

The stream yields exactly `len` bytes deterministically derived from `seed`.

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
