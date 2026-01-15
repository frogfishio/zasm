# Capability: cap.sys.v1 (Normative)

This document defines the system info capability for ABI v1.0.

---

## 1. Capability identity

- kind: `sys`
- name: `default`
- version: `1`
- canonical id: `cap.sys.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("sys","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: INFO

All modes return a stream handle. INFO yields a single record.

### 3.1 INFO (mode = 1)

Record layout:

```
H4 cpu_count
H8 mem_bytes
HSTR platform    ; "linux" | "mac" | "windows" | "other"
HSTR arch        ; "x86_64" | "arm64" | "other"
```

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
