# Capability: cap.proc.v1 (Normative)

This document defines the process/environment capability for ABI v1.0.

---

## 1. Capability identity

- kind: `proc`
- name: `default`
- version: `1`
- canonical id: `cap.proc.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("proc","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: ENV
- 2: ARGV
- 3: CWD
- 4: HOSTNAME
- 5: UIDGID

All modes return a stream handle. Each mode yields a single record.

### 3.1 ENV (mode = 1)

Record layout:

```
H4 n
repeat n:
  HSTR key
  HSTR value
```

### 3.2 ARGV (mode = 2)

Record layout:

```
H4 n
repeat n:
  HSTR arg
```

### 3.3 CWD (mode = 3)

Record layout:

```
HSTR cwd
```

### 3.4 HOSTNAME (mode = 4)

Record layout:

```
HSTR hostname
```

### 3.5 UIDGID (mode = 5)

Record layout:

```
H4 uid
H4 gid
```

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
