# Capability: cap.kv.v1 (Normative)

This document defines the key/value store capability for ABI v1.0.

---

## 1. Capability identity

- kind: `kv`
- name: `default`
- version: `1`
- canonical id: `cap.kv.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("kv","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: GET
- 2: PUT
- 3: DEL
- 4: LIST

All modes return a stream handle.

### 3.1 GET (mode = 1)

Params:

```
HSTR key
```

Stream record (single record):

```
H1 found
if found == 1:
  HBYTES value
```

### 3.2 PUT (mode = 2)

Params:

```
HSTR key
HBYTES value
```

The `_ctl` response ok=1 is the success signal. The returned handle MUST be
endable and yield EOF on read.

### 3.3 DEL (mode = 3)

Params:

```
HSTR key
```

Stream record (single record):

```
H1 removed    ; 1 if deleted, 0 if missing
```

### 3.4 LIST (mode = 4)

Params:

```
HSTR prefix    ; "" for all keys
```

Stream record sequence:

```
HSTR key
```

The stream is a concatenation of HSTR records.

---

## 4. Errors

Errors MUST use `_ctl` error envelopes.
