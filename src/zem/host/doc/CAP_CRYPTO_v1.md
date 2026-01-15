# Capability: cap.crypto.v1 (Normative)

This document defines the crypto capability for ABI v1.0.

---

## 1. Capability identity

- kind: `crypto`
- name: `default`
- version: `1`
- canonical id: `cap.crypto.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("crypto","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

---

## 3. CAPS_OPEN modes (streaming crypto, optional)

Streaming crypto is optional. Pure crypto ops are defined in `03_CTL_OPS.md`.

Mode values (H4):
- 1: HASH
- 2: HMAC
- 3: SIGN
- 4: VERIFY

All modes return a stream handle.

### 3.1 HASH (mode = 1)

Params:

```
HSTR alg
```

Usage:
- `res_write` streams data into the hash.
- `req_read` yields a single HBYTES digest record.

### 3.2 HMAC (mode = 2)

Params:

```
HSTR alg
HBYTES key
```

Usage:
- `res_write` streams data.
- `req_read` yields a single HBYTES mac record.

### 3.3 SIGN (mode = 3)

Params:

```
HSTR alg
HBYTES key_id     ; host-managed key reference
```

Usage:
- `res_write` streams data.
- `req_read` yields a single HBYTES signature record.

### 3.4 VERIFY (mode = 4)

Params:

```
HSTR alg
HBYTES public_key
HBYTES signature
```

Usage:
- `res_write` streams data.
- `req_read` yields a single H1 ok record (1 = valid, 0 = invalid).

---

## 4. Determinism

Crypto operations MUST be deterministic for identical inputs and keys.
