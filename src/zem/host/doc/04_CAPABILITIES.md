# Capability Kinds Specification

**Status:** NORMATIVE  
**Version:** 1.0.0

---

## 1. Overview

This document defines the standard capability kinds and their exact parameter formats for `CAPS_OPEN`.

All payloads are Hopper byte layouts. See `02_ZCL1_WIRE.md` for H1/H2/H4/H8, HSTR, and HBYTES.

**Key principle:** cloaks MAY omit any capability, but MUST report what exists via `CAPS_LIST`.

---

## 2. File Capability

### 2.1 Kind Registration

| Field | Value |
|-------|-------|
| `kind` | "file" |
| `name` | "view" (the cloak's file namespace) |

### 2.2 CAPS_OPEN Alias (Optional)

If a cloak exposes files via `CAPS_OPEN`, the params are:

```
H1 variant
... variant-specific fields ...
```

Variant 1: open by ID (recommended)

```
H1     variant = 1
HBYTES file_id
```

Variant 2: open by path (optional)

```
H1    variant = 2
HSTR  path
```

**Law:** If `variant` is unknown, return `#t_ctl_bad_params`.

### 2.3 FILE_LIST / FILE_OPEN

The canonical file operations are `FILE_LIST` (op=10) and `FILE_OPEN` (op=11).
See `03_CTL_OPS.md` for exact payload layouts.

---

## 3. Network Capability

### 3.1 TCP Registration

| Field | Value |
|-------|-------|
| `kind` | "net" |
| `name` | "tcp" |

### 3.2 Mode Values

| Mode | Meaning |
|------|---------|
| 1 | Connect |
| 2 | Listen (reserved) |

### 3.3 Connect Params

```
H1 variant = 1            ; connect variant
HSTR host                 ; hostname or IP address
H2 port                   ; port number
H4 connect_flags          ; connection flags
```

**connect_flags bits:**

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `ALLOW_DNS` | If 0, host must be literal IP |
| 1 | `PREFER_IPV6` | Prefer IPv6 if available |
| 2 | `NODELAY` | Disable Nagle's algorithm |

`NET_CONNECT` (op=20) uses the same params. See `03_CTL_OPS.md`.

---

## 4. Crypto Capability

Crypto is implemented as pure `_ctl` operations in v1.0:
- `CRYPTO_HASH` (op=50)
- `CRYPTO_HMAC` (op=51)
- `CRYPTO_RANDOM` (op=52)

Streaming crypto (hash/hmac/sign/verify) is optional and uses `CAPS_OPEN`.
See `caps/CAP_CRYPTO_v1.md` for modes and params.

---

## 5. Time Capability

- `kind`: "time"
- `name`: "default"

All time access is via `CAPS_OPEN`. See `caps/CAP_TIME_v1.md`.

---

## 6. KV Store Capability

- `kind`: "kv"
- `name`: "default"

All KV access is via `CAPS_OPEN`. See `caps/CAP_KV_v1.md`.

---

## 7. Additional Capability Packs

For these capabilities, the exact byte layouts are defined in the capability pack:

- `cap.entropy.v1` -> `caps/CAP_ENTROPY_v1.md`
- `cap.proc.v1` -> `caps/CAP_PROC_v1.md`
- `cap.sys.v1` -> `caps/CAP_SYS_v1.md`
- `cap.fs.watch.v1` -> `caps/CAP_FS_WATCH_v1.md`
- `cap.accel.v1` -> `caps/CAP_ACCEL_v1.md`
- `cap.reactor.v1` -> `caps/CAP_REACTOR_v1.md`

---

## 8. CAPS_DESCRIBE Schema

`CAPS_DESCRIBE` returns **opaque bytes**. The schema format is host-defined.
If a host chooses JSON for tooling, it is carried inside HBYTES and is **not**
interpreted by the ABI.

---

## 9. Adding New Capabilities

To add a new capability:

1. Register a new `(kind, name)` pair
2. Define `mode` values (capability-specific)
3. Define `params` encoding with variant tags if needed
4. Define return `meta` format if applicable
5. Document determinism and replay requirements
6. Add it to `CAPS_LIST`

**Law:** New capabilities MUST be exposed via `_ctl`. No new imports are permitted.
