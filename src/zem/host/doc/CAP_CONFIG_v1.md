# Capability: cap.config.v1 (Normative)

This document defines the configuration capability for ABI v1.x.
All MUST/SHOULD/MUST NOT are normative.

---

## 1. Capability identity

- kind: `config`
- name: `default`
- version: `1`
- canonical id: `cap.config.v1`

Hosts MUST advertise this capability via `CAPS_LIST` when implemented.

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("config","default")` returns opaque HBYTES.
If JSON is embedded for tooling, suggested keys (all optional, host-defined):
- `max_key_len`
- `max_val_len`
- `max_items` (for CONFIG_LIST)
- `namespaces` (allowed prefixes)
- `key_charset` (e.g., `A-Z a-z 0-9 . _ -` only)
- `flags` (bit0 = secrets masked in logs, bit1 = case-insensitive keys, bit2 = list_disabled)
- `mutation` (bool: whether SET/UNSET is supported; v1 is read-only; default false)
- `snapshot` (bool: LIST/GET served from an atomic snapshot; recommended true)

If unspecified, defaults are: case-sensitive keys, secrets masked, list enabled,
mutation disabled, `max_items` > 0, and atomic snapshot per request.

These fields are informational only; the ABI surface remains opaque HBYTES.

---

## 3. CONFIG_GET (op = 30)

Request payload:
```
HSTR key           ; UTF-8, deterministic case rules are host-defined but MUST be documented
```

Response payload (success):
```
HBYTES value
```

Requirements:
- Keys MUST be validated against `max_key_len` and allowed namespace rules.
- Values MAY be empty; size MUST respect `max_val_len`.
- Host MUST treat value as sensitive: no logging, zero-copy preferred, zeroize after send.
- Key syntax:
  - MUST be UTF-8.
  - RECOMMENDED charset: ASCII alnum plus `._-`; host MUST document deviations.
  - MAY include `.` as namespace separator; no `..` traversal semantics.
  - MUST NOT include `/` or path traversal.
  - MUST NOT contain NUL or control bytes < 0x20.
- Case rules:
  - If `flags` bit1 = 1, host compares keys case-insensitively but MUST return keys in canonical case.
  - Otherwise comparison is byte-exact.
- If namespaces are declared, host MUST reject keys outside allowed prefixes with `#t_config_bad_key`.
- Host MUST enforce per-request snapshot consistency: LIST/GET MUST see a stable view.

---

## 4. CONFIG_LIST (op = 31)

Request payload:
```
HSTR prefix        ; "" lists root namespace, host MAY scope results by caller
```

Response payload (success):
```
H4 n
repeat n:
  HSTR key
  H4 flags   ; bit0: secret (value redacted), bit1: readonly
```

Requirements:
- Ordering MUST be deterministic (lexicographic by key).
- Hosts MAY elide secret values; listing a key does not guarantee GET permission.
- n MUST NOT exceed `max_items`.
- Returned keys MUST respect the same namespace and case rules as GET.
- Prefix matching MUST be purely lexical (no globbing); `foo.` matches `foo.bar`, not `foobar`.
- If `flags.bit2` (list_disabled) is set, host MUST reject LIST with `#t_config_not_listable`.
- If snapshot=true in describe, LIST MUST reflect a single atomic snapshot.
- If secrets are present, host MUST mark them with flags.bit0=1 and MUST NOT reveal values in LIST.

---

## 5. Errors

Returned via `_ctl` error envelopes:
- `#t_cap_missing`
- `#t_cap_denied`
- `#t_ctl_bad_params`
- `#t_config_not_found`
- `#t_config_bad_key` (invalid namespace/length)
- `#t_config_too_large`
- `#t_config_redacted` (listed but not readable)
- `#t_config_not_listable` (LIST disabled by policy)
- `#t_config_unsupported` (op not supported in this version/policy)

---

## 6. Determinism & Security

- For identical inputs, CONFIG_GET/LIST MUST return identical outputs while the host configuration snapshot is unchanged.
- Hosts MUST freeze a consistent view per request (no partial mutations mid-response).
- Hosts MUST enforce namespace scoping per guest identity/session.
- Secrets MUST NOT be logged; callers SHOULD drop values after use.
- No ambient globals: all configuration flows through these ops; no fallback to env/cwd.
- LIST MUST NOT reveal values for `secret` keys; GET MAY still be denied even if LIST shows a key.
- Hosts SHOULD rate-limit and audit CONFIG_* requests; repeated denied GETs MUST NOT leak information through timing.
- If the host supports dynamic mutation outside the guest, it MUST document consistency guarantees (e.g., snapshot per request).
- Hosts MUST be explicit about case policy, charset, namespaces, and list availability in describe.
- Hosts SHOULD provide stable ordering and stable error behavior across versions for the same inputs.

---

## 7. Examples (wire)

### 7.1 CONFIG_GET request/response
```
Request: HSTR key="app.env"
Response: HBYTES value="prod"          ;; raw bytes
```

### 7.2 CONFIG_LIST with prefix
```
Request: HSTR prefix="db."
Response:
  H4 n=2
    HSTR "db.user"  H4 flags=0b10  ;; readonly
    HSTR "db.pass"  H4 flags=0b11  ;; secret + readonly
```

Deterministic ordering: "db.pass" comes after "db.user" in lexicographic order.
