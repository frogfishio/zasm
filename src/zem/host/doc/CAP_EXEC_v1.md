# Capability: cap.exec.v1 (Normative)

**Status:** NORMATIVE  
**Version:** 1.0.0  
**Primary transport:** `cap.async.v1` (ZAX1) via `cap.async.selectors.v1`

This document defines the sandboxed **process execution** capability for ABI v1.x.
All **MUST/SHOULD/MUST NOT** requirements are normative.

`cap.exec.v1` is an **async capability**:
- Guests request work by sending ZAX1 `REGISTER_FUTURE` commands whose payload encodes a `CAP_SELECTOR` Async Source.
- Hosts complete work by emitting ZAX1 `FUTURE_OK` / `FUTURE_FAIL` events for the corresponding `future_id`.

`_ctl` remains the **bootstrap/control plane** only (open the async hub, discover capabilities).

---

## 1. Capability identity

- kind: `exec`
- name: `default`
- version: `1`
- canonical id: `cap.exec.v1`

Hosts MUST advertise this capability via `_ctl` `CAPS_LIST` when implemented.

---

## 2. Transport and selector surface (normative)

All EXEC operations are defined as selectors carried inside `cap.async.v1` `REGISTER_FUTURE`.

- ZAX1 framing, future lifecycle, and `FUTURE_FAIL` envelope are defined in `CAP_ASYNC_v1.md`.
- `CAP_SELECTOR` Async Source encoding is defined in `cap.async.selectors.v1`.

This document is authoritative for the meaning and payload layouts of the following selectors:

- `exec.start.v1`
- `exec.status.v1`

### 2.1 Canonical dispatch tuple

For this capability, `CAP_SELECTOR` MUST use:

- `cap_kind = "exec"`
- `cap_name = "default"`

Hosts MUST dispatch requests by the tuple `(cap_kind, cap_name, selector)`.

### 2.2 Error transport (normative)

Failures MUST be returned as `FUTURE_FAIL` events using the universal payload envelope defined by `cap.async.v1`:

```
HSTR   trace
HSTR   msg
HBYTES cause
```

- `trace` MUST be a stable, greppable identifier.
- `msg` MUST be human-readable UTF-8.
- `cause` MAY be empty.

Unless stated otherwise, all errors listed in this document are returned via `FUTURE_FAIL.trace`.

### 2.3 Common validation laws

These rules apply to all selectors in this capability:

- Hosts MUST validate Hopper layouts and reject malformed payloads.
- Hosts MUST reject trailing bytes (payload must be consumed exactly).
- Hosts MUST enforce limits declared in `CAPS_DESCRIBE` deterministically.

On validation failure, the host MUST complete the future with `t_async_bad_params`.

---

## 3. CAPS_DESCRIBE schema (informational)

`CAPS_DESCRIBE("exec","default")` returns opaque HBYTES.
If JSON is embedded for tooling, suggested keys (all OPTIONAL, host-defined):

- `allowlist`        : array of allowed program ids (logical names)
- `prog_id_syntax`   : documented syntax for `prog_id` (RECOMMENDED: ASCII alnum plus `/_-`, forbid `..`)
- `max_args`         : maximum argv entries (including argv[0])
- `max_env`          : maximum env entries
- `max_env_bytes`    : total UTF-8 bytes for env keys+vals
- `max_argv_bytes`   : total UTF-8 bytes for argv entries
- `max_stdin_bytes`  : total stdin bytes accepted (0 = no limit)
- `max_stdout_bytes` : per-stream soft limit (enforced deterministically)
- `time_limit_ms`    : wall clock cap (0 = no wall cap)
- `cpu_time_ms`      : CPU cap (0 = no CPU cap)
- `mem_limit_bytes`  : address space / RSS cap
- `max_handles`      : max total handles granted across streams
- `cwd_default`      : normalized default cwd (sandbox-rooted)
- `flags`            : bit0 network blocked (RECOMMENDED default = 1 unless host states otherwise),
                       bit1 inherit cwd allowed,
                       bit2 inherit env allowed,
                       bit3 allow_signals,
                       bit4 allow_tty (stdout/stderr may be pty)
- `signal_allow`     : optional list of signal names allowed if `allow_signals=1`
- `exit_map`         : mapping for timeout/limit/kill codes if different from recommendations

Describe SHOULD also state:
- STATUS retention grace period after process exit (ms)
- stdout/stderr pty policy if bit4 is set (canonicalization rules, still subject to byte limits)

**Law (limits):** If the host publishes any limit, it MUST enforce it deterministically.

---

## 4. Selector: exec.start.v1

Launches a sandboxed process.

### 4.1 Params (request)

All strings are UTF-8 and MUST NOT contain NUL (`0x00`) or control bytes `< 0x20`.

```
HSTR  prog_id
H4    flags          ; bit0=want_stdin, bit1=want_stdout, bit2=want_stderr
H4    argc
repeat argc:
  HSTR arg
H4    envc
repeat envc:
  HSTR key
  HSTR val
```

Validation laws:
- `prog_id` MUST be valid UTF-8 and MUST satisfy `prog_id_syntax` if declared.
- `prog_id` MUST match the host allowlist (if declared). Otherwise host MUST fail with `t_exec_not_allowed`.
- `argc` and `envc` MUST respect `max_args` / `max_env` if declared.
- Total argv bytes and env bytes MUST respect `max_argv_bytes` / `max_env_bytes` if declared.
- Hosts MUST validate UTF-8 for all textual fields; invalid encodings MUST fail with `t_exec_bad_encoding`.

Flags:
- bit0 `want_stdin`
- bit1 `want_stdout`
- bit2 `want_stderr`
- all other bits MUST be 0 in v1; non-zero unknown bits MUST fail with `t_async_bad_params`.

### 4.2 FUTURE_OK payload (success)

```
H4 exec_id
H4 status_flags      ; bit0=started, bit1=detached
H4 stdin_handle      ; 0 if not granted
H4 stdout_handle     ; 0 if not granted
H4 stderr_handle     ; 0 if not granted
```

Semantics:
- `exec_id` MUST be unique within the host process table and reusable only after final cleanup.
- `status_flags.bit0` MUST be set on success.
- If `want_stdin=0`, `stdin_handle` MUST be 0.
- If `want_stdout=0`, `stdout_handle` MUST be 0.
- If `want_stderr=0`, `stderr_handle` MUST be 0.

Handle semantics:
- Handles map to lembeh streams.
- `stdin_handle` is a **sink**: guest writes via `res_write(handle, ptr, len)`.
- `stdout_handle` and `stderr_handle` are **sources**: guest reads via `req_read(handle, ptr, cap)`.
- Host MUST close stdout/stderr handles on process exit or on limit breach.

### 4.3 Deterministic sandbox rules

- Process MUST run under a host-defined sandbox. No ambient filesystem/network access is implied.
- Network MUST remain blocked unless separately granted by another capability; if the host allows network, it MUST document policy in describe.
- Default inheritance: cwd/env/FDs MUST NOT be inherited unless explicitly allowed by describe flags.
- Args/env MUST be passed in the provided order. Host MUST NOT reorder or inject entries unless documented defaults apply.

### 4.4 Errors (FUTURE_FAIL.trace)

- `t_cap_missing`
- `t_cap_denied`
- `t_async_bad_params`
- `t_async_overflow`
- `t_exec_not_allowed` (prog_id not in allowlist)
- `t_exec_bad_prog` (prog_id violates syntax rules)
- `t_exec_bad_args` (argc/envc/bytes violate limits)
- `t_exec_limits` (resource policy denies request)
- `t_exec_not_found` (prog_id resolves to missing program)
- `t_exec_too_many_handles`
- `t_exec_bad_encoding` (argv/env not valid UTF-8)
- `t_exec_tty_denied` (tty requested/required but policy forbids)
- `t_exec_busy` (host scheduler refuses due to global load; MUST be deterministic)
- `t_ctl_timeout` (if host enforces timeout on start; see `CAP_ASYNC_v1.md` policy)

### 4.5 Example (payload bytes)

Example request params:

- `prog_id = "tools/echo"`
- `flags = 0b110` (stdout+stderr)
- `argc = 2` (`"echo"`, `"hi"`)
- `envc = 0`

Hex (params payload only):
```
09 00 00 00 74 6F 6F 6C 73 2F 65 63 68 6F    ; HSTR prog_id
06 00 00 00                                    ; H4 flags = 6
02 00 00 00                                    ; H4 argc = 2
04 00 00 00 65 63 68 6F                        ; HSTR "echo"
02 00 00 00 68 69                              ; HSTR "hi"
00 00 00 00                                    ; H4 envc = 0
```

Example success payload:

- `exec_id = 7`
- `status_flags = 1` (started)
- `stdin_handle = 0`
- `stdout_handle = 11`
- `stderr_handle = 12`

Hex (FUTURE_OK payload only):
```
07 00 00 00
01 00 00 00
00 00 00 00
0B 00 00 00
0C 00 00 00
```

---

## 5. Selector: exec.status.v1

Polls a process status.

### 5.1 Params (request)

```
H4 exec_id
```

### 5.2 FUTURE_OK payload (success)

```
H4 state   ; 0=running,1=exited,2=failed,3=timeout,4=killed
H4 code    ; exit code or host-defined failure/signal
```

State laws:
- State transitions MUST be monotonic: `running -> {exited, failed, timeout, killed}`.
- Once state != running, the process MUST NOT revert to running.

Exit code mapping:
- Hosts SHOULD provide a deterministic mapping from limit/time/kill to `code`.
- RECOMMENDED defaults (if different, publish in `exit_map` and keep stable):
  - timeout: 124
  - killed: 137
  - limits: 125

Handle closure laws:
- Once `state != running`, stdout/stderr MUST be closed (or close immediately after final bytes).
- STATUS visibility MUST be retained for at least the describe grace period (minimum 500 ms) or until all granted handles are closed, whichever is later.

### 5.3 Errors (FUTURE_FAIL.trace)

- `t_cap_missing`
- `t_cap_denied`
- `t_async_bad_params`
- `t_exec_not_listable` (STATUS restricted by policy)
- `t_exec_not_found` (unknown exec_id)

### 5.4 Example (payload bytes)

Request params `exec_id=42`:

Hex:
```
2A 00 00 00
```

Example response (running):

Hex:
```
00 00 00 00   ; state=0
00 00 00 00   ; code=0
```

Example response (timeout with recommended code 124):

Hex:
```
03 00 00 00   ; state=3
7C 00 00 00   ; code=124
```

---

## 6. Stream semantics (normative)

The stream handles returned by `exec.start.v1` MUST follow lembeh semantics.

### 6.1 stdin_handle

- Guest writes via `res_write(h, ptr, len)`.
- Host reads bytes as process stdin.
- If `max_stdin_bytes` is enforced, excess writes MUST fail deterministically.
- Writes after process exit MUST fail deterministically (return `-1`).

### 6.2 stdout_handle / stderr_handle

- Guest reads via `req_read(h, ptr, cap)`.
- Host writes bytes as process stdout/stderr.
- Hosts MAY coalesce writes but MUST preserve write order within each stream.
- Hosts MUST NOT interleave stdout and stderr (they are separate handles).
- EOF is indicated by `req_read` returning `0`.
- EOF MUST be sticky (subsequent reads return `0`).

### 6.3 Backpressure

If host buffers are full, the host MUST apply a deterministic policy:
- block its producer deterministically, or
- drop output deterministically according to documented policy.

Hosts MUST NOT allow unbounded buffer growth.

---

## 7. Determinism & security (normative)

- Hosts MUST enforce an allowlist of executable identities and reject arbitrary paths or `..` traversal.
- Resource limits (time/memory/stdio/handles) MUST be enforced deterministically.
- No implicit inheritance: env/cwd/descriptors are cleared unless explicitly allowed by policy.
- Hosts MUST NOT log argv/env/stdin contents; they may contain secrets.
- Given the same inputs and the same Specimen transcript, outputs MUST be identical.

---

## 8. Extensibility (normative)

- Existing selector strings and payload layouts MUST NOT change.
- New functionality MUST be introduced as new selectors with a new `.vN` suffix (e.g., `exec.signal.v2`).
- Unknown selector versions MUST fail with `t_async_unknown_selector` (from the async hub rules).

---

## 9. Conformance checklist (normative)

Host MUST:
1. Advertise `(kind="exec", name="default")` via `CAPS_LIST` when implemented.
2. Implement `exec.start.v1` and/or `exec.status.v1` exactly as specified if claimed.
3. Enforce bounds and limits deterministically.
4. Return failures via `FUTURE_FAIL` with stable trace codes.
5. Preserve per-stream ordering and close streams deterministically on terminal states.

Guest MUST:
1. Use the async hub (`cap.async.v1`) and `CAP_SELECTOR` encoding for EXEC operations.
2. Validate success payload layouts and reject malformed payloads.
3. Treat handles as lembeh streams and follow read/write direction rules.
