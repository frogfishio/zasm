# zABI Reality Snapshot (zingcore2.2_final)

This document is **descriptive**, not aspirational.

- The old spec(s) are treated as historical/informative only.
- The **actual ABI** is what is exported by the shipped libraries in this folder.
- The job of v2.5 is to take this reality, decide what becomes normative, then harden + converge implementations.

## What this snapshot covers

Primary artifacts:
- `src/zem/zingcore2.2_final/lib/libzingcore.a`
- `src/zem/zingcore2.2_final/lib/libzingcore_debug.a`

This snapshot is derived from:
- exported global symbols (via `nm`), and
- the C definitions in `zingcore/src/*.c`.

## How to regenerate the symbol list

From repo root:

```sh
nm -gU src/zem/zingcore2.2_final/lib/libzingcore.a | egrep ' [Tt] (_)?(zi_|req_|res_|telemetry|_alloc|_free|_ctl|_cap)'
nm -gU src/zem/zingcore2.2_final/lib/libzingcore_debug.a | egrep ' [Tt] (_)?(zi_|req_|res_|telemetry|_alloc|_free|_ctl|_cap)'
```

(If `nm -gU` is unavailable on your platform, use `nm -g`.)

## Key reality notes (important)

### 1) The C ABI is currently *host-pointer flavored*

Several `zi_*` functions in `zingcore/src/zingcore.c` are implemented in terms of native pointers (`void*`, `uintptr_t`) and host-sized integers (`size_t`).

That means:
- the current exported ABI is **not directly WASM-offset portable** without a translation layer,
- and 32-bit vs 64-bit behavior is inherently different wherever `sizeof(void*)` / `sizeof(uintptr_t)` is used.

This is not a judgement; it’s just the current reality that v2.5 must explicitly resolve.

### 2) The shipped header `zingcore/include/zi_abi_v2.h` does not match the shipped implementation

In `zingcore2.2_final`, the header describes an `int32_t`-pointer syscall-style ABI, but the implementation exports different signatures for multiple symbols (notably core I/O, alloc/free/end, and several cap/fs functions).

For v2.5 to be “unbreakable”, the canonical header must be mechanically kept in lockstep with the code (compile-time enforced).

### 3) Guest-visible object layouts depend on host pointer size

Examples in `zingcore/src/zingcore.c`:
- `ZI_BUFFER_HEADER = sizeof(void*) + 8`
- hopper buffer header uses `sizeof(uintptr_t)` and stores a host pointer in the header.

These are guaranteed portability fault lines for 32-bit targets and for WASM/JIT offset-style embeddings.

## Exported ABI surface (by library)

### `libzingcore.a` (minimal runtime)

Exports (subset; see `nm` output for the full list):
- Legacy/env-style: `_alloc`, `_free`, `_ctl`, `_cap`, `req_read`, `res_write`, `res_end`, `telemetry`
- Core v2-ish: `zi_abi_version`, `zi_abi_features`, `zi_read`, `zi_write`, `zi_end`, `zi_telemetry`, `zi_alloc`, `zi_free`
- Proc/env: `zi_argc`, `zi_argv_len`, `zi_argv_copy`, `zi_env_get_len`, `zi_env_get_copy`
- Cap/fs/exec/time: `zi_cap_*`, `zi_fs_*`, `zi_exec_run`, `zi_time_*`
- Async-ish: `zi_zax_*`, `zi_future_*`, `zi_hop_*`
- Utility/runtime objects: `zi_enum_alloc`, `zi_str_from_ptr_len`, `zi_str_concat`, `zi_mvar_*`, `zi_pump_*`

### `libzingcore_debug.a` (debug runtime + caps)

Exports everything from the minimal runtime plus additional cap/async helpers:
- cap registry helpers: `zi_cap_register`, `zi_cap_registry`
- async registry helpers: `zi_async_register`, `zi_async_find`
- network/files cap helpers: `zi_files_*`, `zi_net_policy_allow_connect`, `zi_async_tcp_*`

## Canonical source of truth (today)

Use these files when extracting/confirming real signatures:
- `src/zem/zingcore2.2_final/zingcore/src/zingcore.c`
- `src/zem/zingcore2.2_final/zingcore/src/zi_async.c`
- `src/zem/zingcore2.2_final/zingcore/src/zi_hopper.c`

## v2.5 hardening checklist (derived from reality)

This is the short list of what must be made explicit and enforceable to earn “normative/unbreakable”:

1. **One pointer model**
   - Either make offsets-in-linear-memory the ABI (recommended for portability), or explicitly bless native-address pointers (and accept that WASM/JIT must translate).

2. **One canonical header**
   - Exported symbol prototypes must be compile-time checked against the header in all builds.

3. **No host-pointer-sized fields in guest-visible layouts**
   - Replace `sizeof(void*)` / `sizeof(uintptr_t)`-dependent layouts with fixed-width little-endian layouts, or make them opaque handles.

4. **Conformance tests are part of the ABI**
   - A small runner that validates pointer validation behavior, handle rules, and deterministic ordering.

5. **Version/feature gating is enforced**
   - New functionality must be discoverable and not change meaning of existing calls.
