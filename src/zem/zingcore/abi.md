# Runtime ABI

This document is the **de-facto** description of Zing’s runtime ABI surface: the set of externally-linked symbols that the compiler and standard library assume exist at link/runtime. It is contrary to the specification and it MUST NOT be taken as normative. This is status quo/as found and incorrect.

The ABI is intentionally **tiered** so Zing can be built in multiple configurations:

- a minimal “core” runtime (enough to run simple programs)
- an async-enabled runtime (futures, queues, time)
- a debug/runtime-development build (extra inspection hooks)

The goal is that a project can choose a runtime tier at link-time without changing source code, except where explicitly called out.

---

## Tiers

### Tier 0 — Core

Required to run “normal” programs (including streaming/stdio), regardless of async.

| Symbol | Signature (C) | Meaning | Used by |
|---|---|---|---|
| `alloc` / `_alloc` | `uintptr_t alloc(size_t size)` | Allocate raw memory for compiler/runtime objects. | compiler runtime support |
| `_free` | `void _free(uintptr_t ptr)` | Free memory allocated by `alloc` / `_alloc`. | compiler runtime support |
| `req_read` | `int32_t req_read(int32_t handle, void *ptr, size_t cap)` | Read from an input handle (stdin is `0`). | stdlib `stdin readInto:` |
| `res_write` | `int32_t res_write(int32_t handle, const void *ptr, size_t len)` | Write bytes to an output handle (stdout is `1`). | stdlib `writeBytes:` and streaming |
| `res_end` | `void res_end(int32_t handle)` | End/close a handle (no-op for stdio; meaningful for cap-backed handles). | stdlib / future expansion |
| `telemetry` | `void telemetry(const char *topic_ptr, int32_t topic_len, const char *msg_ptr, int32_t msg_len)` | Best-effort host telemetry. | stdlib `telemetry emit:` |
| `_ctl` | `int32_t _ctl(const void *req_ptr, size_t req_len, void *resp_ptr, size_t resp_cap)` | Host control plane request/response (caps list/open/etc). | stdlib `Zing·Ctl`, `Zing·Async` |

Notes:
- Some platforms/toolchains use underscore-prefixed exports (`_alloc`) while others call the unprefixed name (`alloc`). Both may exist in development builds.
- `_ctl` is the **only** normative capability control-plane entry point. Any `ctl(...)` alias is non-normative convenience.

---

### Tier 1 — Async

Required only if you use `Zing·Async`, `Zing·Future`, futures/scopes, or async capability framing.

| Symbol | Signature (C) | Meaning | Used by |
|---|---|---|---|
| `zi_now_ms_u32` | `uint32_t zi_now_ms_u32(void)` | Current time in ms (low 32 bits). | stdlib `Zing·Async` (`asyncNowMs`) |
| `zi_sleep_ms` | `int32_t zi_sleep_ms(uint32_t ms)` | Sleep/yield for (approximately) ms. | stdlib `Zing·Async` (`asyncSleepMs`) |
| `zi_zax_q_push` | `int32_t zi_zax_q_push(int32_t handle, int64_t ptr, int32_t len)` | Push a full ZAX frame for later re-reading. | stdlib `Zing·Async` (frame pushback) |
| `zi_zax_q_pop` | `int32_t zi_zax_q_pop(int32_t handle, int64_t out_ptr, int32_t out_cap)` | Pop a queued ZAX frame for a handle. | stdlib `Zing·Async` |
| `zi_future_scope_new` | `uint32_t zi_future_scope_new(int32_t handle, uint32_t scope_lo, uint32_t scope_hi)` | Allocate a runtime “scope” id bound to an async handle. | stdlib `Zing·Future` |
| `zi_future_scope_handle` | `int32_t zi_future_scope_handle(uint32_t scope_id)` | Get handle for a scope id. | stdlib `Zing·Future` |
| `zi_future_scope_lo` | `uint32_t zi_future_scope_lo(uint32_t scope_id)` | Get scope low id component. | stdlib `Zing·Future` |
| `zi_future_scope_hi` | `uint32_t zi_future_scope_hi(uint32_t scope_id)` | Get scope high id component. | stdlib `Zing·Future` |
| `zi_future_scope_next_req` | `uint32_t zi_future_scope_next_req(uint32_t scope_id)` | Next request id low component. | stdlib `Zing·Future` |
| `zi_future_scope_next_future` | `uint32_t zi_future_scope_next_future(uint32_t scope_id)` | Next future id low component. | stdlib `Zing·Future` |
| `zi_future_new` | `uint32_t zi_future_new(uint32_t scope_id, uint32_t future_lo, uint32_t future_hi)` | Allocate a runtime “future” id wrapper. | stdlib `Zing·Future` |
| `zi_future_scope` | `uint32_t zi_future_scope(uint32_t future_id)` | Get scope id for a future wrapper. | stdlib `Zing·Future` |
| `zi_future_handle` | `int32_t zi_future_handle(uint32_t future_id)` | Get handle for a future wrapper. | stdlib `Zing·Future` |
| `zi_future_id_lo` | `uint32_t zi_future_id_lo(uint32_t future_id)` | Get future low id component. | stdlib `Zing·Future` |
| `zi_future_id_hi` | `uint32_t zi_future_id_hi(uint32_t future_id)` | Get future high id component. | stdlib `Zing·Future` |

Determinism note:
- `zi_now_ms_u32` introduces runtime nondeterminism unless a deterministic clock is provided by the host runtime. A deterministic build may replace this with a controlled clock source.

---

### Tier 2 — KV / Managed Vars (legacy; slated for `_ctl`)

These provide a small host-side key/value defaulting mechanism.

| Symbol | Signature (C) | Meaning | Used by |
|---|---|---|---|
| `zi_mvar_get_u64` | `uintptr_t zi_mvar_get_u64(uint64_t key)` | Get value for a u64 key, or `0`. | compiler intrinsic lowering |
| `zi_mvar_set_default_u64` | `uintptr_t zi_mvar_set_default_u64(uint64_t key, uintptr_t value)` | Set default if absent; returns stored value. | compiler intrinsic lowering |
| `zi_mvar_get` | `uintptr_t zi_mvar_get(uintptr_t key_str)` | String-keyed wrapper (key hashed). | compiler intrinsic lowering |
| `zi_mvar_set_default` | `uintptr_t zi_mvar_set_default(uintptr_t key_str, uintptr_t value)` | String-keyed wrapper (key hashed). | compiler intrinsic lowering |
| `zi_mvar_preload_utf8` | `int32_t zi_mvar_preload_utf8(const char *key_ptr, int32_t key_len, uintptr_t value)` | Preload a key/value. | runtime tooling / tests |

Migration note:
- These are intended to move behind `_ctl` as a first-class “KV” capability. Until then, they are effectively “ABI KV”.

---

### Tier 3 — Debug / Development

Non-normative developer aids. These are not required for production runtimes.

| Symbol | Signature (C) | Meaning | Used by |
|---|---|---|---|
| `_debug_dump_buf` | `int32_t _debug_dump_buf(...)` | Optional debug dump of a Buffer layout. | compiler debug paths |
| `_debug_dump_u32` | `int32_t _debug_dump_u32(uint32_t v)` | Optional debug dump of a u32. | compiler debug paths |

---

## Compiler “hard dependencies” (must be refactored to remove)

These are currently emitted directly by the compiler backend and therefore behave like ABI, even if we intend to remove them.

| Symbol | Why it exists today | Where used |
|---|---|---|
| `zi_str_concat` | Compiler-emitted concat helper for `Str`/bytes objects. | `src/codegen/emitter/emit_core.c`, `src/codegen/emitter/emit_expressions.c` |
| `res_write_i32/u32/i64/u64` | Compiler-emitted numeric printing helpers. | `src/codegen/emitter/emit_core.c`, `src/codegen/emitter/emit_print.c` |

Policy note:
- If we remove these, we must first change lowering/codegen so concatenation/printing is expressed in terms of stdlib + `res_write`, or another deliberately-designed minimal primitive.

---

## Debug runtime additions (not part of the Zing language ABI)

The debug zingcore used for runtime development may expose additional C symbols (cap registries, handle tables). These are not required by the language/compiler and should not be depended upon by normal Zing programs.

Examples in `ext/debug/host/zingcore.c`:
- `zi_cap_registry`
- `zi_handle_register`, `zi_handle_unregister`, `zi_handle_get`

