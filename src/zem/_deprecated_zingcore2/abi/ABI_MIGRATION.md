# ABI Migration Notes (make it boring)

Goal: stop spending 30–60 minutes debugging flaky cap/runtime behavior by
reducing moving parts and making conformance checkable.

This document is intentionally practical: it describes how to evolve the
implementation while keeping the **portable host ABI** stable.

Normative portable ABI: `ext/debug/doc/01_ABI_CORE.md`.

---

## 1) Freeze the portable host ABI (v1)

Do not add new required imports. Keep the ABI at the fixed 7-function surface:

- `req_read`, `res_write`, `res_end`, `telemetry`, `_alloc`, `_free`, `_ctl`

Everything “extra” is:
- either a capability behind `_ctl`, or
- non-portable native-only linking (explicitly out of scope for portability).

---

## 2) Make `_ctl` small again (discovery + open)

Treat `_ctl` as a tiny control plane whose *required* responsibilities are:

- `CAPS_LIST` (sorted, deterministic)
- `CAPS_OPEN` (open a cap instance and return a handle)

Everything else (file ops, async ops, kv ops…) should be reachable by:
- opening a handle via `CAPS_OPEN`, then
- speaking a single framed data protocol over that handle (or using stream I/O
  directly if the cap is a raw byte stream).

This keeps the “ABI growth rule” intact while removing pressure to keep adding
more and more `_ctl` opcodes.

---

## 3) Separate “cap implementation” from “ABI plumbing”

The fragile part is usually not the ABI — it’s state management:
- handle registries
- per-handle queues
- selector dispatch tables
- lifetime / closing rules

Structure recommendation for the host runtime:

1. A minimal **ABI shim** that only provides the 7 functions.
2. A capability registry (listable, deterministic ordering).
3. Each cap implementation in its own module with explicit state, no hidden
   globals, and conformance tests.

This makes it possible to test cap logic without involving the compiler.

---

## 4) Native / WASM / JIT all fit the same model

### Native
You link a runtime library that *implements* the 7 ABI symbols. `_ctl` can
dispatch to caps that are also linked into the process.

### WASM
The embedder provides the same 7 functions as imports. `_ctl` dispatches to host
caps (filesystem, network, etc) according to the embedding policy.

### JIT
The host provides the 7 functions as callbacks (or trampolines). Same semantics.

The important part: guest code and stdlib don’t need to change.

---

## 5) Add conformance tests (fast feedback)

To avoid long “compile → link → run full suite” cycles, add a host-side
conformance runner that checks, at minimum:

- `CAPS_LIST` ordering and stability
- `CAPS_OPEN` handle allocation rules (0/1/2 reserved; first dynamic is 3)
- handle lifetime (`res_end` idempotence; post-end write failure)
- pointer/length validation behavior (`-1` on invalid pointers)

This should run in seconds, independent of the Zing compiler/tests.

---

## 6) What to do about “direct C calls”

Directly importing arbitrary C functions from Zing is useful for experiments,
but it is *not* portable to WASM/JIT unless:
- you also provide an equivalent capability behind `_ctl`, or
- you accept that the code is native-only.

If portability is the goal, keep the language/stdlib on the 7-function ABI and
put capabilities behind `_ctl`.

