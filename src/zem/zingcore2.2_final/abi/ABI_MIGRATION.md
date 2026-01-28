# zABI Migration Notes (make it boring)

Goal: stop spending 30–60 minutes debugging flaky cap/runtime behavior by
reducing moving parts and making conformance checkable.

This document is intentionally practical: it describes how to evolve the
implementation while keeping the **portable host zABI** stable.

Normative portable zABI: `zingcore/ABI_V2.md`.

---

## 1) Freeze the portable host zABI (v2)

Do not add “random externs”. Keep portability by treating `env.zi_*` as the
only stable host surface.

Required core for “hello world” stays tiny:
- `zi_abi_version`, `zi_abi_features`
- `zi_alloc`, `zi_free`
- `zi_read`, `zi_write`, `zi_end`
- `zi_telemetry`

Optional surfaces are feature-gated (queried via `zi_abi_features()`), and must
be documented + tested when added:
- `file/fs` (`zi_fs_*`)
- `exec/default` (`zi_exec_run`)
- `time/default` (`zi_time_*`)
- `async/default` (`zi_zax_*`, `zi_future_*`, …)
- `proc/default` (`zi_argc`, `zi_argv_*`, `zi_env_*`)

### Integration note: “frozen now” does not mean “no growth”

This migration plan is intentionally conservative:
- ABI v2.0 is treated as stable (no breaking changes).
- We still expect to add new entrypoints and new feature bits as the runtime grows.
- Larger conceptual changes (e.g. unifying pointer model across native/WASM/JIT) would require an ABI major bump, and should be treated as a separate project with a conformance runner.

---

## 2) Capabilities stay typed (no general message protocol)

The v2 direction is: capabilities are listed/opened via typed syscalls (no
general-purpose framed protocol). Keep any “cap plumbing” out of the zABI.

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

If portability is the goal, keep the language/stdlib on the zABI and avoid
making stdlib depend on extra native-only externs.
