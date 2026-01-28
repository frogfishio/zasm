# zingcore2.5 (new runtime)

This folder is the start of the **zABI 2.5 reference runtime** we ship and evolve as a first-class product.

We are intentionally freezing the existing vendor snapshot under `src/zem/zingcore2.2_final/` as a reference/compatibility anchor.

## Goals

- Treat **zABI** as a product surface: predictable, testable, and hard to misuse.
- Provide a **host-side runtime** implementing the zABI 2.5 imports (`env.zi_*`) and capability model.
- Make semantics **precise** and **portable** (no “accidental” behavior from platform quirks).
- Keep codebase modular and auditable (avoid a monolithic `zingcore.c`).

## Non-goals (for now)

- Replacing the current `zingcore2.2_final` usage in `zem`/`zrun` immediately.
- Maintaining ABI1/underscore primitive compatibility.

## Design principles (“by the book”)

- **Specification-first**: behavior is defined by docs/tests; implementation follows.
- **Stable public headers** live in `zingcore/include/`.
- **No constructor side effects** in product code paths unless explicitly intended and tested.
  - Cap/selector registration should be explicit and deterministic.
- **Enumerability**: capability/selector introspection should be first-class (no test-only hacks).
- **Errors are structured**: stable error codes + stable messages where possible.
- **Strictness**: invalid inputs are rejected consistently; no silent truncation.

## Core ABI (golden)

The zABI 2.5 **core wire ABI** is intentionally small and stable. The full contract is declared in
`zingcore/include/zi_sysabi25.h`.

Core calls (always present):

- `zi_abi_version`
- `zi_ctl`
- `zi_read`, `zi_write`, `zi_end`
- `zi_alloc`, `zi_free`
- `zi_telemetry`

There is no `zi_abi_features` in the core ABI: discovery/negotiation is done via `zi_ctl`.

### What the core calls mean

- `zi_ctl` is the **authoritative** control-plane mechanism. Discovery, extensibility, and
  structured replies happen here (ZCL1 framing).
- `zi_read` / `zi_write` / `zi_end` operate on **host-defined handles** (`zi_handle_t`). There is no
  baked-in notion of stdin/stdout/stderr; those are provided by the embedding program.
- `zi_telemetry` is a **best-effort sink**. If the host does not install a telemetry hook it is a
  noop.

### “Facade” reality (wiring model)

The `zi_*` syscall entrypoints are a thin dispatch layer:

- If the embedding installs host hooks via `zi_runtime25_set_host()`, syscalls forward to those
  hooks.
- Otherwise `zi_read/write/end` can use the internal handle table (see `zi_handles25.*`) if the host
  has allocated handles with per-handle ops.
- If neither is wired, the syscall returns `ZI_E_NOSYS`.

This design keeps the ABI stable while allowing very different embeddings (native process, WASM
host, test harnesses, etc.).

## Caps discovery (optional extension)

If a runtime exposes any capabilities, it must provide the caps extension (`zi_cap_*` and
`zi_handle_hflags`). Capability discovery is done via `zi_ctl` (CAPS_LIST) which returns a
deterministic list and per-cap flags/metadata.

## Example: stdio + extra caps

See `zingcore/examples/stdio_caps_demo.c` for a concrete embedding that:

- Initializes `zingcore25`.
- Wires native memory mapping so `zi_ctl` can read/write request/response buffers.
- Registers three extra caps.
- Allocates three stream handles backed by POSIX fds (stdin/stdout/stderr) and then uses
  `zi_read`/`zi_write` on them.

## Explicit registration (no linker magic)

zingcore 2.5 intentionally avoids constructor-based or linker-section auto-registration.
The embedding program (host runtime glue) performs registration explicitly at startup:

1. Call `zingcore25_init()` (or `zi_caps_init()` + `zi_async_init()` if staying low-level).
2. Register capabilities via `zi_cap_register()`.
3. Register selectors via `zi_async_register()`.

This keeps startup deterministic and makes it obvious what the host exposes.

## Layout

- `zingcore/include/` — public headers (what embedders compile against)
- `zingcore/src/` — implementation modules (runtime, memory, streams, env, argv, telemetry)
- `zingcore/caps/` — capability implementations and selector modules
- `abi/` — ABI and capability specifications (human-readable)

## Migration plan (high-level)

1. Keep `zingcore2.2_final/` frozen.
2. Build `zingcore2.5/` runtime behind a separate build target.
3. Add/extend conformance tests that validate ABI behavior at the boundary.
4. Switch `zem`/`zrun` to link `zingcore2.5` when conformance is met.
