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
