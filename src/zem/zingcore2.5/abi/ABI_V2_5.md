# zABI v2.5 — Runtime Notes (WIP)

This document will evolve into the normative description of behavior for the zABI 2.5 runtime implementation.

Scope here is the host-side semantics for:

- Core imports (`env.zi_*`): memory, streams, env, argv, telemetry, exec, etc.
- Capability registry semantics
- Async selector registration / discovery / invocation

Principles:

- The ABI is **small**, **sharp**, and designed for our ecosystem.
- Behavior must be deterministic and testable.

TODO:

- Formalize capability identity (`kind/name`) rules and naming conventions.
- Define selector naming (likely relative, e.g. `run.v1`, vs fully-qualified `exec.run.v1`).
- Define required introspection APIs (caps list, selectors list).
- Define error-code registry and stability policy.
