<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Ownership: `zem` vs `lower`

This document defines a working ownership split between `zem` (mid-end) and `lower` (target backend), and the contract between stages.

The goal is a pipeline where JSONL IR can be heavily analyzed and rewritten in `zem`, then consumed by one or more backends (including `lower`) without smuggling target-specific assumptions into the mid-end.

## Principle model

- **Input:** JSONL IR (zasm IR; one record per line).
- **Mid-end:** `zem` can parse, analyze, optimize, and rewrite IR.
- **Output:** JSONL IR that is semantically equivalent to the input IR.
- **Backend:** `lower` (and other tools) consume optimized IR and perform CPU/system-specific lowering.

In other words: *`zem` is allowed to be aggressive, but not target-specific.*

## What belongs in `zem`

`zem` owns target-independent transformations whose correctness can be defined purely in terms of IR semantics.

Examples:

- Whole-program control-flow cleanup: reachability, jump threading, label canonicalization.
- Local cleanups: redundant loads, dead stores (with conservative alias barriers).
- Canonicalization and normalization: equivalent instruction forms, trivial folds.
- Analysis to produce optional side streams (future): facts/hints that are backend-agnostic.

Non-goals in `zem`:

- No instruction selection.
- No register allocation policy.
- No stack frame layout.
- No target encoding or microarchitectural peepholes.
- No ABI decisions beyond what the IR explicitly defines.

## What belongs in `lower`

`lower` owns CPU/system-specific decisions and any optimization that depends on the target.

Examples:

- Instruction selection and lowering strategy.
- Register allocation and calling convention details.
- Addressing-mode folding and target peepholes.
- Scheduling, code layout decisions driven by target constraints.
- Object format emission and platform integration.

Rule of thumb:

- If an optimization’s legality or benefit depends on a specific CPU, ABI, or encoding, it belongs in `lower`.

## Contract: IR in / IR out

### Required properties

Any `zem --opt` mode must produce IR that is:

1) **Schema-valid** for the current IR version.
2) **Semantics-preserving** under the IR execution model.
3) **Deterministic**: the same input produces byte-identical output (modulo explicitly permitted metadata).

### Practical guardrail

`zem` provides an optional “do-no-harm” validation mode:

- `--opt-validate` executes original and optimized IR and requires matching `rc`, `stdout`, and `stderr`.

This is a tool to accelerate iteration on aggressive mid-end rewrites while keeping a hard correctness backstop for programs that can be executed in `zem`.

Notes:

- `--opt-validate` is an execution-based equivalence check, not a proof.
- Backends should still treat IR validity and semantics as the primary contract.

### Side-streams (future)

If `zem` emits extra information for backends, treat it as:

- An optional hint/facts JSONL stream with explicit record kinds and versioning.
- Never required for correctness (only for quality).

## Compatibility and versioning

- The JSONL IR is the stable integration boundary between stages.
- `zem` should preserve the IR version and remain within the published schema.
- When `zem` must re-emit a modified record, it should keep schema-faithful operand shapes (even if internal parsers normalize forms).

## Determinism

Both `zem` and `lower` should aim for deterministic behavior:

- Stable record ordering.
- No timestamp- or environment-dependent output by default.
- Any optional metadata that can vary should be explicitly flagged and opt-in.
