<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zasm Architecture

zasm is a small, stream-first toolchain that compiles a Z80‑flavored assembly language (“zASM”) into WebAssembly.

The architecture is intentionally simple:

- keep the frontend parser boring and robust
- use a stable, line-delimited IR as the contract between stages
- keep lowering logic explicit, deterministic, and testable

The toolchain is split into **two binaries** (plus a local harness):

- **`zas`** — parses zASM text → emits **JSONL IR** (one record per line)
- **`zld`** — reads JSONL IR → emits **WAT** (one WebAssembly text module)
- **`zrun`** — local runner/harness for executing `.wat/.wasm` and driving golden tests

This separation keeps the system composable:

- other languages (Forth, DSLs, etc.) can target **the IR** without reusing the lexer/parser
- the backend can evolve independently (e.g., better control-flow lowering) without changing the IR contract

> Note: This document explains *how the toolchain is built*. A separate stability/compatibility contract belongs in `STABILITY.md`.

---

## Pipeline

```
zASM source (text)
  → zas (stdin→stdout)
  → JSONL IR (stream)
  → zlnt (stdin→stderr)   ; optional but recommended static analysis
  → zld (stdin→stdout)
  → WAT module (text)
  → wat2wasm / other tool
  → .wasm
```

Both `zas` and `zld` operate as **filters**:

- input on stdin
- output on stdout
- diagnostics on stderr

This supports Unix-style composition and makes it easy to embed the toolchain in other systems.

---

## Stage 1: `zas` (frontend)

### Responsibilities

- lex/parse zASM
- normalize syntax into a small set of IR records
- attach locations (`line`) for diagnostics
- reject invalid syntax early

### Non-goals

- no semantic analysis beyond syntax-level validation
- no code generation decisions (those belong in `zld`)

### Implementation notes

- implemented with **flex/bison** for predictable behavior and strong error handling
- emits JSON objects, one per line (**JSONL**)
- directives (`DB`, `DW`, `RESB`, …) are emitted as records; data packing is performed by `zld`

---

## Pipeline boundary: JSONL IR (contract)

The JSONL IR is the stable contract between stages.

- it is line-delimited (streamable)
- each line is a single JSON object
- a `.zobj.jsonl` file is valid if **every line** validates against the IR schema

Why JSONL:

- easy to generate from many languages
- easy to debug with standard tooling (`jq`, `sed`, `grep`)
- safe to stream without buffering the whole program

Files:

- `schema/record.schema.json` defines one record

Rules of thumb:

- extend by adding optional fields when possible
- breaking schema changes should be rare and deliberate

---

## Stage 2: `zld` (lowering + “linking”)

### Responsibilities

`zld` turns the IR stream into a single WAT module.

It performs the work that a classic assembler + linker would do:

- resolve symbols
- lay out static data in linear memory
- build globals/constants for labels
- lower control flow and calls into valid WebAssembly

### Current baseline (v1.x)

WebAssembly control flow is structured; classic assembly is label + jump. The current backend uses a conservative lowering that preserves the assembly authoring model:

- split each function into basic blocks (labels define block boundaries)
- generate a small **PC dispatch loop** using `br_table`
- `JR` becomes: set `pc` to the target block index; branch back to the dispatcher

This is a correctness-first strategy:

- valid WAT for arbitrary label/jump patterns
- deterministic output (stable block packing and emission order)
- easy to test and fuzz

This lowering strategy is an **implementation detail** (it may change), but the observable behavior is part of the 1.x contract.

### Host primitives

Some calls are reserved “primitives” (symbols starting with `_`).

- they lower to imported functions
- they are the only built-in side effects

This keeps the user-level language small and makes the backend explicitly accountable for capabilities.

---

## Functions and calls

ZASM has a Z80-like feel, but the output is a WebAssembly module.

- Code is sliced into functions based on call targets.
- Each function receives a small fixed parameter set (handled by the module entry wrapper).
- Register-like names (`HL`, `DE`, `A`, etc.) are **function-local authoring constructs**.

### Calling convention (baseline)

The baseline convention used by the current examples and backend is:

- `HL` and `DE` form the primary 2-tuple used throughout the system.
  - most commonly this is a byte slice: `(HL,DE) = (ptr,len)`
- `CALL name` is a function call.
- `RET` returns from the current function.

Important:

- “Registers” are an **authoring model**. The backend is free to change internal lowering as long as observable behavior is preserved.
- Any symbol starting with `_` is reserved for host primitives (capability surface).

---

## Memory model

zasm targets WebAssembly linear memory.

The current policy is intentionally simple and deterministic:

- the module exports a linear memory
- static data directives allocate into a linear data region
- symbols referring to data become `global i32` constants (addresses)
- `RESB` reserves zero-initialized space by advancing the data cursor
- the data cursor advances deterministically and aligns to 4 bytes

This is a *policy*, not an accident. Deterministic layout is important for reproducible builds and content-addressed distribution.

Dynamic allocation is supported via an explicit primitive surface (e.g. `_alloc/_free`) rather than via an OS API.

Memory limits are enforced at two layers:

- `zld` emits a minimum of one page; it only emits a maximum when `--mem-max` is provided.
- `zrun` caps memory by default at 256MB (4096 pages). Override with `--mem` or `ZRUN_MEM`.
- Runner caps have a floor of 2MB and a ceiling of 2GB.
- If a program attempts to grow past the runner cap, `zrun` traps with `OOM: exceeded runner cap (cap=..., requested grow beyond ... pages)`.

---

## Error handling

The toolchain treats invalid input as a first-class case.

- `zas` errors: syntax-level issues (unexpected tokens, malformed directives)
- `zld` errors: unsupported instructions/forms, unknown symbols, invalid control flow

All errors should:

- print a clear tool-prefixed message (`zas:` / `zld:`)
- include a source line number when available

---

## Testing strategy

We prefer **golden end-to-end tests**.

A typical test path is:

```
.asm → zas → zld → (wat2wasm optional) → zrun → output bytes
```

Why golden tests:

- they verify the whole stack: parsing, IR, lowering, runtime ABI
- they prevent regressions when adding new ISA features

Unit tests may be added for:

- IR parsing/validation utilities
- symbol/data layout routines
- individual opcode lowering helpers

But the primary safety net remains end-to-end.

---

## Extensibility roadmap

zasm is designed so new frontends can be added without rewriting the backend.

- implement a new language → emit JSONL IR
- reuse `zld` to produce WAT

On the backend side, future improvements are expected to be incremental:

- more opcodes/directives
- better call/ABI declarations
- optional module/import/export directives
- improved control-flow lowering (fewer dispatch artifacts)

---


## Design principles

- **Stream-first:** stdin/stdout tools with JSONL boundaries.
- **Small contracts:** the IR is the interface; keep it stable.
- **Capability explicitness:** reserved primitives define side effects.
- **Boring correctness:** prefer simple lowering that is easy to validate.
- **Tests over vibes:** every new opcode gets an example + golden test.

---

## Architectural choices

This section captures *why* the project is shaped the way it is. The goal is a toolchain that stays small, deterministic, and easy to reason about.

### Stream-first ABI

zasm assumes a tiny host ABI with explicit streams:

- input is a stream (`zi_read`)
- output is a stream (`zi_write`)
- logging is optional (`zi_telemetry`)

Why:

- makes programs composable (filter-style)
- avoids accidental dependency on an OS surface
- keeps capabilities explicit and audit-friendly

### Slice convention `(DE, BC)`

The canonical data value is a byte slice:

- `DE = ptr`
- `BC = len`

Why:

- works for strings, buffers, and I/O uniformly
- maps cleanly to linear memory
- gives future frontends (Forth / DSLs / a JS subset) a shared convention for “bytes”

### Reserved primitive namespace

Any symbol beginning with `_` is reserved for host-provided primitives.

Why:

- keeps side effects visible in source (`CALL zi_write` is unambiguous)
- provides a clean capability boundary
- avoids “magic” instructions that silently gain power

### Two-stage pipeline with a stable JSONL contract

`zas` and `zld` are split by a versioned JSONL IR.

### Planned opcode pipeline (`zxc`)

Future backend flow adds a second JSONL boundary for low-level opcode streams:

```
zas (zASM text)
  -> JSONL IR (zasm-v1.0)
  -> JSONL opcode stream (zasm-opcodes-v1)
  -> zxc
  -> target backend (zasm opcode bytes | x86_64 | arm64 | ...)
```

Notes:
- The opcode JSONL stream is fully resolved (no labels or relocations).
- `zxc` consumes raw opcode bytes; JSONL is an authoring/tooling format that
  can be packed into the byte stream.

Why:

- enables independent evolution of parsing vs lowering
- makes it easy to lint, diff, and fuzz the boundary
- allows other frontends to target IR directly
- supports concatenation/linking by simple stream composition

### WAT as an artifact, ZASM as the authoring format

The human-facing source is ZASM; WAT is a compilation artifact.

Why:

- WAT is correct but not pleasant to author for non-trivial control flow
- ZASM stays linear and readable while `zld` handles structured lowering

### Correctness-first control-flow lowering

WebAssembly control flow is structured; classic assembly uses labels and jumps. For v1, `zld` lowers label/jump control flow using a conservative PC + `br_table` dispatcher.

Why:

- produces valid WAT deterministically
- avoids a large compiler backend (SSA / CFG restructuring) at MVP time
- keeps lowering logic explicit and testable

This is treated as a stable baseline until a clearly-better structured lowering is justified.

### Deterministic output (hashable builds)

The backend aims to be deterministic:

- stable symbol resolution rules
- stable data layout (fixed start offset, alignment)
- stable emission order

Why:

- reproducible builds
- content-addressing friendliness
- less “heisenbug” debugging

---

## Stability and scope

zasm is intended to be used as core infrastructure. The goal is a small surface area with strong determinism.

### Must-have (stable in 1.x)

- **Stream-first tools**: `zas` and `zld` behave as stdin→stdout filters; diagnostics go to stderr.
- **Stable pipeline boundary**: JSONL IR is the integration contract between stages.
- **Deterministic output**: stable symbol rules, stable data layout policy, stable emission ordering.
- **Explicit capability surface**: side effects are only via reserved primitives (`_in`, `_out`, `_log`, …).
- **Slice convention**: `(HL,DE)` is the canonical `(ptr,len)` value.
- **Strict validation**:
  - unknown mnemonics/directives/operand forms are hard errors
  - unknown/duplicate symbols are hard errors
  - JSONL parse errors are hard errors with line numbers
- **Single-module output**: one WAT module that exports `lembeh_handle(req,res)` and uses zABI 2.0 imports under `"env"`.

### Should-have (quality improvements)

- **Human-friendly constants**: `EQU` and `STR` for offsets/lengths.
- **Analyzer/linter** (`zlnt`):
  - primitive contract checks (required registers)
  - obvious undefined-symbol and dead-label checks
  - machine-readable manifest (imports/exports/primitives)
- **Better debugging metadata**:
  - optional WASM name section (`zld --names`)
  - propagate source locations when available
- **Fuzzing** for both stages and the JSONL boundary.

### Won’t-have (core, by design)

- A WASI-like OS surface by default (files/env/clocks/etc.).
- A large macro language baked into `zas`/`zld`.
- Static typing inside ZASM.
- Non-deterministic output.
- Mandatory runtime/stdlib glued into every module.

## Lessons from real demos

- **FizzBuzz** proved arithmetic ergonomics matter; missing helpers (itoa, div/mod) explode code size.
- **Two-file builds** forced clarity on composition order and symbol ownership.
- **Stream tools (`cat`, `upper`)** validated the slice ABI and exposed the need for clear I/O contracts.
- **itoa library** highlighted that not all helpers belong in the `_` namespace; libraries scale better.

## Design directions (post-1.0)

The items below are framed as design directions rather than a task list. They
capture areas of likely evolution without committing to timelines.

### Memory and safety model

- Define segment metadata (data/heap/stack ranges) so memory is not a single flat blob.
- Consider optional bounds checks in codegen for `(HL)` and slice-based operations.
- Explore typed or annotated memory access forms (e.g., `LD A,(HL:buf)`) for static validation.

### Analyzer depth (`zlnt`)

- Extend safety checks for primitive calls and register liveness.
- Detect suspicious control flow (dead blocks, unused labels, confusing slice boundaries).
- Warn on name collisions between labels and data symbols.

### Contract hardening

- Keep IR version tagging explicit and enforced.
- Lock the memory policy (start offset, alignment, growth behavior).
- Add a primitive allow/deny surface (build-time or link-time).

### Metadata and tooling

- Provide manifest emission modes for tooling.
- Improve debug/name section support.
- Expand fuzz coverage for the JSONL boundary.
